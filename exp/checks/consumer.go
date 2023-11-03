/*
Copyright 2023 Adevinta
*/

package checks

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adevinta/vulcan-agent/v2/log"
)

var (
	ErrInvalidMessage       = errors.New("invalid message")
	ErrUnprocessableMessage = errors.New("unprocessable check message")
	// ErrMaxTimeNoRead is returned by a queue reader when there were no
	// messages available in the queue for more than the configured amount of
	// time.
	ErrMaxTimeNoRead = errors.New("no messages available in the queue for more than the max time")
)

type Message struct {
	Body      string
	TimesRead int
	// Processed will be written when a Consumer considers a message processed.
	// The value written will be true if the message is considered to be
	// successfully processed and can be deleted from the queue, otherwise the
	// value written will be false and the message should not be deleted from
	// queue so the consumer can retry processing it in the future.
	Processed chan<- bool
}

type Queue interface {
	ReadMessage(ctx context.Context) (*Message, error)
}

type CheckRunner interface {
	Run(check Check, timesRead int) error
}

type ConsumerCfg struct {
	MaxConcurrentChecks int
	MaxReadTime         *time.Duration
}

type Consumer struct {
	*sync.RWMutex
	cfg                 ConsumerCfg
	queue               Queue
	wg                  *sync.WaitGroup
	lastMessageReceived *time.Time
	log                 log.Logger
	Runner              CheckRunner
	nProcessingMessages uint32
}

// NewConsumer creates a new Reader with the given processor, queueARN and config.
func NewConsumer(log log.Logger, cfg ConsumerCfg, queue Queue, runner CheckRunner) *Consumer {
	return &Consumer{
		cfg:                 cfg,
		RWMutex:             &sync.RWMutex{},
		Runner:              runner,
		log:                 log,
		wg:                  &sync.WaitGroup{},
		queue:               queue,
		lastMessageReceived: nil,
		nProcessingMessages: 0,
	}
}

// Start starts reading messages from the queue. It will stop reading from the
// queue when the passed in context is canceled. The caller can use the returned
// channel to track when the reader stopped reading from the queue and all the
// checks being run are finished.
func (r *Consumer) Start(ctx context.Context) <-chan error {
	finished := make(chan error, 1)
	if r.cfg.MaxConcurrentChecks < 1 {
		finished <- errors.New("MaxConcurrentChecks must be greater than 0")
		return finished
	}
	done := make(chan error, 1)
	r.wg.Add(1)
	go r.consume(ctx, done)
	go func() {
		err := <-done
		r.wg.Wait()
		finished <- err
		close(finished)
	}()
	return finished
}

func (r *Consumer) consume(ctx context.Context, done chan<- error) {
	defer r.wg.Done()
	if r.Runner == nil {
		done <- errors.New("message processor is missing")
		close(done)
		return
	}
	tokens := make(chan struct{}, r.cfg.MaxConcurrentChecks)
	for i := 0; i < r.cfg.MaxConcurrentChecks; i++ {
		tokens <- struct{}{}
	}
	var (
		err error
		msg Message
	)
loop:
	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			break loop
		case <-tokens:
			msg, err = r.readMessage(ctx)
			if err == ErrMaxTimeNoRead {
				r.log.Infof("reader stopped: max time without reading messages elapsed")
				break loop
			}
			if err != nil {
				break loop
			}
			r.wg.Add(1)
			go r.process(msg, tokens)
		}
	}
	done <- err
	close(done)
}

func (r *Consumer) process(msg Message, done chan<- struct{}) {
	atomic.AddUint32(&r.nProcessingMessages, 1)
	defer func() {
		// Decrement the number of messages being processed, see:
		// https://golang.org/src/sync/atomic/doc.go?s=3841:3896#L87
		atomic.AddUint32(&r.nProcessingMessages, ^uint32(0))
		// Signal the message has been processed.
		done <- struct{}{}
		// Signal de goroutine has exited.
		r.wg.Done()
	}()
	check := Check{
		RunTime: time.Now().Unix(),
	}
	err := json.Unmarshal([]byte(msg.Body), &check)
	if err != nil {
		r.log.Errorf("unable to parse message %q: %v", msg.Body, err)
		msg.Processed <- true
		return
	}
	err = r.Runner.Run(check, msg.TimesRead)
	// A nil Processed channel means the queue reader that returned the message
	// is not interested in knowing when a message was processed.
	if msg.Processed == nil {
		return
	}
	del := true
	if err != nil {
		del = true
		r.log.Errorf("error processing message: %+v", err)
		if errors.Is(err, ErrUnprocessableMessage) {
			del = false
		}
	}
	msg.Processed <- del
}

func (r *Consumer) readMessage(ctx context.Context) (Message, error) {
	maxTimeNoRead := r.cfg.MaxReadTime
	start := time.Now()
	var msg Message
	for {
		readMsg, err := r.queue.ReadMessage(ctx)
		if err != nil {
			if errors.Is(err, ErrInvalidMessage) {
				r.log.Errorf("error reading message: %w")
				continue
			}
			return msg, err
		}
		if readMsg != nil {
			msg = *readMsg
			break
		}
		// Check if we need to stop the reader because we exceed the maximun time
		// trying to read a message.
		now := time.Now()
		n := atomic.LoadUint32(&r.nProcessingMessages)
		if maxTimeNoRead != nil && now.Sub(start) > *maxTimeNoRead && n == 0 {
			return Message{}, ErrMaxTimeNoRead
		}
	}
	now := time.Now()
	r.setLastMessageReceived(&now)
	return msg, nil
}

func (r *Consumer) setLastMessageReceived(t *time.Time) {
	r.Lock()
	r.lastMessageReceived = t
	r.Unlock()
}

// LastMessageReceived returns the time where the last message was received by
// the Reader. If no message was received so far it returns nil.
func (r *Consumer) LastMessageReceived() *time.Time {
	r.RLock()
	defer r.RUnlock()
	return r.lastMessageReceived
}

// SetMessageProcessor sets the queue's message processor. It must be
// set before calling [*Reader.StartReading].
func (r *Consumer) SetMessageProcessor(p CheckRunner) {
	r.Runner = p
}
