/*
Copyright 2023 Adevinta
*/

// Package chanqueue provides a local queue based on channels.
package chanqueue

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/adevinta/vulcan-agent/queue"
)

// ChanQueue represents a queue.
type ChanQueue struct {
	// MaxTimeNoRead is the maximum idle time before stop
	// processing messages.
	MaxTimeNoRead time.Duration

	c    chan queue.Message
	proc queue.MessageProcessor

	// mu protects the fields below.
	mu         sync.RWMutex
	lastReadAt *time.Time
}

// New returns a [ChanQueue]. Messages are processed with proc. If
// proc is nil, a processor must be set with
// [ChanQueue.SetMessageProcessor] before calling
// [ChanQueue.StartReading]. Otherwise, [ChanQueue.StartReading]
// returns an error and stops reading.
func New(proc queue.MessageProcessor) *ChanQueue {
	return &ChanQueue{
		c:             make(chan queue.Message),
		proc:          proc,
		mu:            sync.RWMutex{},
		MaxTimeNoRead: 10 * time.Second,
	}
}

// StartReading starts reading messages from the queue. It reads
// messages only when there are free tokens in the message processor.
// It will stop reading from the queue when the provided context is
// canceled. The caller can use the returned channel to track when the
// reader stops reading from the queue and all the messages have been
// processed.
func (q *ChanQueue) StartReading(ctx context.Context) <-chan error {
	errs := make(chan error)
	go func() {
		q.read(ctx, errs)
		close(errs)
	}()
	return errs
}

// read reads messages from the queue and processes them with the
// provided message processor. If no message processor has been set,
// it sends an error to the channel and returns without reading any
// message.
func (q *ChanQueue) read(ctx context.Context, errs chan<- error) {
	if q.proc == nil {
		errs <- errors.New("message processor is missing")
		return
	}

	var err error

	wg := sync.WaitGroup{}

	procCtx, procCancel := context.WithCancelCause(ctx)
	defer procCancel(nil)

loop:
	for {
		select {
		case <-procCtx.Done():
			err = context.Cause(procCtx)
			break loop
		case token := <-q.proc.FreeTokens():
			wg.Add(1)
			go func() {
				if err := q.process(procCtx, token); err != nil {
					procCancel(err)
				}
				wg.Done()
			}()
		}
	}

	wg.Wait()

	errs <- err
}

// process waits for a message and processes it using the provided
// [queue.MessageProcessor]. If it is not able to get a message in the
// time specified by ChanQueue.MaxTimeNoRead it returns a
// [queue.ErrMaxTimeNoRead] error.
func (q *ChanQueue) process(ctx context.Context, token any) (err error) {
	select {
	case msg := <-q.c:
		q.setLastReadAt(time.Now())

		msg.TimesRead++

		delete := <-q.proc.ProcessMessage(msg, token)
		if !delete {
			q.writeMessage(msg)
		}
	case <-ctx.Done():
		err = context.Cause(ctx)
		q.returnToken(token)
	case <-time.After(q.MaxTimeNoRead):
		err = queue.ErrMaxTimeNoRead
		q.returnToken(token)
	}
	return
}

// returnToken returns a token. It panics if the free tokens channel
// blocks.
func (q *ChanQueue) returnToken(token any) {
	select {
	case q.proc.FreeTokens() <- token:
	default:
		panic("could not return token")
	}
}

// setLastReadAt sets the time that is returned by
// [ChanQueue.LastMessageReceived].
func (q *ChanQueue) setLastReadAt(t time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.lastReadAt = &t
}

// LastMessageReceived returns the time when the last message was
// read. If no messages have been read it returns nil.
func (q *ChanQueue) LastMessageReceived() *time.Time {
	q.mu.RLock()
	defer q.mu.RUnlock()

	return q.lastReadAt
}

// SetMessageProcessor sets the queue's message processor. It must be
// set before calling [ChanQueue.StartReading].
func (q *ChanQueue) SetMessageProcessor(proc queue.MessageProcessor) {
	q.proc = proc
}

// Write writes a message with the specified body into the queue.
func (q *ChanQueue) Write(body string) error {
	go func() {
		q.c <- queue.Message{Body: body}
	}()
	return nil
}

// writeMessage writes the specified message into the queue.
func (q *ChanQueue) writeMessage(msg queue.Message) {
	go func() {
		q.c <- msg
	}()
}
