package sqs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"

	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/queue"
)

const (
	MaxQuantumDelta = 3 // in seconds
)

type Reader struct {
	*sync.RWMutex
	sqs                   sqsiface.SQSAPI
	visibilityTimeout     int
	processMessageQuantum int
	poolingInterval       int
	receiveParams         sqs.ReceiveMessageInput
	wg                    *sync.WaitGroup
	lastMessageReceived   *time.Time
	log                   log.Logger
	maxTimeNoRead         *time.Duration
	Processor             queue.MessageProcessor
}

// NewReader creates a new Reader with the given processor, queueARN and config.
func NewReader(log log.Logger, cfg config.SQSReader, maxTimeNoRead *time.Duration, processor queue.MessageProcessor) (*Reader, error) {
	delta := cfg.VisibilityTimeout - cfg.ProcessQuantum
	if delta < MaxQuantumDelta {
		err := errors.New("difference between visibility timeout and quantum is too short")
		return nil, err
	}
	var consumer *Reader
	sess, err := session.NewSession()
	if err != nil {
		err = fmt.Errorf("error creating AWSSSession, %w", err)
		return consumer, err
	}
	arn, err := arn.Parse(cfg.ARN)
	if err != nil {
		return nil, fmt.Errorf("error parsing SQS queue ARN: %v", err)
	}

	awsCfg := aws.NewConfig()
	if arn.Region != "" {
		awsCfg = awsCfg.WithRegion(arn.Region)
	}
	if cfg.Endpoint != "" {
		awsCfg = awsCfg.WithEndpoint(cfg.Endpoint)
	}

	params := &sqs.GetQueueUrlInput{
		QueueName: aws.String(arn.Resource),
	}
	if arn.AccountID != "" {
		params.SetQueueOwnerAWSAccountId(arn.AccountID)
	}

	srv := sqs.New(sess, awsCfg)
	resp, err := srv.GetQueueUrl(params)
	if err != nil {
		return consumer, fmt.Errorf("error retrieving SQS queue URL: %v", err)
	}

	receiveParams := sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(*resp.QueueUrl),
		MaxNumberOfMessages: aws.Int64(1),
		WaitTimeSeconds:     aws.Int64(0),
		VisibilityTimeout:   aws.Int64(int64(cfg.VisibilityTimeout)),
	}
	return &Reader{
		RWMutex:               &sync.RWMutex{},
		Processor:             processor,
		visibilityTimeout:     cfg.VisibilityTimeout,
		processMessageQuantum: cfg.ProcessQuantum,
		poolingInterval:       cfg.PollingInterval,
		log:                   log,
		wg:                    &sync.WaitGroup{},
		receiveParams:         receiveParams,
		sqs:                   srv,
		maxTimeNoRead:         maxTimeNoRead,
		lastMessageReceived:   nil,
	}, nil

}

// StartReading starts reading messages from the sqs queue. It reads messages
// only when there are free tokens in the message processor. It will stop
// reading from the queue when the passed in context is canceled. The caller can
// use the returned channel to track when the reader stopped reading from the
// queue and all the messages it is tracking are finished processing.
func (r *Reader) StartReading(ctx context.Context) <-chan error {
	var done = make(chan error, 1)
	go r.read(ctx, done)
	var finished = make(chan error, 1)
	go func() {
		err := <-done
		r.wg.Wait()
		finished <- err
		close(finished)
	}()
	return finished
}

func (r *Reader) read(ctx context.Context, done chan<- error) {
	var (
		err error
		msg *sqs.Message
	)
loop:
	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			break loop
		case token := <-r.Processor.FreeTokens():
			msg, err = r.readMessage(ctx)
			if err == queue.ErrMaxTimeNoRead {
				r.log.Infof("reader stopped because max time without reading messages elapsed")
				break loop
			}
			if err != nil {
				break loop
			}
			r.wg.Add(1)
			go r.processAndTrack(msg, token)
		}
	}
	done <- err
	close(done)
}

func (r *Reader) readMessage(ctx context.Context) (*sqs.Message, error) {
	var msg *sqs.Message
	waitTime := int64(0)
	start := time.Now()
	for {
		r.receiveParams.WaitTimeSeconds = &waitTime
		resp, err := r.sqs.ReceiveMessageWithContext(ctx, &r.receiveParams)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, err
			}
			if aerr, ok := err.(awserr.Error); ok && aerr.Code() == request.CanceledErrorCode {
				return nil, context.Canceled
			}
			return nil, err
		}
		if len(resp.Messages) > 0 {
			r.log.Debugf("read message with id %+v from the sqs queue", *resp.Messages[0].MessageId)
			msg = resp.Messages[0]
			break
		}
		// Check if we need to stop the reader because more than expected time has passed.
		now := time.Now()
		if r.maxTimeNoRead != nil && now.Sub(start) > *r.maxTimeNoRead {
			return nil, queue.ErrMaxTimeNoRead
		}
		waitTime = int64(r.poolingInterval)
	}
	now := time.Now()
	r.setLastMessageReceived(&now)
	return msg, nil
}

func (r *Reader) setLastMessageReceived(t *time.Time) {
	r.Lock()
	r.lastMessageReceived = t
	r.Unlock()
}

func (r *Reader) processAndTrack(msg *sqs.Message, token interface{}) {
	defer r.wg.Done()
	if msg.Body == nil {
		r.log.Errorf("unexpected empty body message from sqs")
		// Invalid message delete from queue without processing.
		_, err := r.sqs.DeleteMessage(&sqs.DeleteMessageInput{
			ReceiptHandle: msg.ReceiptHandle,
			QueueUrl:      r.receiveParams.QueueUrl,
		})
		if err != nil {
			r.log.Errorf("deleting processed message", err.Error())
		}
	}
	r.log.Debugf("processing message with id: %s", *msg.MessageId)
	processed := r.Processor.ProcessMessage(*msg.Body, token)
	timer := time.NewTimer(time.Duration(r.processMessageQuantum) * time.Second)
loop:
	for {
		select {
		case <-timer.C:
			extime := int64(r.visibilityTimeout)
			r.log.Debugf("process quatum for message with id: %s elapsed.", *msg.MessageId)
			input := &sqs.ChangeMessageVisibilityInput{
				QueueUrl:          r.receiveParams.QueueUrl,
				ReceiptHandle:     msg.ReceiptHandle,
				VisibilityTimeout: &extime,
			}
			_, err := r.sqs.ChangeMessageVisibility(input)
			if err != nil {
				r.log.Errorf("extending message visibility time for message with id: %s, error: %+v", *msg.MessageId, err)
				break loop
			}
			r.log.Debugf("message with id: %s visibility extended.", *msg.MessageId)
			timer.Reset(time.Duration(r.processMessageQuantum) * time.Second)
		case delete := <-processed:
			r.log.Debugf("message with id: %s processed", *msg.MessageId)
			timer.Stop()
			if !delete {
				r.log.Debugf("unexpected error processing message with id: %s, message not deleted", *msg.MessageId)
				break loop
			}

			input := &sqs.DeleteMessageInput{
				QueueUrl:      r.receiveParams.QueueUrl,
				ReceiptHandle: msg.ReceiptHandle,
			}
			r.log.Debugf("deleting message with id: %s", *msg.MessageId)
			_, err := r.sqs.DeleteMessage(input)
			if err != nil {
				r.log.Errorf("deleting message with id: %s, error: %+v", *msg.MessageId, err)
				break loop
			}
			r.log.Debugf("message with id: %s deleted", *msg.MessageId)
			break loop
		}
	}
}

// LastMessageReceived returns the time where the last message was received by
// the Reader. If no message was received so far it returns nil.
func (r *Reader) LastMessageReceived() *time.Time {
	r.RLock()
	defer r.RUnlock()
	return r.lastMessageReceived
}
