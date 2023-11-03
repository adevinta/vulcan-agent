package queue

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"

	"github.com/adevinta/vulcan-agent/v2/config"
	"github.com/adevinta/vulcan-agent/v2/exp/checks"
	"github.com/adevinta/vulcan-agent/v2/log"
)

const (
	MaxQuantumDelta = 3 // in seconds
)

type SQSReader struct {
	receiveParams         sqs.ReceiveMessageInput
	visibilityTimeout     int
	processMessageQuantum int
	trackingMessagesWG    *sync.WaitGroup
	log                   log.Logger
	sqs                   sqsiface.SQSAPI
}

func NewSQSReader(log log.Logger, cfg config.SQSReader) (*SQSReader, error) {
	sess, err := session.NewSession()
	if err != nil {
		err = fmt.Errorf("error creating AWSSSession, %w", err)
		return nil, err
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
		return nil, fmt.Errorf("error retrieving SQS queue URL: %v", err)
	}
	delta := cfg.VisibilityTimeout - cfg.ProcessQuantum
	if delta < MaxQuantumDelta {
		err := errors.New("difference between visibility timeout and quantum is too short")
		return nil, err
	}
	receiveParams := sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(*resp.QueueUrl),
		MaxNumberOfMessages: aws.Int64(1),
		WaitTimeSeconds:     aws.Int64(0),
		VisibilityTimeout:   aws.Int64(int64(cfg.VisibilityTimeout)),
		AttributeNames:      []*string{aws.String("ApproximateReceiveCount")},
	}
	reader := &SQSReader{
		receiveParams:      receiveParams,
		sqs:                srv,
		visibilityTimeout:  cfg.VisibilityTimeout,
		log:                log,
		trackingMessagesWG: &sync.WaitGroup{},
	}
	return reader, nil
}

func (r *SQSReader) trackMessage(msg sqs.Message, done <-chan bool) {
	defer r.trackingMessagesWG.Done()
	timer := time.NewTimer(time.Duration(r.processMessageQuantum) * time.Second)
loop:
	for {
		select {
		case <-timer.C:
			extendTime := int64(r.visibilityTimeout)
			input := &sqs.ChangeMessageVisibilityInput{
				QueueUrl:          r.receiveParams.QueueUrl,
				ReceiptHandle:     msg.ReceiptHandle,
				VisibilityTimeout: &extendTime,
			}
			_, err := r.sqs.ChangeMessageVisibility(input)
			if err != nil {
				r.log.Errorf("extending message visibility time for message with id: %s, error: %+v", *msg.MessageId, err)
				break loop
			}
			timer.Reset(time.Duration(r.processMessageQuantum) * time.Second)
		case delete := <-done:
			timer.Stop()
			if !delete {
				r.log.Errorf("unexpected error processing message with id: %s, message not deleted", *msg.MessageId)
				break loop
			}
			r.log.Debugf("deleting message with id %s", *msg.MessageId)
			input := &sqs.DeleteMessageInput{
				QueueUrl:      r.receiveParams.QueueUrl,
				ReceiptHandle: msg.ReceiptHandle,
			}
			_, err := r.sqs.DeleteMessage(input)
			if err != nil {
				r.log.Errorf("deleting message with id: %s, error: %+v", *msg.MessageId, err)
				break loop
			}
			break loop
		}
	}
}

func (r *SQSReader) ReadMessage(ctx context.Context) (*checks.Message, error) {
	var msg *sqs.Message
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

	if len(resp.Messages) == 0 {
		return nil, nil
	}
	msg = resp.Messages[0]
	err = validateSQSMessage(msg)
	if err != nil {
		// If the message is invalid we delete it from the queue.
		if msg.ReceiptHandle == nil {
			delErr := errors.New("can't delete invalid message, receipt handle is empty")
			return nil, errors.Join(delErr, err)
		}
		// Invalid message delete from queue without processing.
		_, err := r.sqs.DeleteMessage(&sqs.DeleteMessageInput{
			ReceiptHandle: msg.ReceiptHandle,
			QueueUrl:      r.receiveParams.QueueUrl,
		})
		if err != nil {
			delErr := fmt.Errorf("deleting invalid message: %w", err)
			return nil, errors.Join(delErr, err)
		}
		return nil, err
	}
	m := checks.Message{Body: *msg.Body}
	var n int
	if rc, ok := msg.Attributes["ApproximateReceiveCount"]; ok && rc != nil {
		n, err = strconv.Atoi(*rc)
		if err != nil {
			return nil, fmt.Errorf("error reading ApproximateReceiveCount msg attribute %v", err)
		}
	}
	m.TimesRead = n
	processed := make(chan bool, 1)
	m.Processed = processed
	r.trackingMessagesWG.Add(1)
	go r.trackMessage(*msg, processed)
	return &m, nil
}

func validateSQSMessage(msg *sqs.Message) error {
	if msg == nil {
		invalidErr := errors.New("%w: unexpected empty message")
		return errors.Join(checks.ErrInvalidMessage, invalidErr)
	}
	if msg.Body == nil {
		invalidErr := errors.New("unexpected empty body message")
		return errors.Join(checks.ErrInvalidMessage, invalidErr)
	}
	if msg.MessageId == nil {
		invalidErr := errors.New("unexpected empty message id")
		return errors.Join(checks.ErrInvalidMessage, invalidErr)
	}
	if msg.ReceiptHandle == nil {
		invalidErr := errors.New("unexpected empty receipt handle")
		return errors.Join(checks.ErrInvalidMessage, invalidErr)
	}
	return nil
}
