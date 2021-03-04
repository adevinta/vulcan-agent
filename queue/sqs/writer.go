package sqs

import (
	"errors"
	"fmt"
	"sync"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
)

// Writer writes messages to and AWS SQS queue.
type Writer struct {
	*sync.RWMutex
	sqs      sqsiface.SQSAPI
	queueURL string
}

// NewWriter creates a new SQS writer to writer to given queue ARN using the
// passed in endpoint, or the default one if the it is empty.
func NewWriter(queueARN string, endpoint string, log log.Logger) (*Writer, error) {
	sess, err := session.NewSession()
	if err != nil {
		err = fmt.Errorf("creating AWS session %w", err)
		return nil, err
	}

	arn, err := arn.Parse(queueARN)
	if err != nil {
		err = fmt.Errorf("error parsing SQS queue ARN: %w", err)
		return nil, err
	}

	awsCfg := aws.NewConfig()
	if arn.Region != "" {
		awsCfg = awsCfg.WithRegion(arn.Region)
	}
	if endpoint != "" {
		awsCfg = awsCfg.WithEndpoint(endpoint)
	}
	sqsSrv := sqs.New(sess, awsCfg)

	params := &sqs.GetQueueUrlInput{
		QueueName: aws.String(arn.Resource),
	}
	if arn.AccountID != "" {
		params.SetQueueOwnerAWSAccountId(arn.AccountID)
	}
	resp, err := sqsSrv.GetQueueUrl(params)
	if err != nil {
		err = fmt.Errorf("error retrieving SQS queue URL: %w", err)
		return nil, err
	}
	if resp.QueueUrl == nil {
		return nil, errors.New("unexpected nill getting queue ARN")
	}
	return &Writer{
		queueURL: *resp.QueueUrl,
		sqs:      sqsSrv,
	}, nil
}

func (w *Writer) Write(body string) error {
	msg := &sqs.SendMessageInput{
		QueueUrl:    &w.queueURL,
		MessageBody: &body,
	}
	_, err := w.sqs.SendMessage(msg)
	return err
}
