package sqs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/queue"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/aws/aws-sdk-go/service/sqs/sqsiface"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var ErrMockError = errors.New("mockerror")

type SqsMock struct {
	sqsiface.SQSAPI
	MessageVisibilityChanger func(input *sqs.ChangeMessageVisibilityInput) (*sqs.ChangeMessageVisibilityOutput, error)
	MessageReceiver          func(ctx context.Context, input *sqs.ReceiveMessageInput, options ...request.Option) (*sqs.ReceiveMessageOutput, error)
	MessageDeleter           func(input *sqs.DeleteMessageInput) (*sqs.DeleteMessageOutput, error)
}

func (sq *SqsMock) ChangeMessageVisibility(input *sqs.ChangeMessageVisibilityInput) (*sqs.ChangeMessageVisibilityOutput, error) {
	return sq.MessageVisibilityChanger(input)
}

func (sq *SqsMock) ReceiveMessageWithContext(ctx context.Context, input *sqs.ReceiveMessageInput, options ...request.Option) (*sqs.ReceiveMessageOutput, error) {
	return sq.MessageReceiver(ctx, input, options...)
}

func (sq *SqsMock) DeleteMessage(input *sqs.DeleteMessageInput) (*sqs.DeleteMessageOutput, error) {
	return sq.MessageDeleter(input)
}

type InMemSQS struct {
	*sync.Mutex
	sqsiface.SQSAPI
	CVisiMsgs   []sqs.ChangeMessageVisibilityInput
	Msgs        []sqs.ReceiveMessageOutput
	InflightMsg []sqs.ReceiveMessageOutput
}

func (sq *InMemSQS) ChangeMessageVisibility(input *sqs.ChangeMessageVisibilityInput) (*sqs.ChangeMessageVisibilityOutput, error) {
	sq.Lock()
	defer sq.Unlock()
	for _, m := range sq.InflightMsg {
		if *m.Messages[0].ReceiptHandle == *input.ReceiptHandle {
			sq.CVisiMsgs = append(sq.CVisiMsgs, *input)
			return &sqs.ChangeMessageVisibilityOutput{}, nil
		}
	}
	return nil, ErrMockError
}

func (sq *InMemSQS) ReceiveMessageWithContext(ctx context.Context, input *sqs.ReceiveMessageInput, options ...request.Option) (*sqs.ReceiveMessageOutput, error) {
	if errors.Is(context.DeadlineExceeded, ctx.Err()) || errors.Is(context.Canceled, ctx.Err()) {
		return nil, ctx.Err()
	}
	sq.Lock()
	defer sq.Unlock()
	if len(sq.Msgs) < 1 {
		if *input.WaitTimeSeconds > 0 {
			waitTime := *input.WaitTimeSeconds
			time.Sleep(time.Second * time.Duration(waitTime))
		}
		return &sqs.ReceiveMessageOutput{}, nil
	}
	msg := sq.Msgs[len(sq.Msgs)-1]
	sq.Msgs = sq.Msgs[:len(sq.Msgs)-1]
	sq.InflightMsg = append(sq.InflightMsg, msg)
	return &msg, nil
}

func (sq *InMemSQS) DeleteMessage(input *sqs.DeleteMessageInput) (*sqs.DeleteMessageOutput, error) {
	sq.Lock()
	defer sq.Unlock()
	for i, m := range sq.InflightMsg {
		if *m.Messages[0].ReceiptHandle == *input.ReceiptHandle {
			head := sq.InflightMsg[0:i]
			var tail []sqs.ReceiveMessageOutput
			if i < len(sq.Msgs)-2 {
				tail = sq.InflightMsg[i:len(sq.Msgs)]
			}
			sq.InflightMsg = append(head, tail...)
			return &sqs.DeleteMessageOutput{}, nil
		}
	}
	return nil, ErrMockError
}

type messageProcessorMock struct {
	freeTokens     func() chan interface{}
	processMessage func(msg string, token interface{}) <-chan bool
}

func (mp *messageProcessorMock) FreeTokens() chan interface{} {
	return mp.freeTokens()
}

func (mp *messageProcessorMock) ProcessMessage(msg string, token interface{}) <-chan bool {
	return mp.processMessage(msg, token)
}

func TestReader_StartReading(t *testing.T) {
	type stateChecker func(r *Reader) string
	type fields struct {
		RWMutex               *sync.RWMutex
		sqs                   sqsiface.SQSAPI
		visibilityTimeout     int
		processMessageQuantum int
		poolingInterval       int
		receiveParams         sqs.ReceiveMessageInput
		wg                    *sync.WaitGroup
		lastMessageReceived   *time.Time
		log                   log.Logger
		Processor             queue.MessageProcessor
	}

	tests := []struct {
		name           string
		fields         fields
		runCtxProvider func() context.Context
		want           error
		stateChecker   stateChecker
	}{
		{
			name: "ReadsAndDeletesMessages",
			fields: fields{
				RWMutex: &sync.RWMutex{},
				sqs: &InMemSQS{
					Mutex: &sync.Mutex{},
					Msgs: []sqs.ReceiveMessageOutput{
						{
							Messages: []*sqs.Message{
								{
									Body:          strToPtr("msg1"),
									MessageId:     strToPtr("msg1"),
									ReceiptHandle: strToPtr("msg1"),
								},
							},
						},
					},
				},
				visibilityTimeout:     60,
				processMessageQuantum: 2,
				poolingInterval:       3,
				receiveParams:         sqs.ReceiveMessageInput{},
				log:                   &log.NullLog{},
				wg:                    &sync.WaitGroup{},
				Processor: &messageProcessorMock{
					freeTokens: func() chan interface{} {
						res := make(chan interface{}, 10)
						res <- struct{}{}
						return res
					},
					processMessage: func(msg string, token interface{}) <-chan bool {
						c := make(chan bool, 1)
						go func() {
							time.Sleep(3 * time.Second)
							c <- true
						}()
						return c
					},
				},
			},
			runCtxProvider: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				go func() {
					time.Sleep(6 * time.Second)
					cancel()
				}()
				return ctx
			},
			want: context.Canceled,
			stateChecker: func(r *Reader) string {
				gotSqs := r.sqs.(*InMemSQS)
				wantSqs := InMemSQS{

					InflightMsg: []sqs.ReceiveMessageOutput{},
					Msgs:        []sqs.ReceiveMessageOutput{},
					CVisiMsgs: []sqs.ChangeMessageVisibilityInput{
						{
							ReceiptHandle:     strToPtr("msg1"),
							VisibilityTimeout: intToPtr(60),
						},
					},
				}
				diff := cmp.Diff(wantSqs, *gotSqs, cmpopts.IgnoreFields(InMemSQS{}, "Mutex"))
				return diff
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Reader{
				RWMutex:               tt.fields.RWMutex,
				sqs:                   tt.fields.sqs,
				visibilityTimeout:     tt.fields.visibilityTimeout,
				processMessageQuantum: tt.fields.processMessageQuantum,
				poolingInterval:       tt.fields.poolingInterval,
				receiveParams:         tt.fields.receiveParams,
				wg:                    tt.fields.wg,
				lastMessageReceived:   tt.fields.lastMessageReceived,
				log:                   tt.fields.log,
				Processor:             tt.fields.Processor,
			}
			ctx := tt.runCtxProvider()
			finished := r.StartReading(ctx)
			gotErr := <-finished
			if !errors.Is(gotErr, tt.want) {
				t.Fatalf("gotErr != wantErr, %+v!=%+v", gotErr, tt.want)
			}
			stateDiff := tt.stateChecker(r)
			if stateDiff != "" {
				t.Fatalf("want state!=gotState, diff %s", stateDiff)
			}
		})
	}
}

func strToPtr(input string) *string {
	return &input
}

func intToPtr(in int64) *int64 {
	return &in
}
