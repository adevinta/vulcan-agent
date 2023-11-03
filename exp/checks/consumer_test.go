/*
Copyright 2021 Adevinta
*/

package checks

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/adevinta/vulcan-agent/v2/log"
)

type mockQueue struct {
	readMessage func(ctx context.Context) (*Message, error)
}

func (m mockQueue) ReadMessage(ctx context.Context) (*Message, error) {
	return m.readMessage(ctx)
}

type TrackDeletedMessage struct {
}

type mockMessage struct {
	Body      string
	Err       error
	TimesRead int
}

type inMemQueue struct {
	sync.Mutex
	wg           sync.WaitGroup
	current      int
	Messages     []mockMessage
	Processed    []Message
	NotProcessed []Message
}

// Wait waits for all the onogoing goroutines that are wating for a message to
// be consumed to finish.
func (i *inMemQueue) Wait() {
	i.wg.Wait()
}

func (i *inMemQueue) ReadMessage(_ context.Context) (*Message, error) {
	i.Lock()
	defer i.Unlock()
	if i.current >= len(i.Messages) {
		return nil, nil
	}
	msg := i.Messages[i.current]
	i.current++

	err := msg.Err
	if err != nil {
		return nil, err
	}
	processed := make(chan bool, 1)
	result := &Message{
		Body:      msg.Body,
		TimesRead: msg.TimesRead,
		Processed: processed,
	}
	i.wg.Add(1)
	go func(msg Message) {
		defer i.wg.Done()
		del := <-processed
		i.Lock()
		defer i.Unlock()
		if del {
			i.Processed = append(i.Processed, msg)
			return
		}
		i.NotProcessed = append(i.NotProcessed, msg)
	}(*result)
	return result, nil
}

type mockRunner struct {
	run func(check Check, timesRead int) error
}

func (m mockRunner) Run(check Check, timesRead int) error {
	return m.run(check, timesRead)
}

func TestConsumer(t *testing.T) {
	type fields struct {
		queue  Queue
		cfg    ConsumerCfg
		log    log.Logger
		Runner CheckRunner
	}
	tests := []struct {
		name   string
		fields fields
		ctx    context.Context
		want   error
		// wantState checks the internal states of a consumer for a given test.
		// if the state is the expected it returns an empty string, if it isn't,
		// it returns the difference between the wanted and the state the
		// consumer got.
		wantState func(c *Consumer) string
	}{
		{
			name: "RunsChecksReadFromQueueAndStops",
			fields: fields{
				log: &log.NullLog{},
				cfg: ConsumerCfg{
					MaxConcurrentChecks: 10,
					MaxReadTime:         toPtr(1 * time.Second),
				},
				queue: &inMemQueue{
					Messages: []mockMessage{
						{
							Body: string(mustMarshal(checkFixture)),
						},
					},
				},
				Runner: mockRunner{
					run: func(check Check, timesRead int) error {
						return nil
					},
				},
			},
			ctx:  context.Background(),
			want: ErrMaxTimeNoRead,
			wantState: func(c *Consumer) string {
				q := c.queue.(*inMemQueue)
				q.Wait()
				gotProcessed := q.Processed
				gotNotProcessed := q.NotProcessed
				wantProcessed := []Message{{
					Body: string(mustMarshal(checkFixture)),
				}}
				wantNotProcessed := []Message{}
				processedDiff := cmp.Diff(wantProcessed, gotProcessed)
				notProcessedDiff := cmp.Diff(wantNotProcessed, gotNotProcessed)
				return fmt.Sprintf("%s%s", processedDiff, notProcessedDiff)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConsumer(tt.fields.log, tt.fields.cfg, tt.fields.queue, tt.fields.Runner)
			done := c.Start(tt.ctx)
			got := <-done
			if !errors.Is(tt.want, got) {
				t.Fatalf("error want!=got, %+v!=%+v", tt.want, got)
			}
			stateDiff := tt.wantState(c)
			if stateDiff != "" {
				t.Fatalf("want state!=got state, diff %s", stateDiff)
			}
		})
	}
}

func toPtr[T any](v T) *T {
	return &v
}
