package chanqueue

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/adevinta/vulcan-agent/queue"
)

func TestChanQueue(t *testing.T) {
	msgs := []queue.Message{
		{
			Body:      "foo",
			TimesRead: 1,
		},
		{
			Body:      "bar",
			TimesRead: 1,
		},
		{
			Body:      "foobar",
			TimesRead: 1,
		},
	}

	rec := newMessageRecorder()
	q := New(rec)
	q.MaxTimeNoRead = 100 * time.Millisecond

	for _, msg := range msgs {
		q.Write(msg.Body)
	}

	err := <-q.StartReading(context.Background())

	if err != queue.ErrMaxTimeNoRead {
		t.Errorf("unexpected error: want: queue.ErrMaxTimeNoRead, got: %v", err)
	}

	if diff := cmp.Diff(msgs, rec.Messages(), cmpopts.SortSlices(messageLess)); diff != "" {
		t.Errorf("messages mismatch (-want +got):\n%v", diff)
	}
}

func TestChanQueue_multiple_reads(t *testing.T) {
	msgs := []queue.Message{
		{
			Body:      "foo",
			TimesRead: 1,
		},
		{
			Body:      "bar",
			TimesRead: 1,
		},
		{
			Body:      "foobar",
			TimesRead: 1,
		},
	}
	const firstBatch = 1

	rec := newMessageRecorder()
	q := New(rec)
	q.MaxTimeNoRead = 100 * time.Millisecond

	// First batch.
	for _, msg := range msgs[:firstBatch] {
		q.Write(msg.Body)
	}

	err := <-q.StartReading(context.Background())
	if err != queue.ErrMaxTimeNoRead {
		t.Errorf("unexpected error: want: queue.ErrMaxTimeNoRead, got: %v", err)
	}

	if diff := cmp.Diff(msgs[:firstBatch], rec.Messages(), cmpopts.SortSlices(messageLess)); diff != "" {
		t.Errorf("messages mismatch (-want +got):\n%v", diff)
	}

	// Second batch.
	for _, msg := range msgs[firstBatch:] {
		q.Write(msg.Body)
	}

	err = <-q.StartReading(context.Background())
	if err != queue.ErrMaxTimeNoRead {
		t.Errorf("unexpected error: want: queue.ErrMaxTimeNoRead, got: %v", err)
	}

	if diff := cmp.Diff(msgs, rec.Messages(), cmpopts.SortSlices(messageLess)); diff != "" {
		t.Errorf("messages mismatch (-want +got):\n%v", diff)
	}
}

func TestChanQueue_context(t *testing.T) {
	rec := newMessageRecorder()
	q := New(rec)
	q.MaxTimeNoRead = 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := <-q.StartReading(ctx)

	if err != context.DeadlineExceeded {
		t.Errorf("unexpected error: want: context.DeadlineExceeded, got: %v", err)
	}

	if got := rec.Messages(); got != nil {
		t.Errorf("unexpected msgs: %#v", got)
	}
}

func TestChanQueue_retry(t *testing.T) {
	msg := queue.Message{
		Body:      "foo",
		TimesRead: 5,
	}

	rec := newMessageRecorder()
	rec.Fails = 4

	q := New(rec)
	q.MaxTimeNoRead = 100 * time.Millisecond

	q.Write(msg.Body)

	err := <-q.StartReading(context.Background())

	if err != queue.ErrMaxTimeNoRead {
		t.Errorf("unexpected error: want: queue.ErrMaxTimeNoRead, got: %v", err)
	}

	if diff := cmp.Diff([]queue.Message{msg}, rec.Messages(), cmpopts.SortSlices(messageLess)); diff != "" {
		t.Errorf("messages mismatch (-want +got):\n%v", diff)
	}
}

type messageRecorder struct {
	tokens chan any
	mu     sync.RWMutex
	msgs   []queue.Message
	Fails  int
}

func newMessageRecorder() *messageRecorder {
	tokens := make(chan any, 1)
	tokens <- struct{}{}
	return &messageRecorder{
		tokens: tokens,
	}
}

func (rec *messageRecorder) FreeTokens() chan any {
	return rec.tokens
}

func (rec *messageRecorder) ProcessMessage(msg queue.Message, token any) <-chan bool {
	c := make(chan bool)
	go func() {
		ok := rec.success()
		if ok {
			rec.recordMessage(msg)
		}
		rec.tokens <- token
		c <- ok
	}()
	return c
}

func (rec *messageRecorder) success() bool {
	rec.mu.Lock()
	defer rec.mu.Unlock()

	if rec.Fails == 0 {
		return true
	}
	rec.Fails--
	return false
}

func (rec *messageRecorder) recordMessage(msg queue.Message) {
	rec.mu.Lock()
	defer rec.mu.Unlock()

	rec.msgs = append(rec.msgs, msg)
}

func (rec *messageRecorder) Messages() []queue.Message {
	rec.mu.RLock()
	defer rec.mu.RUnlock()

	return rec.msgs
}

func messageLess(a, b queue.Message) bool {
	return a.Body < b.Body
}
