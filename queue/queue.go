package queue

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrMaxTimeNoRead is returned by a queue reader when there were no
	// messages available in the queue for more than the configured amount of
	// time.
	ErrMaxTimeNoRead = errors.New("no messages available in the queue for more than the max time")
)

// MessageProcessor defines the methods needed by a queue reader implementation
// to process the messages it reads.
type MessageProcessor interface {
	FreeTokens() chan interface{}
	ProcessMessage(msg string, token interface{}) <-chan bool
}

// Reader defines the functions that all the concrete queue reader
// implementations must fullfil.
type Reader interface {
	StartReading(ctx context.Context) <-chan error
	LastMessageReceived() *time.Time
}

// Writer defines the functions that a queue writer must implement.
type Writer interface {
	Write(body string) error
}
