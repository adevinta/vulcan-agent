package queue

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrMaxTimeNoRead is returned by a reader when more than the specified
	// amount of seconds has passed without getting a message from the queue.
	ErrMaxTimeNoRead = errors.New("maximun allowed for reading a message exceeded")
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
