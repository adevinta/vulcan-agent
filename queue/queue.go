/*
Copyright 2019 Adevinta
*/

package queue

import (
	"context"
	"errors"
	"time"
)

// ErrMaxTimeNoRead is returned by a queue reader when there were no
// messages available in the queue for more than the configured amount of
// time.
var ErrMaxTimeNoRead = errors.New("no messages available in the queue for more than the max time")

// Message defines the information a queue reader passes to a processor about a
// message.
type Message struct {
	// Body contains the body of the message to be processed.
	Body string
	// TimesRead contains the number of times this concrete message has been
	// read so far.
	TimesRead int
}

// MessageProcessor defines the methods needed by a queue reader implementation
// to process the messages it reads.
type MessageProcessor interface {
	FreeTokens() chan interface{}
	ProcessMessage(msg Message, token interface{}) <-chan bool
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
