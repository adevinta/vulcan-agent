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

// MessageProcessor defines the methods needed by a queue reader
// implementation to process the messages it reads.
//
// FreeTokens returns a channel that can be used to get a token to
// call ProcessMessage.
//
// ProcessMessage processes the message given a token that must be
// obtained from FreeTokens. ProcessMessage is in charge of returning
// the token once the message has been processed. When the message has
// been processed the returned channel will indicate if the message
// must be deleted from the queue or not.
type MessageProcessor interface {
	FreeTokens() chan any
	ProcessMessage(msg Message, token any) <-chan bool
}

// Reader defines the methods that all the queue reader
// implementations must fulfill.
//
// StartReading starts reading messages from the queue. The caller can
// use the returned channel to track when the reader stops reading
// from the queue and all the messages have been processed.
//
// LastMessageReceived returns the time when the last message was
// read. If no messages have been read it returns nil.
type Reader interface {
	StartReading(ctx context.Context) <-chan error
	LastMessageReceived() *time.Time
}

// Writer defines the functions that a queue writer must implement.
type Writer interface {
	Write(body string) error
}

// discard is a [MessageProcessor] that discards all the received
// messages.
type discard struct {
	tokens chan any
}

// Discard returns a [MessageProcessor] that discards all the received
// messages.
func Discard() MessageProcessor {
	tokens := make(chan any, 1)
	tokens <- struct{}{}
	return &discard{
		tokens: tokens,
	}
}

// FreeTokens returns a channel that can be used to get a free token
// to call ProcessMessage.
func (proc *discard) FreeTokens() chan any {
	return proc.tokens
}

// ProcessMessage discards the message and returns the provided token.
func (proc *discard) ProcessMessage(msg Message, token any) <-chan bool {
	c := make(chan bool)
	go func() {
		select {
		case proc.tokens <- token:
		default:
			panic("could not return token")
		}
		c <- true
	}()
	return c
}
