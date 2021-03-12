/*
Copyright 2021 Adevinta
*/

package stream

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/adevinta/vulcan-agent/log"
)

var (
	// ReadTimeout specifies the time, in seconds, the streams wait for reading
	// the next message.
	ReadTimeout = 5
)

type readMessageResult struct {
	Error   error
	Message Message
}

// Retryer represents the functions used by the Stream for retrying when
// connecting to the stream.
type Retryer interface {
	WithRetries(op string, exec func() error) error
}

// Message describes a stream message
type Message struct {
	CheckID string `json:"check_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	ScanID  string `json:"scan_id,omitempty"`
	Action  string `json:"action"`
}

// MsgProcessor defines the function that the Stream will call when an abort
// message has been received.
type MsgProcessor interface {
	AbortCheck(ID string)
}

// Stream reads messages from the stream server and process them using a given
// message processor.
type Stream struct {
	p        MsgProcessor
	dialer   *WSDialerWithRetries
	l        log.Logger
	endpoint string
}

// New creates a new stream that will use the given processor to process the messages
// received by the Stream.
func New(l log.Logger, processor MsgProcessor, retryer Retryer, endpoint string) *Stream {
	dialer := NewWSDialerWithRetries(websocket.DefaultDialer, l, retryer)
	return &Stream{
		p:        processor,
		l:        l,
		dialer:   dialer,
		endpoint: endpoint,
	}
}

// ListenAndProcess start listening for new messages from a stream.
func (s *Stream) ListenAndProcess(ctx context.Context) (<-chan error, error) {
	conn, _, err := s.dialer.Dial(ctx, s.endpoint, http.Header{})
	if err != nil {
		return nil, err
	}
	var done = make(chan error, 1)
	go s.listenAndProcess(ctx, conn, done)
	return done, nil
}

func (s *Stream) listenAndProcess(ctx context.Context, conn *websocket.Conn, done chan<- error) {
	var (
		msgRead = s.readMessage(conn)
		err     error
	)
LOOP:
	for {
		select {
		case readRes := <-msgRead:
			err = readRes.Error
			if err != nil {
				if !errIsTimeout(err) {
					s.l.Errorf("error reading message from the stream: %s", err)
				}
				conn, err = s.reconnect(ctx)
				if err != nil {
					break LOOP
				}
				msgRead = s.readMessage(conn)
				continue
			}
			s.processMessage(readRes.Message)
			msgRead = s.readMessage(conn)
		case <-ctx.Done():
			err = ctx.Err()
			break LOOP
		}
	}
	// Ensure the read goroutine existed.
	<-s.readMessage(conn)
	done <- err
}

func (s *Stream) reconnect(ctx context.Context) (*websocket.Conn, error) {
	// Try to reconnect until a success or until the context is cancelled.
	var (
		conn *websocket.Conn
		err  error
	)
	for {
		conn, _, err = s.dialer.Dial(ctx, s.endpoint, http.Header{})
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			s.l.Errorf("trying to dial stream: %v", err)
			continue
		}
		return conn, nil
	}
}

func (s *Stream) readMessage(conn *websocket.Conn) <-chan readMessageResult {
	var read = make(chan readMessageResult)
	go func() {
		nextTime := time.Now()
		nextTime = nextTime.Add(time.Second * time.Duration(ReadTimeout))
		conn.SetReadDeadline(nextTime)
		var msg = new(Message)
		err := conn.ReadJSON(msg)
		read <- readMessageResult{Error: err, Message: *msg}
		close(read)
	}()
	return read
}

func (s *Stream) processMessage(msg Message) {
	switch msg.Action {
	case "ping":
	case "abort":
		if msg.CheckID == "" {
			s.l.Errorf("error, reading stream message abort without checkID")
			return
		}
		s.p.AbortCheck(msg.CheckID)
	default:
		s.l.Errorf("error unknown message received: %+v", msg)
	}
}

func errIsTimeout(err error) bool {
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return true
	}
	return false
}
