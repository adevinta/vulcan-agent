package stream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"

	agent "github.com/adevinta/vulcan-agent"
	"github.com/adevinta/vulcan-agent/check"
	metrics "github.com/adevinta/vulcan-metrics-client"
)

// Internal mutex
var mu sync.Mutex

// Possible statuses for the stream.
const (
	StatusConnecting   = "CONNECTING"
	StatusConnected    = "CONNECTED"
	StatusReconnecting = "RECONNECTING"
	StatusDisconnected = "DISCONNECTED"
)

// BufLen holds the length of the events buffer.
const BufLen = 10

// Stream represents a stream
type Stream struct {
	ctx           context.Context
	cancel        context.CancelFunc
	agent         agent.Agent
	storage       check.Storage
	metricsClient metrics.Client
	status        string
	endpoint      string
	stream        *websocket.Conn
	streamDialer  *WSDialerWithRetries
	timeout       time.Duration
	events        chan Message
	log           *logrus.Entry
}

// Message represents a Stream message
type Message struct {
	Action  string `json:"action"`
	AgentID string `json:"agent_id"`
	ScanID  string `json:"scan_id"`
}

// New initializes and connects a new Stream
func New(ctx context.Context, cancel context.CancelFunc,
	agent agent.Agent, storage check.Storage, metricsClient metrics.Client, endpoint string,
	timeout time.Duration, log *logrus.Entry, retries int, retryInterval time.Duration) (Stream, error) {

	dialer := NewWSDialerWithRetries(websocket.DefaultDialer, log.WithField("stream", "dialer"), retries, retryInterval)
	conn, _, err := dialer.Dial(endpoint, http.Header{})
	if err != nil {
		return Stream{}, err
	}
	events := make(chan Message, BufLen)
	s := Stream{
		ctx:           ctx,
		cancel:        cancel,
		agent:         agent,
		storage:       storage,
		metricsClient: metricsClient,
		status:        StatusConnecting,
		endpoint:      endpoint,
		stream:        conn,
		streamDialer:  dialer,
		events:        events,
		timeout:       timeout,
		log:           log,
	}

	return s, nil
}

// HandleRegister manages the initial handshake with the persistence
// in a synchronous way.
func (s *Stream) HandleRegister() error {
	done := s.connect(func(msg Message) bool {
		// We consider the agent registered if, before the default timeout
		// passes, we receive a register message for this agent.
		return msg.Action == "register" && msg.AgentID == s.agent.ID()
	})
	err := <-done
	if err != nil {
		s.setStatus(StatusDisconnected)
		// Disconnect agent.
		s.cancel()
		return err
	}
	s.setStatus(StatusConnected)
	return nil
}

func (s *Stream) connect(connected func(Message) bool) <-chan error {
	done := make(chan error)
	go func() {
		var err error
		ticker := time.NewTicker(100 * time.Millisecond)
		// We set the timeout here in order to ensure we only read from
		// the websocket, at most, until the timeout elapses.
		s.stream.SetReadDeadline(time.Now().Add(s.timeout))
	LOOP:
		for {
			select {
			case <-ticker.C:
				msg := Message{}
				rcvErr := websocket.ReadJSON(s.stream, &msg)
				if rcvErr != nil {
					if strings.HasPrefix(rcvErr.Error(), "json:") {
						s.log.WithError(rcvErr).WithFields(logrus.Fields{
							"message": msg,
						}).Warn("error decoding stream message")
						continue
					}
					s.log.WithError(rcvErr).WithFields(logrus.Fields{
						"message": msg,
					}).Warn("error receiving stream message")
					err = rcvErr
					break LOOP
				}
				s.log.WithFields(logrus.Fields{
					"message": msg,
				}).Debug("stream message received")
				if connected(msg) {
					break LOOP
				}
			case <-s.ctx.Done():
				err = errors.New("agent context is done in stream")
				break LOOP
			}
		}
		done <- err
	}()
	return done
}

func (s *Stream) reconnect() error {
	s.setStatus(StatusReconnecting)
	s.log.Warn("stream reconnecting")
	conn, _, err := s.streamDialer.Dial(s.endpoint, http.Header{})
	if err != nil {
		return err
	}
	s.stream = conn
	done := s.connect(func(msg Message) bool {
		// We consider the agent to be reconnected if we receive any correct
		// message before the timeout passes.
		return true
	})
	err = <-done
	if err != nil {
		s.setStatus(StatusDisconnected)
		return err
	}
	s.log.Info("stream connected")
	s.setStatus(StatusConnected)
	return nil
}

func (s *Stream) processMessage(actions map[string]func(agent.Agent, string), msg Message) {
	if msg.AgentID != "" && msg.AgentID != s.agent.ID() {
		s.log.Debug("stream message for unknown agent")
		return
	}
	// We can safely pass the scanID to any function because only the
	// abortScan function takes into account the second parameter. If
	// that changes in the future we must redesign the way we run
	// functions to attend stream messages.
	if f, ok := actions[msg.Action]; ok {
		go f(s.agent, msg.ScanID)
	} else {
		s.log.WithFields(logrus.Fields{
			"action": msg.Action,
		}).Warn("stream message with unknown action")
	}
}

// HandleMessages handle Stream messages
func (s *Stream) HandleMessages(actions map[string]func(agent.Agent, string)) error {
	s.setStatus(StatusConnected)
	done := make(chan error)
	go func() {
		var err error
		ticker := time.NewTicker(100 * time.Millisecond)
	LOOP:
		for {
			select {
			case <-ticker.C:
				msg := Message{}
				// We set the timeout here in order to ensure we only read from
				// the websocket, at most, until the timeout elapses each time
				// we read.
				s.stream.SetReadDeadline(time.Now().Add(s.timeout))
				rcvErr := websocket.ReadJSON(s.stream, &msg)
				if rcvErr != nil {
					if strings.HasPrefix(rcvErr.Error(), "json:") {
						s.log.WithError(rcvErr).WithFields(logrus.Fields{
							"message": msg,
						}).Warn("error decoding stream message")
						continue
					}
					s.log.WithError(rcvErr).WithFields(logrus.Fields{
						"message": msg,
					}).Warn("error receiving stream message")
					// We had a timeout error try to reconnect one time.
					s.log.Warn("stream connection lost")
					err = s.reconnect()
					if err != nil {
						break LOOP
					}
					continue
				}
				s.log.WithFields(logrus.Fields{
					"message": msg,
				}).Debug("stream message received")
				s.incrReceivedMssgs(msg)
				s.processMessage(actions, msg)
			case <-s.ctx.Done():
				s.log.Debug("agent context in is done in stream")
				break LOOP
			}
		}
		done <- err
	}()
	err := <-done
	if err != nil {
		s.log.WithError(err).Error("stream disconnected")
		s.setStatus(StatusDisconnected)
		// Disconnect agent.
		s.cancel()
		return err
	}
	return nil
}

// disconnect closes the connection to a Stream
// This method exists for testing purposes only.
func (s *Stream) disconnect() error {
	return s.stream.Close()
}

// Status returns the status of a Stream
func (s *Stream) Status() string {
	mu.Lock()
	defer mu.Unlock()
	return s.status
}

// setStatus set the status of a Stream
func (s *Stream) setStatus(status string) {
	mu.Lock()
	defer mu.Unlock()
	s.status = status
}

// incrReceivedMssgs increments the metric for
// received messages from stream broadcasting.
func (s *Stream) incrReceivedMssgs(msg Message) {
	s.metricsClient.Push(metrics.Metric{
		Name:  "vulcan.stream.mssgs.received",
		Typ:   metrics.Count,
		Value: 1,
		Tags: []string{
			"component:agent",
			fmt.Sprint("action:", msg.Action),
		},
	})
}
