package stream

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lestrrat-go/backoff"
	"github.com/sirupsen/logrus"
)

// WSDialerWithRetries provides retries with backoff and jitter
// when initiating a connection to a websocket.
type WSDialerWithRetries struct {
	*websocket.Dialer
	p backoff.Policy
	l *logrus.Entry
}

// NewWSDialerWithRetries creates a WSDialer with the given retries parameters.
func NewWSDialerWithRetries(dialer *websocket.Dialer, log *logrus.Entry, retries int, interval time.Duration) *WSDialerWithRetries {
	p := backoff.NewExponential(
		backoff.WithInterval(interval),
		backoff.WithJitterFactor(0.05),
		backoff.WithMaxRetries(retries),
	)
	return &WSDialerWithRetries{dialer, p, log}
}

// Dial wraps the dial function of the websocket dialer adding retries
// functionality.
func (ws *WSDialerWithRetries) Dial(urlStr string, requestHeader http.Header) (*websocket.Conn, *http.Response, error) {
	var (
		conn *websocket.Conn
		resp *http.Response
	)
	err := withBackoff(ws.p, ws.l.WithField("websocket", "dial"), func() error {
		var err error
		conn, resp, err = websocket.DefaultDialer.Dial(urlStr, requestHeader)
		return err
	})
	return conn, resp, err
}

func withBackoff(p backoff.Policy, l *logrus.Entry, exec func() error) error {
	var err error
	retry, cancel := p.Start(context.Background())
	defer cancel()
	n := 0
	for {
		err = exec()
		if err == nil {
			return nil
		}
		select {
		case <-retry.Done():
			l.WithField("retry_number", n).Error("backoff finished unable to perform operation")
			return err
		case <-retry.Next():
			n++
			if n > 1 {
				l.WithField("retry_number", n-1).Error("backoff fired. Retrying")
			}
		}
	}
}
