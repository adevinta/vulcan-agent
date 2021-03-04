package stream

import (
	"context"
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/adevinta/vulcan-agent/log"
)

// WSDialerWithRetries provides retries with backoff and jitter
// when initiating a connection to a websocket.
type WSDialerWithRetries struct {
	*websocket.Dialer
	retryer Retryer
	l       log.Logger
}

// NewWSDialerWithRetries creates a WSDialer with the given retries parameters.
func NewWSDialerWithRetries(dialer *websocket.Dialer, l log.Logger, r Retryer) *WSDialerWithRetries {
	return &WSDialerWithRetries{dialer, r, l}
}

// Dial wraps the dial function of the websocket dialer adding retries
// functionality.
func (ws *WSDialerWithRetries) Dial(ctx context.Context, urlStr string, requestHeader http.Header) (*websocket.Conn, *http.Response, error) {
	var (
		conn *websocket.Conn
		resp *http.Response
	)
	err := ws.retryer.WithRetries("WSDialer.Dial", func() error {
		var err error
		conn, resp, err = websocket.DefaultDialer.DialContext(ctx, urlStr, requestHeader)
		if err != nil {
			ws.l.Errorf("websocked error dialing %+v", err)
		}
		return err
	})
	return conn, resp, err
}
