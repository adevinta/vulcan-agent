/*
Copyright 2021 Adevinta
*/

package aborted

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/retryer"
)

// Retryer represents the functions used by the Checks struct for retrying http
// requests.
type Retryer interface {
	WithRetries(op string, exec func() error) error
}

// Checks provides methods to query current checks that are aborted so they must
// not be started.
type Checks struct {
	sync.RWMutex
	addr     string
	client   http.Client
	canceled map[string]struct{}
	retryer  Retryer
}

// New return a new Checks structure that can be used to test if a concrete
// check has been aborted or not.
func New(l log.Logger, addr string, retryer Retryer) (*Checks, error) {
	_, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	c := http.Client{
		Transport: http.DefaultTransport,
	}
	return &Checks{
		addr:     addr,
		client:   c,
		canceled: make(map[string]struct{}),
		retryer:  retryer,
	}, nil
}

// IsAborted returns true if the specified ID has been marked to be aborted.
func (c *Checks) IsAborted(ID string) (bool, error) {
	c.RWMutex.RLock()
	_, ok := c.canceled[ID]
	c.RWMutex.RUnlock()
	if ok {
		return true, nil
	}
	// Update the internal list of checks and check again.
	ids, err := c.get()
	if err != nil {
		return false, err
	}
	c.RWMutex.Lock()
	c.canceled = make(map[string]struct{})
	for _, id := range ids {
		c.canceled[id] = struct{}{}
	}
	c.RWMutex.Unlock()

	c.RWMutex.RLock()
	_, ok = c.canceled[ID]
	c.RWMutex.RUnlock()
	return ok, nil
}

func (c *Checks) get() ([]string, error) {
	var (
		ids []string
		err error
	)
	err = c.retryer.WithRetries("GetAbortedChecks",
		func() error {
			resp, err := c.client.Get(c.addr)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errStr := fmt.Sprintf("getting current aborted checks, unexpected status code: %d", resp.StatusCode)
				err = fmt.Errorf("%s, %w", errStr, retryer.ErrPermanent)
				return err
			}
			ids = []string{""}
			content, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			err = json.Unmarshal(content, &ids)
			if err != nil && !errors.Is(err, io.EOF) {
				errStr := fmt.Sprintf("unmarshalling current aborted checks: %+v, body: %s", err, string(content))
				err = fmt.Errorf("%s, %w", errStr, retryer.ErrPermanent)
				return err
			}
			return err
		})
	return ids, err
}

// None return always false when asked if a check is aborted.
type None struct{}

// IsAborted restruns always false.
func (c *None) IsAborted(ID string) (bool, error) {
	return false, nil
}
