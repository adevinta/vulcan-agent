package retryer

import (
	"context"
	"errors"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/lestrrat-go/backoff"
)

var (
	// ErrPermanent defines an error that when returned by an operation
	// shortcircuits the retries process.
	ErrPermanent = errors.New("permanet error")
)

// Retryer allows to execute operations using a retries with exponential backoff
// and optionally a shortcircuit function.
type Retryer struct {
	interval int
	retries  int
	log      log.Logger
}

// NewRetryer allows to execute operations with retries and shortcircuit.
func NewRetryer(retries, interval int, l log.Logger) Retryer {
	return Retryer{
		retries:  retries,
		interval: interval,
		log:      l,
	}
}

// WithRetries executes the openation named "op", specified in the "exec"
// function using the exponential retries with backoff policy defined in the
// receiver.
func (b Retryer) WithRetries(op string, exec func() error) error {
	var err error
	policy := backoff.NewExponential(
		backoff.WithInterval(time.Duration(b.interval)*time.Second),
		backoff.WithJitterFactor(0.05),
		backoff.WithMaxRetries(b.retries),
	)
	retry, cancel := policy.Start(context.Background())
	defer cancel()
	// In order to avoid counting the first call to the function as a retry we
	// initialize the retries counter to -1.
	retries := -1
	for {
		err = exec()
		retries++
		if err == nil {
			return nil
		}
		// Here we check if the error thar we are getting is a controlled one or not, that is,
		// if makes sense to continue retrying or not.
		if errors.Is(err, ErrPermanent) {
			b.log.Errorf(" ErrPersistent returned backoff finished, operation %+v, err %+v", op, err)
			return err
		}
		if retries == b.retries {
			b.log.Errorf("backoff finished at retry %d, unable to to finish operation %s, err %+v", retries, op, err)
			return err
		}
		select {
		case <-retry.Done():
			b.log.Errorf("backoff finished at retry %d, unable to to finish operation %s, err %+v", retries, op, err)
			return err
		case <-retry.Next():
			b.log.Errorf("retrying operation, retry: %d, operation  %s, err %+v", retries, op, err)
		}
	}
}
