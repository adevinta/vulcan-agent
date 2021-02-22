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
	policy  backoff.Policy
	retries int
	log     log.Logger
}

// MustShortCircuit defines a function that will be called after getting an error.
// The function gets an error and returns true if a retry should not be triggered
// and false otherwise.
type MustShortCircuit func(error) bool

// NewRetryer allows to execute operations with retries and shortcircuit.
func NewRetryer(retries, interval int, l log.Logger) Retryer {
	policy := backoff.NewExponential(
		backoff.WithInterval(time.Duration(interval)*time.Second),
		backoff.WithJitterFactor(0.05),
		backoff.WithMaxRetries(retries),
	)
	return Retryer{
		retries: retries,
		policy:  policy,
		log:     l,
	}
}

// WithRetries executes the openation named "op", specified in the "exec"
// function using the exponential retries with backoff policy defined in the
// receiver. It also uses the given MustShorcircuit function to know if a
// concrete error indicates that no more retries must be performed.
func (b Retryer) WithRetries(op string, exec func() error) error {
	var err error
	retry, cancel := b.policy.Start(context.Background())
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
