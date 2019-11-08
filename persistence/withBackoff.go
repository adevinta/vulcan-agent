package persistence

import (
	"context"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/lestrrat-go/backoff"
	"github.com/adevinta/vulcan-agent/check"
)

type withBackoff struct {
	PersisterCheckStateUpdater
	policy backoff.Policy
	log    *logrus.Entry
}

// BackoffShortCircuit defines a function that will be called after getting an error.
// The function gets an error and returns true if a retry should not be triggered
// and false otherwise.
type BackoffShortCircuit func(error) bool

// WithBackoff wraps a persistence service with a backoff layer.
func WithBackoff(p PersisterCheckStateUpdater, retries int, log *logrus.Entry) PersisterCheckStateUpdater {
	policy := backoff.NewExponential(
		backoff.WithInterval(200*time.Millisecond),
		backoff.WithJitterFactor(0.05),
		backoff.WithMaxRetries(retries),
	)

	return withBackoff{
		PersisterCheckStateUpdater: p,
		policy:                     policy,
		log:                        log,
	}
}

func (b withBackoff) withBackoff(exec func() error) error {
	return b.withBackoffWithShortCircuit(exec, nil)
}

func (b withBackoff) withBackoffWithShortCircuit(exec func() error, shortCircuit BackoffShortCircuit) error {
	var err error
	retry, cancel := b.policy.Start(context.Background())
	defer cancel()
	n := 0
	for {
		err = exec()
		if err == nil {
			return nil
		}
		// Here we check if the error thar we are getting is a controlled one or not, that is,
		// if makes sense to continue retrying or not.
		if shortCircuit != nil && shortCircuit(err) {
			b.log.WithField("retry_number: ", n).Error("backoff finished because shortCircuit()=true")
			return err
		}
		select {
		case <-retry.Done():
			b.log.WithField("retry_number: ", n).Error("backoff finished unable to perform operation")
			return err
		case <-retry.Next():
			n++
			b.log.WithField("retry_number: ", n).Error("backoff fired. Retrying")
		}
	}
}

func (b withBackoff) CreateAgent(agentVersion, jobqueueID string) (agentID, jobqueueARN string, err error) {
	err = b.withBackoff(func() error {
		agentID, jobqueueARN, err = b.PersisterCheckStateUpdater.CreateAgent(agentVersion, jobqueueID)
		return err
	})
	return
}

func (b withBackoff) UpdateAgentStatus(agentID, agentStatus string) error {
	return b.withBackoff(func() error {
		return b.PersisterCheckStateUpdater.UpdateAgentStatus(agentID, agentStatus)
	})
}

func (b withBackoff) UpdateAgentHeartbeat(agentID string) error {
	return b.withBackoff(func() error {
		return b.PersisterCheckStateUpdater.UpdateAgentHeartbeat(agentID)
	})
}

func (b withBackoff) UpdateCheckAgent(checkID, agentID string) error {
	return b.withBackoff(func() error {
		return b.PersisterCheckStateUpdater.UpdateCheckAgent(checkID, agentID)
	})
}

func (b withBackoff) UpdateCheckState(checkID string, state check.State) error {
	return b.withBackoffWithShortCircuit(
		func() error {
			return b.PersisterCheckStateUpdater.UpdateCheckState(checkID, state)
		}, func(err error) bool {
			httpError, ok := err.(*HTTPError)
			if ok {
				// We want to shortcircuit the retry loop when the error is
				// because the check state is incorrect. For instance when we
				// are trying to set the status of a check to ABORTED when is
				// already FINISHED.
				stop := httpError.StatusCode == http.StatusPreconditionFailed ||
					httpError.StatusCode == http.StatusConflict
				return stop
			}
			return false
		})
}

func (b withBackoff) UpdateCheckRaw(checkID string, rawLink string) error {
	return b.withBackoff(func() error {
		return b.PersisterCheckStateUpdater.UpdateCheckRaw(checkID, rawLink)
	})
}

func (b withBackoff) UpdateCheckReport(checkID string, reportLink string) error {
	return b.withBackoff(func() error {
		return b.PersisterCheckStateUpdater.UpdateCheckReport(checkID, reportLink)
	})
}
