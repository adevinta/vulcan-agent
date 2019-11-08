package check

import (
	"context"
	"errors"
	"sync"

	"github.com/sirupsen/logrus"
)

var errInconsistent = errors.New("error compensating local status, the check state was left inconsistent")

// PersistenceUpdater defines a type that provides to the combined storage the ability to
// update in the persistence the status of the check "at the same time" that the state is
// updated in the local storage.
type PersistenceUpdater interface {
	UpdateCheckState(checkID string, state State) error
}

// CombinedStorage provides a storage that will update both locally and remotely the status of a check.
type CombinedStorage struct {
	log    *logrus.Entry
	remote PersistenceUpdater
	Storage
	m sync.Mutex
}

// NewCombinedStorage creates a new instance with the fields properly initialized.
func NewCombinedStorage(log *logrus.Entry, s Storage, r PersistenceUpdater) *CombinedStorage {
	return &CombinedStorage{
		log:     log,
		Storage: s,
		remote:  r,
		m:       sync.Mutex{},
	}
}

// NewJob Creates and add new job to the local and remote storage.
func (c *CombinedStorage) NewJob(parent context.Context, params JobParams, log *logrus.Entry) (Job, error) {
	j, err := c.Storage.NewJob(parent, params, log)
	if err != nil {
		if params.CheckID == "" {
			return j, err
		}
		status := StatusMalformed
		if _, ok := err.(*UnableToAddJobError); ok {
			status = StatusFailed
		}
		innerErr := c.remote.UpdateCheckState(params.CheckID, State{Status: status})
		if innerErr != nil {
			c.log.WithError(innerErr).Error("error updating check status in persistence")
		}
	}
	return j, err
}

// SetState update bot locally and in the remote storage the new state.
func (c *CombinedStorage) SetState(checkID string, state State) error {
	c.m.Lock()
	defer c.m.Unlock()
	// Check if the check is labeled to be timeout and we are
	// setting the status of the check to aborted.
	job, err := c.Storage.Get(checkID)
	if err != nil {
		return err
	}
	if job.WillTimeout && state.Status == StatusAborted {
		state.Status = StatusTimeout
	}
	prevState, err := c.Storage.State(checkID)
	if err != nil {
		return err
	}
	// Update the local storage. This also validates the state.
	err = c.Storage.SetState(checkID, state)
	if err != nil {
		return err
	}
	// Update the remote status of the check.
	err = c.remote.UpdateCheckState(checkID, state)
	// If an error happens here we will have an inconsistent status because locally the check will have a status
	// different from the remote one. We will let the caller handle this error, but should compensate the local state so
	// the two the states are consistent.
	if err != nil {
		// Compensate the state so we will not leave local state inconsistent.
		// In order to do it in a completely proper way we would need two phase commit support in the persistence,
		// by now we will assume the local state will not fail never and if it does we just return and inconsistent local state
		// so we can see the error in the logs.
		compErr := c.Storage.SetState(checkID, prevState)
		if compErr != nil {
			c.log.WithError(compErr).Error(errInconsistent)
		}
		return err
	}
	return nil
}
