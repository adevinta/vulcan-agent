package check

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// UnableToAddJobError error returned when was impossible to add a job to the local storage.
type UnableToAddJobError struct {
	error
}

// Storage defines Check storage interface
type Storage interface {
	// Add a check job to the check storage.
	Add(job Job) error
	// Get returns a check job from the check storage.
	Get(checkID string) (Job, error)
	// GetAll returns all check jobs from the check storage.
	GetAll() ([]Job, error)
	// GetAllByStatus returns all check jobs from the check storage with a specific status.
	GetAllByStatus(status string) ([]Job, error)
	// GetTerminal returns all check jobs from the check storage in terminal or
	// not terminal status, according to the specified in the parameter.
	GetTerminal(terminal bool) ([]Job, error)

	// Meta returns the metadata for a check job.
	Meta(checkID string) (interface{}, error)
	// SetMeta sets the metadata for a check job.
	SetMeta(checkID string, meta interface{}) error

	// State returns the current state of a check job.
	State(checkID string) (State, error)
	// SetState sets the current state of a check job.
	SetState(checkID string, state State) error

	// SetTimeout updates the context and cancel function of the Job with the
	// received timeout.
	SetTimeout(checkID string, timeout int) (Job, error)

	// SetTimeoutIfAbort marks a job to be labeled as timeout.
	// After this method is called for a given check if a call to SetState with status
	// canceled is made the state stored will timeout not aborted.
	SetTimeoutIfAbort(checkID string) error

	// NewJob creates and adds a job to the internal storage from the given parent context, params and log.
	NewJob(parent context.Context, params JobParams, log *logrus.Entry) (Job, error)
}

// MemoryStorage represent a Check storage
type MemoryStorage struct {
	checks map[string]Job
	mutex  sync.RWMutex
}

// NewMemoryStorage declares a new MemoryStorage
func NewMemoryStorage() MemoryStorage {
	return MemoryStorage{
		checks: make(map[string]Job),
		mutex:  sync.RWMutex{},
	}
}

// Add adds a check Job to a MemoryStorage
func (m *MemoryStorage) Add(job Job) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.checks[job.CheckID] = job

	return nil
}

// Get returns check Job for the given checkID
func (m *MemoryStorage) Get(checkID string) (Job, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	job, ok := m.checks[checkID]
	if !ok {
		return Job{}, errors.New("error retrieving unexisting job")
	}

	return job, nil
}

// GetAll returns all check jobs stored in the MemoryStorage
func (m *MemoryStorage) GetAll() ([]Job, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var jobs []Job

	for _, job := range m.checks {
		jobs = append(jobs, job)
	}

	return jobs, nil
}

// GetAllByStatus returns all check jobs from the check storage with a specific status.
func (m *MemoryStorage) GetAllByStatus(status string) ([]Job, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var jobs []Job

	for _, job := range m.checks {
		if job.State.Status == status {
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

// GetTerminal returns all check jobs from the check storage in terminal or
// not terminal status, according to the specified in the parameter.
func (m *MemoryStorage) GetTerminal(terminal bool) ([]Job, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var jobs []Job

	for _, job := range m.checks {
		t := IsStatusTerminal(job.State.Status)
		if (terminal && t) || (!terminal && !t) {
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

// Meta returns a check job metadata for the given checkID
func (m *MemoryStorage) Meta(checkID string) (interface{}, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	job, ok := m.checks[checkID]
	if !ok {
		return Job{}, errors.New("error retrieving metadata for unexisting job")
	}

	return job.Meta, nil
}

// SetMeta sets check job metadata for the given checkID
func (m *MemoryStorage) SetMeta(checkID string, meta interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	job, ok := m.checks[checkID]
	if !ok {
		return errors.New("error setting metadata for unexisting job")
	}

	job.Meta = meta
	m.checks[job.CheckID] = job

	return nil
}

// SetTimeout sets a timeout to the given checkID.
func (m *MemoryStorage) SetTimeout(checkID string, timeout int) (Job, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	job, ok := m.checks[checkID]
	if !ok {
		return Job{}, errors.New("error setting timeout for unexisting job")
	}

	job.Ctx, job.Cancel = context.WithTimeout(job.Ctx, time.Duration(timeout)*time.Second)

	m.checks[job.CheckID] = job

	return job, nil
}

// NewJob creates and adds a new Job from its JobParams.
// It will ensure that required parameters are not missing.
// It will return the newly created Job along with any errors encountered.
func (m *MemoryStorage) NewJob(parent context.Context, params JobParams, log *logrus.Entry) (Job, error) {
	var err error
	// Validate all the mandatory params are present.
	switch {
	case params.CheckID == "":
		err = errors.New("check job missing check ID")
	case params.Target == "":
		err = errors.New("check job missing image")
	case params.Timeout <= 0:
		err = errors.New("check job missing timeout")
	}

	if err != nil {
		return Job{}, err
	}

	job := Job{
		JobParams: JobParams{
			ScanID:        params.ScanID,
			ScanStartTime: params.ScanStartTime,
			CheckID:       params.CheckID,
			Target:        params.Target,
			Options:       params.Options,
			Image:         params.Image,
			Timeout:       params.Timeout,
		},
		log: log,
	}

	job.Ctx, job.Cancel = context.WithCancel(parent)

	err = m.Add(job)
	if err != nil {
		return Job{}, UnableToAddJobError{err}
	}
	return job, nil
}

// State returns check job state for the given checkID
func (m *MemoryStorage) State(checkID string) (State, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	job, ok := m.checks[checkID]
	if !ok {
		return State{}, errors.New("error retrieving state for unexisting job")
	}

	return job.State, nil
}

// SetState sets check job state for the given checkID
func (m *MemoryStorage) SetState(checkID string, state State) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	job, ok := m.checks[checkID]
	if !ok {
		return errors.New("error setting state for unexisting job")
	}

	// The status should never be empty.
	// We assume a nil status as no change.
	if state.Status != "" {
		job.State.Status = state.Status
	}

	// The progress should never go back.
	// We assume a nil progress as no change.
	if state.Progress != 0.0 {
		job.State.Progress = state.Progress
	}

	// The report should contain all mandatory fields.
	if state.Report.CheckID != "" {
		// We will return an error if it doesn't.
		err := state.Report.Validate()
		if err != nil {
			return err
		}

		job.State.Report = state.Report
	}

	m.checks[job.CheckID] = job

	return nil
}

// SetTimeoutIfAbort marks a job to be labeled as timeout.
// After this method is called for a given check, if a call to SetState with status
// aborted is made, the state stored will be timeout not aborted.
func (m *MemoryStorage) SetTimeoutIfAbort(checkID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	job, ok := m.checks[checkID]
	if !ok {
		return errors.New("error setting state for unexisting job")
	}
	job.WillTimeout = true
	m.checks[checkID] = job
	return nil
}
