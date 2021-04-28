/*
Copyright 2021 Adevinta
*/

package stateupdater

import (
	"encoding/json"
	"sync"
)

const (
	StatusCreated      = "CREATED"
	StatusQueued       = "QUEUED"
	StatusAssigned     = "ASSIGNED"
	StatusRunning      = "RUNNING"
	StatusTimeout      = "TIMEOUT"
	StatusAborted      = "ABORTED"
	StatusPurging      = "PURGING"
	StatusKilled       = "KILLED"
	StatusFailed       = "FAILED"
	StatusFinished     = "FINISHED"
	StatusMalformed    = "MALFORMED"
	StatusInconclusive = "INCONCLUSIVE"
)

// TerminalStatuses contains all the possible statuses of a check that are
// terminal.
var TerminalStatuses = map[string]struct{}{
	StatusFailed:       {},
	StatusFinished:     {},
	StatusInconclusive: {},
	StatusKilled:       {},
	StatusMalformed:    {},
	StatusTimeout:      {},
}

// CheckState defines the all the possible fields of the states
// sent to the check state queue.
type CheckState struct {
	ID       string   `json:"id" validate:"required"`
	Status   *string  `json:"status,omitempty"`
	AgentID  *string  `json:"agent_id,omitempty"`
	Report   *string  `json:"report,omitempty"`
	Raw      *string  `json:"raw,omitempty"`
	Progress *float32 `json:"progress,omitempty"`
}

// QueueWriter defines the queue services used by and
// updater to send the status updates.
type QueueWriter interface {
	Write(body string) error
}

// Updater takes a CheckState an send its to a queue using the defined queue
// writer.
type Updater struct {
	qw             QueueWriter
	terminalChecks sync.Map
}

// New creates a new updater using the provided queue writer.
func New(qw QueueWriter) *Updater {
	return &Updater{qw, sync.Map{}}
}

// UpdateState updates the state of tha check into the underlaying queue.
func (u *Updater) UpdateState(s CheckState) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	err = u.qw.Write(string(body))
	if err != nil {
		return err
	}
	status := ""
	if s.Status != nil {
		status = *s.Status
	}
	if _, ok := TerminalStatuses[status]; ok {
		u.terminalChecks.Store(s.ID, struct{}{})
	}
	return nil
}

// CheckStatusTerminal returns true if a check with the given ID has
// sent so far a state update including a status in a terminal state.
func (u *Updater) CheckStatusTerminal(ID string) bool {
	_, ok := u.terminalChecks.Load(ID)
	return ok
}

// DeleteCheckStatusTerminal deletes the information about a check that the
// Updater is storing.
func (u *Updater) DeleteCheckStatusTerminal(ID string) {
	u.terminalChecks.Delete(ID)
}
