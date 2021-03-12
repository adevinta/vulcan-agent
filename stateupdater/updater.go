/*
Copyright 2021 Adevinta
*/
package stateupdater

import "encoding/json"

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
	qw QueueWriter
}

// New creates a new updater using the provided queue writer.
func New(qw QueueWriter) *Updater {
	return &Updater{qw}
}

// UpdateState updates the state of tha check into the underlaying queue.
func (u *Updater) UpdateState(s CheckState) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return u.qw.Write(string(body))
}
