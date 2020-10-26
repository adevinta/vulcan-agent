package check

import (
	"context"
	"encoding/json"
	"time"

	report "github.com/adevinta/vulcan-report"

	"github.com/sirupsen/logrus"
)

// Constants defining the possible statuses for a check job.
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

var terminalStatuses = []string{StatusAborted, StatusKilled, StatusFailed, StatusFinished, StatusMalformed, StatusTimeout, StatusInconclusive}

// JobParams stores the information necessary to create a new check job.
type JobParams struct {
	CheckID       string            `json:"check_id"`      // Required
	ScanID        string            `json:"scan_id"`       // Required
	ScanStartTime time.Time         `json:"start_time"`    // Required
	Image         string            `json:"image"`         // Required
	Target        string            `json:"target"`        // Required
	TargetType    string            `json:"target_type"`   // Required
	Timeout       int               `json:"timeout"`       // Required
	Options       string            `json:"options"`       // Optional
	RequiredVars  []string          `json:"required_vars"` // Optional
	Metadata      map[string]string `json:"metadata"`      // Optional
}

//UnmarshalJSON handles the special format for scanStartTime
//and also replace the scan_id with the check_id if the former is not foung
func (jp *JobParams) UnmarshalJSON(data []byte) error {
	type Alias JobParams
	tmp := &struct {
		ScanStartTime string `json:"start_time"`
		*Alias
	}{
		Alias: (*Alias)(jp),
	}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	parsedDate, err := time.Parse("2006-01-02 15:04:05 MST", tmp.ScanStartTime)
	if err != nil {
		return err
	}

	jp.ScanStartTime = parsedDate

	if jp.ScanID == "" {
		jp.ScanID = jp.CheckID
	}

	return nil
}

// State holds the values related to the state of a check.
type State struct {
	Report   report.Report `json:"report,omitempty"`
	Progress float32       `json:"progress,omitempty"`
	Status   string        `json:"status,omitempty"`
}

// Job stores the information for a running job.
// It holds its own logger, context and cancel function.
// The Meta field can contain any value, and it is meant to store implementation-specific data.
type Job struct {
	// Main check parameters.
	JobParams

	// State of the check itself.
	State State `json:"state"`

	// Up to the agent implementation to store whatever here.
	Meta interface{} `json:"meta"`

	Ctx    context.Context    `json:"-"`
	Cancel context.CancelFunc `json:"-"`

	log *logrus.Entry

	// WillTimeout bill be true whenever the check is marked to be canceled
	// because it exceed its time out period.
	WillTimeout bool
}

// IsStatusTerminal returns whether or not a given status is terminal.
func IsStatusTerminal(status string) bool {
	for _, terminalStatus := range terminalStatuses {
		if status == terminalStatus {
			return true
		}
	}

	return false
}
