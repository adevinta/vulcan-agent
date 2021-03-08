package api

import (
	"errors"
	"fmt"
	"time"

	report "github.com/adevinta/vulcan-report"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/stateupdater"
)

var (
	// ErrCheckIDMandatory is returned when the API is asked to update the state
	// of the check but no checkID is provided.
	ErrCheckIDMandatory = errors.New("a check must inform always a check id when updating its state")

	// ErrStatusMandatory is returned when the API is asked to update the state
	// of the check but no status is provided.
	ErrStatusMandatory = errors.New("a check must inform always a stauts when updating its state")
)

// CheckState holds the values related to the state of a check. The values
// defined here the one written to the check states queue
type CheckState struct {
	ID       string
	Report   *report.Report `json:"report,omitempty"`
	Progress *float32       `json:"progress,omitempty"`
	Status   *string        `json:"status,omitempty"`
}

// Stats defines the general information that the API provides about the agent.
type Stats struct {
	// Timestamp of the last queue message received.
	LastMessageReceived *time.Time `json:"last_message_received,omitempty"`
	ChecksRunning       int        `json:"checks_running"`
}

// CheckStateUpdater defines the method needed by the API in order to send check
// updates messages to the corresponding queue.
type CheckStateUpdater interface {
	UpdateState(stateupdater.CheckState) error
	UpdateCheckReport(checkID string, startTime time.Time, report report.Report) (string, error)
}

// AgentStats defined the methods needed by the API to gather the information
// about agent stats that it exposed to the outside world.
type AgentStats interface {
	ChecksRunning() int
	LastMessageReceived() *time.Time
}

// API defines the methods of the API that the agent exposes to the outside.
type API struct {
	stateUpdate CheckStateUpdater
	agentStats  AgentStats
	log         log.Logger
}

// New returns an API filled with the provided check state updater and the agent
// stats service.
func New(log log.Logger, supdater CheckStateUpdater, astats AgentStats) *API {
	return &API{
		log:         log,
		stateUpdate: supdater,
		agentStats:  astats,
	}
}

// CheckUpdate attends the request sent by a check in order to update its state.
func (a *API) CheckUpdate(c CheckState) error {
	if c.Status == nil {
		err := ErrStatusMandatory
		a.log.Errorf("%+v", err)
		return err
	}
	if c.ID == "" {
		err := ErrCheckIDMandatory
		a.log.Errorf("%+v", err)
		return err

	}
	var rlink *string
	if c.Report != nil {
		link, err := a.stateUpdate.UpdateCheckReport(c.ID, c.Report.StartTime, *c.Report)
		if err != nil {
			err = fmt.Errorf("error uploading check report, checkID %s, error: %w", c.ID, err)
			a.log.Errorf("%+v", err)
			return err
		}
		rlink = &link
	}
	ustate := stateupdater.CheckState{
		ID:     c.ID,
		Status: c.Status,
		Report: rlink,
	}
	if c.Progress != nil && *c.Progress > 0 {
		ustate.Progress = c.Progress
	}
	err := a.stateUpdate.UpdateState(ustate)
	if err != nil {
		err = fmt.Errorf("error updating check state, checkID %s, error: %w", c.ID, err)
		a.log.Errorf("%+v", err)
		return err
	}
	return nil
}

// Stats exposed some stats about the agent to the outside world.
func (a *API) Stats() (Stats, error) {
	last := a.agentStats.LastMessageReceived()
	n := a.agentStats.ChecksRunning()
	return Stats{LastMessageReceived: last, ChecksRunning: n}, nil
}
