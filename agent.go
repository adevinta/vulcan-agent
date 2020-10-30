package agent

import (
	"context"

	"github.com/adevinta/vulcan-agent/check"
	"github.com/adevinta/vulcan-agent/config"

	"github.com/sirupsen/logrus"
)

// Constants defining environment variables that a check expects.
const (
	CheckIDVar          = "VULCAN_CHECK_ID"
	ChecktypeNameVar    = "VULCAN_CHECKTYPE_NAME"
	ChecktypeVersionVar = "VULCAN_CHECKTYPE_VERSION"
	CheckTargetVar      = "VULCAN_CHECK_TARGET"
	CheckAssetTypeVar   = "VULCAN_CHECK_ASSET_TYPE"
	CheckOptionsVar     = "VULCAN_CHECK_OPTIONS"
	CheckLogLevelVar    = "VULCAN_CHECK_LOG_LVL"

	AgentAddressVar = "VULCAN_AGENT_ADDRESS"
)

// Constants defining the possible statuses for an Agent.
const (
	StatusNew          = "NEW"
	StatusRegistering  = "REGISTERING"
	StatusRegistered   = "REGISTERED"
	StatusRunning      = "RUNNING"
	StatusPausing      = "PAUSING"
	StatusPaused       = "PAUSED"
	StatusDisconnected = "DISCONNECTED"
	StatusPurging      = "PURGING"
	StatusDown         = "DOWN"
)

// The Agent interface defines the methods any Agent should expose.
// An Agent represents a runtime that is able to run checks as Docker containers.
// Example of an Agent could be a Docker host or a Kubernetes or Mesos cluster.
// NOTE: This interface assumes that communication between the agent and the jobs is possible.
//       Since this will not always be possible outside of a local Docker host, this may change in the future.
type Agent interface {
	// ID returns the ID assigned to the Agent when created.
	ID() string
	// Status returns the current status of the Agent.
	Status() string
	// SetStatus sets the current status of the Agent.
	SetStatus(status string)

	// Run a job in the agent's runtime and return any error encountered.
	Run(checkID string) error
	// Kill a job and return any error encountered.
	// NOTE: Kill stops the check by killing the container.
	Kill(checkID string) error
	// Abort a job and return any error encountered.
	// NOTE: Abort stops the check by sending it a SIGTERM.
	Abort(checkID string) error
	// AbortChecks abort all the running jobs that belong to a given scan.
	AbortChecks(scanID string) error
	// Raw returns the raw output of a check container.
	Raw(checkID string) ([]byte, error)
}

type AgentFactory func(ctx context.Context, cancel context.CancelFunc, id string, storage check.Storage, l *logrus.Entry, cfg config.Config) (Agent, error)
