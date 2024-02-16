/*
Copyright 2021 Adevinta
*/

package backend

import (
	"context"
	"errors"
	"strings"

	"github.com/distribution/reference"
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
	AgentAddressVar     = "VULCAN_AGENT_ADDRESS"
)

// ErrNonZeroExitCode is returned by the docker backend when a container
// finished with an exit code different from 0.
var ErrNonZeroExitCode = errors.New("container finished unexpectedly")

// RunResult defines the info that must be returned when a check is
// finished.
type RunResult struct {
	Output []byte
	Error  error
}

type RunParams struct {
	CheckID          string
	CheckTypeName    string
	ChecktypeVersion string
	Image            string
	Target           string
	AssetType        string
	Options          string
	RequiredVars     []string
	Metadata         map[string]string
}

// CheckVars contains the static checks vars that some checks needs to be
// injected in their docker to run.
type CheckVars = map[string]string

// APIConfig defines address where a component of the agent will be listening to
// the http requests sent by the checks running.
type APIConfig struct {
	Port  string `json:"port"`               // Port where the api for for the check should listen on
	IName string `json:"iname" toml:"iname"` // Interface name that defines the ip a check should use to reach the agent api.
	Host  string `json:"host" toml:"host"`   // Hostname a check should use to reach the agent. Overrides the IName config param.
}

// Backend defines the shape of the backend that executes checks.
type Backend interface {
	Run(ctx context.Context, params RunParams) (<-chan RunResult, error)
}

// ParseImage validates and enrich the image with domain (docker.io if domain missing), tag (latest if missing),.
func ParseImage(image string) (domain, path, tag string, err error) {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return
	}
	// add latests if tag is missing
	named = reference.TagNameOnly(named)
	domain = reference.Domain(named)
	path = reference.Path(named)
	tagged, isTagged := named.(reference.Tagged)
	if domain == "docker.io" {
		// Ignore docker.io and "library/" as we don't expect a check in docker.io/library.
		path = strings.TrimPrefix(path, "library/")
	}
	if isTagged {
		tag = tagged.Tag()
	}
	return
}
