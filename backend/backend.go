/*
Copyright 2019 Adevinta
*/

package backend

import "context"

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

// APIConfig defines addres where a component of the agent will be listening to
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
