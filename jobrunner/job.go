/*
Copyright 2021 Adevinta
*/
package jobrunner

import (
	"time"
)

// Job stores the information necessary to create a new check job. This is the
// information written in the queue where the agents read the messages from.
type Job struct {
	CheckID      string            `json:"check_id"`      // Required
	StartTime    time.Time         `json:"start_time"`    // Required
	Image        string            `json:"image"`         // Required
	Target       string            `json:"target"`        // Required
	Timeout      int               `json:"timeout"`       // Required
	AssetType    string            `json:"assettype"`     // Optional
	Options      string            `json:"options"`       // Optional
	RequiredVars []string          `json:"required_vars"` // Optional
	Metadata     map[string]string `json:"metadata"`      // Optional
}
