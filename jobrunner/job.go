/*
Copyright 2021 Adevinta
*/

package jobrunner

import (
	"fmt"
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
	RunTime      int64
}

func (j *Job) logTrace(msg, action string) string {
	if j.RunTime == 0 {
		j.RunTime = time.Now().Unix()
	}
	return fmt.Sprintf(
		"event=checkTrace checkID=%s target=%s assetType=%s checkImage=%s queuedTime=%d runningTime=%d action=%s msg=\"%s\"",
		j.CheckID,
		j.Target,
		j.AssetType,
		j.Image,
		j.RunTime-j.StartTime.Unix(),
		time.Now().Unix()-j.RunTime,
		action,
		msg,
	)
}
