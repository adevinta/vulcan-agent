/*
Copyright 2021 Adevinta
*/

package checks

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/adevinta/vulcan-agent/v2/backend"
	"github.com/adevinta/vulcan-agent/v2/log"
	"github.com/adevinta/vulcan-agent/v2/stateupdater"
)

var (
	// ErrCheckWithSameID is returned when the runner is about to run a check
	// with and ID equal to the ID of an already running check.
	ErrCheckWithSameID = errors.New("check with a same ID is already running")

	// DefaultMaxMessageProcessedTimes defines the maximun number of times the
	// processor tries to processe a checks message before it declares the check
	// as failed.
	DefaultMaxMessageProcessedTimes = 200
)

type checkAborter struct {
	cancels sync.Map
}

func (c *checkAborter) Add(checkID string, cancel context.CancelFunc) error {
	_, exists := c.cancels.LoadOrStore(checkID, cancel)
	if exists {
		return ErrCheckWithSameID
	}
	return nil
}

func (c *checkAborter) Remove(checkID string) {
	c.cancels.Delete(checkID)
}

func (c *checkAborter) Exist(checkID string) bool {
	_, ok := c.cancels.Load(checkID)
	return ok
}

func (c *checkAborter) Abort(checkID string) {
	v, ok := c.cancels.Load(checkID)
	if !ok {
		return
	}
	cancel := v.(context.CancelFunc)
	cancel()
}

func (c *checkAborter) AbortAll() {
	c.cancels.Range(func(_, v interface{}) bool {
		cancel := v.(context.CancelFunc)
		cancel()
		return true
	})
}

// Running returns the number the checks that are in a given point of time being
// tracked by the Aborter component. In other words the number of checks
// running.
func (c *checkAborter) Running() int {
	count := 0
	c.cancels.Range(func(_, v interface{}) bool {
		count++
		return true
	})
	return count
}

type CheckStateUpdater interface {
	UpdateState(stateupdater.CheckState) error
	UploadCheckData(checkID, kind string, startedAt time.Time, content []byte) (string, error)
	CheckStatusTerminal(ID string) bool
	FlushCheckStatus(ID string) error
	UpdateCheckStatusTerminal(stateupdater.CheckState)
}

// AbortedChecks defines the shape of the component needed by a Runner in order
// to know if a check is aborted before it is exected.
type AbortedChecks interface {
	IsAborted(ID string) (bool, error)
}

// Runner runs the checks associated to a concreate message by receiving calls
// to it ProcessMessage function.
type Runner struct {
	Backend                  backend.Backend
	Logger                   log.Logger
	CheckUpdater             CheckStateUpdater
	cAborter                 *checkAborter
	abortedChecks            AbortedChecks
	defaultTimeout           time.Duration
	maxMessageProcessedTimes int
}

// RunnerConfig contains config parameters for a Runner.
type RunnerConfig struct {
	DefaultTimeout         int
	MaxProcessMessageTimes int
}

// New creates a Runner initialized with the given log, backend and
// maximun number of tokens. The maximum number of tokens is the maximun number
// jobs that the Runner can execute at the same time.
func New(logger log.Logger, backend backend.Backend, checkUpdater CheckStateUpdater,
	aborted AbortedChecks, cfg RunnerConfig) *Runner {
	if cfg.MaxProcessMessageTimes < 1 {
		cfg.MaxProcessMessageTimes = DefaultMaxMessageProcessedTimes
	}
	return &Runner{
		Backend:      backend,
		CheckUpdater: checkUpdater,
		cAborter: &checkAborter{
			cancels: sync.Map{},
		},
		abortedChecks:            aborted,
		Logger:                   logger,
		maxMessageProcessedTimes: cfg.MaxProcessMessageTimes,
		defaultTimeout:           time.Duration(cfg.DefaultTimeout * int(time.Second)),
	}
}

// Abort aborts a check if it is running.
func (cr *Runner) Abort(ID string) {
	cr.cAborter.Abort(ID)
}

// AbortAll aborts all the checks that are running.
func (cr *Runner) AbortAll() {
	cr.cAborter.AbortAll()
}

// Run executes the job.
func (cr *Runner) Run(check Check, timesRead int) error {
	var err error
	readMsg := fmt.Sprintf("check read from queue #[%d] times", timesRead)
	cr.Logger.Debugf(check.logTrace(readMsg, "read"))
	// Check if the message has been processed more than the maximum defined
	// times.
	if timesRead > cr.maxMessageProcessedTimes {
		status := stateupdater.StatusFailed
		err = cr.CheckUpdater.UpdateState(
			stateupdater.CheckState{
				ID:     check.CheckID,
				Status: &status,
			})
		if err != nil {
			err = fmt.Errorf("error updating the status of the check: %s: %w", check.CheckID, err)
			return err
		}
		cr.Logger.Errorf("error max processed times exceeded for check: %s", check.CheckID)
		// We flush the terminal status and send the final status to the writer.
		err = cr.CheckUpdater.FlushCheckStatus(check.CheckID)
		if err != nil {
			err = fmt.Errorf("error deleting the terminal status of the check: %s: %w", check.CheckID, err)
			return err
		}
		return nil
	}
	// Check if the check has been aborted.
	aborted, err := cr.abortedChecks.IsAborted(check.CheckID)
	if err != nil {
		err = fmt.Errorf("error querying aborted checks %w", err)
		return err
	}

	if aborted {
		status := stateupdater.StatusAborted
		err = cr.CheckUpdater.UpdateState(
			stateupdater.CheckState{
				ID:     check.CheckID,
				Status: &status,
			})
		if err != nil {
			err = fmt.Errorf("error updating the status of the check %s: %w", check.CheckID, err)
			return err
		}
		cr.Logger.Infof("check %s already aborted", check.CheckID)
		return nil
	}

	var timeout time.Duration
	if check.Timeout != 0 {
		timeout = time.Duration(check.Timeout * int(time.Second))
	} else {
		timeout = cr.defaultTimeout
	}

	// Create the context under which the backend will execute the check. The
	// context will be cancelled either because the function cancel will be
	// called by the aborter or because the timeout for the check has elapsed.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err = cr.cAborter.Add(check.CheckID, cancel)
	// The above function can only return an error if the check already exists.
	// So we just avoid executing it twice.
	if err != nil {
		return nil
	}
	ctName, ctVersion, err := getChecktypeInfo(check.Image)
	if err != nil {
		cr.cAborter.Remove(check.CheckID)
		return fmt.Errorf("unable to read checktype info: %w", err)
	}
	runParams := backend.RunParams{
		CheckID:          check.CheckID,
		Target:           check.Target,
		Image:            check.Image,
		AssetType:        check.AssetType,
		Options:          check.Options,
		RequiredVars:     check.RequiredVars,
		CheckTypeName:    ctName,
		ChecktypeVersion: ctVersion,
	}
	cr.Logger.Infof(check.logTrace("running check", "running"))
	finished, err := cr.Backend.Run(ctx, runParams)
	if err != nil {
		cr.cAborter.Remove(check.CheckID)
		return fmt.Errorf("unable to run check: %w", err)
	}
	var logsLink string
	// The finished channel is written by the backend when a check has finished.
	// The value written to the channel contains the logs of the check(stdin and
	// stdout) plus a field Error indicanting if there were any unexpected error
	// during the execution. If that error is not nil, the backend was unable to
	// retrieve the output of the check so the Output field will be nil.
	res := <-finished
	// When the check is finished it can not be aborted anymore
	// so we remove it from aborter.
	cr.cAborter.Remove(check.CheckID)
	// Try always to upload the logs of the check if present.
	if res.Output != nil {
		logsLink, err = cr.CheckUpdater.UploadCheckData(check.CheckID, "logs", check.StartTime, res.Output)
		if err != nil {
			err = fmt.Errorf("unable to store the logs of the check %s: %w", check.CheckID, err)
			// We return to retry the log upload later.
			return err
		}

		// Set the link for the logs of the check.
		err = cr.CheckUpdater.UpdateState(stateupdater.CheckState{
			ID:  check.CheckID,
			Raw: &logsLink,
		})
		if err != nil {
			err = fmt.Errorf("unable to update the link to the logs of the check %s: %w", check.CheckID, err)
			return err
		}
		cr.Logger.Debugf(check.logTrace(logsLink, "raw_logs"))
	}

	// We query if the check has sent any status update with a terminal status.
	isTerminal := cr.CheckUpdater.CheckStatusTerminal(check.CheckID)

	// Check if the backend returned any not expected error while running the check.
	execErr := res.Error
	if execErr != nil &&
		!errors.Is(execErr, context.DeadlineExceeded) &&
		!errors.Is(execErr, context.Canceled) &&
		!errors.Is(execErr, backend.ErrNonZeroExitCode) {
		return execErr
	}

	// The times this component has to set the state of a check are
	// when the check is canceled, timeout or finished with an exit status code
	// different from 0. That's because, in those cases, it's possible for the
	// check to not have had time to set the state by itself.
	var status string
	if errors.Is(execErr, context.DeadlineExceeded) {
		status = stateupdater.StatusTimeout
	}
	if errors.Is(execErr, context.Canceled) {
		status = stateupdater.StatusAborted
	}
	if errors.Is(execErr, backend.ErrNonZeroExitCode) {
		status = stateupdater.StatusFailed
	}
	// Ensure the check sent a status update with a terminal status.
	if status == "" && !isTerminal {
		status = stateupdater.StatusFailed
	}
	// If the check was not canceled or aborted we just finish its execution.
	if status == "" {
		// We signal the CheckUpdater that we don't need it to store that
		// information any more.
		err = cr.CheckUpdater.FlushCheckStatus(check.CheckID)
		if err != nil {
			err = fmt.Errorf("error deleting the terminal status of the check%s: %w", check.CheckID, err)
			return err
		}
		return err
	}
	err = cr.CheckUpdater.UpdateState(stateupdater.CheckState{
		ID:     check.CheckID,
		Status: &status,
	})
	if err != nil {
		err = fmt.Errorf("error updating the status of the check %s: %w", check.CheckID, err)
		return err
	}
	// We signal the CheckUpdater that we don't need it to store that
	// information any more.
	err = cr.CheckUpdater.FlushCheckStatus(check.CheckID)
	if err != nil {
		err = fmt.Errorf("error deleting the terminal status of the check %s: %w", check.CheckID, err)
		return err
	}
	return err
}

// Running returns the current number of checks running.
func (cr *Runner) Running() int {
	return cr.cAborter.Running()
}

// getChecktypeInfo extracts checktype data from a Docker image URI.
func getChecktypeInfo(imageURI string) (checktypeName string, checktypeVersion string, err error) {
	domain, path, tag, err := backend.ParseImage(imageURI)
	if err != nil {
		err = fmt.Errorf("unable to parse image %s - %w", imageURI, err)
		return
	}
	checktypeName = fmt.Sprintf("%s/%s", domain, path)
	if domain == "docker.io" {
		checktypeName = path
	}
	checktypeVersion = tag
	return
}
