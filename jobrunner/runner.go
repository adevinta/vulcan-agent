/*
Copyright 2021 Adevinta
*/

package jobrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/queue"
	"github.com/adevinta/vulcan-agent/stateupdater"
)

var (
	// ErrInvalidToken is returned when caller of the ProcessMessage function
	// does not pass a valid token written by Runner in its Token channel.
	ErrInvalidToken = errors.New("invalid token")

	// ErrCheckWithSameID is returned when the runner is about to run a check
	// with and ID equal to the ID of an already running check.
	ErrCheckWithSameID = errors.New("check with a same ID is already running")

	// DefaultMaxMessageProcessedTimes defines the maximun number of times the
	// processor tries to processe a checks message before it declares the check
	// as failed.
	DefaultMaxMessageProcessedTimes = 200
)

type token = struct{}

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
	Backend backend.Backend
	// Tokens contains the currently free tokens of a runner. Any
	// caller of the Run function must take a token from this channel before
	// actually calling "Run" in order to ensure there are no more than
	// maxTokens jobs running at the same time.
	Tokens                   chan interface{}
	Logger                   log.Logger
	CheckUpdater             CheckStateUpdater
	cAborter                 *checkAborter
	abortedChecks            AbortedChecks
	defaultTimeout           time.Duration
	maxMessageProcessedTimes int
}

// RunnerConfig contains config parameters for a Runner.
type RunnerConfig struct {
	MaxTokens              int
	DefaultTimeout         int
	MaxProcessMessageTimes int
}

// New creates a Runner initialized with the given log, backend and
// maximun number of tokens. The maximum number of tokens is the maximun number
// jobs that the Runner can execute at the same time.
func New(logger log.Logger, backend backend.Backend, checkUpdater CheckStateUpdater,
	aborted AbortedChecks, cfg RunnerConfig) *Runner {
	tokens := make(chan interface{}, cfg.MaxTokens)
	for i := 0; i < cfg.MaxTokens; i++ {
		tokens <- token{}
	}
	if cfg.MaxProcessMessageTimes < 1 {
		cfg.MaxProcessMessageTimes = DefaultMaxMessageProcessedTimes
	}
	return &Runner{
		Backend:      backend,
		Tokens:       tokens,
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

// AbortCheck aborts a check if it is running.
func (cr *Runner) AbortCheck(ID string) {
	cr.cAborter.Abort(ID)
}

// AbortAllChecks aborts all the checks that are running.
func (cr *Runner) AbortAllChecks(ID string) {
	cr.cAborter.AbortAll()
}

// FreeTokens returns a channel that can be used to get a free token to call the
// ProcessMessage method.
func (cr *Runner) FreeTokens() chan interface{} {
	return cr.Tokens
}

// ProcessMessage executes the job specified in a message given a free token
// that must be obtained from the Tokens channel. The func does not actually do
// anything with the token, the parameter is present just to make obvious that
// there must be free tokens on the channel before calling this method. When the
// message if processed the channel returned will indicate if the message must
// be deleted or not.
func (cr *Runner) ProcessMessage(msg queue.Message, token interface{}) <-chan bool {
	processed := make(chan bool, 1)
	go cr.runJob(msg, token, processed)
	return processed
}

func (cr *Runner) runJob(m queue.Message, t interface{}, processed chan bool) {
	j := &Job{
		RunTime: time.Now().Unix(),
	}
	// Check the token is valid.
	if _, ok := t.(token); !ok {
		cr.finishJob(j, "queued", processed, false, ErrInvalidToken)
		return
	}
	err := json.Unmarshal([]byte(m.Body), j)
	if err != nil {
		cr.finishJob(j, "read", processed, true, err)
		return
	}
	readMsg := fmt.Sprintf("check read from queue #[%d] times", m.TimesRead)
	cr.Logger.Debugf(j.logTrace(readMsg, "read"))
	// Check if the message has been processed more than the maximum defined
	// times.
	if m.TimesRead > cr.maxMessageProcessedTimes {
		status := stateupdater.StatusFailed
		err = cr.CheckUpdater.UpdateState(
			stateupdater.CheckState{
				ID:     j.CheckID,
				Status: &status,
			})
		if err != nil {
			err = fmt.Errorf("error updating the status of the check: %s, error: %w", j.CheckID, err)
			cr.finishJob(j, status, processed, false, err)
			return
		}
		cr.Logger.Errorf("error max processed times exceeded for check: %s", j.CheckID)
		// We flush the terminal status and send the final status to the writer.
		err = cr.CheckUpdater.FlushCheckStatus(j.CheckID)
		if err != nil {
			err = fmt.Errorf("error deleting the terminal status of the check: %s, error: %w", j.CheckID, err)
			cr.finishJob(j, status, processed, false, err)
			return
		}
		cr.finishJob(j, status, processed, true, nil)
		return
	}
	// Check if the check has been aborted.
	aborted, err := cr.abortedChecks.IsAborted(j.CheckID)
	if err != nil {
		err = fmt.Errorf("error querying aborted checks %w", err)
		cr.finishJob(j, "abort", processed, false, err)
		return
	}

	if aborted {
		status := stateupdater.StatusAborted
		err = cr.CheckUpdater.UpdateState(
			stateupdater.CheckState{
				ID:     j.CheckID,
				Status: &status,
			})
		if err != nil {
			err = fmt.Errorf("error updating the status of the check: %s, error: %w", j.CheckID, err)
			cr.finishJob(j, "aborting", processed, false, err)
			return
		}
		cr.Logger.Infof("check %s already aborted", j.CheckID)
		cr.finishJob(j, "aborted", processed, true, nil)
		return
	}

	var timeout time.Duration
	if j.Timeout != 0 {
		timeout = time.Duration(j.Timeout * int(time.Second))
	} else {
		timeout = cr.defaultTimeout
	}

	// Create the context under which the backend will execute the check. The
	// context will be cancelled either because the function cancel will be
	// called by the aborter or because the timeout for the check has elapsed.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err = cr.cAborter.Add(j.CheckID, cancel)
	// The above function can only return an error if the check already exists.
	// So we just avoid executing it twice.
	if err != nil {
		cr.finishJob(j, "process", processed, true, err)
		return
	}
	ctName, ctVersion, err := getChecktypeInfo(j.Image)
	if err != nil {
		cr.cAborter.Remove(j.CheckID)
		cr.finishJob(j, "processing", processed, false, err)
		return
	}
	runParams := backend.RunParams{
		CheckID:          j.CheckID,
		Target:           j.Target,
		Image:            j.Image,
		AssetType:        j.AssetType,
		Options:          j.Options,
		RequiredVars:     j.RequiredVars,
		CheckTypeName:    ctName,
		ChecktypeVersion: ctVersion,
	}
	cr.Logger.Infof(j.logTrace("running check", "running"))
	finished, err := cr.Backend.Run(ctx, runParams)
	if err != nil {
		cr.cAborter.Remove(j.CheckID)
		cr.finishJob(j, "failed", processed, false, err)
		return
	}
	var logsLink string
	// The finished channel is written by the backend when a check has finished.
	// The value written to the channel contains the logs of the check(stdin and
	// stdout) plus a field Error indicanting if there were any unexpected error
	// running the execution. If that error is not nil the backend was unable to
	// retrieve the output of the check so the Output field will be nil.
	res := <-finished
	// When the check is finished it can not be aborted anymore
	// so we remove it from aborter.
	cr.cAborter.Remove(j.CheckID)

	// Try always to upload the logs of the check if present.
	if res.Output != nil {
		logsLink, err = cr.CheckUpdater.UploadCheckData(j.CheckID, "logs", j.StartTime, res.Output)
		if err != nil {
			err = fmt.Errorf("error storing the logs of the check: %s, error %w", j.CheckID, err)
			cr.finishJob(j, "uploading_raw", processed, false, err)
			// We return to retry the log upload later.
			return
		}

		// Set the link for the logs of the check.
		err = cr.CheckUpdater.UpdateState(stateupdater.CheckState{
			ID:  j.CheckID,
			Raw: &logsLink,
		})
		if err != nil {
			err = fmt.Errorf("error updating the link to the logs of the check: %s, error: %w", j.CheckID, err)
			cr.finishJob(j, "linking_raw", processed, false, err)
		}

		cr.Logger.Debugf(j.logTrace(logsLink, "raw_logs"))
	}

	// We query if the check has sent any status update with a terminal status.
	isTerminal := cr.CheckUpdater.CheckStatusTerminal(j.CheckID)

	// Check if the backend returned any not expected error while running the check.
	execErr := res.Error
	if execErr != nil &&
		!errors.Is(execErr, context.DeadlineExceeded) &&
		!errors.Is(execErr, context.Canceled) &&
		!errors.Is(execErr, backend.ErrNonZeroExitCode) {
		cr.finishJob(j, "backend_error", processed, false, execErr)
		return
	}

	// The only times when this component has to set the state of a check are
	// when the check is canceled, timedout or finished with an exit status code
	// different from 0 . That's because, in those cases, it is possible for the
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
		err = cr.CheckUpdater.FlushCheckStatus(j.CheckID)
		if err != nil {
			err = fmt.Errorf("error deleting the terminal status of the check: %s, error: %w", j.CheckID, err)
			cr.finishJob(j, status, processed, false, err)
			return
		}
		cr.finishJob(j, "completed", processed, true, err)
		return
	}
	err = cr.CheckUpdater.UpdateState(stateupdater.CheckState{
		ID:     j.CheckID,
		Status: &status,
	})
	if err != nil {
		err = fmt.Errorf("error updating the status of the check: %s, error: %w", j.CheckID, err)
	}
	// We signal the CheckUpdater that we don't need it to store that
	// information any more.
	err = cr.CheckUpdater.FlushCheckStatus(j.CheckID)
	if err != nil {
		err = fmt.Errorf("error deleting the terminal status of the check: %s, error: %w", j.CheckID, err)
		cr.finishJob(j, status, processed, false, err)
		return
	}
	cr.finishJob(j, "finished", processed, err == nil, err)
}

func (cr *Runner) finishJob(j *Job, checkState string, processed chan<- bool, delete bool, err error) {
	checkID := j.CheckID
	if err == nil && checkID != "" {
		cr.Logger.Infof(j.logTrace("check finished successfully", "finished"))
	}
	if err != nil && checkID != "" {
		cr.Logger.Errorf(j.logTrace(err.Error(), "error"))
	}
	if err != nil && checkID == "" {
		msg := fmt.Sprintf("invalid message %+v", err)
		cr.Logger.Errorf(j.logTrace(msg, "error"))
	}
	// Return a token to free tokens channel.
	// This write must not block ever.
	select {
	case cr.Tokens <- token{}:
	default:
		cr.Logger.Errorf(j.logTrace("error, unexpected lock when writing to the tokens channel", "error"))
	}
	// Signal the caller that the job related to a message is finalized. It also
	// states if the message related to the job must be deleted or not.
	processed <- delete
	close(processed)
}

// ChecksRunning returns the current number of checks running.
func (cr *Runner) ChecksRunning() int {
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
