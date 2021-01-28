package jobrunner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/stateupdater"
)

var (
	// ErrInvalidToken is returned when caller of the ProcessMessage function
	// does not pass a valid token written by Runner in its Token channel.
	ErrInvalidToken = errors.New("invalid token")

	// ErrCheckWithSameID is returned when the runner is about to
	ErrCheckWithSameID = errors.New("check with a same ID is already runing")
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

// Backend defines the shape of the backend needed by the CheckRunner to execute
// a Job.
type Backend interface {
	Run(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error)
}

// ChecksLogsStore provides functionality to store the logs of a check.
type ChecksLogsStore interface {
	UpdateCheckRaw(checkID, scanID string, scanStartTime time.Time, raw []byte) (string, error)
}

type CheckStateUpdater interface {
	UpdateState(stateupdater.CheckState) error
}

type Runner struct {
	Backend Backend
	// Tokens contains the currently free tokens of a runner. Any
	// caller of the Run function must take a token from this channel before
	// actually calling "Run" in order to ensure there are no more than
	// maxTokens jobs running at the same time.
	Tokens       chan interface{}
	Logger       log.Logger
	CheckUpdater CheckStateUpdater
	LogStore     ChecksLogsStore
	cAborter     checkAborter
	// wg is used to allow a caller to wait for all jobs that are running to be
	// finish.
	wg             *sync.WaitGroup
	ctx            context.Context
	defaultTimeout time.Duration
}

// RunnerConfig contains config parameters for a Runner.
type RunnerConfig struct {
	MaxTokens      int
	DefaultTimeout int
}

// NewRunner creates a Runner initialized with the given log, backend and
// maximun number of tokens. The maximum number of tokens is the maximun number
// jobs that the Runner can execute at the same time.
func NewRunner(logger log.Logger, backend Backend, checkUpdater CheckStateUpdater,
	logsStore ChecksLogsStore, cfg RunnerConfig) *Runner {
	var tokens = make(chan interface{}, cfg.MaxTokens)
	for i := 0; i < cfg.MaxTokens; i++ {
		tokens <- token{}
	}
	return &Runner{
		Backend:      backend,
		Tokens:       tokens,
		CheckUpdater: checkUpdater,
		LogStore:     logsStore,
		cAborter: checkAborter{
			cancels: sync.Map{},
		},
		Logger:         logger,
		wg:             &sync.WaitGroup{},
		defaultTimeout: time.Duration(cfg.DefaultTimeout * int(time.Second)),
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

// ProcessMessage executes the job specified in a message given a free token
// that must be obtained from the Tokens channel. The func does not actually do
// anything with the token, the parameter is present just to make obvious that
// there must be free tokens on the channel before calling this method. When the
// message if processed the channel returned will indicate if the message must
// be deleted or not.
func (cr *Runner) ProcessMessage(msg string, token interface{}) <-chan bool {
	cr.wg.Add(1)
	var processed = make(chan bool, 1)
	go cr.runJob(msg, token, processed)
	return processed
}

func (cr *Runner) runJob(msg string, t interface{}, processed chan bool) {
	// Check the token is valid.
	if _, ok := t.(token); !ok {
		cr.finishJob("", processed, false, ErrInvalidToken)
	}
	j := &JobParams{}
	err := j.UnmarshalJSON([]byte(msg))
	if err != nil {
		err = fmt.Errorf("error unmarshaling message %+v", msg)
		cr.finishJob("", processed, true, err)
	}

	var timeout time.Duration
	if j.Timeout != 0 {
		timeout = time.Duration(j.Timeout * int(time.Second))
	} else {
		timeout = cr.defaultTimeout
	}

	startTime := time.Now()
	// Create the context under which the backend will execute the check. The
	// context will be cancelled either because the function cancel will be
	// called by the aborter or because the timeout for the check has elapsed.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err = cr.cAborter.Add(j.CheckID, cancel)
	// The above function can only return an error if the check already exists.
	// So we just avoid executing it twice.
	if err != nil {
		cr.finishJob(j.CheckID, processed, true, err)
		return
	}
	runParams := backend.RunParams{
		CheckID:      j.CheckID,
		Target:       j.Target,
		Image:        j.Image,
		AssetType:    j.AssetType,
		Options:      j.Options,
		RequiredVars: j.RequiredVars,
	}
	finished, err := cr.Backend.Run(ctx, runParams)
	if err != nil {
		cr.cAborter.Remove(j.CheckID)
		cr.finishJob(j.CheckID, processed, false, err)
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
	// Check if the backend returned any error running the check.
	err = res.Error
	if err != nil {
		cr.finishJob(j.CheckID, processed, false, err)
		return
	}
	logsLink, err = cr.LogStore.UpdateCheckRaw(j.CheckID, j.ScanID, startTime, res.Output)
	if err != nil {
		err = fmt.Errorf("error storing the logs of the check %w", err)
		cr.finishJob(j.CheckID, processed, false, err)
		return
	}
	// Set the link for the logs of the check.
	err = cr.CheckUpdater.UpdateState(stateupdater.CheckState{
		ID:  j.CheckID,
		Raw: &logsLink,
	})
	if err != nil {
		err = fmt.Errorf("error updating the link to the logs of the check %w", err)
		cr.finishJob(j.CheckID, processed, false, err)
		return
	}
	// The only times when this component has to set the state of a check are
	// when the check is canceled or timed. That's because, in those cases, it
	// is possible for the check to not have had time to set the state itself.
	var status string
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		status = stateupdater.StatusTimeout
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		status = stateupdater.StatusAborted
	}
	// If the check was not canceled or aborted we just finish its execution.
	if status == "" {
		cr.finishJob(j.CheckID, processed, true, err)
		return
	}
	err = cr.CheckUpdater.UpdateState(stateupdater.CheckState{
		ID:     j.CheckID,
		Status: &status,
	})
	if err != nil {
		err = fmt.Errorf("error updating the link to the logs of the check %w", err)
	}
	cr.finishJob(j.CheckID, processed, err == nil, err)
}

func (cr *Runner) finishJob(checkID string, processed chan<- bool, delete bool, err error) {
	defer cr.wg.Done()
	if err != nil && checkID != "" {
		cr.Logger.Errorf("error %+v running check_id %s", err, checkID)
	}
	if err != nil && checkID == "" {
		cr.Logger.Errorf("invalid message %+v", err)
	}
	// Return a token to free tokens channel.
	// This write must not block ever.
	select {
	case cr.Tokens <- token{}:
	default:
		cr.Logger.Errorf("error, unexpected lock when writting to the tokens channel")
	}
	// Signal the caller that the job related to a message is finalized.
	// It also states if the message related to the job must be deleted or not.
	processed <- delete
	close(processed)
}
