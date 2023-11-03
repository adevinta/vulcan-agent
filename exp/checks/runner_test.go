/*
Copyright 2021 Adevinta
*/

package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/adevinta/vulcan-agent/v2/backend"
	"github.com/adevinta/vulcan-agent/v2/log"
	"github.com/adevinta/vulcan-agent/v2/stateupdater"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

var (
	errUnexpectedTest     = errors.New("unexpected")
	errUploadingLogsTests = errors.New("error uploading logs")
	checkFixture          = Check{
		CheckID:      uuid.NewString(),
		StartTime:    time.Now(),
		Image:        "job1:latest",
		Target:       "example.com",
		Timeout:      60,
		AssetType:    "hostname",
		Options:      "{}",
		RequiredVars: []string{"var1"},
	}
)

type CheckRaw struct {
	Raw       []byte
	CheckID   string
	StartTime time.Time
}

type inMemChecksUpdater struct {
	updates        []stateupdater.CheckState
	raws           []CheckRaw
	terminalStatus map[string]stateupdater.CheckState
	uploadLogError error
}

func (im *inMemChecksUpdater) UpdateState(cs stateupdater.CheckState) error {
	status := ""
	if cs.Status != nil {
		status = *cs.Status
	} else {
		storedCheckStatus, ok := im.terminalStatus[cs.ID]
		if ok {
			status = *storedCheckStatus.Status
		}
	}
	if _, ok := stateupdater.TerminalStatuses[status]; ok {
		im.UpdateCheckStatusTerminal(cs)
		return nil
	}
	if im.updates == nil {
		im.updates = make([]stateupdater.CheckState, 0)
	}
	im.updates = append(im.updates, cs)
	return nil
}

func (im *inMemChecksUpdater) UploadCheckData(checkID string, kind string, stime time.Time, raw []byte) (string, error) {
	if im.uploadLogError != nil {
		return "", im.uploadLogError
	}

	if im.raws != nil {
		im.raws = make([]CheckRaw, 0)
	}
	im.raws = append(im.raws, CheckRaw{
		Raw:       raw,
		CheckID:   checkID,
		StartTime: stime,
	})
	return fmt.Sprintf("%s/%s", checkID, kind), nil
}

func (im *inMemChecksUpdater) CheckStatusTerminal(ID string) bool {
	_, ok := im.terminalStatus[ID]
	return ok
}

func (im *inMemChecksUpdater) UpdateCheckStatusTerminal(s stateupdater.CheckState) {
	if im.terminalStatus == nil {
		im.terminalStatus = make(map[string]stateupdater.CheckState)
	}
	cs, ok := im.terminalStatus[s.ID]
	if !ok {
		im.terminalStatus[s.ID] = s
		return
	}

	// We update the existing CheckState.
	cs.Merge(s)

	im.terminalStatus[cs.ID] = cs
}

func (im *inMemChecksUpdater) FlushCheckStatus(ID string) error {
	if im.updates == nil {
		im.updates = make([]stateupdater.CheckState, 0)
	}
	terminalStatus, ok := im.terminalStatus[ID]
	if ok {
		im.updates = append(im.updates, terminalStatus)
	}
	return nil
}

type mockChecksUpdater struct {
	stateUpdater         func(cs stateupdater.CheckState) error
	checkRawUpload       func(checkID, kind string, startedAt time.Time, content []byte) (string, error)
	checkTerminalChecker func(ID string) bool
	checkTerminalDeleter func(ID string) error
	checkTerminalUpdater func(cs stateupdater.CheckState)
}

func (m *mockChecksUpdater) UpdateState(cs stateupdater.CheckState) error {
	return m.stateUpdater(cs)
}

func (m *mockChecksUpdater) UploadCheckData(checkID, kind string, stime time.Time, raw []byte) (string, error) {
	return m.checkRawUpload(checkID, kind, stime, raw)
}

func (m *mockChecksUpdater) CheckStatusTerminal(ID string) bool {
	return m.checkTerminalChecker(ID)
}

func (m *mockChecksUpdater) FlushCheckStatus(ID string) error {
	return m.checkTerminalDeleter(ID)
}

func (m *mockChecksUpdater) UpdateCheckStatusTerminal(cs stateupdater.CheckState) {
	m.checkTerminalUpdater(cs)
}

type mockBackend struct {
	CheckRunner func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error)
}

func (mb *mockBackend) Run(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
	return mb.CheckRunner(ctx, params)
}

type jRunnerStateChecker func(r *Runner) string

type inMemAbortedChecks struct {
	aborted map[string]struct{}
	err     error
}

func (ia *inMemAbortedChecks) IsAborted(ID string) (bool, error) {
	if ia.err != nil {
		return false, ia.err
	}
	_, ok := ia.aborted[ID]
	return ok, nil
}

func TestRunner_ProcessMessage(t *testing.T) {
	type fields struct {
		Backend                  backend.Backend
		Tokens                   chan interface{}
		Logger                   log.Logger
		CheckUpdater             CheckStateUpdater
		cAborter                 *checkAborter
		aborted                  AbortedChecks
		defaultTimeout           time.Duration
		maxMessageProcessedTimes int
	}
	type args struct {
		check     Check
		timesRead int
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      error
		wantState jRunnerStateChecker
	}{
		{
			name: "RunsACheck",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted:        &inMemAbortedChecks{make(map[string]struct{}), nil},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater: &inMemChecksUpdater{
					terminalStatus: map[string]stateupdater.CheckState{
						checkFixture.CheckID: {
							ID:     checkFixture.CheckID,
							Status: str2ptr(stateupdater.StatusFinished),
						},
					},
				},
			},
			args: args{
				check: checkFixture,
			},
			want: nil,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRunParams := backend.RunParams{
					CheckID:          checkFixture.CheckID,
					CheckTypeName:    "job1",
					ChecktypeVersion: "latest",
					Image:            checkFixture.Image,
					Options:          checkFixture.Options,
					Target:           checkFixture.Target,
					AssetType:        checkFixture.AssetType,
					RequiredVars:     checkFixture.RequiredVars,
				}
				wantRaws := []CheckRaw{{
					Raw:       mustMarshalRunParams(wantRunParams),
					CheckID:   checkFixture.CheckID,
					StartTime: checkFixture.StartTime,
				}}
				gotUpdates := updater.updates
				rawLink := fmt.Sprintf("%s/logs", checkFixture.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:     checkFixture.CheckID,
						Raw:    &rawLink,
						Status: str2ptr(stateupdater.StatusFinished),
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "TerminatesACheckIfNeeded",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted:        &inMemAbortedChecks{make(map[string]struct{}), nil},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater:   &inMemChecksUpdater{},
			},
			args: args{
				check: checkFixture,
			},
			want: nil,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRunParams := backend.RunParams{
					CheckID:          checkFixture.CheckID,
					CheckTypeName:    "job1",
					ChecktypeVersion: "latest",
					Image:            checkFixture.Image,
					Options:          checkFixture.Options,
					Target:           checkFixture.Target,
					AssetType:        checkFixture.AssetType,
					RequiredVars:     checkFixture.RequiredVars,
				}
				wantRaws := []CheckRaw{{
					Raw:       mustMarshalRunParams(wantRunParams),
					CheckID:   checkFixture.CheckID,
					StartTime: checkFixture.StartTime,
				}}
				gotUpdates := updater.updates
				rawLink := fmt.Sprintf("%s/logs", checkFixture.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:  checkFixture.CheckID,
						Raw: &rawLink,
					},
					{
						ID:     checkFixture.CheckID,
						Status: str2ptr(stateupdater.StatusFailed),
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "ReturnsAnError",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							results := backend.RunResult{
								Error: errUnexpectedTest,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted:        &inMemAbortedChecks{make(map[string]struct{}), nil},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater:   &inMemChecksUpdater{},
			},
			args: args{
				check: checkFixture,
			},
			want: errUnexpectedTest,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				var wantRaws []CheckRaw
				gotUpdates := updater.updates
				var wantUpdates []stateupdater.CheckState
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "UpdatesStateWhenCheckTimedout",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
								Error:  context.DeadlineExceeded,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted:        &inMemAbortedChecks{make(map[string]struct{}), nil},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater:   &inMemChecksUpdater{},
			},
			args: args{
				check: checkFixture,
			},
			want: nil,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRunParams := backend.RunParams{
					CheckID:          checkFixture.CheckID,
					CheckTypeName:    "job1",
					ChecktypeVersion: "latest",
					Image:            checkFixture.Image,
					Options:          checkFixture.Options,
					Target:           checkFixture.Target,
					AssetType:        checkFixture.AssetType,
					RequiredVars:     checkFixture.RequiredVars,
				}
				wantRaws := []CheckRaw{{
					Raw:       mustMarshalRunParams(wantRunParams),
					CheckID:   checkFixture.CheckID,
					StartTime: checkFixture.StartTime,
				}}
				gotUpdates := updater.updates
				state := stateupdater.StatusTimeout
				rawLink := fmt.Sprintf("%s/logs", checkFixture.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:  checkFixture.CheckID,
						Raw: &rawLink,
					},
					{
						ID:     checkFixture.CheckID,
						Status: &state,
						// Raw: &rawLink,
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "UpdatesStateWhenCheckCanceled",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
								Error:  context.Canceled,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted:        &inMemAbortedChecks{make(map[string]struct{}), nil},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater:   &inMemChecksUpdater{},
			},
			args: args{
				check: checkFixture,
			},
			want: nil,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRunParams := backend.RunParams{
					CheckID:          checkFixture.CheckID,
					CheckTypeName:    "job1",
					ChecktypeVersion: "latest",
					Image:            checkFixture.Image,
					Options:          checkFixture.Options,
					Target:           checkFixture.Target,
					AssetType:        checkFixture.AssetType,
					RequiredVars:     checkFixture.RequiredVars,
				}
				wantRaws := []CheckRaw{{
					Raw:       mustMarshalRunParams(wantRunParams),
					CheckID:   checkFixture.CheckID,
					StartTime: checkFixture.StartTime,
				}}
				gotUpdates := updater.updates
				state := stateupdater.StatusAborted
				rawLink := fmt.Sprintf("%s/logs", checkFixture.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:  checkFixture.CheckID,
						Raw: &rawLink,
					},
					{
						ID:     checkFixture.CheckID,
						Status: &state,
						// Raw: &rawLink,
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "DoesNotRunAbortedChecks",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
								Error:  context.Canceled,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted: &inMemAbortedChecks{
					aborted: map[string]struct{}{
						checkFixture.CheckID: {},
					},
				},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater:   &inMemChecksUpdater{},
			},
			args: args{
				check: checkFixture,
			},
			want: nil,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				var wantRaws []CheckRaw
				gotUpdates := updater.updates
				state := stateupdater.StatusAborted
				wantUpdates := []stateupdater.CheckState{
					{
						ID:     checkFixture.CheckID,
						Status: &state,
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "ReturnErrorWhenUnableToUpdateStatus",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted: &inMemAbortedChecks{
					aborted: map[string]struct{}{
						checkFixture.CheckID: {},
					},
				},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater: &mockChecksUpdater{
					stateUpdater: func(cs stateupdater.CheckState) error {
						return errUnexpectedTest
					},
					checkRawUpload: func(checkID string, kind string, stime time.Time, raw []byte) (string, error) {
						return "link", nil
					},
					checkTerminalChecker: func(ID string) bool {
						return false
					},
					checkTerminalDeleter: func(string) error {
						return nil
					},
					checkTerminalUpdater: func(cs stateupdater.CheckState) {
					},
				},
			},
			args: args{
				check: checkFixture,
			},
			want: errUnexpectedTest,
			wantState: func(r *Runner) string {
				return ""
			},
		},
		{
			name: "UpdatesLogsWhenUnexpectedError",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							results := backend.RunResult{
								Output: []byte("logs"),
								Error:  errUnexpectedTest,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted: &inMemAbortedChecks{
					aborted: map[string]struct{}{},
				},
				defaultTimeout:           time.Duration(10 * time.Second),
				Tokens:                   make(chan interface{}, 10),
				Logger:                   &log.NullLog{},
				CheckUpdater:             &inMemChecksUpdater{},
				maxMessageProcessedTimes: 1,
			},
			args: args{
				check: checkFixture,
			},
			want: errUnexpectedTest,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRaws := []CheckRaw{{
					Raw:       []byte("logs"),
					CheckID:   checkFixture.CheckID,
					StartTime: checkFixture.StartTime,
				}}
				gotUpdates := updater.updates
				rawLink := fmt.Sprintf("%s/logs", checkFixture.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:  checkFixture.CheckID,
						Raw: &rawLink,
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "DoesNotRunChecksProcessedTooManyTimes",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
								Error:  context.Canceled,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted: &inMemAbortedChecks{
					aborted: map[string]struct{}{},
				},
				defaultTimeout:           time.Duration(10 * time.Second),
				maxMessageProcessedTimes: 1,
				Tokens:                   make(chan interface{}, 10),
				Logger:                   &log.NullLog{},
				CheckUpdater:             &inMemChecksUpdater{},
			},
			args: args{
				check:     checkFixture,
				timesRead: 2,
			},
			want: nil,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				var wantRaws []CheckRaw
				gotUpdates := updater.updates
				state := stateupdater.StatusFailed
				wantUpdates := []stateupdater.CheckState{
					{
						ID:     checkFixture.CheckID,
						Status: &state,
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "UpdatesStateWhenErrorUpdatedStatus",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
								Error:  backend.ErrNonZeroExitCode,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted:        &inMemAbortedChecks{make(map[string]struct{}), nil},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater:   &inMemChecksUpdater{},
			},
			args: args{
				check: checkFixture,
			},
			want: nil,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRunParams := backend.RunParams{
					CheckID:          checkFixture.CheckID,
					CheckTypeName:    "job1",
					ChecktypeVersion: "latest",
					Image:            checkFixture.Image,
					Options:          checkFixture.Options,
					Target:           checkFixture.Target,
					AssetType:        checkFixture.AssetType,
					RequiredVars:     checkFixture.RequiredVars,
				}
				wantRaws := []CheckRaw{{
					Raw:       mustMarshalRunParams(wantRunParams),
					CheckID:   checkFixture.CheckID,
					StartTime: checkFixture.StartTime,
				}}
				gotUpdates := updater.updates
				state := stateupdater.StatusFailed
				rawLink := fmt.Sprintf("%s/logs", checkFixture.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:  checkFixture.CheckID,
						Raw: &rawLink,
					},
					{
						ID:     checkFixture.CheckID,
						Status: &state,
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
		{
			name: "ReturnsErrorWhenUnableToUploadLogs",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						res := make(chan backend.RunResult)
						go func() {
							output, err := json.Marshal(params)
							if err != nil {
								panic(err)
							}
							results := backend.RunResult{
								Output: output,
							}
							res <- results
						}()
						return res, nil
					},
				},
				cAborter: &checkAborter{
					cancels: sync.Map{},
				},
				aborted:        &inMemAbortedChecks{make(map[string]struct{}), nil},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater: &inMemChecksUpdater{
					terminalStatus: map[string]stateupdater.CheckState{
						checkFixture.CheckID: {
							ID:     checkFixture.CheckID,
							Status: str2ptr(stateupdater.StatusFinished),
						},
					},
					uploadLogError: errUploadingLogsTests,
				},
			},
			args: args{
				check: checkFixture,
			},
			want: errUploadingLogsTests,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				var wantRaws []CheckRaw
				gotUpdates := updater.updates
				// No update with a FAILED terminal status will be sent because
				// it will be reattempted.
				var wantUpdates []stateupdater.CheckState
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := &Runner{
				Backend:                  tt.fields.Backend,
				Logger:                   tt.fields.Logger,
				CheckUpdater:             tt.fields.CheckUpdater,
				abortedChecks:            tt.fields.aborted,
				cAborter:                 tt.fields.cAborter,
				defaultTimeout:           tt.fields.defaultTimeout,
				maxMessageProcessedTimes: tt.fields.maxMessageProcessedTimes,
			}
			got := cr.Run(tt.args.check, tt.args.timesRead)
			if !errors.Is(got, tt.want) {
				t.Fatalf("error want!=got, %+v!=%+v", tt.want, got)
			}
			stateDiff := tt.wantState(cr)
			if stateDiff != "" {
				t.Fatalf("want state!=got state, diff %s", stateDiff)
			}
		})
	}
}

func mustMarshal(params Check) []byte {
	res, err := json.Marshal(params)
	if err != nil {
		panic(err)
	}
	return res
}

func mustMarshalRunParams(params backend.RunParams) []byte {
	res, err := json.Marshal(params)
	if err != nil {
		panic(err)
	}
	return res
}

func str2ptr(str string) *string {
	return &str
}

func TestRunner_getChecktypeInfo(t *testing.T) {
	tests := []struct {
		image    string
		wants    []string
		wantsErr bool
	}{
		{
			image: "check",
			wants: []string{"check", "latest"},
		},
		{
			image: "check:1",
			wants: []string{"check", "1"},
		},
		{
			image: "vulcan/check1",
			wants: []string{"vulcan/check1", "latest"},
		},
		{ // Should be error?
			image: "docker.io/check1",
			wants: []string{"check1", "latest"},
		},
		{
			image: "docker.io/vulcansec/check1",
			wants: []string{"vulcansec/check1", "latest"},
		},
		{
			image: "artifactory.com/check1",
			wants: []string{"artifactory.com/check1", "latest"},
		},
		{
			image: "artifactory.com/vulcan/check1",
			wants: []string{"artifactory.com/vulcan/check1", "latest"},
		},
		{
			image: "artifactory.com/vulcan/check1:1",
			wants: []string{"artifactory.com/vulcan/check1", "1"},
		},
		{
			image: "artifactory.com:1234/vulcan/check1:1",
			wants: []string{"artifactory.com:1234/vulcan/check1", "1"},
		},
		{
			image:    "http://artifactory.com:1234/vulcan/check1:1",
			wants:    []string{"", ""},
			wantsErr: true,
		},
		{
			image:    "image with spaces",
			wants:    []string{"", ""},
			wantsErr: true,
		},
	}
	for _, c := range tests {
		n, v, err := getChecktypeInfo(c.image)
		if c.wantsErr != (err != nil) {
			t.Errorf("image:%s want error %v and got %v", c.image, c.wantsErr, err)
		}
		if diff := cmp.Diff(c.wants, []string{n, v}); diff != "" {
			t.Errorf("image:%s want state!=got state, diff %s", c.image, diff)
		}
	}
}
