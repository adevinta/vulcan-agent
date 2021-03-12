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
	"testing"
	"time"

	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/stateupdater"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

var (
	errUnexpectedTest = errors.New("unexpected")

	runJobFixture1 = Job{
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
	updates []stateupdater.CheckState
	raws    []CheckRaw
}

func (im *inMemChecksUpdater) UpdateState(cs stateupdater.CheckState) error {
	if im.updates == nil {
		im.updates = make([]stateupdater.CheckState, 0)
	}
	im.updates = append(im.updates, cs)
	return nil
}

func (im *inMemChecksUpdater) UpdateCheckRaw(checkID string, stime time.Time, raw []byte) (string, error) {
	if im.raws != nil {
		im.raws = make([]CheckRaw, 0)
	}
	im.raws = append(im.raws, CheckRaw{
		Raw:       raw,
		CheckID:   checkID,
		StartTime: stime,
	})
	return fmt.Sprintf("%s/logs", checkID), nil
}

type mockChecksUpdater struct {
	stateUpdater    func(cs stateupdater.CheckState) error
	checkRawUpdater func(checkID string, stime time.Time, raw []byte) (string, error)
}

func (m *mockChecksUpdater) UpdateState(cs stateupdater.CheckState) error {
	return m.stateUpdater(cs)
}

func (m *mockChecksUpdater) UpdateCheckRaw(checkID string, stime time.Time, raw []byte) (string, error) {
	return m.checkRawUpdater(checkID, stime, raw)
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
		Backend        backend.Backend
		Tokens         chan interface{}
		Logger         log.Logger
		CheckUpdater   CheckStateUpdater
		cAborter       *checkAborter
		aborted        AbortedChecks
		defaultTimeout time.Duration
	}
	type args struct {
		msg   string
		token interface{}
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      bool
		wantState jRunnerStateChecker
	}{
		{
			name: "RunsACheck",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						var res = make(chan backend.RunResult)
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
				msg:   string(mustMarshal(runJobFixture1)),
				token: token{},
			},
			want: true,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRunParams := backend.RunParams{
					CheckID:          runJobFixture1.CheckID,
					CheckTypeName:    "job1",
					ChecktypeVersion: "latest",
					Image:            runJobFixture1.Image,
					Options:          runJobFixture1.Options,
					Target:           runJobFixture1.Target,
					AssetType:        runJobFixture1.AssetType,
					RequiredVars:     runJobFixture1.RequiredVars,
				}
				wantRaws := []CheckRaw{{
					Raw:       mustMarshalRunParams(wantRunParams),
					CheckID:   runJobFixture1.CheckID,
					StartTime: runJobFixture1.StartTime,
				}}
				gotUpdates := updater.updates
				rawLink := fmt.Sprintf("%s/logs", runJobFixture1.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:  runJobFixture1.CheckID,
						Raw: &rawLink,
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
						var res = make(chan backend.RunResult)
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
				msg:   string(mustMarshal(runJobFixture1)),
				token: token{},
			},
			want: false,
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
						var res = make(chan backend.RunResult)
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
				msg:   string(mustMarshal(runJobFixture1)),
				token: token{},
			},
			want: true,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRunParams := backend.RunParams{
					CheckID:          runJobFixture1.CheckID,
					CheckTypeName:    "job1",
					ChecktypeVersion: "latest",
					Image:            runJobFixture1.Image,
					Options:          runJobFixture1.Options,
					Target:           runJobFixture1.Target,
					AssetType:        runJobFixture1.AssetType,
					RequiredVars:     runJobFixture1.RequiredVars,
				}
				wantRaws := []CheckRaw{{
					Raw:       mustMarshalRunParams(wantRunParams),
					CheckID:   runJobFixture1.CheckID,
					StartTime: runJobFixture1.StartTime,
				}}
				gotUpdates := updater.updates
				state := stateupdater.StatusTimeout
				rawLink := fmt.Sprintf("%s/logs", runJobFixture1.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:  runJobFixture1.CheckID,
						Raw: &rawLink,
					},
					{
						ID:     runJobFixture1.CheckID,
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
						var res = make(chan backend.RunResult)
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
				msg:   string(mustMarshal(runJobFixture1)),
				token: token{},
			},
			want: true,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				wantRunParams := backend.RunParams{
					CheckID:          runJobFixture1.CheckID,
					CheckTypeName:    "job1",
					ChecktypeVersion: "latest",
					Image:            runJobFixture1.Image,
					Options:          runJobFixture1.Options,
					Target:           runJobFixture1.Target,
					AssetType:        runJobFixture1.AssetType,
					RequiredVars:     runJobFixture1.RequiredVars,
				}
				wantRaws := []CheckRaw{{
					Raw:       mustMarshalRunParams(wantRunParams),
					CheckID:   runJobFixture1.CheckID,
					StartTime: runJobFixture1.StartTime,
				}}
				gotUpdates := updater.updates
				state := stateupdater.StatusAborted
				rawLink := fmt.Sprintf("%s/logs", runJobFixture1.CheckID)
				wantUpdates := []stateupdater.CheckState{
					{
						ID:  runJobFixture1.CheckID,
						Raw: &rawLink,
					},
					{
						ID:     runJobFixture1.CheckID,
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
						var res = make(chan backend.RunResult)
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
						runJobFixture1.CheckID: {},
					},
				},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater:   &inMemChecksUpdater{},
			},
			args: args{
				msg:   string(mustMarshal(runJobFixture1)),
				token: token{},
			},
			want: true,
			wantState: func(r *Runner) string {
				updater := r.CheckUpdater.(*inMemChecksUpdater)
				gotRaws := updater.raws
				var wantRaws []CheckRaw
				gotUpdates := updater.updates
				state := stateupdater.StatusAborted
				wantUpdates := []stateupdater.CheckState{
					{
						ID:     runJobFixture1.CheckID,
						Status: &state,
					},
				}
				rawsDiff := cmp.Diff(wantRaws, gotRaws)
				updateDiff := cmp.Diff(wantUpdates, gotUpdates)
				return fmt.Sprintf("%s%s", rawsDiff, updateDiff)
			},
		},

		{
			name: "DontDeleteWhenErrorUpdatingStatus",
			fields: fields{
				Backend: &mockBackend{
					CheckRunner: func(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
						var res = make(chan backend.RunResult)
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
						runJobFixture1.CheckID: {},
					},
				},
				defaultTimeout: time.Duration(10 * time.Second),
				Tokens:         make(chan interface{}, 10),
				Logger:         &log.NullLog{},
				CheckUpdater: &mockChecksUpdater{
					stateUpdater: func(cs stateupdater.CheckState) error {
						return errUnexpectedTest
					},
					checkRawUpdater: func(checkID string, stime time.Time, raw []byte) (string, error) {
						return "link", nil
					},
				},
			},
			args: args{
				msg:   string(mustMarshal(runJobFixture1)),
				token: token{},
			},
			want: false,
			wantState: func(r *Runner) string {
				return ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := &Runner{
				Backend:        tt.fields.Backend,
				Tokens:         tt.fields.Tokens,
				Logger:         tt.fields.Logger,
				CheckUpdater:   tt.fields.CheckUpdater,
				abortedChecks:  tt.fields.aborted,
				cAborter:       tt.fields.cAborter,
				defaultTimeout: tt.fields.defaultTimeout,
			}
			gotChan := cr.ProcessMessage(tt.args.msg, tt.args.token)
			got := <-gotChan
			if tt.want != got {
				t.Fatalf("error want!=got, %+v!=%+v", tt.want, got)
			}
			stateDiff := tt.wantState(cr)
			if stateDiff != "" {
				t.Fatalf("want state!=got state, diff %s", stateDiff)
			}

		})
	}
}

func mustMarshal(params Job) []byte {
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
