package persistence

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/adevinta/vulcan-agent/check"

	"github.com/sirupsen/logrus"
	"github.com/lestrrat-go/backoff"
)

var (
	errSim                      = errors.New("Simulating an error")
	httpPreconditionFailedError = &HTTPError{
		Status:     "Precondition failed",
		StatusCode: http.StatusPreconditionFailed,
	}
	httpConflitError = &HTTPError{
		Status:     "Conflict",
		StatusCode: http.StatusConflict,
	}
)

type createAgentPersisterMock struct {
	PersisterCheckStateUpdater
	retries  int
	callback func(m *createAgentPersisterMock, agentVersion, jobqueueID string) (string, string, error)
}

func (m *createAgentPersisterMock) CreateAgent(agentVersion, jobqueueID string) (string, string, error) {
	return m.callback(m, agentVersion, jobqueueID)
}

func Test_withBackoff_CreateAgent(t *testing.T) {
	testLog := logrus.New().WithField("Test_withBackoff_CreateAgent", "")
	type fields struct {
		PersisterCheckStateUpdater PersisterCheckStateUpdater
		policy                     backoff.Policy
		log                        *logrus.Entry
	}
	type args struct {
		agentVersion string
		jobqueueID   string
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		wantAgentID     string
		wantJobqueueARN string
		wantErr         error
	}{
		{
			name: "No retries needed",
			fields: fields{
				PersisterCheckStateUpdater: &createAgentPersisterMock{
					callback: func(m *createAgentPersisterMock, agentVersion, jobqueueID string) (string, string, error) {
						return "agentID", "arn", nil
					},
				},
				policy: backoff.NewExponential(
					backoff.WithInterval(200*time.Millisecond),
					backoff.WithJitterFactor(0.05),
					backoff.WithMaxRetries(2),
				),
				log: testLog,
			},
			args: args{
				agentVersion: "1",
				jobqueueID:   "queue",
			},
			wantAgentID:     "agentID",
			wantJobqueueARN: "arn",
		},
		{
			name: "One retry",
			fields: fields{
				PersisterCheckStateUpdater: &createAgentPersisterMock{
					retries: 1,
					callback: func(m *createAgentPersisterMock, agentVersion, jobqueueID string) (string, string, error) {
						m.retries--
						if m.retries < 0 {
							return "agentID", "arn", nil
						}
						return "", "", errSim
					},
				},
				policy: backoff.NewExponential(
					backoff.WithInterval(200*time.Millisecond),
					backoff.WithJitterFactor(0.05),
					backoff.WithMaxRetries(2),
				),
				log: testLog,
			},
			args: args{
				agentVersion: "1",
				jobqueueID:   "queue",
			},
			wantAgentID:     "agentID",
			wantJobqueueARN: "arn",
		},
		{
			name: "Max Retries Exceeded",
			fields: fields{
				PersisterCheckStateUpdater: &createAgentPersisterMock{
					retries: 4, // Three retries and the first call.
					callback: func(m *createAgentPersisterMock, agentVersion, jobqueueID string) (string, string, error) {
						m.retries--
						if m.retries < 0 {
							return "agentID", "arn", nil
						}
						return "", "", errSim
					},
				},
				policy: backoff.NewExponential(
					backoff.WithInterval(200*time.Millisecond),
					backoff.WithJitterFactor(0.05),
					backoff.WithMaxRetries(2),
				),
				log: testLog,
			},
			args: args{
				agentVersion: "1",
				jobqueueID:   "queue",
			},
			wantErr: errSim,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := withBackoff{
				PersisterCheckStateUpdater: tt.fields.PersisterCheckStateUpdater,
				policy:                     tt.fields.policy,
				log:                        tt.fields.log,
			}
			gotAgentID, gotJobqueueARN, err := b.CreateAgent(tt.args.agentVersion, tt.args.jobqueueID)
			if (err != nil) && err != tt.wantErr {
				t.Errorf("withBackoff.CreateAgent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotAgentID != tt.wantAgentID {
				t.Errorf("withBackoff.CreateAgent() gotAgentID = %v, want %v", gotAgentID, tt.wantAgentID)
			}
			if gotJobqueueARN != tt.wantJobqueueARN {
				t.Errorf("withBackoff.CreateAgent() gotJobqueueARN = %v, want %v", gotJobqueueARN, tt.wantJobqueueARN)
			}
		})
	}
}

type UpdateAgentStatusPersisterMock struct {
	PersisterCheckStateUpdater
	retries  int
	callback func(m *UpdateAgentStatusPersisterMock, agentID, agentStatus string) error
}

func (m *UpdateAgentStatusPersisterMock) UpdateAgentStatus(agentID, agentStatus string) error {
	return m.callback(m, agentID, agentStatus)
}

func Test_withBackoff_UpdateAgentStatus(t *testing.T) {
	testLog := logrus.New().WithField("Test_withBackoff_UpdateAgentStatus", "")
	type fields struct {
		PersisterCheckStateUpdater PersisterCheckStateUpdater
		policy                     backoff.Policy
		log                        *logrus.Entry
	}
	type args struct {
		agentID     string
		agentStatus string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "No retries needed",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateAgentStatusPersisterMock{
					callback: func(m *UpdateAgentStatusPersisterMock, agentID, agentStatus string) error {
						return nil
					},
				},
				policy: backoff.NewExponential(
					backoff.WithInterval(200*time.Millisecond),
					backoff.WithJitterFactor(0.05),
					backoff.WithMaxRetries(2),
				),
				log: testLog,
			},
			args: args{
				agentID:     "1",
				agentStatus: "queue",
			},
		},
		{
			name: "One retry",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateAgentStatusPersisterMock{
					retries: 1,
					callback: func(m *UpdateAgentStatusPersisterMock, agentID, agentStatus string) error {
						m.retries--
						if m.retries < 0 {
							return nil
						}
						return errSim
					},
				},
				policy: backoff.NewExponential(
					backoff.WithInterval(200*time.Millisecond),
					backoff.WithJitterFactor(0.05),
					backoff.WithMaxRetries(2),
				),
				log: testLog,
			},
			args: args{
				agentID:     "1",
				agentStatus: "queue",
			},
		},
		{
			name: "Max Retries Exceeded",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateAgentStatusPersisterMock{
					retries: 4,
					callback: func(m *UpdateAgentStatusPersisterMock, agentID, agentStatus string) error {
						m.retries--
						if m.retries < 0 {
							return nil
						}
						return errSim
					},
				},
				policy: backoff.NewExponential(
					backoff.WithInterval(200*time.Millisecond),
					backoff.WithJitterFactor(0.05),
					backoff.WithMaxRetries(2),
				),
				log: testLog,
			},
			args: args{
				agentID:     "1",
				agentStatus: "queue",
			},

			wantErr: errSim,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := withBackoff{
				PersisterCheckStateUpdater: tt.fields.PersisterCheckStateUpdater,
				policy:                     tt.fields.policy,
				log:                        tt.fields.log,
			}
			err := b.UpdateAgentStatus(tt.args.agentID, tt.args.agentStatus)
			if (err != nil) && err != tt.wantErr {
				t.Errorf("withBackoff.UpdateAgentStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_WithBackoff(t *testing.T) {
	testLog := logrus.New().WithField("Test_WithBackoff", "")
	type fields struct {
		PersisterCheckStateUpdater PersisterCheckStateUpdater
		retries                    int
		log                        *logrus.Entry
	}
	type args struct {
		agentID     string
		agentStatus string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "No retries needed",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateAgentStatusPersisterMock{
					callback: func(m *UpdateAgentStatusPersisterMock, agentID, agentStatus string) error {
						return nil
					},
				},
				retries: 2,
				log:     testLog,
			},
			args: args{
				agentID:     "1",
				agentStatus: "queue",
			},
		},
		{
			name: "One retry",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateAgentStatusPersisterMock{
					retries: 1,
					callback: func(m *UpdateAgentStatusPersisterMock, agentID, agentStatus string) error {
						m.retries--
						if m.retries < 0 {
							return nil
						}
						return errSim
					},
				},
				retries: 2,
				log:     testLog,
			},
			args: args{
				agentID:     "1",
				agentStatus: "queue",
			},
		},
		{
			name: "Max Retries Exceeded",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateAgentStatusPersisterMock{
					retries: 4,
					callback: func(m *UpdateAgentStatusPersisterMock, agentID, agentStatus string) error {
						m.retries--
						if m.retries < 0 {
							return nil
						}
						return errSim
					},
				},
				retries: 2,
				log:     testLog,
			},
			args: args{
				agentID:     "1",
				agentStatus: "queue",
			},

			wantErr: errSim,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := WithBackoff(tt.fields.PersisterCheckStateUpdater, tt.fields.retries, tt.fields.log)
			err := b.UpdateAgentStatus(tt.args.agentID, tt.args.agentStatus)
			if (err != nil) && err != tt.wantErr {
				t.Errorf("withBackoff.UpdateAgentStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

type UpdateCheckStatusPersisterMock struct {
	PersisterCheckStateUpdater
	retries  int
	callback func(m *UpdateCheckStatusPersisterMock, checkID string, state check.State) error
}

func (m *UpdateCheckStatusPersisterMock) UpdateCheckState(checkID string, state check.State) error {
	return m.callback(m, checkID, state)
}

func Test_UpdateCheckStateWithBackoff(t *testing.T) {
	testLog := logrus.New().WithField("UpdateCheckStateWithBackoff", "")
	type fields struct {
		PersisterCheckStateUpdater PersisterCheckStateUpdater
		retries                    int
		log                        *logrus.Entry
	}
	type args struct {
		checkID    string
		checkState check.State
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "No retries needed",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateCheckStatusPersisterMock{
					callback: func(m *UpdateCheckStatusPersisterMock, checkID string, state check.State) error {
						return nil
					},
				},
				retries: 2,
				log:     testLog,
			},
			args: args{
				checkID: "1",
				checkState: check.State{
					Progress: 0,
					Status:   "RUNNING",
				},
			},
		},
		{
			name: "1 retries",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateCheckStatusPersisterMock{
					retries: 1,
					callback: func(m *UpdateCheckStatusPersisterMock, checkID string, state check.State) error {
						m.retries--
						if m.retries < 1 {
							return nil
						}
						return errSim
					},
				},
				retries: 1,
				log:     testLog,
			},
			args: args{
				checkID: "1",
				checkState: check.State{
					Progress: 0,
					Status:   "RUNNING",
				},
			},
		},
		{
			name: "ShortcircuitsTheBackoff",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateCheckStatusPersisterMock{
					retries: 2,
					callback: func(m *UpdateCheckStatusPersisterMock, checkID string, state check.State) error {
						m.retries--
						if m.retries < 1 {
							return errors.New("UnexpectedError")
						}
						if m.retries == 1 {
							return httpPreconditionFailedError
						}
						return nil
					},
				},
				retries: 5,
				log:     testLog,
			},
			args: args{
				checkID: "1",
				checkState: check.State{
					Progress: 0,
					Status:   "RUNNING",
				},
			},
			wantErr: httpPreconditionFailedError,
		},

		{
			name: "ShortcircuitsTheBackoffWithConflitError",
			fields: fields{
				PersisterCheckStateUpdater: &UpdateCheckStatusPersisterMock{
					retries: 2,
					callback: func(m *UpdateCheckStatusPersisterMock, checkID string, state check.State) error {
						m.retries--
						if m.retries < 1 {
							return errors.New("UnexpectedError")
						}
						if m.retries == 1 {
							return httpConflitError
						}
						return nil
					},
				},
				retries: 5,
				log:     testLog,
			},
			args: args{
				checkID: "1",
				checkState: check.State{
					Progress: 0,
					Status:   "RUNNING",
				},
			},
			wantErr: httpConflitError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := WithBackoff(tt.fields.PersisterCheckStateUpdater, tt.fields.retries, tt.fields.log)
			err := b.UpdateCheckState(tt.args.checkID, tt.args.checkState)
			if (err != nil) && err != tt.wantErr {
				t.Errorf("withBackoff.UpdateCheckState() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

		})
	}
}
