package retryer

import (
	"errors"
	"fmt"
	"testing"

	"github.com/adevinta/vulcan-agent/log"
)

var errTest = errors.New("test")

type ExecTester struct {
	NOfCalls int
	op       func(calls int) error
}

func (e *ExecTester) exec() error {
	e.NOfCalls++
	return e.op(e.NOfCalls)
}

func TestRetryer_WithRetries(t *testing.T) {
	type fields struct {
		log      log.Logger
		interval int
		retries  int
	}
	tests := []struct {
		name        string
		fields      fields
		op          string
		exec        *ExecTester
		wantErr     error
		wantOpCalls int
	}{
		{
			name: "DoesNotRetryIfNoError",
			fields: fields{
				retries:  2,
				interval: 1,
				log:      &log.NullLog{},
			},
			exec: &ExecTester{
				op: func(calls int) error {
					return nil
				},
			},
			wantErr:     nil,
			wantOpCalls: 1,
		},
		{
			name: "RetriesIfNotShortCircuit",
			fields: fields{
				retries:  2,
				interval: 1,
				log:      &log.NullLog{},
			},
			exec: &ExecTester{
				op: func(calls int) error {
					return errTest
				},
			},
			wantErr:     errTest,
			wantOpCalls: 3,
		},
		{
			name: "StopRetryingIfPermanentError",
			fields: fields{
				retries:  2,
				interval: 1,
				log:      &log.NullLog{},
			},
			exec: &ExecTester{
				op: func(calls int) error {
					if calls == 2 {
						return fmt.Errorf("a permanent error %w", ErrPermanent)
					}
					return errTest
				},
			},
			wantErr:     ErrPermanent,
			wantOpCalls: 2,
		},
		{
			name: "ShortCircuits",
			fields: fields{
				retries:  2,
				interval: 1,
				log:      &log.NullLog{},
			},
			exec: &ExecTester{
				op: func(calls int) error {
					if calls == 2 {
						return nil
					}
					return errTest
				},
			},
			wantErr:     nil,
			wantOpCalls: 2,
		},
		{
			name: "ShortCircuits",
			fields: fields{
				retries:  2,
				interval: 1,
				log:      &log.NullLog{},
			},
			exec: &ExecTester{
				op: func(calls int) error {
					if calls == 2 {
						return nil
					}
					return errTest
				},
			},
			wantErr:     nil,
			wantOpCalls: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := Retryer{
				interval: tt.fields.interval,
				log:      tt.fields.log,
				retries:  tt.fields.retries,
			}
			err := b.WithRetries(tt.op, tt.exec.exec)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("wantErr != err, err %+v", err)
			}
			gotCalls := tt.exec.NOfCalls
			if tt.wantOpCalls != gotCalls {
				t.Fatalf("wantCalls != gotCalls, %d!=%d", tt.wantOpCalls, gotCalls)
			}
		})
	}
}
