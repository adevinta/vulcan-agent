/*
Copyright 2023 Adevinta
*/

package queue

import (
	"errors"
	"testing"

	"github.com/adevinta/vulcan-agent/v2/jobrunner"
)

func TestDiscard(t *testing.T) {
	proc := jobrunner.NewDiscard()
	for i := 0; i < 2; i++ {
		token, err := getToken(proc)
		if err != nil {
			t.Fatalf("could not get token: %v", err)
		}
		delete := <-proc.ProcessMessage(jobrunner.Message{}, token)
		if !delete {
			t.Errorf("message is not marked for deletion")
		}
	}
}

func getToken(proc MessageProcessor) (token jobrunner.Token, err error) {
	select {
	case token := <-proc.FreeTokens():
		return token, nil
	default:
		return nil, errors.New("no tokens available")
	}
}
