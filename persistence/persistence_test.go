package persistence

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/julienschmidt/httprouter"

	"github.com/adevinta/vulcan-agent"
	"github.com/adevinta/vulcan-agent/check"
)

var (
	router *httprouter.Router

	timeout = 2 * time.Second

	testJobqueue = Jobqueue{
		ID:  "ffffffff-ffff-ffff-ffff-ffffffffffff",
		ARN: "arn:aws:sqs:eu-west-1:999999999999:queue",
	}

	testAgent = Agent{
		Version:    "abc1234",
		JobqueueID: "ffffffff-ffff-ffff-ffff-ffffffffffff",
	}

	testCheck = Check{
		ID: "00000000-0000-0000-0000-000000000000",
	}

	agents = map[string]*Agent{}

	checks = map[string]*Check{
		testCheck.ID: &testCheck,
	}
)

func TestTimeout(t *testing.T) {
	log := logrus.New()
	log.Level = logrus.DebugLevel
	l := logrus.NewEntry(log)

	// Create a slow router.
	h, _, _ := router.Lookup("POST", "/agents")
	slowRouter := httprouter.New()
	slowRouter.POST("/agents", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		time.Sleep(timeout + time.Second)
		h(w, r, ps)
	})

	ts := httptest.NewServer(slowRouter)

	p, err := New(ts.URL, timeout, l)
	if err != nil {
		t.Fatal(err)
	}

	testAgent.ID, _, err = p.CreateAgent(testAgent.Version, testAgent.JobqueueID)
	if err == nil {
		t.Fatal(errors.New("persistence request did't time out"))
	}

	log.Error(err)
}

func TestUnit(t *testing.T) {
	log := logrus.New()
	log.Level = logrus.DebugLevel
	l := logrus.NewEntry(log)

	ts := httptest.NewServer(router)

	p, err := New(ts.URL, timeout, l)
	if err != nil {
		t.Fatal(err)
	}

	testAgent.ID, _, err = p.CreateAgent(testAgent.Version, testAgent.JobqueueID)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		agent    Agent
		check    Check
		testFunc func(error) error
	}{
		{
			name:     "positive",
			agent:    testAgent,
			check:    testCheck,
			testFunc: func(err error) error { return err },
		},
		{
			name:  "negative",
			agent: Agent{},
			check: Check{},
			testFunc: func(err error) error {
				if err == nil {
					return fmt.Errorf("expected error")
				}
				return nil
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var terr error

			err = p.UpdateAgentStatus(tc.agent.ID, agent.StatusRegistered)
			terr = tc.testFunc(err)
			if terr != nil {
				t.Fatal(terr)
			}

			err = p.UpdateAgentHeartbeat(tc.agent.ID)
			terr = tc.testFunc(err)
			if terr != nil {
				t.Fatal(terr)
			}

			err = p.UpdateCheckAgent(tc.check.ID, tc.agent.ID)
			terr = tc.testFunc(err)
			if terr != nil {
				t.Fatal(terr)
			}

			err = p.UpdateCheckState(tc.check.ID, check.State{
				Status:   check.StatusRunning,
				Progress: 1.0,
			})
			terr = tc.testFunc(err)
			if terr != nil {
				t.Fatal(terr)
			}

			err = p.UpdateCheckReport(tc.check.ID, tc.check.Report)
			terr = tc.testFunc(err)
			if terr != nil {
				t.Fatal(terr)
			}
		})
	}
}

func uuid() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func init() {
	router = httprouter.New()

	router.POST("/agents", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		a, err := readJSONAgentRequest(r)
		if err != nil {
			writeJSONResponse(w, http.StatusInternalServerError, nil)
			return
		}
		id, err := uuid()
		if err != nil {
			writeJSONResponse(w, http.StatusInternalServerError, nil)
			return
		}
		a.ID = id
		a.Status = agent.StatusNew
		a.Enabled = true
		a.Jobqueue = testJobqueue

		agents[a.ID] = &a

		writeJSONResponse(w, http.StatusOK, AgentData{Agent: *agents[a.ID]})
	})

	router.POST("/agents/:id/heartbeat", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		id := ps.ByName("id")

		if _, ok := agents[id]; ok {
			writeJSONResponse(w, http.StatusOK, AgentData{Agent: *agents[id]})
			return
		}

		writeJSONResponse(w, http.StatusNotFound, nil)
		return
	})

	router.PATCH("/agents/:id", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		id := ps.ByName("id")
		a, err := readJSONAgentRequest(r)
		if err != nil {
			writeJSONResponse(w, http.StatusInternalServerError, nil)
			return
		}

		if _, ok := agents[id]; ok {
			// Only fields that are actually updated by the agent.
			if agents[id].Status != a.Status && a.Status != "" {
				agents[id].Status = a.Status
			}
			writeJSONResponse(w, http.StatusOK, AgentData{Agent: *agents[id]})
			return
		}

		writeJSONResponse(w, http.StatusNotFound, nil)
	})

	router.PATCH("/checks/:id", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		id := ps.ByName("id")
		c, err := readJSONCheckRequest(r)
		if err != nil {
			writeJSONResponse(w, http.StatusInternalServerError, nil)
			return
		}

		if _, ok := checks[id]; ok {
			// Only fields that are actually updated by the agent.
			if checks[id].AgentID != c.AgentID && c.AgentID != "" {
				checks[id].AgentID = c.AgentID
			}
			if checks[id].Status != c.Status && c.Status != "" {
				checks[id].Status = c.Status
			}
			if checks[id].Progress != c.Progress && c.Progress != 0.0 {
				checks[id].Progress = c.Progress
			}
			if checks[id].Raw != c.Raw && c.Raw != "" {
				checks[id].Raw = c.Raw
			}
			if checks[id].Report != c.Report && c.Report != "" {
				checks[id].Report = c.Report
			}

			writeJSONResponse(w, http.StatusOK, CheckData{Check: *checks[id]})
			return
		}

		writeJSONResponse(w, http.StatusNotFound, nil)
	})

	router.POST("/checks/:id/raw", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		id := ps.ByName("id")

		if _, ok := checks[id]; ok {
			writeJSONResponse(w, http.StatusOK, CheckData{Check: *checks[id]})
			return
		}

		writeJSONResponse(w, http.StatusNotFound, nil)
		return
	})

	router.POST("/checks/:id/report", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		id := ps.ByName("id")

		if _, ok := checks[id]; ok {
			writeJSONResponse(w, http.StatusOK, CheckData{Check: *checks[id]})
			return
		}

		writeJSONResponse(w, http.StatusNotFound, nil)
		return
	})
}

func readJSONAgentRequest(r *http.Request) (Agent, error) {
	dec := json.NewDecoder(r.Body)
	var a Agent
	err := dec.Decode(&a)
	if err != nil {
		return Agent{}, err
	}
	defer func() {
		err = r.Body.Close()
		if err != nil {
			log.Println(err)
		}
	}()
	return a, nil
}

func readJSONCheckRequest(r *http.Request) (Check, error) {
	dec := json.NewDecoder(r.Body)
	var a Check
	err := dec.Decode(&a)
	if err != nil {
		return Check{}, err
	}
	defer func() {
		err = r.Body.Close()
		if err != nil {
			log.Println(err)
		}
	}()
	return a, nil
}

func writeJSONResponse(w http.ResponseWriter, code int, v interface{}) {
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
	}
}
