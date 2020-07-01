package stream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/danfaizer/gowse"
	"github.com/sirupsen/logrus"

	agent "github.com/adevinta/vulcan-agent"
	"github.com/adevinta/vulcan-agent/check"
	metrics "github.com/adevinta/vulcan-metrics-client"
)

const (
	streamName    = "events"
	streamTimeout = 2 * time.Second
	pingInterval  = 1 * time.Second
	waitTime      = 100 * time.Millisecond
)

var (
	knownAgentID   = "00000000-0000-0000-0000-000000000000"
	unknownAgentID = "11111111-1111-1111-1111-111111111111"

	knownCheckJob = check.JobParams{
		ScanID:  "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaab",
		CheckID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		Target:  "test",
		Image:   "test",
		Timeout: 10,
	}

	unknownCheckJob = check.JobParams{
		CheckID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		Target:  "test",
		Image:   "test",
		Timeout: 10,
	}
)

type testMeta struct {
	aborted bool
}

type TestAgent struct {
	id      string
	status  string
	storage check.Storage
	jobs    map[string]check.Job
	ctx     context.Context
	log     *logrus.Entry
}

func (ta *TestAgent) ID() string {
	return ta.id
}

func (ta *TestAgent) Status() string {
	mu.Lock()
	defer mu.Unlock()
	return ta.status
}

func (ta *TestAgent) SetStatus(status string) {
	mu.Lock()
	defer mu.Unlock()
	ta.status = status
}

func (ta *TestAgent) Job(checkID string) check.Job {
	job, err := ta.storage.Get(checkID)
	if err != nil {
		return check.Job{}
	}

	return job
}

func (ta *TestAgent) Jobs() map[string]check.Job {
	return ta.jobs
}

func (ta *TestAgent) Run(checkID string) error {
	var err error

	_, err = ta.storage.Get(checkID)
	if err != nil {
		return err
	}

	return ta.storage.SetMeta(checkID, testMeta{})
}

func (ta *TestAgent) Kill(checkID string) error {
	return nil
}

func (ta *TestAgent) AbortChecks(scanID string) error {
	var err error
	jobs, err := ta.storage.GetAll()
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.ScanID == scanID {
			ta.Abort(j.CheckID)
		}
	}
	return nil
}

func (ta *TestAgent) Abort(checkID string) error {
	var err error
	_, err = ta.storage.Get(checkID)
	if err != nil {
		return err
	}

	err = ta.storage.SetMeta(checkID, testMeta{aborted: true})
	if err != nil {
		return err
	}

	ta.log.WithFields(logrus.Fields{
		"check_id": checkID,
	}).Info("check aborted")

	return nil
}

func (ta *TestAgent) Raw(checkID string) ([]byte, error) {
	return []byte{}, nil
}

type mockMetricsClient struct {
	metrics.Client
	mx      sync.Mutex
	metrics []metrics.Metric
}

func (mc *mockMetricsClient) Push(m metrics.Metric) {
	mc.mx.Lock()
	mc.metrics = append(mc.metrics, m)
	mc.mx.Unlock()
}

func TestStreamActions(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	mc := &mockMetricsClient{}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	s, err := New(agentCtx, agentCancel, &a, &stor, mc, wsURL.String(),
		streamTimeout, l, 1, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	job, err := stor.NewJob(agentCtx, knownCheckJob, l)
	if err != nil {
		t.Fatal(err)
	}

	err = a.Run(job.CheckID)
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]func(agent.Agent, string){
		"disconnect": func(a agent.Agent, checkID string) {
			a.SetStatus(agent.StatusDisconnected)
		},
		"abort": func(a agent.Agent, scanID string) {
			err := a.AbortChecks(scanID)
			if err != nil {
				t.Fatal(err)
			}
		},
		"ping": func(_ agent.Agent, _ string) {},
	}

	// Keep sending pings.
	go func() {
		ticker := time.NewTicker(pingInterval)
		agentDone := agentCtx.Done()
	LOOP:
		for {
			select {
			case <-ticker.C:
				topic.Broadcast(Message{Action: "ping"})
			case <-agentDone:
				break LOOP
			}
		}
	}()

	go func() {
		err = s.HandleMessages(actions)
		if err != nil {
			log.Error(err)
		}
	}()

	time.Sleep(waitTime)

	tests := []struct {
		name     string
		message  Message
		testFunc func(ta *TestAgent) bool
	}{
		{
			name:    "malformed-message",
			message: Message{},
		},
		{
			name:    "empty-action",
			message: Message{AgentID: knownAgentID},
		},
		{
			name:    "unknown-action",
			message: Message{AgentID: knownAgentID, Action: "unknown"},
		},
		{
			name:    "unknown-scan",
			message: Message{ScanID: unknownCheckJob.ScanID, Action: "abort"},
		},
		{
			name:     "known-scan",
			message:  Message{ScanID: knownCheckJob.ScanID, Action: "abort"},
			testFunc: func(ta *TestAgent) bool { return a.Job(knownCheckJob.CheckID).Meta.(testMeta).aborted },
		},
		{
			name:    "unknown-agent",
			message: Message{AgentID: unknownAgentID, Action: "disconnect"},
		},
		{
			name:     "known-agent",
			message:  Message{AgentID: knownAgentID, Action: "disconnect"},
			testFunc: func(ta *TestAgent) bool { return true },
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			topic.Broadcast(tc.message)
			time.Sleep(waitTime)
			if tc.testFunc != nil {
				if !tc.testFunc(&a) {
					t.Fatalf("test %v failed", tc.name)
				}
			}

			// Verify that broadcasted mssg was passed
			// to metrics client and metrics pushed.
			// (we have to use a mutex because otherwise
			// we gate a race condition due to ping actions)
			found := false
			mc.mx.Lock()
			for _, m := range mc.metrics {
				for _, tag := range m.Tags {
					if tag == fmt.Sprint("action:", tc.message.Action) {
						found = true
					}
				}
			}
			mc.mx.Unlock()
			if !found {
				t.Fatalf("test %v failed: no metris pushed for broadcasted mssg", tc.name)
			}
		})
	}

	agentCancel()
}

func TestStreamConnectTimeout(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	s, err := New(agentCtx, agentCancel, &a, &stor, &mockMetricsClient{}, wsURL.String(),
		streamTimeout, l, 1, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	actions := map[string]func(agent.Agent, string){
		"disconnect": func(a agent.Agent, checkID string) {
			a.SetStatus(agent.StatusDisconnected)
		},
		"ping": func(_ agent.Agent, _ string) {},
	}

	if err := s.HandleMessages(actions); err == nil {
		log.Error(err)
		t.Fatal(errors.New("stream connection didn't time out"))
	}

	agentCancel()
}

func TestStreamHandleRegister(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	s, err := New(agentCtx, agentCancel, &a, &stor, &mockMetricsClient{}, wsURL.String(),
		streamTimeout, l, 1, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Keep sending register events.
	go func() {
		ticker := time.NewTicker(pingInterval)
		agentDone := agentCtx.Done()
	LOOP:
		for {
			select {
			case <-ticker.C:
				topic.Broadcast(Message{Action: "register", AgentID: knownAgentID})
			case <-agentDone:
				break LOOP
			}
		}
	}()

	if err := s.HandleRegister(); err != nil {
		log.Error(err)
		t.Fatal(errors.New("stream connection not registered"))
	}

	agentCancel()
}

func TestStreamHandleRegisterMalformedMessage(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	s, err := New(agentCtx, agentCancel, &a, &stor, &mockMetricsClient{}, wsURL.String(),
		streamTimeout, l, 1, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Keep sending malformed messages.
	go func() {
		ticker := time.NewTicker(pingInterval)
		agentDone := agentCtx.Done()
	LOOP:
		for {
			select {
			case <-ticker.C:
				topic.Broadcast("malformed")
			case <-agentDone:
				break LOOP
			}
		}
	}()

	if err := s.HandleRegister(); err == nil {
		log.Error(err)
		t.Fatal(errors.New("stream registered correctly"))
	}

	agentCancel()
}

func TestStreamHandleRegisterAgentDone(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	s, err := New(agentCtx, agentCancel, &a, &stor, &mockMetricsClient{}, wsURL.String(),
		streamTimeout, l, 1, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	agentCancel()

	if err := s.HandleRegister(); err == nil {
		log.Error(err)
		t.Fatal(errors.New("agent context not cancelled"))
	}
}

func TestStreamHandleRegisterTimeout(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	agentCtx, agentCancel := context.WithCancel(context.Background())

	s, err := New(agentCtx, agentCancel, &a, &stor, &mockMetricsClient{}, wsURL.String(),
		streamTimeout, l, 1, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.HandleRegister(); err == nil {
		log.Error(err)
		t.Fatal(errors.New("stream did not timeout"))
	}
}

func TestStreamReconnect(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	s, err := New(agentCtx, agentCancel, &a, &stor, &mockMetricsClient{}, wsURL.String(),
		streamTimeout, l, 1, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	job, err := stor.NewJob(agentCtx, knownCheckJob, l)
	if err != nil {
		t.Fatal(err)
	}

	err = a.Run(job.CheckID)
	if err != nil {
		t.Fatal(err)
	}

	actions := map[string]func(agent.Agent, string){
		"disconnect": func(a agent.Agent, checkID string) {
			a.SetStatus(agent.StatusDisconnected)
		},
		"ping": func(_ agent.Agent, _ string) {},
	}

	go func() { _ = s.HandleMessages(actions) }()

	// Keep sending pings.
	go func() {
		ticker := time.NewTicker(pingInterval)
		agentDone := agentCtx.Done()
	LOOP:
		for {
			select {
			case <-ticker.C:
				topic.Broadcast(Message{Action: "ping"})
			case <-agentDone:
				break LOOP
			}
		}
	}()

	// Wait until stream connection is established.
	for s.Status() != StatusConnected {
		time.Sleep(waitTime)
	}

	// Disconnect stream.
	err = s.disconnect()
	if err != nil {
		t.Fatal(err)
	}

	// Wait for agent to reconnect.
	for s.Status() != StatusConnected {
		time.Sleep(waitTime)
	}

	time.Sleep(2 * streamTimeout)

	// Disconnect existing agent.
	topic.Broadcast(Message{Action: "disconnect", AgentID: knownAgentID})

	time.Sleep(2 * streamTimeout)

	if a.Status() != agent.StatusDisconnected {
		t.Fatalf("agent %v has not disconnected", knownAgentID)
	}

	agentCancel()
}

func TestStreamDisconnect(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	s, err := New(agentCtx, agentCancel, &a, &stor, &mockMetricsClient{}, wsURL.String(),
		streamTimeout, l, 2, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	job, err := stor.NewJob(agentCtx, knownCheckJob, l)
	if err != nil {
		t.Fatal(err)
	}

	err = a.Run(job.CheckID)
	if err != nil {
		t.Fatal(err)
	}

	actions := map[string]func(agent.Agent, string){
		"ping": func(_ agent.Agent, _ string) {},
	}

	// Wait for the scheduler to die.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_ = s.HandleMessages(actions)
		defer wg.Done()
	}()

	// Keep sending pings.
	go func() {
		ticker := time.NewTicker(pingInterval)
		agentDone := agentCtx.Done()
	LOOP:
		for {
			select {
			case <-ticker.C:
				topic.Broadcast(Message{Action: "ping"})
			case <-agentDone:
				break LOOP
			}
		}
	}()

	// Close server.
	ts.Close()

	// Disconnect stream.
	err = s.disconnect()
	if err != nil {
		t.Fatal(err)
	}

	wg.Wait()
	agentCancel()
}

func TestStreamCancel(t *testing.T) {
	log := logrus.New()
	logrus.SetLevel(logrus.DebugLevel)
	l := logrus.NewEntry(log)

	// Test server.
	server := gowse.NewServer(l)
	topic := server.CreateTopic(streamName)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := topic.SubscriberHandler(w, r); err != nil {
			l.Printf("error handling subscriber request: %+v", err)
		}
	})

	ts := httptest.NewServer(mux)
	wsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	wsURL.Scheme = "ws"
	wss := http.Server{Addr: ts.Listener.Addr().String(), Handler: mux}
	go wss.ListenAndServe()

	// Test client.
	stor := check.NewMemoryStorage()
	a := TestAgent{id: knownAgentID, storage: &stor, jobs: make(map[string]check.Job), log: l}
	agentCtx, agentCancel := context.WithCancel(context.Background())
	s, err := New(agentCtx, agentCancel, &a, &stor, &mockMetricsClient{}, wsURL.String(),
		streamTimeout, l, 1, time.Duration(1)*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	job, err := stor.NewJob(agentCtx, knownCheckJob, l)
	if err != nil {
		t.Fatal(err)
	}

	err = a.Run(job.CheckID)
	if err != nil {
		t.Fatal(err)
	}

	actions := map[string]func(agent.Agent, string){
		"ping": func(_ agent.Agent, _ string) {},
	}

	// Check that the stream stops handling messages
	// when the agent context is cancelled.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		_ = s.HandleMessages(actions)
		defer wg.Done()
	}()

	// Keep sending pings.
	go func() {
		ticker := time.NewTicker(pingInterval)
		agentDone := agentCtx.Done()
	LOOP:
		for {
			select {
			case <-ticker.C:
				topic.Broadcast(Message{Action: "ping"})
			case <-agentDone:
				break LOOP
			}
		}
	}()

	agentCancel()
	wg.Wait()
}
