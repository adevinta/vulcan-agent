package scheduler

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	agent "github.com/adevinta/vulcan-agent"
	"github.com/adevinta/vulcan-agent/check"
	"github.com/adevinta/vulcan-agent/persistence"
	"github.com/adevinta/vulcan-agent/queue"
	metrics "github.com/adevinta/vulcan-metrics-client"
)

const (
	dogStatsDGracePeriod = 30
)

// Scheduler represents a scheduler
type Scheduler struct {
	ctx           context.Context
	cancel        context.CancelFunc
	jobs          *Jobs
	agent         agent.Agent
	storage       check.Storage
	persister     persistence.PersisterService
	queueManager  queue.Manager
	metricsClient metrics.Client
	config        Config
	log           *logrus.Entry

	stats Stats
	mutex sync.RWMutex
}

// RemoteCheckStateUpdater allows the Scheduler to update the remote check update
type RemoteCheckStateUpdater interface {
	UpdateCheckState(checkID string, state check.State) error
}

// Params represent a set of Scheduler parameters
type Params struct {
	Jobs          *Jobs
	Agent         agent.Agent
	Storage       check.Storage
	QueueManager  queue.Manager
	Persister     persistence.PersisterService
	MetricsClient metrics.Client
	Config        Config
}

// Config represents
type Config struct {
	MonitorInterval   int
	HeartbeatInterval int
}

// Stats stores execution information of the agent.
type Stats struct {
	LastMessageReceived time.Time // Timestamp of the last queue message received.
	AgentID             string
}

// New initializes a new Scheduler
func New(ctx context.Context, cancel context.CancelFunc, params Params, log *logrus.Entry) *Scheduler {
	stats := Stats{
		LastMessageReceived: time.Now(),
		AgentID:             params.Agent.ID(),
	}

	return &Scheduler{
		ctx:           ctx,
		cancel:        cancel,
		jobs:          params.Jobs,
		agent:         params.Agent,
		storage:       params.Storage,
		persister:     params.Persister,
		queueManager:  params.QueueManager,
		metricsClient: params.MetricsClient,
		config:        params.Config,
		log:           log,
		stats:         stats,
	}
}

func (s *Scheduler) Stats() Stats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.stats
}

// Run starts a Scheduler
func (s *Scheduler) Run() {
	var err error

	go s.heartbeat()

	// Check if agent disconnected before running.
	if s.ctx.Err() == nil {
		msgs, errs := s.queueManager.Messages()

		s.agent.SetStatus(agent.StatusRunning)

		err = s.persister.UpdateAgentStatus(s.agent.ID(), agent.StatusRunning)
		if err != nil {
			err = errors.New("error updating agent status")
		}

		for err == nil {
			select {
			// If agent has been disconnected.
			case <-s.ctx.Done():
				err = errors.New("agent disconnected")
			case msg, ok := <-msgs:
				if !ok {
					err = errors.New("error reading from closed messages channel")
				}

				s.log.WithFields(logrus.Fields{
					"message": msg,
				}).Debug("processing message")
				s.log.WithFields(logrus.Fields{
					"message_id": msg.ID(),
				}).Info("processing message")

				s.mutex.Lock()
				s.stats.LastMessageReceived = time.Now()
				s.mutex.Unlock()

				go s.processMessage(msg)
			case errVal, ok := <-errs:
				if !ok {
					err = errors.New("error reading from closed errors channel")
					break
				}
				err = errVal
			}
		}
	}

	s.log.WithError(err).Error("error running agent")

	s.agent.SetStatus(agent.StatusDisconnected)

	err = s.persister.UpdateAgentStatus(s.agent.ID(), agent.StatusDisconnected)
	if err != nil {
		s.log.WithError(err).Error("error updating agent status")
	}

	// TODO: Decide if something should be done at this stage.

	s.agent.SetStatus(agent.StatusPurging)

	err = s.persister.UpdateAgentStatus(s.agent.ID(), agent.StatusPurging)
	if err != nil {
		s.log.WithError(err).Error("error updating agent status")
	}

	// Disconnect agent.
	s.cancel()
	// Wait for all jobs to finish.
	s.jobs.Wait()
	// Extra grace period for DogStatsD to send metrics.
	time.Sleep(dogStatsDGracePeriod * time.Second)

	s.log.Warn("agent scheduler finished")
}
