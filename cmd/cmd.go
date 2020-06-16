package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	agent "github.com/adevinta/vulcan-agent"
	"github.com/adevinta/vulcan-agent/api"
	"github.com/adevinta/vulcan-agent/check"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/persistence"
	"github.com/adevinta/vulcan-agent/queue"
	"github.com/adevinta/vulcan-agent/results"
	"github.com/adevinta/vulcan-agent/scheduler"
	"github.com/adevinta/vulcan-agent/stream"
	metrics "github.com/adevinta/vulcan-metrics-client"
)

var version string

func MainWithExitCode(factory agent.AgentFactory) int {
	var err error

	if len(os.Args) < 2 {
		fmt.Println("Usage: vulcan-agent config_file")
		return 1
	}

	log := logrus.New()

	cfg, err := config.ReadConfig(os.Args[1])
	if err != nil {
		log.Errorf("error reading configuration file: %v", err)
		return 1
	}

	if cfg.Agent.LogFile != "" {
		var logFile *os.File
		logFile, err = os.OpenFile(cfg.Agent.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Errorf("error opening log file: %v", err)
			return 1
		}
		log.Out = logFile
		log.Formatter = &logrus.TextFormatter{
			FullTimestamp:   true,
			DisableColors:   true,
			TimestampFormat: time.RFC3339Nano,
		}
	} else {
		log.Out = os.Stdout
		log.Formatter = &logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339Nano,
		}
	}

	log.Level = parseLogLevel(cfg.Agent.LogLevel)

	hostname, err := os.Hostname()
	if err != nil {
		log.Errorf("error retrieving hostname: %v", err)
		return 1
	}

	// Add hostname to all log entries.
	l := logrus.NewEntry(log).WithFields(logrus.Fields{"hostname": hostname})

	l.Info("initializing agent")

	persisterWithUpdateCheckStatus, err := persistence.New(
		cfg.Persistence.Endpoint,
		time.Duration(cfg.Persistence.Timeout)*time.Second,
		l,
	)
	if err != nil {
		log.WithError(err).Error("error connecting to persistence")
		return 1
	}

	persisterWithUpdateCheckStatus = persistence.WithBackoff(persisterWithUpdateCheckStatus, cfg.Persistence.Retries, l)
	// We are casting to PersistenceService in order to have a reference to an interface
	// that doesn't have the ability to update the check status.
	// We ensure the components that don't need to update the status are not able to by
	// injecting this reference to them.

	persister := persistence.PersisterService(persisterWithUpdateCheckStatus)
	uploader, err := results.New(
		cfg.Uploader.Endpoint,
		time.Duration(cfg.Uploader.Timeout)*time.Second,
		l,
	)
	if err != nil {
		log.WithError(err).Error("error creating uploader to results service")
		return 1
	}

	agentID, jobqueueARN, err := persister.CreateAgent(version, cfg.Agent.JobqueueID)
	if err != nil {
		log.WithError(err).Error("error creating agent")
		return 1
	}

	// Before returning, set the agent as down.
	defer func() {
		err = persister.UpdateAgentStatus(agentID, agent.StatusDown)
		if err != nil {
			l.WithError(err).Error("error updating agent status")
		}
	}()

	// Add agent ID to all log entries.
	l = l.WithFields(logrus.Fields{"agent_id": agentID})
	memStorage := check.NewMemoryStorage()
	storage := check.NewCombinedStorage(l, &memStorage, persisterWithUpdateCheckStatus)

	// Context used to disconnect the agent.
	agentCtx, agentCancel := context.WithCancel(context.Background())

	agt, err := factory(agentCtx, agentCancel, agentID, storage, l, cfg)
	if err != nil {
		l.WithError(err).Error("error initializing agent")
		return 1
	}

	l.Info("connecting agent to queue")

	// NOTE: Capacity needs to be buffered to not block.
	capacityChan := make(chan int, 10)
	pauseChan := make(chan bool)

	jobs := scheduler.NewJobScheduler(cfg.Scheduler.ConcurrentJobs, capacityChan, pauseChan)

	sqs, err := queue.NewSQSQueueManager(jobqueueARN, cfg.SQS, capacityChan, pauseChan)
	if err != nil {
		l.WithError(err).Error("error connecting agent to SQS queue")
		return 1
	}

	metricsClient, err := metrics.NewClient()
	if err != nil {
		l.WithError(err).Error("error creating metrics client")
		return 1
	}

	schedulerParams := scheduler.Params{
		Jobs:          &jobs,
		Agent:         agt,
		Storage:       storage,
		QueueManager:  sqs,
		Persister:     persister,
		MetricsClient: metricsClient,
		Config: scheduler.Config{
			MonitorInterval:   cfg.Scheduler.MonitorInterval,
			HeartbeatInterval: cfg.Scheduler.HeartbeatInterval,
		},
	}

	scheduler := scheduler.New(agentCtx, agentCancel, schedulerParams, l)

	// The API will listen always in the address ":port".
	api := api.New(agentCtx, agt, storage, persister, uploader, scheduler, cfg.API.Port, l)

	go func() {
		apiErr := api.ListenAndServe()
		if apiErr != nil {
			l.WithError(apiErr).Error("error exposing agent API")
			agentCancel()
		}
	}()

	// Map stream actions to function calls.
	actions := map[string]func(agent.Agent, string){
		"abort": func(a agent.Agent, scanID string) {
			abortErr := a.AbortChecks(scanID)
			if err != nil {
				l.WithField("scan_id", scanID).WithError(abortErr).Error("error aborting checks")
				return
			}
		},
		"pause": func(a agent.Agent, _ string) {
			// Stop scheduling new jobs.
			jobs.Pause()
			a.SetStatus(agent.StatusPausing)
			// Wait for scheduled jobs to finish.
			jobs.Wait()
			a.SetStatus(agent.StatusPaused)
			pauseErr := persister.UpdateAgentStatus(a.ID(), agent.StatusPaused)
			if pauseErr != nil {
				l.WithError(pauseErr).Error("error updating agent status")
			}
		},
		"resume": func(a agent.Agent, _ string) {
			jobs.Resume()
			a.SetStatus(agent.StatusRunning)
			resumeErr := persister.UpdateAgentStatus(a.ID(), agent.StatusRunning)
			if resumeErr != nil {
				l.WithError(resumeErr).Error("error updating agent status")
			}
		},
		"disconnect": func(a agent.Agent, _ string) {
			l.Warn("disconnecting agent")
			agentCancel()
		},
		"ping": func(a agent.Agent, _ string) {
			l.Debug("ping received")
		},
	}

	l.Info("connecting agent to stream")
	streamTimeout := time.Duration(cfg.Stream.Timeout) * time.Second
	// Set a default interval for the stream retries. A 0 seconds interval is
	// not allowed.
	if cfg.Stream.RetryInterval == 0 {
		cfg.Stream.RetryInterval = 5
	}
	sInterval := time.Duration(cfg.Stream.RetryInterval) * time.Second
	strm, err := stream.New(
		agentCtx, agentCancel, agt, storage,
		cfg.Stream.Endpoint, streamTimeout, l,
		cfg.Stream.Retries,
		sInterval,
	)
	if err != nil {
		l.WithError(err).Error("error connecting agent to stream")
		return 1
	}

	if err := persister.UpdateAgentStatus(agentID, agent.StatusRegistering); err != nil {
		l.WithError(err).Error("error updating agent status")
		return 1
	}

	if err := strm.HandleRegister(); err != nil {
		l.WithError(err).Error("error registering agent")
		return 1
	}

	if err := persister.UpdateAgentStatus(agentID, agent.StatusRegistered); err != nil {
		l.WithError(err).Error("error updating agent status")
		return 1
	}

	agt.SetStatus(agent.StatusRegistered)

	l.Info("agent registered")

	// Start handling stream messages.
	go func() {
		err = strm.HandleMessages(actions)
		if err != nil {
			l.WithError(err).Error("error handling stream messages")
		}
	}()

	// Start processing messages from the queue.
	scheduler.Run()

	return 0
}

func parseLogLevel(logLevel string) logrus.Level {
	switch logLevel {
	case "panic":
		return logrus.PanicLevel
	case "fatal":
		return logrus.FatalLevel
	case "error":
		return logrus.ErrorLevel
	case "warn":
		return logrus.WarnLevel
	case "info":
		return logrus.InfoLevel
	case "debug":
		return logrus.DebugLevel
	default:
		return logrus.InfoLevel
	}
}
