/*
Copyright 2019 Adevinta
*/

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/julienschmidt/httprouter"

	"github.com/adevinta/vulcan-agent/aborted"
	"github.com/adevinta/vulcan-agent/api"
	httpapi "github.com/adevinta/vulcan-agent/api/http"
	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/metrics"
	"github.com/adevinta/vulcan-agent/queue"
	"github.com/adevinta/vulcan-agent/queue/sqs"
	"github.com/adevinta/vulcan-agent/retryer"
	"github.com/adevinta/vulcan-agent/stateupdater"
	"github.com/adevinta/vulcan-agent/storage"
	"github.com/adevinta/vulcan-agent/stream"
)

// Run executes the agent using the given config and backend.
// It uses SQS for its internal queues.
// When the function finishes it returns an exit code of
// 0 if the agent terminated gracefully, either by receiving a TERM signal or
// because it passed more time than configured without reading a message.
func Run(cfg config.Config, store storage.Store, back backend.Backend, logger log.Logger) int {
	// Build queue writer.
	qw, err := sqs.NewWriter(cfg.SQSWriter.ARN, cfg.SQSWriter.Endpoint, logger)
	if err != nil {
		logger.Errorf("error creating SQS writer: %+v", err)
		return 1
	}

	// Build queue reader.
	var maxTimeNoMsg *time.Duration
	if cfg.Agent.MaxNoMsgsInterval > 0 {
		t := time.Duration(cfg.Agent.MaxNoMsgsInterval) * time.Second
		maxTimeNoMsg = &t
	}

	// A nil queue.MessageProcessor is passed as argument because
	// RunWithQueues will set it before starting reading messages.
	qr, err := sqs.NewReader(logger, cfg.SQSReader, maxTimeNoMsg, nil)
	if err != nil {
		logger.Errorf("error creating SQS reader: %+v", err)
		return 1
	}

	// Run agent with SQS queues.
	return RunWithQueues(cfg, store, back, qw, qr, logger)
}

// An AgentQueueReader is a [queue.Reader] that provides a callback to
// set a custom message processor.
type AgentQueueReader interface {
	queue.Reader
	SetMessageProcessor(queue.MessageProcessor)
}

// RunWithQueues is like [Run] but accepts custom queue
// implementations. The fields [config.Config.SQSReader] and
// [config.Config.SQSWriter] must be zero.
func RunWithQueues(cfg config.Config, store storage.Store, back backend.Backend, statesQueue queue.Writer, jobsQueue AgentQueueReader, logger log.Logger) int {
	if (cfg.SQSReader != config.SQSReader{} || cfg.SQSWriter != config.SQSWriter{}) {
		logger.Errorf("agent.RunWithQueues does not allow SQS configurations")
		return 1
	}

	// Build state updater.
	stateUpdater := stateupdater.New(statesQueue)
	updater := struct {
		*stateupdater.Updater
		storage.Store
	}{stateUpdater, store}

	// Build job runner.
	jrunner, err := newJobRunner(cfg, back, updater, logger)
	if err != nil {
		logger.Errorf("error creating job runner: %+v", err)
		return 1
	}

	// Set queue's message processor.
	jobsQueue.SetMessageProcessor(jrunner)

	// Run agent.
	if err := run(cfg, jrunner, updater, jobsQueue, logger); err != nil {
		logger.Errorf("error running agent: %+v", err)
		return 1
	}

	return 0
}

// newJobRunner returns a new job runner with the provided agent
// configuration.
func newJobRunner(cfg config.Config, back backend.Backend, updater jobrunner.CheckStateUpdater, logger log.Logger) (*jobrunner.Runner, error) {
	// Build the aborted checks component that will be used to know if a check
	// has been aborted or not before starting to execute it.
	var (
		err           error
		abortedChecks jobrunner.AbortedChecks
	)
	re := retryer.NewRetryer(cfg.Stream.Retries, cfg.Stream.RetryInterval, logger)
	if cfg.Stream.QueryEndpoint == "" {
		logger.Infof("stream query_endpoint is empty, the agent will not check for aborted checks")
		abortedChecks = &aborted.None{}
	} else {
		abortedChecks, err = aborted.New(logger, cfg.Stream.QueryEndpoint, re)
		if err != nil {
			return nil, fmt.Errorf("create aborted checks: %w", err)
		}
	}

	// Build job runner.
	runnerCfg := jobrunner.RunnerConfig{
		MaxTokens:              cfg.Agent.ConcurrentJobs,
		DefaultTimeout:         cfg.Agent.Timeout,
		MaxProcessMessageTimes: cfg.Agent.MaxProcessMessageTimes,
	}
	jrunner := jobrunner.New(logger, back, updater, abortedChecks, runnerCfg)
	return jrunner, nil
}

// run runs the agent.
func run(cfg config.Config, jrunner *jobrunner.Runner, updater api.CheckStateUpdater, jobsQueue queue.Reader, logger log.Logger) error {
	// Build metrics component.
	metrics := metrics.NewMetrics(logger, cfg.DataDog, jrunner)

	// Create a context to orchestrate the shutdown of the
	// different components.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize check cancel stream if an endpoint is provided.
	var (
		err        error
		streamDone <-chan error
	)
	if cfg.Stream.Endpoint == "" {
		logger.Infof("check cancel stream disabled")
	} else {
		re := retryer.NewRetryer(cfg.Stream.Retries, cfg.Stream.RetryInterval, logger)
		// metrics is passed as a message processor to allow
		// aborting checks.
		stream := stream.New(logger, metrics, re, cfg.Stream.Endpoint)
		streamDone, err = stream.ListenAndProcess(ctx)
		if err != nil {
			return fmt.Errorf("stream start: %w", err)
		}
	}

	// Build stats components that exposes information about the
	// agent.
	stats := struct {
		*jobrunner.Runner
		queue.Reader
	}{jrunner, jobsQueue}

	// Start agent's HTTP API.
	api := api.New(logger, updater, stats)
	router := httprouter.New()
	httpapi.NewREST(logger, api, router)
	srv := http.Server{
		Addr:    cfg.API.Port,
		Handler: router,
	}
	httpDone := make(chan error)
	go func() {
		err := srv.ListenAndServe()
		httpDone <- err
		close(httpDone)
	}()

	// Wait while the agent runs.
	qrdone := jobsQueue.StartReading(ctx)
	metricsDone := metrics.StartPolling(ctx)

	logger.Infof("agent running on address %s", srv.Addr)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		// Signal SQS queue reader to stop reading messages
		// from the queue.
		logger.Infof("SIG received, stopping agent")
		cancel()
	case err := <-httpDone:
		logger.Errorf("error running agent: %+v", err)
		cancel()
	case err := <-qrdone:
		cancel()
		if err != nil {
			if !errors.Is(err, queue.ErrMaxTimeNoRead) && !errors.Is(err, context.Canceled) {
				return fmt.Errorf("agent run: %w", err)
			}
		}
	}

	// Wait for all pending jobs to finish.
	logger.Infof("waiting for checks to finish")
	err = <-qrdone
	if err != nil && !errors.Is(err, context.Canceled) {
		logger.Errorf("error waiting for checks to finish %+v", err)
	}

	// Wait for metrics to stop polling.
	logger.Debugf("waiting for metrics to stop")
	<-metricsDone

	// Stop listening API HTTP requests.
	logger.Debugf("stop listening API requests")
	err = srv.Shutdown(context.Background())
	if err != nil {
		return fmt.Errorf("http server shutdown: %w", err)
	}

	// Wait for HTTP API to shutdown.
	err = <-httpDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server shutdown wait: %w", err)
	}

	// Wait for stream to finish.
	if streamDone != nil {
		logger.Debugf("waiting for stream to stop")
		err = <-streamDone
		if err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("stream stop wait: %w", err)
		}
	}

	logger.Infof("agent finished gracefully")
	return nil
}
