package cmd

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
	"github.com/adevinta/vulcan-agent/results"
	"github.com/adevinta/vulcan-agent/retryer"
	"github.com/adevinta/vulcan-agent/stateupdater"
	"github.com/adevinta/vulcan-agent/stream"
)

// BackendCreator defines the shape of the function that will be called by the
// function MainWithExitCode in order to create the backend that will run the
// checks.
type BackendCreator func(log.Logger, config.Config, backend.CheckVars) (backend.Backend, error)

// MainWithExitCode executes the agent with the backend created by calling the
// passed BackendCreator. When the function finishes it returns an exit code of
// 0 if the agent terminated gracefully, either by receiving a TERM signal or
// because it passed more time than configured without reading a message.
func MainWithExitCode(bc BackendCreator) int {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, "Usage: vulcan-agent config_file")
		return 1
	}
	cfg, err := config.ReadConfig(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading configuration file: %v", err)
		return 1
	}
	l, err := log.New(cfg.Agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading creating log: %v", err)
		return 1
	}

	// Build the backend.
	b, err := bc(l, cfg, cfg.Check.Vars)
	if err != nil {
		l.Errorf("error creating the backend to run the checks %v", err)
		return 1
	}

	// Build the results service.
	timeout := time.Duration(cfg.Uploader.Timeout * int(time.Second))
	interval := cfg.Uploader.RetryInterval
	retries := cfg.Uploader.Retries
	re := retryer.NewRetryer(retries, interval, l)
	endpoint := cfg.Uploader.Endpoint
	r := results.New(endpoint, re, timeout)

	// Build the sqs writer.
	qw, err := sqs.NewWriter(cfg.SQSWriter.ARN, cfg.SQSWriter.Endpoint, l)
	if err != nil {
		l.Errorf("error creating sqs writer %+v", err)
		return 1
	}

	// Build the state updater.
	stateUpdater := stateupdater.New(qw)
	updater := struct {
		*stateupdater.Updater
		*results.Uploader
	}{stateUpdater, r}

	var abortedChecks jobrunner.AbortedChecks

	// Build the aborted checks component that will be used to know if a check
	// has been aborted or not defore starting to execute it.
	endpoint = cfg.Stream.QueryEndpoint
	retries = cfg.Stream.Retries
	interval = cfg.Stream.RetryInterval
	re = retryer.NewRetryer(retries, interval, l)
	if endpoint == "" {
		l.Infof("stream query_endpoint is empty, the agent will not check for aborted checks")
		abortedChecks = &aborted.None{}
	} else {
		abortedChecks, err = aborted.New(l, endpoint, re)
		if err != nil {
			l.Errorf("error creating aborted checks %+v", abortedChecks)
			return 1
		}
	}

	runnerCfg := jobrunner.RunnerConfig{
		MaxTokens:              cfg.Agent.ConcurrentJobs,
		DefaultTimeout:         cfg.Agent.Timeout,
		MaxProcessMessageTimes: cfg.Agent.MaxProcessMessageTimes,
	}

	jrunner := jobrunner.New(l, b, updater, abortedChecks, runnerCfg)

	// Setup metrics.
	metrics := metrics.NewMetrics(l, cfg.DataDog, jrunner)

	ctxqr, cancelqr := context.WithCancel(context.Background())

	endpoint = cfg.Stream.Endpoint
	stream := stream.New(l, metrics, re, endpoint)
	streamDone, err := stream.ListenAndProcess(ctxqr)
	if err != nil {
		l.Errorf("error starting stream: %+v", err)
		cancelqr()
		return 1
	}

	var maxTimeNoMsg *time.Duration
	if cfg.Agent.MaxNoMsgsInterval > 0 {
		t := time.Duration(cfg.Agent.MaxNoMsgsInterval) * time.Second
		maxTimeNoMsg = &t
	}

	qr, err := sqs.NewReader(l, cfg.SQSReader, maxTimeNoMsg, jrunner)
	if err != nil {
		l.Errorf("error starting SQSReader: %+v", err)
		cancelqr()
		return 1
	}
	stats := struct {
		*jobrunner.Runner
		*sqs.Reader
	}{
		jrunner,
		qr,
	}
	api := api.New(l, updater, stats)
	router := httprouter.New()
	httpapi.NewREST(l, api, router)
	srv := http.Server{
		Addr:    cfg.API.Port,
		Handler: router,
	}
	var httpDone = make(chan error)
	go func() {
		err := srv.ListenAndServe()
		httpDone <- err
		close(httpDone)
	}()

	qrdone := qr.StartReading(ctxqr)
	metricsDone := metrics.StartPolling(ctxqr)

	l.Infof("agent running on address %s", srv.Addr)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		// Signal the sqs queue reader to stop reading messages from the queue.
		l.Infof("SIG received, stoping agent")
		cancelqr()
	case err := <-httpDone:
		l.Errorf("error running the the agent %+v", err)
		cancelqr()
	case err := <-qrdone:
		cancelqr()
		if err != nil {
			if !errors.Is(err, queue.ErrMaxTimeNoRead) && !errors.Is(err, context.Canceled) {
				l.Errorf("error running agent %+v", err)
				return 1
			}
		}
	}

	// Wait for all the pending jobs to finish.
	l.Infof("waiting for the checks to finish")
	err = <-qrdone
	if err != nil && !errors.Is(err, context.Canceled) {
		l.Errorf("error waiting for the checks to finish %+v", err)
	}
	// Wait for the metrics to stop polling.
	l.Debugf("waiting for the metrics top stop")
	<-metricsDone
	l.Debugf("stop listening api calls")
	// Stop listening for api calls.
	err = srv.Shutdown(context.Background())
	if err != nil {
		l.Errorf("error stoping http server: %+v", err)
		return 1
	}
	err = <-httpDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		l.Errorf("http server stopped with error: %+v", err)
		return 1
	}
	// Wait for the stream to finish.
	l.Debugf("waiting for the stream to stop")
	err = <-streamDone
	if err != nil && !errors.Is(err, context.Canceled) {
		l.Errorf("stream stopped with error %+v", err)
		return 1
	}
	l.Infof("agent finished gracefully")
	return 0
}
