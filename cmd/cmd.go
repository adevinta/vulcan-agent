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
	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-agent/api"
	httpapi "github.com/adevinta/vulcan-agent/api/http"
	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/queue"
	"github.com/adevinta/vulcan-agent/queue/sqs"
	"github.com/adevinta/vulcan-agent/results"
	"github.com/adevinta/vulcan-agent/stateupdater"
	// "github.com/adevinta/vulcan-agent/stream"
	// metrics "github.com/adevinta/vulcan-metrics-client"
)

type backendCreator func(log.Logger, config.Config, backend.CheckVars) (backend.Backend, error)

func MainWithExitCode(bc backendCreator) int {
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
	b, err := bc(l, cfg, cfg.Check.Vars)
	if err != nil {
		l.Errorf("error creating the backend to run the checks %v", err)
		return 1
	}

	r, err := results.New(cfg.Uploader.Endpoint, time.Duration(cfg.Uploader.Timeout*int(time.Second)))
	if err != nil {
		l.Errorf("error creating results client %+v", err)
		return 1
	}

	qw, err := sqs.NewWriter(cfg.SQSWriter.ARN, cfg.SQSWriter.Endpoint, l)
	if err != nil {
		l.Errorf("error creating sqs writer %+v", err)
		return 1
	}

	stateUpdater := stateupdater.New(qw)
	updater := struct {
		*stateupdater.Updater
		*results.Uploader
	}{stateUpdater, r}

	runnerCfg := jobrunner.RunnerConfig{
		MaxTokens:      cfg.Agent.ConcurrentJobs,
		DefaultTimeout: cfg.Agent.Timeout,
	}
	jrunner := jobrunner.New(l, b, updater, runnerCfg)
	qr, err := sqs.NewReader(l, cfg.SQSReader, jrunner)
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

	ctxqr, cancelqr := context.WithCancel(context.Background())
	qrdone := qr.StartReading(ctxqr)

	maxTimeNoMsg := time.Duration(cfg.Agent.MaxNoMsgsInterval) * time.Second
	qStopper := queue.ReaderStopper{
		R:       qr,
		MaxTime: maxTimeNoMsg,
	}

	stopperDone := qStopper.Track(ctxqr)
	l.Infof("agent running on address %s", srv.Addr)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sig:
		// Signal the sqs queue reader to stop reading messages from the queue.
		cancelqr()
	case err = <-stopperDone:
		cancelqr()
	}

	// Wait fot the queue stopper to finish.
	err = <-stopperDone
	if err != nil && !errors.Is(err, context.Canceled) {
		l.Errorf("error stopping the reader tracker %+v", err)
	}
	// Wait for all the pending jobs to finish.
	err = <-qrdone
	if err != nil && !errors.Is(err, context.Canceled) {
		l.Errorf("error stopping agent %+v", err)
	}
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
