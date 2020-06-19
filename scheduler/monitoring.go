package scheduler

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-agent/check"
)

func (s *Scheduler) heartbeat() {
	var err error

	ticker := time.NewTicker(time.Duration(s.config.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		err = s.persister.UpdateAgentHeartbeat(s.agent.ID())
		if err != nil {
			s.log.WithError(err).Error("error updating agent heartbeat")
			break
		}
	}

	// Disconnect agent.
	s.cancel()
}

func (s *Scheduler) monitor(job check.Job) {
	// Unschedule job when finished.
	defer s.jobs.Done()

	l := s.log.WithFields(logrus.Fields{"check_id": job.CheckID})

	l.Debug("starting to monitor check")

	// Wait for check to be done.
	<-job.Ctx.Done()

	var err error

	if job.Ctx.Err() == context.DeadlineExceeded {
		// terminateCheck marks the check to be timed out and calls
		// the abort method that will stop the check this will block this goroutine
		// so after the check is aborted or the time for aborting the check gracefully
		// has expired.
		s.terminateCheck(l, job.CheckID)
	}

	// Ensure that the job is killed.
	// NOTE: The check will not be set to check.StatusKilled since
	// there are many reasons for a check being killed at this stage.
	// The check will be left in the terminal status that led to
	// its context being cancelled in the first place.
	l.Info("ensure check container is finished")
	err = s.agent.Kill(job.CheckID)
	if err != nil {
		l.WithError(err).Error("Error trying to ensure check container if finished")
		// Here we are not returning because it's better to know that something went
		// wrong trying to ensure this check is killed.
	}

	// Retrieve the final state of the check.
	state, err := s.storage.State(job.CheckID)
	if err != nil {
		l.WithError(err).Error("error retrieving check status from internal storage")
		return
	}

	// If the check was still running, set it as killed.
	// NOTE: This means that the check was killed while the agent was purging.
	if state.Status == check.StatusRunning {
		l.Info("check is still running forcing the status to killed.")
		err = s.storage.SetState(job.CheckID, check.State{Status: check.StatusKilled})
		if err != nil {
			l.WithError(err).Error("error updating check status in internal storage")
		}
	}
}

func (s *Scheduler) terminateCheck(l *logrus.Entry, id string) {
	l.Warn("check timeout")
	// Set the check to be timeout so when it notifies its status as aborted
	// the agent can translate that state to timeout.
	err := s.storage.SetTimeoutIfAbort(id)
	if err != nil {
		l.WithError(err).Error("error labeling the check to be timeout")
		return
	}
	err = s.agent.Abort(id)
	if err != nil {
		l.WithError(err).Error("error aborting check")
	}
	b, err := s.agent.Raw(id)
	if err != nil {
		l.WithError(err).Error("error getting raw logs from the check")
		return
	}
	l.WithFields(logrus.Fields{"raw": string(b)}).Warn("raw logs from the check")
}
