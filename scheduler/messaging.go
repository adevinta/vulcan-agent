package scheduler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/adevinta/vulcan-agent/check"
	"github.com/adevinta/vulcan-agent/queue"
	metrics "github.com/adevinta/vulcan-metrics-client"
	"github.com/sirupsen/logrus"
)

func (s *Scheduler) processMessage(m queue.Message) {
	// Allocate job in the job scheduler.
	// This will throw an error if the scheduler can't schedule the job.
	err := s.jobs.Add()
	if err != nil {
		s.log.WithError(err).Error("error scheduling job")
		return
	}
	s.incrCheckMetrics()

	var params check.JobParams
	err = params.UnmarshalJSON([]byte(m.Body()))
	if err != nil {
		// Delete message if it is malformed.
		s.deleteMessage(m)
		s.log.WithError(err).Error("error unmarshalling message body")
		s.jobs.Done()
		s.decrCheckMetrics()
		return
	}

	l := s.log.WithFields(logrus.Fields{"check_id": params.CheckID})

	// NOTE: Check ownership is updated for traceability reasons but
	// the check is not yet marked as assigned since it has not been
	// created in the storage yet.

	err = s.persister.UpdateCheckAgent(params.CheckID, s.agent.ID())
	if err != nil {
		l.WithError(err).Error("error updating check agent in persistence the check will not run")
		s.jobs.Done()
		s.decrCheckMetrics()
		return
	}

	job, err := s.storage.NewJob(s.ctx, params, l)
	if err != nil {
		l.WithError(err).Error("error creating check job")
		s.jobs.Done()
		s.decrCheckMetrics()
		return
	}
	l.Debug("trying to assign check")
	err = s.storage.SetState(params.CheckID, check.State{Status: check.StatusAssigned})
	if err != nil && !mustAbortCheck(err) {
		l.WithError(err).Error("error updating check status in storage")
		s.jobs.Done()
		s.decrCheckMetrics()
		return
	}

	s.deleteMessage(m)

	if mustAbortCheck(err) {
		err = s.storage.SetState(params.CheckID, check.State{Status: check.StatusAborted})
		if err != nil {
			l.WithError(err).Error("error trying to set check state to aborted after a precondition failed response received")
		}
		s.jobs.Done()
		s.decrCheckMetrics()
		return
	}

	l.WithFields(logrus.Fields{
		"image":   job.Image,
		"target":  job.Target,
		"options": job.Options,
	}).Info("running check")

	// The agent will run the check asynchronously.
	err = s.agent.Run(job.CheckID)
	if err != nil {
		if err == context.DeadlineExceeded {
			l.WithError(err).Error("timeout starting the check")
		} else {
			l.WithError(err).Error("error running check in container")
		}
		err = s.storage.SetState(params.CheckID, check.State{Status: check.StatusFailed})
		if err != nil {
			l.WithError(err).Error("error updating agent status, check leaked")
		}
		s.jobs.Done()
		s.decrCheckMetrics()
		return
	}

	job, err = s.storage.SetTimeout(job.CheckID, params.Timeout)
	if err != nil {
		l.WithError(err).Error("error updating check job with timeout")
		err = s.storage.SetState(params.CheckID, check.State{Status: check.StatusFailed})
		if err != nil {
			l.WithError(err).Error("error updating agent status, check leaked")
		}
		s.jobs.Done()
		s.decrCheckMetrics()
		return
	}

	// NOTE: We don't update the status of the check here wait for the SDK to report back to update
	go s.monitor(job)

	l.Debug("message processed successfully")
}

func (s *Scheduler) deleteMessage(m queue.Message) {
	s.log.WithFields(logrus.Fields{
		"message_id": m.ID(),
	}).Info("deleting message")
	if err := m.Delete(); err != nil {
		s.log.WithError(err).Error("error deleting message")
		return
	}
}

func (s *Scheduler) incrCheckMetrics() {
	s.pushCheckMetrics(1)
}

func (s *Scheduler) decrCheckMetrics() {
	s.pushCheckMetrics(-1)
}

func (s *Scheduler) pushCheckMetrics(variation float64) {
	s.metricsClient.Push(metrics.Metric{
		Name:  "vulcan.scan.check.running",
		Typ:   metrics.Gauge,
		Value: variation,
		Tags:  []string{"component:agent", fmt.Sprint("agentid:", s.agent.ID())},
	})
}

// musabortCheck returns true if an error is an httpError and
// the http status is PreconditionFailed.
func mustAbortCheck(err error) bool {
	if err == nil {
		return false
	}
	type httpCodeError interface {
		Code() int
	}
	// It would be much better to import the package
	// github.com/adevinta/vulcan-agent/persistence that has
	// the type HTTPError defined, but in that case, it would be a cyclic
	// dependency. To avoid that cyclic dependency.
	aux := interface{}(err)
	httpErr, ok := aux.(httpCodeError)
	return ok && httpErr.Code() == http.StatusPreconditionFailed
}
