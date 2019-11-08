package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/adevinta/vulcan-agent"
	"github.com/adevinta/vulcan-agent/check"
	"github.com/adevinta/vulcan-agent/persistence"
	"github.com/adevinta/vulcan-agent/results"
	"github.com/adevinta/vulcan-agent/scheduler"

	"github.com/sirupsen/logrus"
	"github.com/julienschmidt/httprouter"
)

// API represents Agent API
type API struct {
	addr      string
	agent     agent.Agent
	storage   check.Storage
	persister persistence.PersisterService
	uploader  results.Uploader
	sched     *scheduler.Scheduler
	log       *logrus.Entry
}

// JobsResponse represents a job check response
type JobsResponse struct {
	Jobs  []check.Job `json:"jobs"`
	Error string      `json:"error,omitempty"`
}

// CheckResponse represents a check response
type CheckResponse struct {
	check.State `json:"state"`
	Error       string `json:"error,omitempty"`
}

// StatsResponse represents a stats response
type StatsResponse struct {
	scheduler.Stats `json:"stats"`
}

// New declares a new API
func New(ctx context.Context, agent agent.Agent, storage check.Storage, persister persistence.PersisterService, uploader results.Uploader, sched *scheduler.Scheduler, addr string, log *logrus.Entry) API {
	return API{
		addr:      addr,
		agent:     agent,
		storage:   storage,
		persister: persister,
		uploader:  uploader,
		sched:     sched,
		log:       log,
	}
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	writeJSONResponse(w, http.StatusOK, a.agent.Status())
	return
}

func (a *API) handleJobs(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var jobs []check.Job
	var err error

	queryValues := r.URL.Query()
	terminal := queryValues.Get("terminal")
	switch terminal {
	case "":
		jobs, err = a.storage.GetAll()
	case "false":
		jobs, err = a.storage.GetTerminal(false)
	case "true":
		jobs, err = a.storage.GetTerminal(true)
	default:
		err = fmt.Errorf("invalid value for terminal parameter: %v", terminal)
		a.log.WithError(err).Error("")
		writeJSONResponse(w, http.StatusInternalServerError, JobsResponse{Error: err.Error()})
		return
	}
	if err != nil {
		a.log.WithError(err).Error("error retrieving jobs from internal storage")
		writeJSONResponse(w, http.StatusInternalServerError, JobsResponse{Error: err.Error()})
		return
	}

	writeJSONResponse(w, http.StatusOK, JobsResponse{Jobs: jobs})
	return
}

func (a *API) handleCheck(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	job, err := a.storage.Get(ps.ByName("id"))
	if err != nil {
		a.log.WithError(err).Error("error retrieving check from internal storage")
		writeJSONResponse(w, http.StatusInternalServerError, CheckResponse{Error: err.Error()})
		return
	}

	writeJSONResponse(w, http.StatusOK, CheckResponse{State: job.State})
	return
}

func (a *API) updateCheckInfo(job check.Job, c check.State) error {
	l := a.log.WithFields(logrus.Fields{"check_id": job.CheckID})
	l.Info("retrieving check raw")
	raw, err := a.agent.Raw(job.CheckID)
	if err != nil {
		l.WithError(err).Error("error retrieving check raw")
		return fmt.Errorf("error retrieving check raw: %v", err.Error())
	}

	a.log.WithFields(logrus.Fields{"check_id": job.CheckID}).Info("uploading check raw logs to results service")
	rawLink, err := a.uploader.UpdateCheckRaw(job.CheckID, job.ScanID, job.ScanStartTime, raw)
	if err != nil {
		l.WithError(err).Error("error uploading check raw logs to results service")
		return fmt.Errorf("error uploading check raw logs to results service: %v", err.Error())
	}

	l.Info("updating check raw logs reference in persistence")
	if err := a.persister.UpdateCheckRaw(job.CheckID, rawLink); err != nil {
		l.WithError(err).Error("error updating check raw logs reference in persistence")
		return fmt.Errorf("error updating check raw logs reference in persistence: %v", err.Error())
	}

	l.Info("uploading check report to results service")
	reportLink, err := a.uploader.UpdateCheckReport(job.CheckID, job.ScanID, job.ScanStartTime, c.Report)
	if err != nil {
		l.WithError(err).Error("error uploading check report to results service")
		return fmt.Errorf("error uploading check report to results service: %v", err.Error())
	}

	a.log.WithFields(logrus.Fields{"check_id": job.CheckID}).Info("updating check report reference in persistence")

	if err := a.persister.UpdateCheckReport(job.CheckID, reportLink); err != nil {
		l.WithError(err).Error("error updating check report reference in persistence")
		return err
	}

	return nil
}

func (a *API) handleCheckUpdate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	/*
		As general rule we consider an error in this method to cause the check as failed and to be killed.
		This will be done by calling job.Cancel so the monitoring component will take care of finishing the job.
		The are only two exceptions:
		1. If we can not find the check id that is performing request
		2. The check trying to update the status is already in a terminal status.
		In both cases we log the error and ignore the request.
	*/

	// Response data returned to the check.
	var (
		c          check.State
		err        error
		statusCode int
		job        check.Job
	)
	statusCode = http.StatusOK

	defer func() {
		if err != nil {
			writeJSONResponse(w, statusCode, CheckResponse{Error: err.Error()})
			if job.CheckID != "" {
				c.Status = check.StatusFailed
				if innerErr := a.storage.SetState(job.CheckID, c); innerErr != nil {
					a.log.WithError(innerErr).Error("error updating the to check state")
				}
				job.Cancel()
			}
			return
		}
		writeJSONResponse(w, statusCode, CheckResponse{State: c})
	}()

	job, err = a.storage.Get(ps.ByName("id"))
	if err != nil {
		a.log.WithError(err).Error("error retrieving check from internal storage")
		err = fmt.Errorf("error retrieving check from internal storage: %v", err.Error())
		statusCode = http.StatusServiceUnavailable
		return
	}

	l := a.log.WithFields(logrus.Fields{"check_id": job.CheckID})

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.WithError(err).Error("error reading check update request")
		err = fmt.Errorf("error reading check update request: %v", err.Error())
		statusCode = http.StatusBadRequest
		return
	}

	l.WithFields(logrus.Fields{"body": string(body)}).Debug("received check update")

	// Don't allow updates on checks in terminal statuses.
	if check.IsStatusTerminal(job.State.Status) {
		l.Warn("check attempted to update from terminal status")
		// In this case we let the check continue running so we don't return an error
		statusCode = http.StatusForbidden
		return
	}

	err = json.Unmarshal(body, &c)
	if err != nil {
		l.WithError(err).Error("error decoding check update request")
		err = fmt.Errorf("error decoding check update request: %v", err.Error())
		statusCode = http.StatusBadRequest
		return
	}

	// If any new progress is reported, update both raw and report.
	if c.Progress > 0 {
		a.log.WithFields(logrus.Fields{
			"progress": c.Progress,
		}).Info("check reported progress")
		err = a.updateCheckInfo(job, c)
		if err != nil {
			statusCode = http.StatusServiceUnavailable
			return
		}
	}

	finishJob := true
	switch c.Status {
	case check.StatusRunning:
		l.Debug("check reported as running")
		finishJob = false
	case check.StatusFinished:
		l.Info("check reported as finished")
	case check.StatusAborted:
		l.Info("check reported as aborted")
	case check.StatusFailed:
		l.Warn("check reported as failed")
	default:
		err = errors.New("error updating check to unknown status")
		l.WithFields(logrus.Fields{
			"status": c.Status,
		}).Warn("check reported unknown status")
		statusCode = http.StatusBadRequest
		return
	}

	err = a.storage.SetState(job.CheckID, c)
	if err != nil {
		l.WithError(err).Error("error updating check state in internal storage")
		err = fmt.Errorf("error updating check state in internal storage: %v", err.Error())
		statusCode = http.StatusServiceUnavailable
		return
	}

	if finishJob {
		job.Cancel()
	}
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	writeJSONResponse(w, http.StatusOK, StatsResponse{Stats: a.sched.Stats()})
	return
}

// ListenAndServe starts and exposes an API
func (a API) ListenAndServe() error {
	router := httprouter.New()

	// Retrieve the current status of the agent.
	router.GET("/status", a.handleStatus)
	// Retrieve all jobs owned by the agent.
	router.GET("/jobs", a.handleJobs)

	// Retrieve the current state of a check.
	router.GET("/check/:id", a.handleCheck)
	// Update the current status of a check.
	router.PATCH("/check/:id", a.handleCheckUpdate)

	// Retrieve stats of the agent
	router.GET("/stats", a.handleStats)

	return http.ListenAndServe(a.addr, router)

	// TODO: Close gracefully.
}

func writeJSONResponse(w http.ResponseWriter, code int, v interface{}) {
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
	}
}
