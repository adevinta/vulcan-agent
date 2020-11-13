package persistence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-agent/check"
)

var (
	// validStatusOperations defines the valid http status codes for the given http
	// methods. If an http method is not present in the map then any http status will
	// be considered correct.
	validStatusOperations = map[string][]int{
		"POST":  {http.StatusOK, http.StatusCreated},
		"PATCH": {http.StatusOK, http.StatusCreated},
	}
)

// AgentData represents an Agent object in vulcan-persistence format
type AgentData struct {
	Agent Agent `json:"agent,omitempty"`
}

// Agent represents an Agent
type Agent struct {
	ID         string   `json:"id,omitempty"`
	JobqueueID string   `json:"jobqueue_id,omitempty"`
	Status     string   `json:"status,omitempty"`
	Version    string   `json:"version,omitempty"`
	Enabled    bool     `json:"enabled,omitempty"`
	Jobqueue   Jobqueue `json:"jobqueue,omitempty"`
}

// CheckData represents a Check object in vulcan-persistence format
type CheckData struct {
	Check Check `json:"check,omitempty"`
}

// Check represents a Check
type Check struct {
	ID          string    `json:"id,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	ChecktypeID string    `json:"checktype_id,omitempty"`
	Status      string    `json:"status,omitempty"`
	Progress    float32   `json:"progress,omitempty"`
	Target      string    `json:"target,omitempty"`
	Options     string    `json:"options,omitempty"`
	Webhook     string    `json:"webhook,omitempty"`
	Raw         string    `json:"raw,omitempty"`
	Report      string    `json:"report,omitempty"`
	Agent       Agent     `json:"agent,omitempty"`
	Checktype   Checktype `json:"checktype,omitempty"`
}

// ChecktypeData represents a Checktype object in vulcan-persistence format
type ChecktypeData struct {
	Checktype Checktype `json:"checktype,omitempty"`
}

// Checktype represents a Checktype
type Checktype struct {
	ID          string `json:"id,omitempty"`
	AgentID     string `json:"agent_id,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	Timeout     int    `json:"timeout,omitempty"`
	Image       string `json:"image,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
	Agent       Agent  `json:"agent,omitempty"`
}

// JobqueueData represents a JobqueueData object in vulcan-persistence format
type JobqueueData struct {
	Jobqueue Jobqueue `json:"jobqueue,omitempty"`
}

// Jobqueue represents a Jobqueue
type Jobqueue struct {
	ID          string `json:"id,omitempty"`
	ARN         string `json:"arn,omitempty"`
	Description string `json:"description,omitempty"`
}

// RawData represents a check RawData object in vulcan-persistence format
type RawData struct {
	Raw Raw `json:"raw"`
}

// Raw represents a check Raw object
type Raw []byte

// ReportData represents a check ReportData object in vulcan-persistence format
type ReportData struct {
	Report Report `json:"report"`
}

// Report represents a check Report object
type Report []byte

// PersisterService represents the basic service to interact with the persistence.
type PersisterService interface {
	CreateAgent(agentVersion, jobqueueID string) (agentID, jobqueueARN string, err error)
	UpdateAgentStatus(agentID, agentStatus string) error
	UpdateAgentHeartbeat(agentID string) error
	UpdateCheckAgent(checkID, agentID string) error

	UpdateCheckRaw(checkID string, rawLink string) error
	UpdateCheckReport(checkID string, reportLink string) error
}

// PersisterCheckStateUpdater provides the same methods that the PersistenceService plus a method to update
// the state of a check.
type PersisterCheckStateUpdater interface {
	PersisterService
	UpdateCheckState(checkID string, state check.State) error
}

// Persister represents a Persister
type Persister struct {
	endpoint string
	timeout  time.Duration
	log      *logrus.Entry
}

// HTTPError is returned when a response for a persistence operation returns
// a status code  different than the expected for that operation.
type HTTPError struct {
	StatusCode int
	Status     string
}

// Error returns a string with information about the current error.
func (e *HTTPError) Error() string {
	return fmt.Sprintf("request returned %v status", e.Status)
}

// Code returns the http status code that triggered the error.
func (e *HTTPError) Code() int {
	return e.StatusCode
}

// New defines a new Persister
func New(endpoint string, timeout time.Duration, log *logrus.Entry) (PersisterCheckStateUpdater, error) {
	return &Persister{
		endpoint: endpoint,
		timeout:  timeout,
		log:      log,
	}, nil
}

// CreateAgent creates an Agent on the Persister with given Agent version and JobqueueID
func (p *Persister) CreateAgent(agentVersion, jobqueueID string) (agentID, jobqueueARN string, err error) {
	action := "creating agent"

	p.log.Info(action)

	aReq := Agent{Version: agentVersion, JobqueueID: jobqueueID}

	log := p.log.WithFields(logrus.Fields{"action": action})

	aRes, err := p.requestAgent("POST", "", aReq, log)
	if err != nil {
		return "", "", err
	}

	p.log = p.log.WithFields(logrus.Fields{"agentID": aRes.ID})

	return aRes.ID, aRes.Jobqueue.ARN, nil
}

// UpdateAgentStatus updates the state of an Agent for the given agentID
func (p *Persister) UpdateAgentStatus(agentID, agentStatus string) error {
	action := "updating agent status"

	p.log.WithFields(logrus.Fields{
		"status": agentStatus,
	}).Info(action)

	aReq := Agent{ID: agentID, Status: agentStatus}

	log := p.log.WithFields(logrus.Fields{"action": action})

	_, err := p.requestAgent("PATCH", "", aReq, log)

	return err
}

// UpdateAgentHeartbeat sends a heartbeat to the Persister for the given agentID
func (p *Persister) UpdateAgentHeartbeat(agentID string) error {
	action := "updating agent heartbeat"

	p.log.Info(action)

	aReq := Agent{ID: agentID}

	log := p.log.WithFields(logrus.Fields{"action": action})

	_, err := p.requestAgent("POST", "heartbeat", aReq, log)

	return err
}

// UpdateCheckAgent updates the state of an Agent on the Persister for the given agentID
func (p *Persister) UpdateCheckAgent(checkID, agentID string) error {
	action := "updating check agent"

	p.log.WithFields(logrus.Fields{
		"check_id": checkID,
	}).Info(action)

	cReq := Check{ID: checkID, AgentID: agentID}

	log := p.log.WithFields(logrus.Fields{"action": action})

	_, err := p.requestCheck("PATCH", "", cReq, log)

	return err
}

// UpdateCheckState updates the state of a Check on the Persister for the given checkID
func (p *Persister) UpdateCheckState(checkID string, state check.State) error {
	action := "updating check state"

	p.log.WithFields(logrus.Fields{
		"check_id": checkID,
		"state":    state,
	}).Info(action)

	cReq := Check{ID: checkID, Status: state.Status, Progress: state.Progress}
	log := p.log.WithFields(logrus.Fields{"action": action})
	_, err := p.requestCheck("PATCH", "", cReq, log)
	if err != nil {
		p.log.WithFields(logrus.Fields{
			"check_id":  checkID,
			"state":     state.Status,
			"operation": "UpdateCheckState",
		}).WithError(err)
	}
	return err
}

// UpdateCheckRaw updates Raw data for a Check on the Persister for the given checkID
func (p *Persister) UpdateCheckRaw(checkID string, rawLink string) error {
	action := "updating check raw"

	p.log.WithFields(logrus.Fields{
		"check_id": checkID,
		"link":     rawLink,
	}).Info(action)

	cReq := Check{ID: checkID, Raw: rawLink}

	log := p.log.WithFields(logrus.Fields{"action": action})

	_, err := p.requestCheck("PATCH", "", cReq, log)

	return err
}

// UpdateCheckReport updates Report data for a Check on the Persister for the given checkID
func (p *Persister) UpdateCheckReport(checkID string, reportLink string) error {
	action := "updating check report"

	p.log.WithFields(logrus.Fields{
		"check_id": checkID,
		"link":     reportLink,
	}).Info(action)

	cReq := Check{ID: checkID, Report: reportLink}

	log := p.log.WithFields(logrus.Fields{"action": action})

	_, err := p.requestCheck("PATCH", "", cReq, log)

	return err
}

func (p *Persister) requestAgent(method, suffix string, a Agent, log *logrus.Entry) (Agent, error) {
	path := path.Join("agents", a.ID, suffix)

	v, err := p.jsonRequest(method, path, a, log)
	if err != nil {
		return Agent{}, err
	}

	return *v.(*Agent), nil
}

func (p *Persister) requestCheck(method, suffix string, c Check, log *logrus.Entry) (Check, error) {
	path := path.Join("checks", c.ID, suffix)

	v, err := p.jsonRequest(method, path, c, log)
	if err != nil {
		return Check{}, err
	}

	return *v.(*Check), nil
}

func (p *Persister) requestChecktype(method, suffix string, ct Checktype, log *logrus.Entry) (Checktype, error) {
	path := path.Join("checktypes", ct.ID, suffix)

	v, err := p.jsonRequest(method, path, ct, log)
	if err != nil {
		return Checktype{}, err
	}

	return *v.(*Checktype), nil
}

func (p *Persister) requestJobqueue(method, suffix string, jq Jobqueue, log *logrus.Entry) (Jobqueue, error) {
	path := path.Join("jobqueues", jq.ID, suffix)

	v, err := p.jsonRequest(method, path, jq, log)
	if err != nil {
		return Jobqueue{}, err
	}

	return *v.(*Jobqueue), nil
}

func (p *Persister) jsonRequest(method, route string, v interface{}, log *logrus.Entry) (interface{}, error) {
	var err error

	u, err := url.Parse(p.endpoint)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, route)

	reqBody, err := marshalReq(v)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, u.String(), reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	log.WithFields(logrus.Fields{
		"method": method,
		"url":    u.String(),
		"body":   reqBody.String(),
	}).Debug("performing request to persistence")

	// Only to test not reusing connections.
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	c := &http.Client{Transport: tr, Timeout: p.timeout}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	log.WithFields(logrus.Fields{
		"request_route":   route,
		"response_body":   string(resBody),
		"response_status": res.Status,
	}).Debug("received response from persistence")

	// Sometimes the agent returns a response with an empty
	resObj, err := unmarshalRes(resBody)
	if err != nil {
		return nil, err
	}

	valid, ok := validStatusOperations[method]
	if !ok {
		return resObj, nil
	}

	for _, c := range valid {
		if c == res.StatusCode {
			return resObj, nil
		}
	}

	return nil, &HTTPError{Status: res.Status, StatusCode: res.StatusCode}
}

// Malshal the request into the appropriate JSON object.
// The type will depend on the type of the interface.
// Example:
// Agent -> AgentData{Agent} -> {"agent": {...}}
// Check -> CheckData{Check} -> {"check": {...}}
func marshalReq(v interface{}) (*bytes.Buffer, error) {
	reqBody := new(bytes.Buffer)

	var err error
	switch r := v.(type) {
	case Agent:
		err = json.NewEncoder(reqBody).Encode(AgentData{Agent: r})
	case Check:
		err = json.NewEncoder(reqBody).Encode(CheckData{Check: r})
	case Checktype:
		err = json.NewEncoder(reqBody).Encode(ChecktypeData{Checktype: r})
	case Jobqueue:
		err = json.NewEncoder(reqBody).Encode(JobqueueData{Jobqueue: r})
	case Raw:
		err = json.NewEncoder(reqBody).Encode(RawData{Raw: r})
	case Report:
		err = json.NewEncoder(reqBody).Encode(ReportData{Report: r})
	default:
		return nil, errors.New("error processing request of unknown type")
	}

	return reqBody, err
}

// Unmarshal the JSON response into the appropriate object.
// The type will depend on the top-level JSON object.
// Example:
// {"agent": {...}} -> Agent
// {"check": {...}} -> Check
func unmarshalRes(resBody []byte) (interface{}, error) {
	var err error
	// In some cases the persistence is returning an body with blanks and no
	// content, is those cases wit just return nil.
	if strings.Trim(string(resBody), " ") == "" {
		return nil, nil
	}
	var data map[string]json.RawMessage
	err = json.Unmarshal(resBody, &data)
	if err != nil {
		return nil, err
	}

	var (
		raw json.RawMessage
		obj interface{}
	)
	for k, v := range data {
		raw = v

		switch k {
		case "agent":
			obj = &Agent{}
		case "check":
			obj = &Check{}
		case "checktype":
			obj = &Checktype{}
		case "jobqueue":
			obj = &Jobqueue{}
		default:
			err = fmt.Errorf("error processing response of type %v raw message: %s", k, string(resBody))
		}

		break
	}
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(raw, obj)
	if err != nil {
		return nil, err
	}

	return obj, nil
}
