/*
Copyright 2021 Adevinta
*/
package results

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/retryer"
	report "github.com/adevinta/vulcan-report"
)

// ReportData represents the payload for report upload requests.
type ReportData struct {
	Report        string    `json:"report"`
	CheckID       string    `json:"check_id"`
	ScanID        string    `json:"scan_id"`
	ScanStartTime time.Time `json:"scan_start_time"`
}

// Retryer represents the functions used by the Uploader for retrying http
// requests.
type Retryer interface {
	WithRetries(op string, exec func() error) error
}

// RawData represents the payload for raw upload requests.
type RawData struct {
	Raw           []byte    `json:"raw"`
	CheckID       string    `json:"check_id"`
	ScanID        string    `json:"scan_id"`
	ScanStartTime time.Time `json:"scan_start_time"`
}

// Uploader is responsible for uploading reports and logs to vulcan-results.
type Uploader struct {
	retryer  Retryer
	endpoint string
	timeout  time.Duration
	log      log.Logger
}

// New returns a new Uploader object pointing to the given endpoint.
func New(endpoint string, retryer Retryer, timeout time.Duration) *Uploader {
	return &Uploader{
		retryer:  retryer,
		endpoint: endpoint,
		timeout:  timeout,
	}
}

// UpdateCheckReport stores the report of a check in the results service and
// returns the link that can be used to retreive that report.
func (u *Uploader) UpdateCheckReport(checkID string, scanStartTime time.Time, report report.Report) (string, error) {
	path := path.Join("report")
	reportJSON, err := json.Marshal(&report)
	if err != nil {
		return "", err
	}

	reportData := ReportData{
		CheckID:       checkID,
		ScanID:        checkID,
		ScanStartTime: scanStartTime,
		Report:        string(reportJSON),
	}

	reportDataBytes, err := json.Marshal(reportData)
	if err != nil {
		return "", err
	}

	var reportLocation string
	if u.retryer != nil {
		u.retryer.WithRetries("Uploader.UploadLogs", func() error {
			reportLocation, err = u.jsonRequest(path, reportDataBytes)
			return err
		})
	} else {
		reportLocation, err = u.jsonRequest(path, reportDataBytes)
	}

	return reportLocation, err
}

// UpdateCheckRaw stores the log of the execution of a check in results service
// an returns a link that can be used to retreive the logs.
func (u *Uploader) UpdateCheckRaw(checkID string, scanStartTime time.Time, raw []byte) (string, error) {
	path := path.Join("raw")
	// We are not going to process scan id's at he agent level.
	rawData := RawData{
		CheckID:       checkID,
		ScanID:        checkID,
		ScanStartTime: scanStartTime,
		Raw:           raw,
	}

	rawDataBytes, err := json.Marshal(rawData)
	if err != nil {
		return "", err
	}
	var logLocation string
	if u.retryer != nil {
		u.retryer.WithRetries("Uploader.UploadLogs", func() error {
			logLocation, err = u.jsonRequest(path, rawDataBytes)
			return err
		})
	} else {
		logLocation, err = u.jsonRequest(path, rawDataBytes)
	}
	return logLocation, err
}

func (u *Uploader) jsonRequest(route string, reqBody []byte) (string, error) {
	var err error
	url, err := url.Parse(u.endpoint)
	if err != nil {
		return "", err
	}
	url.Path = path.Join(url.Path, route)

	req, err := http.NewRequest("POST", url.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/json; charset=utf-8")

	c := http.Client{Timeout: u.timeout}

	res, err := c.Do(req)
	if err != nil {
		return "", err
	}

	location, exists := res.Header["Location"]
	if !exists || len(location) <= 0 {
		body := u.tryReadBody(res)
		errMsg := fmt.Sprintf("invalid response, status: %s, body: %s", res.Status, body)
		err := fmt.Errorf("%s, %w", errMsg, retryer.ErrPermanent)
		return "", err
	}
	if res.StatusCode == http.StatusCreated && len(location) > 0 {
		return location[0], nil
	}
	errMsg := fmt.Sprintf("invalid response status: %s", res.Status)
	err = fmt.Errorf("%s, %w", errMsg, retryer.ErrPermanent)
	return "", err
}

func (u *Uploader) tryReadBody(res *http.Response) string {
	if res.ContentLength == 0 {
		return ""
	}
	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		u.log.Errorf("error reading body from results service %+v", err)
		return ""
	}
	return string(content)
}
