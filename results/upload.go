package results

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	report "github.com/adevinta/vulcan-report"

	"github.com/sirupsen/logrus"
)

//ReportData represents the payload for report upload requests
type ReportData struct {
	Report        string    `json:"report"`
	CheckID       string    `json:"check_id"`
	ScanID        string    `json:"scan_id"`
	ScanStartTime time.Time `json:"scan_start_time"`
}

//RawData represents the payload for raw upload requests
type RawData struct {
	Raw           []byte    `json:"raw"`
	CheckID       string    `json:"check_id"`
	ScanID        string    `json:"scan_id"`
	ScanStartTime time.Time `json:"scan_start_time"`
}

//Uploader represents the Uploader class, responsible for uploading reports and
//logs to vulcan-results
type Uploader struct {
	endpoint string
	timeout  time.Duration
	log      *logrus.Entry
}

//New returns a new Uploader object pointing to the given endpoint
func New(endpoint string, timeout time.Duration, log *logrus.Entry) (Uploader, error) {
	return Uploader{
		endpoint: endpoint,
		timeout:  timeout,
		log:      log,
	}, nil
}

//UpdateCheckReport ...
func (u *Uploader) UpdateCheckReport(checkID, scanID string, scanStartTime time.Time, report report.Report) (string, error) {
	action := "uploading check report"
	path := path.Join("report")

	u.log.WithFields(logrus.Fields{
		"check_id": checkID,
	}).Debug(action)

	log := u.log.WithFields(logrus.Fields{"action": action})

	reportJSON, err := json.Marshal(&report)
	if err != nil {
		return "", err
	}

	reportData := ReportData{
		CheckID:       checkID,
		ScanID:        scanID,
		ScanStartTime: scanStartTime,
		Report:        string(reportJSON),
	}

	reportDataBytes, err := json.Marshal(reportData)
	if err != nil {
		return "", err
	}

	return u.jsonRequest(path, reportDataBytes, log)
}

//UpdateCheckRaw ...
func (u *Uploader) UpdateCheckRaw(checkID, scanID string, scanStartTime time.Time, raw []byte) (string, error) {
	action := "uploading check raw"
	path := path.Join("raw")

	u.log.WithFields(logrus.Fields{
		"check_id": checkID,
		"size":     len(raw),
	}).Debug(action)

	log := u.log.WithFields(logrus.Fields{"action": action})

	rawData := RawData{
		CheckID:       checkID,
		ScanID:        scanID,
		ScanStartTime: scanStartTime,
		Raw:           raw,
	}

	rawDataBytes, err := json.Marshal(rawData)
	if err != nil {
		return "", err
	}

	return u.jsonRequest(path, rawDataBytes, log)
}

// TODO: Implement retrying here.
func (u *Uploader) jsonRequest(route string, reqBody []byte, log *logrus.Entry) (string, error) {
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

	log.WithFields(logrus.Fields{
		"url":  url.String(),
		"body": string(reqBody),
	}).Debug("performing request to results service")

	c := http.Client{Timeout: u.timeout}

	res, err := c.Do(req)
	if err != nil {
		return "", err
	}

	location, exists := res.Header["Location"]
	if exists && len(location) > 0 {
		log.WithFields(logrus.Fields{
			"Location Header": location[0],
		}).Debug("received response from results service")
	}

	if res.StatusCode == http.StatusCreated && len(location) > 0 {
		return location[0], nil
	}

	return "", fmt.Errorf("request returned %v status", res.Status)
}
