package results

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	report "github.com/adevinta/vulcan-report"
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
	log      log.Logger
}

//New returns a new Uploader object pointing to the given endpoint
func New(endpoint string, timeout time.Duration) (*Uploader, error) {
	return &Uploader{
		endpoint: endpoint,
		timeout:  timeout,
	}, nil
}

// UpdateCheckReport ...
func (u *Uploader) UpdateCheckReport(checkID string, scanStartTime time.Time, report report.Report) (string, error) {
	path := path.Join("report")
	reportJSON, err := json.Marshal(&report)
	if err != nil {
		return "", err
	}

	reportData := ReportData{
		CheckID:       checkID,
		ScanID:        "notset",
		ScanStartTime: scanStartTime,
		Report:        string(reportJSON),
	}

	reportDataBytes, err := json.Marshal(reportData)
	if err != nil {
		return "", err
	}

	return u.jsonRequest(path, reportDataBytes)
}

//UpdateCheckRaw ...
func (u *Uploader) UpdateCheckRaw(checkID string, scanStartTime time.Time, raw []byte) (string, error) {
	path := path.Join("raw")
	rawData := RawData{
		CheckID:       checkID,
		ScanID:        "notset",
		ScanStartTime: scanStartTime,
		Raw:           raw,
	}

	rawDataBytes, err := json.Marshal(rawData)
	if err != nil {
		return "", err
	}

	return u.jsonRequest(path, rawDataBytes)
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
		return "", errors.New("unexpected response uploading content to the results service")
	}

	if res.StatusCode == http.StatusCreated && len(location) > 0 {
		return location[0], nil
	}

	return "", fmt.Errorf("request returned %v status", res.Status)
}
