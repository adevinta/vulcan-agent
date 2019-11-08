package results

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	report "github.com/adevinta/vulcan-report"
)

func buildMockReportServer() (*httptest.Server, *[]ReportData, *[]RawData) {
	reports := &[]ReportData{}
	raws := &[]RawData{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusCreated
		switch r.URL.Path {
		case "/raw":
			decoder := json.NewDecoder(r.Body)
			msg := &RawData{}
			err := decoder.Decode(msg)
			if err != nil {
				status = http.StatusInternalServerError
			} else {
				*raws = append(*raws, *msg)
				w.Header().Add("Location", fmt.Sprintf("ref/%s", msg.CheckID))
			}

		case "/report":
			decoder := json.NewDecoder(r.Body)
			msg := &ReportData{}
			err := decoder.Decode(msg)
			if err != nil {
				status = http.StatusInternalServerError
			} else {
				*reports = append(*reports, *msg)
				w.Header().Add("Location", fmt.Sprintf("ref/%s", msg.CheckID))
			}
		default:
			fmt.Printf("enter default: %s", r.URL.Path)
			status = http.StatusInternalServerError
		}
		w.WriteHeader(status)

	})
	return httptest.NewServer(h), reports, raws
}
func TestUploader_UpdateCheckRaw(t *testing.T) {
	type args struct {
		checkID       string
		scanID        string
		scanStartTime time.Time
		raw           []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "HappyPath",
			args: args{
				checkID: "id1",
				scanID:  "scan1",
				raw:     []byte("payload"),
			},
			want: "ref/id1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, _ := buildMockReportServer()
			u := Uploader{
				endpoint: srv.URL,
				log:      logrus.New().WithField("test", tt.name),
				timeout:  time.Duration(time.Second),
			}
			got, err := u.UpdateCheckRaw(tt.args.checkID, tt.args.scanID, tt.args.scanStartTime, tt.args.raw)
			if (err != nil) != tt.wantErr {
				t.Errorf("Uploader.UpdateCheckRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Uploader.UpdateCheckRaw() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUploader_UpdateCheckReport(t *testing.T) {
	type args struct {
		checkID       string
		scanID        string
		scanStartTime time.Time
		report        report.Report
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "HappyPath",
			args: args{
				checkID: "id1",
				scanID:  "scan1",
				report:  report.Report{},
			},
			want: "ref/id1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, _ := buildMockReportServer()
			u := Uploader{
				endpoint: srv.URL,
				log:      logrus.New().WithField("test", tt.name),
				timeout:  time.Duration(time.Second),
			}
			got, err := u.UpdateCheckReport(tt.args.checkID, tt.args.scanID, tt.args.scanStartTime, tt.args.report)
			if (err != nil) != tt.wantErr {
				t.Errorf("Uploader.UpdateCheckRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Uploader.UpdateCheckRaw() = %v, want %v", got, tt.want)
			}
		})
	}
}
