/*
Copyright 2023 Adevinta
*/

package s3

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

const (
	validBucketReports = "bucketReports"
	validBucketLogs    = "bucketLogs"
	validLinkBase      = "https://example.com"
	validRegion        = "us-west-1"
)

type mockS3Client struct {
	s3iface.S3API
	UploadOutput *s3.PutObjectOutput
	UploadError  error
}

func (m *mockS3Client) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	return m.UploadOutput, m.UploadError
}

func TestNewWriter(t *testing.T) {
	testCases := []struct {
		bucketReports string
		bucketLogs    string
		linkBase      string
		region        string
		s3link        bool
		expectedErr   error
	}{
		{
			validBucketReports,
			validBucketLogs,
			validLinkBase,
			validRegion,
			false,
			nil,
		},
		{
			"",
			validBucketLogs,
			validLinkBase,
			validRegion,
			false,
			ErrReportsBucketNotDefined,
		},
		{
			validBucketReports,
			"",
			validLinkBase,
			validRegion,
			false,
			ErrLogsBucketNotDefined,
		},
		{
			validBucketReports,
			validBucketLogs,
			"",
			validRegion,
			false,
			ErrLinkBaseNotDefined,
		},
		{
			validBucketReports,
			validBucketLogs,
			"",
			validRegion,
			true,
			nil,
		},
		{
			validBucketReports,
			validBucketLogs,
			validLinkBase,
			"",
			false,
			nil,
		},
	}

	for _, tc := range testCases {
		l, _ := log.New(config.AgentConfig{})
		writer, err := NewWriter(tc.bucketReports, tc.bucketLogs, tc.linkBase, tc.region, tc.s3link, l)
		if err != tc.expectedErr {
			t.Errorf("Expected error: %v, but got: %v", tc.expectedErr, err)
		}

		if tc.expectedErr != nil {
			continue
		}

		// Verify the Writer fields are set correctly
		if writer.svc == nil {
			t.Error("Writer's svc field is not set")
		}
		if writer.cfg.BucketReports != tc.bucketReports {
			t.Errorf("Expected BucketReports to be %s, but got %s", tc.bucketReports, writer.cfg.BucketReports)
		}
		if writer.cfg.BucketLogs != tc.bucketLogs {
			t.Errorf("Expected BucketLogs to be %s, but got %s", tc.bucketLogs, writer.cfg.BucketLogs)
		}
		if writer.cfg.LinkBase != tc.linkBase {
			t.Errorf("Expected LinkBase to be %s, but got %s", tc.linkBase, writer.cfg.LinkBase)
		}
	}
}

func TestUploadCheckData(t *testing.T) {
	testCases := []struct {
		name          string
		kind          string
		extension     string
		contentType   string
		bucket        string
		s3link        bool
		expectedLink  string
		expectedError error
	}{
		{
			name:          "ValidKindReports",
			kind:          "reports",
			extension:     "json",
			contentType:   "test/json",
			bucket:        "bucketReports",
			s3link:        false,
			expectedLink:  "https://www.example.com/reports/dt=2023-05-12/check123/check123.json",
			expectedError: nil,
		},
		{
			name:          "ValidKindLogs",
			kind:          "logs",
			extension:     "log",
			contentType:   "test/plain",
			bucket:        "bucketLogs",
			s3link:        false,
			expectedLink:  "https://www.example.com/logs/dt=2023-05-12/check123/check123.log",
			expectedError: nil,
		},
		{
			name:          "ValidKindReportsS3Link",
			kind:          "reports",
			extension:     "json",
			contentType:   "test/json",
			bucket:        "bucketReports",
			s3link:        true,
			expectedLink:  "s3://bucketReports/check123.json",
			expectedError: nil,
		},
		{
			name:          "ValidKindLogsS3Link",
			kind:          "logs",
			extension:     "log",
			contentType:   "test/plain",
			bucket:        "bucketLogs",
			s3link:        true,
			expectedLink:  "s3://bucketLogs/check123.log",
			expectedError: nil,
		},
		{
			name:          "UnsupportedKind",
			kind:          "unsupported",
			bucket:        "",
			expectedLink:  "",
			expectedError: ErrUnsupportedKind,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock S3 client and its response
			mockSvc := &mockS3Client{
				UploadOutput: &s3.PutObjectOutput{},
				UploadError:  nil,
			}

			l, _ := log.New(config.AgentConfig{})
			writer := &Writer{
				svc: mockSvc,
				cfg: Config{
					BucketReports: "bucketReports",
					BucketLogs:    "bucketLogs",
					LinkBase:      "https://www.example.com",
					S3Link:        tc.s3link,
				},
				l: l,
			}

			checkID := "check123"
			startedAt := time.Date(2023, time.May, 12, 0, 0, 0, 0, time.UTC)
			content := []byte("content")

			link, err := writer.UploadCheckData(checkID, tc.kind, startedAt, content)
			if !errors.Is(err, tc.expectedError) {
				t.Errorf("Expected error: %v, but got: %v", tc.expectedError, err)
			}

			// Verify the returned link
			if link != tc.expectedLink {
				t.Errorf("Expected link to be %s, but got %s", tc.expectedLink, link)
			}
		})
	}
}

func TestUrlConcat(t *testing.T) {
	baseURL := "https://example.com"
	testCases := []struct {
		toConcat []string
		expected string
	}{
		{[]string{"path1", "path2"}, "https://example.com/path1/path2"},
		{[]string{"path1/", "/path2"}, "https://example.com/path1/path2"},
		{[]string{"path1", "/path2"}, "https://example.com/path1/path2"},
		{[]string{""}, "https://example.com"},
		{[]string{}, "https://example.com"},
	}

	for _, tc := range testCases {
		result, err := urlConcat(baseURL, tc.toConcat...)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if result != tc.expected {
			t.Errorf("Expected %s, but got %s", tc.expected, result)
		}
	}
}

func TestUrlConcatError(t *testing.T) {
	invalidURL := ":invalid:"
	url, err := urlConcat(invalidURL, "path")
	fmt.Println(url)
	if err == nil {
		t.Error("Expected an error, but got nil")
	}
}
