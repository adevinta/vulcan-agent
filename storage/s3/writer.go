/*
Copyright 2023 Adevinta
*/

package s3

import (
	"bytes"
	"errors"
	"fmt"

	"net/url"
	"path"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
)

const (
	DefaultAWSRegion = "eu-west-1" // Default AWS region.
)

var (
	ErrReportsBucketNotDefined = errors.New("reports bucket must be defined")
	ErrLogsBucketNotDefined    = errors.New("logs bucket must be defined")
	ErrLinkBaseNotDefined      = errors.New("link base must be defined or s3 link enabled")
	ErrUnsupportedKind         = errors.New("unsupported kind")
)

// Config represents the configuration options for S3Storage objects
type Config struct {
	BucketReports string
	BucketLogs    string
	LinkBase      string
	S3Link        bool
}

// Writer writes messages to and AWS SQS queue.
type Writer struct {
	cfg Config
	svc s3iface.S3API
	l   log.Logger
}

// NewWriter creates a new S3 writer.
func NewWriter(bucketReports, bucketLogs, linkBase, region string, s3link bool, l log.Logger) (*Writer, error) {
	if bucketReports == "" {
		return nil, ErrReportsBucketNotDefined
	}
	if bucketLogs == "" {
		return nil, ErrLogsBucketNotDefined
	}
	if linkBase == "" && !s3link {
		return nil, ErrLinkBaseNotDefined
	}

	c := Config{
		BucketReports: bucketReports,
		BucketLogs:    bucketLogs,
		LinkBase:      linkBase,
		S3Link:        s3link,
	}

	sess, err := session.NewSession()
	if err != nil {
		err = fmt.Errorf("creating AWS session %w", err)
		return nil, err
	}

	awsCfg := aws.NewConfig()
	if region == "" {
		region = DefaultAWSRegion
	}
	awsCfg = awsCfg.WithRegion(region)

	s3Svc := s3.New(sess, awsCfg)

	l.Infof(
		"s3 writer created. Region [%s] LogsBucket [%s] ReportsBucket [%s] LinkBase [%s] S3Link [%t]",
		region, bucketLogs, bucketReports, linkBase, s3link,
	)
	return &Writer{
		svc: s3Svc,
		cfg: c,
		l:   l,
	}, nil
}

// Upload uploads the provided byte array data as a file to an S3 bucket.
func (w *Writer) UploadCheckData(checkID, kind string, startedAt time.Time, content []byte) (string, error) {
	st := time.Now()
	// see http://docs.aws.amazon.com/athena/latest/ug/partitions.html
	dt := startedAt.Format("dt=2006-01-02")
	var bucket, key, contentType, extension, link string

	switch kind {
	case "reports":
		extension = "json"
		contentType = "text/json"
		bucket = w.cfg.BucketReports
	case "logs":
		extension = "log"
		contentType = "text/plain"
		bucket = w.cfg.BucketLogs
	default:
		return "", ErrUnsupportedKind
	}

	key = fmt.Sprintf("%s/%s.%s", kind, checkID, extension)
	link = fmt.Sprintf("s3://%s/%s/%s.%s", bucket, kind, checkID, extension)
	// This is for retrocompatibility with the vulcan-results clients.
	if !w.cfg.S3Link {
		key = fmt.Sprintf("%s/%s/%s.%s", dt, checkID, checkID, extension)
		var err error
		link, err = urlConcat(w.cfg.LinkBase, kind, key)
		if err != nil {
			w.l.Errorf("unable to generate link for key [%s]", key)
			return "", err
		}
	}

	putParams := &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(content),
		ContentType: aws.String(contentType),
	}

	_, putErr := w.svc.PutObject(putParams)
	if putErr != nil {
		w.l.Errorf("unable to upload file [%s] to bucket [%s]: %s", key, bucket, putErr)
		return "", fmt.Errorf("unable to upload file %s to bucket %s: %w", key, bucket, putErr)
	}

	et := time.Since(st)
	w.l.Debugf(
		"event=checkTrace checkID=%s action=s3upload kind=%s bucket=%s key=\"%s\" size=%d uploadTime=%.2f link=\"%s\"",
		checkID,
		kind,
		bucket,
		key,
		len(content),
		et.Seconds(),
		link,
	)

	return link, nil
}

func urlConcat(baseURL string, toConcat ...string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	toJoin := append([]string{u.Path}, toConcat...)
	u.Path = path.Join(toJoin...)

	return u.String(), nil
}
