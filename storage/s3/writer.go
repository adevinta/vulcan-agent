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

	"github.com/adevinta/vulcan-agent/config"
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
	ErrLinkBaseNotDefined      = errors.New("link base must be defined or S3 link enabled")
	ErrUnsupportedKind         = errors.New("unsupported kind")
)

// Writer defines an AWS S3 writer.
type Writer struct {
	cfg config.S3Writer
	svc s3iface.S3API
	l   log.Logger
}

// NewWriter creates a new S3 writer.
func NewWriter(cfg config.S3Writer, l log.Logger) (*Writer, error) {
	if cfg.BucketReports == "" {
		return nil, ErrReportsBucketNotDefined
	}
	if cfg.BucketLogs == "" {
		return nil, ErrLogsBucketNotDefined
	}
	if cfg.LinkBase == "" && !cfg.S3Link {
		return nil, ErrLinkBaseNotDefined
	}

	sess, err := session.NewSession()
	if err != nil {
		err = fmt.Errorf("creating AWS session %w", err)
		return nil, err
	}

	awsCfg := aws.NewConfig()
	if cfg.Region == "" {
		cfg.Region = DefaultAWSRegion
	}
	awsCfg = awsCfg.WithRegion(cfg.Region)
	if cfg.Endpoint != "" {
		awsCfg = awsCfg.WithEndpoint(cfg.Endpoint).WithS3ForcePathStyle(cfg.PathStyle)
	}

	s3Svc := s3.New(sess, awsCfg)
	l.Infof(
		"s3 writer created. Region [%s] LogsBucket [%s] ReportsBucket [%s] LinkBase [%s] S3Link [%t] Endpoint [%s] PathStyle [%t]",
		cfg.Region, cfg.BucketLogs, cfg.BucketReports, cfg.LinkBase, cfg.S3Link, cfg.Endpoint, cfg.PathStyle,
	)
	return &Writer{
		svc: s3Svc,
		cfg: cfg,
		l:   l,
	}, nil
}

// Upload uploads the provided byte array data as a file to an S3 bucket.
func (w *Writer) UploadCheckData(checkID, kind string, startedAt time.Time, content []byte) (string, error) {
	st := time.Now()
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
		// see http://docs.aws.amazon.com/athena/latest/ug/partitions.html
		dt := startedAt.Format("dt=2006-01-02")
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
