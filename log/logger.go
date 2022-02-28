/*
Copyright 2021 Adevinta
*/

package log

import (
	"os"
	"time"

	"github.com/adevinta/vulcan-agent/config"
	"github.com/sirupsen/logrus"
)

type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

type NullLog struct{}

func (n *NullLog) Debugf(format string, args ...interface{}) {
}

func (n *NullLog) Infof(format string, args ...interface{}) {
}

func (n *NullLog) Errorf(format string, args ...interface{}) {
}

// Log implements the default logger.
type Log struct {
	*logrus.Entry
}

// New returns the default log using the passed in configuration.
func New(cfg config.AgentConfig) (Logger, error) {
	logger := logrus.New()
	logger.Level = ParseLogLevel(cfg.LogLevel)
	hostname, err := os.Hostname()
	if err != nil {
		logger.Errorf("error retrieving hostname: %v", err)
		return nil, err
	}

	formatter := &logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
	}
	logger.Out = os.Stdout
	if cfg.LogFile != "" {
		logFile, err := os.OpenFile(cfg.LogFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			logger.Errorf("error opening log file: %v", err)
			return nil, err
		}
		logger.Out = logFile
		formatter.DisableColors = true
	}
	logger.Formatter = formatter
	// Add hostname to all log entries.
	l := logrus.NewEntry(logger).WithFields(logrus.Fields{"hostname": hostname})
	return &Log{l}, nil
}

func ParseLogLevel(logLevel string) logrus.Level {
	switch logLevel {
	case "panic":
		return logrus.PanicLevel
	case "fatal":
		return logrus.FatalLevel
	case "error":
		return logrus.ErrorLevel
	case "warn":
		return logrus.WarnLevel
	case "info":
		return logrus.InfoLevel
	case "debug":
		return logrus.DebugLevel
	default:
		return logrus.InfoLevel
	}
}
