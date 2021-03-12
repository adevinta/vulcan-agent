/*
Copyright 2021 Adevinta
*/

package config

import (
	"io/ioutil"

	"github.com/BurntSushi/toml"
)

// Config represents the configuration for the agent.
type Config struct {
	Agent     AgentConfig    `toml:"agent"`
	Stream    StreamConfig   `toml:"stream"`
	Uploader  UploaderConfig `toml:"uploader"`
	SQSReader SQSReader      `toml:"sqs_reader"`
	SQSWriter SQSWriter      `toml:"sqs_writer"`
	API       APIConfig      `toml:"api"`
	Check     CheckConfig    `toml:"check"`
	Runtime   RuntimeConfig  `toml:"runtime"`
	DataDog   DatadogConfig  `toml:"datadog"`
}

// AgentConfig defines the higher level configuration for the agent.
type AgentConfig struct {
	LogLevel       string `toml:"log_level"`
	LogFile        string `toml:"log_file"`
	Timeout        int    `toml:"timeout"` // Timeout to start running a check.
	ConcurrentJobs int    `toml:"concurrent_jobs"`
	// MaxMsgsInterval defines the maximun time, in seconds, the agent can
	// running without reading any message from the queue.
	MaxNoMsgsInterval int `toml:"max_no_msgs_interval"`
}

// StreamConfig defines the configuration for the event stream.
type StreamConfig struct {
	Endpoint      string `toml:"endpoint"`
	QueryEndpoint string `toml:"query_endpoint"`
	Timeout       int    `toml:"timeout"`
	Retries       int    `toml:"retries"`
	RetryInterval int    `toml:"retry_interval"`
}

// UploaderConfig defines the configuration for the results service.
type UploaderConfig struct {
	Endpoint      string `toml:"endpoint"`
	Timeout       int    `toml:"timeout"`
	Retries       int    `toml:"retries"`
	RetryInterval int    `toml:"retry_interval"`
}

// SQSReader defines the config of sqs reader.
type SQSReader struct {
	Endpoint          string `toml:"endpoint"`
	ARN               string `toml:"arn"`
	VisibilityTimeout int    `toml:"visibility_timeout"`
	PollingInterval   int    `toml:"polling_interval"`
	ProcessQuantum    int    `toml:"process_quantum"`
}

// SQSWriter defines the config params from the sqs writer.
type SQSWriter struct {
	Endpoint string `toml:"endpoint"`
	ARN      string `toml:"arn"`
}

// APIConfig defines the configuration for the agent API.
type APIConfig struct {
	Port  string `json:"port"`               // Port where the api for for the check should listen on
	IName string `json:"iname" toml:"iname"` // Interface name that defines the ip a check should use to reach the agent api.
	Host  string `json:"host" toml:"host"`   // Hostname a check should use to reach the agent. Overrides the IName config param.
}

// CheckConfig defines the configuration for the checks.
type CheckConfig struct {
	AbortTimeout int               `toml:"abort_timeout"` // Time to wait for a check container to stop gracefully.
	LogLevel     string            `toml:"log_level"`     // Log level for the check default logger.
	Vars         map[string]string `toml:"vars"`          // Environment variables to inject to checks.
}

// RuntimeConfig defines the configuration for the check runtimes.
type RuntimeConfig struct {
	Docker     DockerConfig     `toml:"docker"`
	Kubernetes KubernetesConfig `toml:"kubernetes"`
}

// DockerConfig defines the configuration for the Docker runtime environment.
type DockerConfig struct {
	Registry RegistryConfig `toml:"registry"`
}

// RegistryConfig defines the configuration for the Docker registry.
type RegistryConfig struct {
	Server              string  `toml:"server"`
	User                string  `toml:"user"`
	Pass                string  `toml:"pass"`
	BackoffInterval     int     `toml:"backoff_interval"`
	BackoffMaxRetries   int     `toml:"backoff_max_retries"`
	BackoffJitterFactor float64 `toml:"backoff_jitter_factor"`
}

// KubernetesConfig defines the configuration for the Kubernetes runtime environment.
type KubernetesConfig struct {
	Cluster     ClusterConfig     `toml:"cluster"`
	Context     ContextConfig     `toml:"context"`
	Credentials CredentialsConfig `toml:"credentials"`
}

// ClusterConfig defines the configuration for the Kubernetes cluster.
type ClusterConfig struct {
	Name   string `toml:"name"`
	Server string `toml:"server"`
}

// ContextConfig defines the configuration for the Kubernetes context.
type ContextConfig struct {
	Name      string `toml:"name"`
	Cluster   string `toml:"cluster"`
	Namespace string `toml:"namespace"`
	User      string `toml:"user"`
}

// CredentialsConfig defines the configuration for the Kubernetes user.
type CredentialsConfig struct {
	Name  string `toml:"name"`
	Token string `toml:"token"`
}

// DatadogConfig defines the configuration for DataDog.
type DatadogConfig struct {
	Enabled bool   `toml:"metrics_enabled"`
	Statsd  string `toml:"dogstatsd"`
}

// ReadConfig reads and parses a configuration file.
func ReadConfig(configFile string) (Config, error) {
	configData, err := ioutil.ReadFile(configFile)
	if err != nil {
		return Config{}, err
	}

	var config Config
	if _, err := toml.Decode(string(configData), &config); err != nil {
		return Config{}, err
	}

	return config, nil
}
