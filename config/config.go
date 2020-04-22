package config

import (
	"io/ioutil"

	"github.com/BurntSushi/toml"
)

// Config represents the configuration for the agent.
type Config struct {
	Agent       AgentConfig       `toml:"agent"`
	Scheduler   SchedulerConfig   `toml:"scheduler"`
	Persistence PersistenceConfig `toml:"persistence"`
	Stream      StreamConfig      `toml:"stream"`
	Uploader    UploaderConfig    `toml:"uploader"`
	SQS         SQSConfig         `toml:"sqs"`
	API         APIConfig         `toml:"api"`
	Check       CheckConfig       `toml:"check"`
	Runtime     RuntimeConfig     `toml:"runtime"`
}

// AgentConfig defines the higher level configuration for the agent.
type AgentConfig struct {
	JobqueueID string `toml:"jobqueue_id"`
	LogLevel   string `toml:"log_level"`
	LogFile    string `toml:"log_file"`
	Timeout    int    `toml:"timeout"` // Timeout to start running a check.
}

// SchedulerConfig defines the configuration for the scheduler.
type SchedulerConfig struct {
	ConcurrentJobs    int `toml:"concurrent_jobs"`
	MonitorInterval   int `toml:"monitor_interval"`
	HeartbeatInterval int `toml:"heartbeat_interval"`
}

// PersistenceConfig defines the configuration for the persistence service.
type PersistenceConfig struct {
	Endpoint string `toml:"endpoint"`
	Timeout  int    `toml:"timeout"`
	Retries  int    `toml:"retries"`
}

// StreamConfig defines the configuration for the event stream.
type StreamConfig struct {
	Endpoint      string `toml:"endpoint"`
	Timeout       int    `toml:"timeout"`
	Retries       int    `toml:"retries"`
	RetryInterval int    `toml:"retry_interval"`
}

// UploaderConfig defines the configuration for the results service.
type UploaderConfig struct {
	Endpoint string `toml:"endpoint"`
	Timeout  int    `toml:"timeout"`
}

// SQSConfig defines the configuration for the SQS queue.
type SQSConfig struct {
	PollingInterval int    `toml:"polling_interval"`
	Endpoint        string `toml:"endpoint"`
	Region          string `toml:"region"`
	QueueName       string `toml:"queue_name"`
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
