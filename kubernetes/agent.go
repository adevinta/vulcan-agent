package kubernetes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sync"

	agent "github.com/adevinta/vulcan-agent"
	"github.com/adevinta/vulcan-agent/check"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/sirupsen/logrus"
)

const (
	defaultPublicIfaceName = "eth0"
)

// CheckConfig stores the configuration required to run a check.
type CheckConfig struct {
	CheckAbortTimeout int                          // Time to wait for a check container to stop gracefully.
	CheckLogLevel     string                       // Log level for the check default logger.
	CheckVars         map[string]map[string]string // Environment variables to inject to checks.
	AgentAPIAddr      string                       // Address exposed by the agent API.
}

// Agent implements the agent.Agent interface.
// It holds the necessary information to do so for the Docker runtime environment.
type Agent struct {
	id      string
	addr    string
	status  string
	ctx     context.Context
	log     *logrus.Entry
	cancel  context.CancelFunc
	storage check.Storage
	config  config.Config
	mutex   sync.RWMutex
}

// NewAgent creates a new Agent.
// It returns a Agent and any errors encountered while creating it.
func NewAgent(ctx context.Context, cancel context.CancelFunc, id string, storage check.Storage, l *logrus.Entry, cfg config.Config) (agent.Agent, error) {
	addr, err := getAgentAddr(cfg.API.Port, cfg.API.IName)
	if err != nil {
		return &Agent{}, err
	}

	err = setKubectlConfig(cfg.Runtime.Kubernetes)
	if err != nil {
		return &Agent{}, err
	}

	return &Agent{
		id:      id,
		addr:    addr,
		status:  agent.StatusNew,
		ctx:     ctx,
		log:     l,
		cancel:  cancel,
		storage: storage,
		config:  cfg,
		mutex:   sync.RWMutex{},
	}, nil
}

// ID returns the ID assigned when creating the Agent.
func (a *Agent) ID() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return a.id
}

// Status returns the current Status of the Agent.
func (a *Agent) Status() string {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	return a.status
}

// SetStatus sets the current Status of the Agent.
func (a *Agent) SetStatus(status string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.status = status
}

// Run runs the job in the Kubernetes cluster.
// It will store the pod name in the job.Meta field.
// It will update the job stored in the jobs map.
// It will return any errors encountered.
func (a *Agent) Run(checkID string) error {
	var err error

	job, err := a.storage.Get(checkID)
	if err != nil {
		return err
	}

	envVars := a.getEnvVars(job)

	cmd := exec.Command(
		"kubectl",
		append(
			[]string{
				"run",
				// Pod name
				job.CheckID,
				// Never restart
				"--restart", "Never",
				// Kubernetes label
				"-l", "run=vulcan-check",
				// Docker image
				"--image", job.Image,
			},
			// Environment variables
			envVars...,
		)...,
	)

	return cmd.Run()
}

// Kill will forcefully remove a container and return any error encountered.
func (a *Agent) Kill(checkID string) error {
	job, err := a.storage.Get(checkID)
	if err != nil {
		return err
	}

	cmd := exec.Command("kubectl", "delete", "pod", "--grace-period", "0", job.CheckID)

	return cmd.Run()
}

// AbortChecks gets the all the checks belonging to a scan that are currently running
// and call abort in each of them.
func (a *Agent) AbortChecks(scanID string) error {
	jobs, err := a.storage.GetAllByStatus(check.StatusRunning)
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.ScanID == scanID {
			err := a.Abort(j.CheckID)
			if err != nil {
				// TODO: Check if the error is because the pod is already
				// finished.
				return err
			}
		}
	}
	return nil
}

// Abort will send the SIGTERM signal to a check and wait for it to stop.
// It will return any error encountered while doing so.
func (a *Agent) Abort(checkID string) error {
	job, err := a.storage.Get(checkID)
	if err != nil {
		return err
	}

	timeout := a.config.Check.AbortTimeout

	// This command will send a SIGTERM signal to the entrypoint.
	// It will wait for the amount of seconds configured and then
	// forcefully delete the pod.
	cmd := exec.Command("kubectl", "delete", "pod", "--grace-period", string(timeout), job.CheckID)

	return cmd.Run()
}

// Raw returns the raw output of the check and any errors encountered.
// It will use the Docker API to retrieve the container logs.
func (a *Agent) Raw(checkID string) ([]byte, error) {
	job, err := a.storage.Get(checkID)
	if err != nil {
		return []byte{}, err
	}

	cmd := exec.Command("kubectl", "get", "logs", job.CheckID)

	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return []byte{}, err
	}

	return out.Bytes(), nil
}

// getEnvVars will return the environment variable flags for a given job.
// It will inject the check options and target as environment variables.
// It will return the generated slice of flags.
func (a *Agent) getEnvVars(job check.Job) []string {
	checktypeName, checktypeVersion := getChecktypeInfo(job.Image)
	logLevel := a.config.Check.LogLevel

	vars := kubectlVars(job.RequiredVars, a.config.Check.Vars)

	return append(
		[]string{
			"--env", fmt.Sprintf("%s=%s", agent.CheckIDVar, job.CheckID),
			"--env", fmt.Sprintf("%s=%s", agent.ChecktypeNameVar, checktypeName),
			"--env", fmt.Sprintf("%s=%s", agent.ChecktypeVersionVar, checktypeVersion),
			"--env", fmt.Sprintf("%s=%s", agent.CheckTargetVar, job.Target),
			"--env", fmt.Sprintf("%s=%s", agent.CheckTargetTypeVar, job.TargetType),
			"--env", fmt.Sprintf("%s=%s", agent.CheckOptionsVar, job.Options),
			"--env", fmt.Sprintf("%s=%s", agent.CheckLogLevelVar, logLevel),
			"--env", fmt.Sprintf("%s=%s", agent.AgentAddressVar, a.addr),
		},
		vars...,
	)
}

// getAgentAddr returns the current address of the agent API from the Internet.
// It will also return any errors encountered while doing so.
func getAgentAddr(port, ifaceName string) (string, error) {
	connAddr, err := net.ResolveTCPAddr("tcp", port)
	if err != nil {
		return "", err
	}
	if ifaceName == "" {
		ifaceName = defaultPublicIfaceName
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return "", err
		}

		// Check if it is IPv4.
		if ip.To4() != nil {
			connAddr.IP = ip
			return connAddr.String(), nil
		}
	}

	return "", errors.New("failed to determine agent public IP address")
}

// getChecktypeInfo extracts checktype data from a Docker image URI.
func getChecktypeInfo(imageURI string) (checktypeName string, checktypeVersion string) {
	// https://github.com/docker/distribution/blob/master/reference/reference.go#L1-L24
	re := regexp.MustCompile(`(?P<checktype_name>[a-z0-9]+(?:[-_.][a-z0-9]+)*):(?P<checktype_version>[\w][\w.-]{0,127})`)

	matches := re.FindStringSubmatch(imageURI)

	checktypeName = matches[1]
	checktypeVersion = matches[2]

	return
}

// setKubectlConfig sets the configuration for Kubectl
func setKubectlConfig(config config.KubernetesConfig) error {
	cmd := exec.Command("kubectl", "config", "set-cluster", config.Cluster.Name,
		"--server", config.Cluster.Server,
	)
	err := cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("kubectl", "config", "set-context", config.Context.Name,
		"--cluster", config.Context.Cluster,
		"--namespace", config.Context.Namespace,
		"--user", config.Context.User,
	)
	err = cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("kubectl", "config", "set-credentials", config.Credentials.Name,
		"--token", config.Credentials.Token,
	)
	err = cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("kubectl", "config", "set", "current-context", config.Context.Name)
	return cmd.Run()
}

// kubectlVars assigns the required environment variables in a format supported by Kubectl.
func kubectlVars(requiredVars []string, envVars map[string]string) []string {
	var kubectlVars []string

	for _, requiredVar := range requiredVars {
		kubectlVars = append(kubectlVars, "--env", fmt.Sprintf("%s=%s", requiredVar, envVars[requiredVar]))
	}

	return kubectlVars
}
