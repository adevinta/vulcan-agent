package docker

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	docker "github.com/adevinta/dockerutils"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/lestrrat-go/backoff"
	"github.com/sirupsen/logrus"

	agent "github.com/adevinta/vulcan-agent"
	"github.com/adevinta/vulcan-agent/check"
	"github.com/adevinta/vulcan-agent/config"
)

const (
	defaultDockerIfaceName    = "docker0"
	noSuchContainerErrorToken = "No such container"
	containerAlreadyStopped   = "Container already stopped"
)

// Agent implements the agent.Agent interface.
// It holds the necessary information to do so for the Docker runtime environment.
type Agent struct {
	id      string
	addr    string
	status  string
	cli     *docker.Client
	ctx     context.Context
	log     *logrus.Entry
	cancel  context.CancelFunc
	storage check.Storage
	config  config.Config
	mutex   sync.RWMutex
}

// dockerContainer stores information for the check.Job specific to Docker.
// This information will be stored in the check.Job Meta field.
type dockerContainer struct {
	ContID string `json:"cont_id"`
}

// NewAgent creates a new Agent.
// It instantiates a docker.Client and logs it to the registry with credentials from registryConfig.
// It returns a Agent and any errors encountered while creating it.
func NewAgent(ctx context.Context, cancel context.CancelFunc, id string, storage check.Storage, log *logrus.Entry, cfg config.Config) (agent.Agent, error) {
	envCli, err := client.NewEnvClient()
	if err != nil {
		return &Agent{}, err
	}

	cli := docker.NewClient(envCli)

	// If registry server is not provided we assume public
	// DockerHub is being used without authenticate.
	if cfg.Runtime.Docker.Registry.Server != "" {
		err = cli.Login(
			ctx,
			cfg.Runtime.Docker.Registry.Server,
			cfg.Runtime.Docker.Registry.User,
			cfg.Runtime.Docker.Registry.Pass,
		)
		if err != nil {
			return &Agent{}, err
		}
	}
	var addr string
	if cfg.API.Host != "" {
		addr = cfg.API.Host + cfg.API.Port
	} else {
		addr, err = getAgentAddr(cfg.API.Port, cfg.API.IName)
	}

	if err != nil {
		return &Agent{}, err
	}

	return &Agent{
		id:      id,
		addr:    addr,
		log:     log,
		status:  agent.StatusNew,
		cli:     cli,
		ctx:     ctx,
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

// Run runs the job in the local Docker host.
// It will pull the job image from the registry if not already chached.
// It will store the container ID in the job.Meta field.
// It will update the job stored in the jobs map.
// It will return any errors encountered.
func (a *Agent) Run(checkID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(a.config.Agent.Timeout)*time.Second)
	defer cancel()

	job, err := a.storage.Get(checkID)
	if err != nil {
		return err
	}

	err = a.pullWithBackoff(ctx, job.Image)
	if err != nil {
		return err
	}

	runCfg := a.getRunConfig(job)
	contID, err := a.cli.Create(ctx, runCfg, job.CheckID)
	if err != nil {
		return err
	}

	meta := dockerContainer{
		ContID: contID,
	}
	if err := a.storage.SetMeta(job.CheckID, meta); err != nil {
		return err
	}

	return a.cli.RunExisting(ctx, runCfg, contID)
}

// Kill will forcefully remove a container and return any error encountered.
func (a *Agent) Kill(checkID string) error {
	job, err := a.storage.Get(checkID)
	if err != nil {
		return err
	}

	meta, ok := job.Meta.(dockerContainer)
	if !ok {
		return errors.New("check is missing Docker metadata")
	}

	return a.cli.ContainerRemove(
		// We use an empty context since the kill operation must always
		// be executed, even when the job or the agent are cancelled.
		context.Background(),
		meta.ContID,
		types.ContainerRemoveOptions{
			Force: true,
		},
	)
}

// AbortChecks gets the all the checks belonging to a scan that are currently running
// and call abort in each of them.
func (a *Agent) AbortChecks(scanID string) error {
	l := a.log.WithFields(logrus.Fields{"scan_id": scanID, "action": "AbortChecks"})
	l.Debug("Aborting checks for scan")
	jobs, err := a.storage.GetAllByStatus(check.StatusRunning)
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if j.ScanID == scanID {
			l.WithFields(logrus.Fields{"check_id": j.CheckID}).Info("Aborting check")
			err := a.Abort(j.CheckID)
			if err != nil {
				errMsg := err.Error()
				// Even if the checks where running when we got them they could
				// be finished by the time we called abort so we must filter
				// those errors.
				if strings.Contains(errMsg, noSuchContainerErrorToken) || strings.Contains(errMsg, containerAlreadyStopped) {
					l.WithFields(logrus.Fields{"check_id": j.CheckID}).Info("Aborting check. Check already finished")
					continue
				}
				return err
			}
			l.WithFields(logrus.Fields{"check_id": j.CheckID}).Info("Aborting Check. Check aborted")
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
	meta, ok := job.Meta.(dockerContainer)
	if !ok {
		return errors.New("check is missing Docker metadata")
	}

	timeout := time.Duration(a.config.Check.AbortTimeout) * time.Second

	// ContainerStop will send a SIGTERM signal to the entrypoint.
	// It will wait for the amount of seconds configured and then
	// send a SIGKILL signal that will terminate the process.
	// We use an empty context since the stop operation is called
	// when the ctx of the check is already finish because a time out.
	return a.cli.ContainerStop(
		context.Background(),
		meta.ContID,
		&timeout,
	)
}

// Raw returns the raw output of the check and any errors encountered.
// It will use the Docker API to retrieve the container logs.
func (a *Agent) Raw(checkID string) ([]byte, error) {
	job, err := a.storage.Get(checkID)
	if err != nil {
		return []byte{}, err
	}

	meta, ok := job.Meta.(dockerContainer)
	if !ok {
		return []byte{}, errors.New("check is missing Docker metadata")
	}

	opts := types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	}

	logs, err := a.cli.ContainerLogs(a.ctx, meta.ContID, opts)
	if err != nil {
		return []byte{}, err
	}
	defer func() { _ = logs.Close() }()

	return ioutil.ReadAll(logs)
}

// pullWithBackoff pulls a Docker image and retries using a backoff policy
// to prevent overloading the Docker registry in the case of temporary errors.
func (a *Agent) pullWithBackoff(ctx context.Context, image string) error {

	backoffPolicy := backoff.NewExponential(
		backoff.WithInterval(time.Duration(a.config.Runtime.Docker.Registry.BackoffInterval)*time.Second),
		backoff.WithMaxRetries(a.config.Runtime.Docker.Registry.BackoffMaxRetries),
		backoff.WithJitterFactor(a.config.Runtime.Docker.Registry.BackoffJitterFactor),
	)

	b, cancel := backoffPolicy.Start(context.Background())
	defer cancel()

	for backoff.Continue(b) {
		err := a.cli.Pull(ctx, image)
		if err == nil {
			return nil
		}
		a.log.WithFields(logrus.Fields{"image": image}).Warning("Error pulling Docker image")
	}
	return errors.New("backoff retry exceeded pulling Docker image")
}

// getRunConfig will generate a docker.RunConfig for a given job.
// It will inject the check options and target as environment variables.
// It will return the generated docker.RunConfig.
func (a *Agent) getRunConfig(job check.Job) docker.RunConfig {
	checktypeName, checktypeVersion := getChecktypeInfo(job.Image)
	logLevel := a.config.Check.LogLevel

	a.log.WithFields(logrus.Fields{"variables": job.RequiredVars}).Debug("fetching check variables from configuration")
	vars := dockerVars(job.RequiredVars, a.config.Check.Vars)
	return docker.RunConfig{
		ContainerConfig: &container.Config{
			Hostname: job.CheckID,
			Image:    job.Image,
			Env: append([]string{
				fmt.Sprintf("%s=%s", agent.CheckIDVar, job.CheckID),
				fmt.Sprintf("%s=%s", agent.ChecktypeNameVar, checktypeName),
				fmt.Sprintf("%s=%s", agent.ChecktypeVersionVar, checktypeVersion),
				fmt.Sprintf("%s=%s", agent.CheckTargetVar, job.Target),
				fmt.Sprintf("%s=%s", agent.CheckAssetTypeVar, job.AssetType),
				fmt.Sprintf("%s=%s", agent.CheckOptionsVar, job.Options),
				fmt.Sprintf("%s=%s", agent.CheckLogLevelVar, logLevel),
				fmt.Sprintf("%s=%s", agent.AgentAddressVar, a.addr),
			},
				vars...,
			),
		},
		HostConfig:            &container.HostConfig{},
		NetConfig:             &network.NetworkingConfig{},
		ContainerStartOptions: types.ContainerStartOptions{},
	}
}

// getAgentAddr returns the current address of the agent API from the Docker network.
// It will also return any errors encountered while doing so.
func getAgentAddr(port, ifaceName string) (string, error) {
	connAddr, err := net.ResolveTCPAddr("tcp", port)
	if err != nil {
		return "", err
	}
	if ifaceName == "" {
		ifaceName = defaultDockerIfaceName
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

	return "", errors.New("failed to determine Docker agent IP address")
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

// dockerVars assigns the required environment variables in a format supported by Docker.
func dockerVars(requiredVars []string, envVars map[string]string) []string {
	var dockerVars []string

	for _, requiredVar := range requiredVars {
		dockerVars = append(dockerVars, fmt.Sprintf("%s=%s", requiredVar, envVars[requiredVar]))
	}

	return dockerVars
}
