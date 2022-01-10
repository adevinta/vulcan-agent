/*
Copyright 2021 Adevinta
*/

package docker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/retryer"
)

const abortTimeout = 5 * time.Second
const defaultDockerIfaceName = "docker0"

// Client defines the shape of the docker client component needed by the docker
// backend in order to be able to run checks.
type Client interface {
	Create(ctx context.Context, cfg RunConfig, name string) (contID string, err error)
	ContainerStop(ctx context.Context, containerID string, timeout *time.Duration) error
	ContainerRemove(ctx context.Context, containerID string, options types.ContainerRemoveOptions) error
	ContainerStart(ctx context.Context, containerID string, options types.ContainerStartOptions) error
	ContainerWait(ctx context.Context, containerID string) (int64, error)
	ContainerLogs(ctx context.Context, container string, options types.ContainerLogsOptions) (io.ReadCloser, error)
	Pull(ctx context.Context, imageRef string) error
}

// RunConfig contains the configuration for executing a check in a container.
type RunConfig struct {
	ContainerConfig       *container.Config
	HostConfig            *container.HostConfig
	NetConfig             *network.NetworkingConfig
	ContainerStartOptions types.ContainerStartOptions
}

// Hook allows to update the docker configuration just before the container creation.
type Hook func(backend.RunParams, *RunConfig) error

// Retryer represents the functions used by the docker backend for retrying
// docker registry operations.
type Retryer interface {
	WithRetries(op string, exec func() error) error
}

// Docker implements a docker backend for runing jobs if the local docker.
type Docker struct {
	config    config.RegistryConfig
	agentAddr string
	checkVars backend.CheckVars
	log       log.Logger
	cli       *client.Client
	auth      types.AuthConfig
	retryer   Retryer
	hook      Hook
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

// New created a new Docker backend using the given config, agent api addres and
// CheckVars.
func NewBackend(log log.Logger, cfg config.Config, hook Hook) (backend.Backend, error) {
	var (
		agentAddr string
		err       error
	)
	if cfg.API.Host != "" {
		agentAddr = cfg.API.Host + cfg.API.Port
	} else {
		agentAddr, err = getAgentAddr(cfg.API.Port, cfg.API.IName)
		if err == nil {
			return &Docker{}, err
		}
	}

	cfgReg := cfg.Runtime.Docker.Registry
	interval := cfgReg.BackoffInterval
	retries := cfgReg.BackoffMaxRetries
	re := retryer.NewRetryer(retries, interval, log)

	envCli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return &Docker{}, err
	}

	b := &Docker{
		config:    cfg.Runtime.Docker.Registry,
		agentAddr: agentAddr,
		log:       log,
		checkVars: cfg.Check.Vars,
		cli:       envCli,
		retryer:   re,
		hook:      hook,
	}

	if cfgReg.Server == "" {
		return b, nil
	}

	pass := cfgReg.Pass
	user := cfgReg.User
	if pass == "" {
		creds, err := Credentials(cfgReg.Server)
		if err != nil {
			return nil, err
		}
		pass = creds.Secret
		user = creds.Username
	}
	auth := types.AuthConfig{
		Username:      user,
		Password:      pass,
		ServerAddress: cfgReg.Server,
	}
	_, err = b.cli.RegistryLogin(context.Background(), auth)
	if err != nil {
		return nil, err
	}
	b.auth = auth
	return b, nil
}

// Run starts executing a check as a local container and returns a channel that
// will contain the result of the execution when it finishes.
func (b *Docker) Run(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
	if b.config.Server != "" {
		err := b.pull(ctx, params.Image)
		if err != nil {
			return nil, err
		}
	}

	var res = make(chan backend.RunResult)
	go b.run(ctx, params, res)
	return res, nil
}

func (b *Docker) run(ctx context.Context, params backend.RunParams, res chan<- backend.RunResult) {
	cfg := b.getRunConfig(params)

	if b.hook != nil {
		err := b.hook(params, &cfg)
		if err != nil {
			res <- backend.RunResult{Error: err}
			return
		}
	}
	cc, err := b.cli.ContainerCreate(ctx, cfg.ContainerConfig, cfg.HostConfig, cfg.NetConfig, nil, "")
	contID := cc.ID
	if err != nil {
		res <- backend.RunResult{Error: err}
		return
	}
	defer func() {
		removeOpts := types.ContainerRemoveOptions{Force: true}
		removeErr := b.cli.ContainerRemove(context.Background(), contID, removeOpts)
		if removeErr != nil {
			b.log.Errorf("error removing container %s: %v", params.CheckID, err)
		}
	}()
	err = b.cli.ContainerStart(
		ctx, contID, cfg.ContainerStartOptions,
	)
	if err != nil {
		err := fmt.Errorf("error starting container for check %s: %w", params.CheckID, err)
		res <- backend.RunResult{Error: err}
		return
	}

	resultC, errC := b.cli.ContainerWait(context.Background(), cc.ID, "")
	var exit int64
	select {
	case err = <-errC:
	case result := <-resultC:
		if result.Error != nil {
			// TODO: Review how to manage this, ... generate an error?
			b.log.Errorf("check: %s wait error message %s", result.Error.Message)
		}
		exit = result.StatusCode
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		err := fmt.Errorf("error running container for check %s: %w", params.CheckID, err)
		res <- backend.RunResult{Error: err}
		return
	}

	if exit != 0 && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		err = fmt.Errorf("%w exit: %d", backend.ErrNonZeroExitCode, exit)
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		// ContainerStop will send a SIGTERM signal to the entrypoint. It will
		// wait for the amount of seconds configured and then send a SIGKILL
		// signal that will terminate the process. We use an empty context since
		// the stop operation is called when the ctx of the check is already
		// finish  a time out.
		b.log.Infof("check: %s timeout or aborted ensure container %s is stopped", params.CheckID, contID)
		timeout := abortTimeout
		b.cli.ContainerStop(context.Background(), contID, &timeout)
	}

	out, logErr := b.getContainerlogs(contID)
	if logErr != nil {
		b.log.Errorf("getting logs for the check %s, %+v", params.CheckID, err)
	}
	res <- backend.RunResult{Output: out, Error: err}
}

func (b Docker) getContainerlogs(ID string) ([]byte, error) {
	logOpts := types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	}
	r, err := b.cli.ContainerLogs(context.Background(), ID, logOpts)
	if err != nil {
		err = fmt.Errorf("error getting logs for container %s: %w", ID, err)
		return nil, err
	}
	defer r.Close()
	out, err := readContainerLogs(r)
	if err != nil {
		err := fmt.Errorf("error reading logs for check %s: %w", ID, err)
		return nil, err
	}
	return out, nil
}

func (b Docker) pull(ctx context.Context, image string) error {
	err := b.retryer.WithRetries("PullDockerImage", func() error {
		buf, err := json.Marshal(b.auth)
		if err != nil {
			return err
		}
		encodedAuth := base64.URLEncoding.EncodeToString(buf)
		pullOpts := types.ImagePullOptions{
			RegistryAuth: encodedAuth,
		}
		respBody, err := b.cli.ImagePull(ctx, image, pullOpts)
		if err != nil {
			return err
		}
		defer respBody.Close()
		if _, err := io.Copy(ioutil.Discard, respBody); err != nil {
			return err
		}
		return nil
	})
	return err
}

// getRunConfig will generate a docker.RunConfig for a given job.
// It will inject the check options and target as environment variables.
// It will return the generated docker.RunConfig.
func (b *Docker) getRunConfig(params backend.RunParams) RunConfig {
	b.log.Debugf("fetching check required variables %+v", params.RequiredVars)
	vars := dockerVars(params.RequiredVars, b.checkVars)
	return RunConfig{
		ContainerConfig: &container.Config{
			Hostname: params.CheckID,
			Image:    params.Image,
			Labels:   map[string]string{"CheckID": params.CheckID},
			Env: append([]string{
				fmt.Sprintf("%s=%s", backend.CheckIDVar, params.CheckID),
				fmt.Sprintf("%s=%s", backend.ChecktypeNameVar, params.CheckTypeName),
				fmt.Sprintf("%s=%s", backend.ChecktypeVersionVar, params.ChecktypeVersion),
				fmt.Sprintf("%s=%s", backend.CheckTargetVar, params.Target),
				fmt.Sprintf("%s=%s", backend.CheckAssetTypeVar, params.AssetType),
				fmt.Sprintf("%s=%s", backend.CheckOptionsVar, params.Options),
				fmt.Sprintf("%s=%s", backend.AgentAddressVar, b.agentAddr),
			},
				vars...,
			),
		},
		HostConfig:            &container.HostConfig{},
		NetConfig:             &network.NetworkingConfig{},
		ContainerStartOptions: types.ContainerStartOptions{},
	}
}

// dockerVars assigns the required environment variables in a format supported by Docker.
func dockerVars(requiredVars []string, envVars map[string]string) []string {
	var dockerVars []string
	for _, requiredVar := range requiredVars {
		dockerVars = append(dockerVars, fmt.Sprintf("%s=%s", requiredVar, envVars[requiredVar]))
	}
	return dockerVars
}

func readContainerLogs(r io.ReadCloser) ([]byte, error) {
	bout, berr := &bytes.Buffer{}, &bytes.Buffer{}
	_, err := stdcopy.StdCopy(bout, berr, r)
	if err != nil {
		return nil, err
	}
	outContent := bout.Bytes()
	errContent := berr.Bytes()
	contents := [][]byte{}
	contents = append(contents, outContent)
	contents = append(contents, errContent)
	out := bytes.Join(contents, []byte("\n"))
	return out, nil
}
