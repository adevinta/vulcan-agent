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
	"net"
	"sync"
	"time"

	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/retryer"
	dockercliconfig "github.com/docker/cli/cli/config"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	abortTimeout           = 5 // Seconds.
	defaultDockerIfaceName = "docker0"
)

// RunConfig contains the configuration for executing a check in a container.
type RunConfig struct {
	ContainerConfig       *container.Config
	HostConfig            *container.HostConfig
	NetConfig             *network.NetworkingConfig
	ContainerStartOptions types.ContainerStartOptions
}

// ConfigUpdater allows to update the docker configuration just before the container creation.
//
//	 updater := func(params backend.RunParams, rc *RunConfig) error {
//		 // If the asset type is Hostname pass an extra env variable to the container.
//		 if params.AssetType == "Hostname" {
//		 	rc.ContainerConfig.Env = append(rc.ContainerConfig.Env, "FOO=BAR")
//		 }
//		 return nil
//	 }
type ConfigUpdater func(backend.RunParams, *RunConfig) error

// Retryer represents the functions used by the docker backend for retrying
// docker registry operations.
type Retryer interface {
	WithRetries(op string, exec func() error) error
}

type registryAuths struct {
	auths map[string]*types.AuthConfig
	mu    sync.RWMutex
}

func (b *registryAuths) fetchAuth(domain string) (*types.AuthConfig, bool) {
	domain = getAuthDomain(domain)

	b.mu.RLock()
	defer b.mu.RUnlock()
	auth, ok := b.auths[domain]
	return auth, ok
}

func (b *registryAuths) storeAuth(domain string, auth *types.AuthConfig) {
	domain = getAuthDomain(domain)

	b.mu.Lock()
	defer b.mu.Unlock()
	b.auths[domain] = auth
}

func getAuthDomain(domain string) string {
	if domain == "docker.io" {
		return "index.docker.io"
	}
	return domain
}

// Docker implements a docker backend for running jobs if the local docker.
type Docker struct {
	config    config.RegistryConfig
	agentAddr string
	checkVars backend.CheckVars
	log       log.Logger
	cli       *client.Client
	retryer   Retryer
	updater   ConfigUpdater
	auths     registryAuths
}

// getAgentAddr returns the address where Vulcan checks can find the
// agent's API in the Docker network.
func getAgentAddr(cfg config.APIConfig) (string, error) {
	var agentPort string
	if cfg.Listener != nil {
		addr := cfg.Listener.Addr().String()
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return "", fmt.Errorf("split host port %q: %w", addr, err)
		}
		agentPort = ":" + port
	} else {
		agentPort = cfg.Port
	}

	var err error
	var agentAddr string
	if cfg.Host != "" {
		agentAddr = cfg.Host + agentPort
	} else {
		agentAddr, err = getIfaceAddr(agentPort, cfg.IName)
		if err != nil {
			return "", err
		}
	}

	return agentAddr, nil
}

func getIfaceAddr(port, ifaceName string) (string, error) {
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

// NewBackend creates a new Docker backend using the given config, agent api address and CheckVars.
// A ConfigUpdater function can be passed to inspect/update the final docker RunConfig
// before creating the container for each check.
func NewBackend(log log.Logger, cfg config.Config, updater ConfigUpdater) (backend.Backend, error) {
	agentAddr, err := getAgentAddr(cfg.API)
	if err != nil {
		return &Docker{}, fmt.Errorf("get agent addr: %w", err)
	}

	cfgReg := cfg.Runtime.Docker.Registry
	interval := cfgReg.BackoffInterval
	retries := cfgReg.BackoffMaxRetries
	re := retryer.NewRetryer(retries, interval, log)

	envCli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
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
		updater:   updater,
		auths: registryAuths{
			auths: make(map[string]*types.AuthConfig),
		},
	}

	if b.config.Auths == nil {
		b.config.Auths = []config.Auth{}
	}
	// Add the legacy single registry auth to the slice.
	if b.config.Server != "" {
		b.config.Auths = append(b.config.Auths, config.Auth{
			Server: b.config.Server,
			User:   b.config.User,
			Pass:   b.config.Pass,
		})
	}

	// Eager validation of the configured registries.
	for _, a := range b.config.Auths {
		auth := &types.AuthConfig{
			Username:      a.User,
			Password:      a.Pass,
			ServerAddress: a.Server,
		}

		// This prevents the agent to start with wrong supplied credentials.
		if err = b.addRegistryAuth(auth.ServerAddress, auth); err != nil {
			log.Errorf("unable to login in %s: %+v", a.Server, err)
			return nil, err
		}
	}
	return b, nil
}

// addRegistryAuth adds the auth to the map only if valid.
func (b *Docker) addRegistryAuth(domain string, auth *types.AuthConfig) error {
	if domain == "" {
		b.log.Debugf("skipping to validate empty auth")
		return nil
	}

	if _, ok := b.auths.fetchAuth(domain); ok {
		b.log.Infof("an auth for %s already exists", domain)
		return nil
	}

	if _, err := b.cli.RegistryLogin(context.Background(), *auth); err != nil {
		b.log.Errorf("wrong credentials provided for %s %s error=%+v",
			domain, auth.ServerAddress, err,
		)
		return err
	}

	b.log.Infof("Auth validated for %s %s with %s", domain, auth.ServerAddress, auth.Username)
	b.auths.storeAuth(domain, auth)

	return nil
}

// getRegistryAuth tries to find an authentication for the domain
// First it looks into the provided authenticated servers
// If not avialiable it looks into the docker system stored credentials.
func (b *Docker) getRegistryAuth(domain string) *types.AuthConfig {
	auth, ok := b.auths.fetchAuth(domain)
	if ok {
		return auth
	}

	auth = b.getStoredCredentials(domain)
	if auth == nil {
		// Store nil to prevent trying again for this domain.
		b.auths.storeAuth(domain, nil)
		return nil
	}

	// Validate the credentials
	if err := b.addRegistryAuth(domain, auth); err != nil {
		// Store nil to prevent trying again for this domain.
		b.auths.storeAuth(domain, nil)
		return nil
	}

	return auth
}

func (b *Docker) getStoredCredentials(domain string) *types.AuthConfig {
	domain = getAuthDomain(domain)

	buf := new(bytes.Buffer)
	dockerConfig := dockercliconfig.LoadDefaultConfigFile(buf)
	if dockerConfig == nil {
		b.log.Errorf("unable to loadDefaultConfigFile %s")
		return nil
	}

	if buf.String() != "" {
		b.log.Errorf("unable to load docker default config %s", buf.String())
		return nil
	}
	a, err := dockerConfig.GetAuthConfig(domain)
	if err != nil {
		b.log.Infof("error getting credentials for %s - %+v", err)
		return nil
	}

	if a.ServerAddress == "" {
		b.log.Infof("empty credentials for %s", domain)
		return nil
	}

	// Copy all the data (same struct in different packages).
	return &types.AuthConfig{
		Username:      a.Username,
		Password:      a.Password,
		Auth:          a.Auth,
		IdentityToken: a.IdentityToken,
		ServerAddress: a.ServerAddress,
	}
}

// Run starts executing a check as a local container and returns a channel that
// will contain the result of the execution when it finishes.
func (b *Docker) Run(ctx context.Context, params backend.RunParams) (<-chan backend.RunResult, error) {
	err := b.pull(ctx, params.Image)
	if err != nil {
		return nil, err
	}
	res := make(chan backend.RunResult)
	go b.run(ctx, params, res)
	return res, nil
}

func (b *Docker) run(ctx context.Context, params backend.RunParams, res chan<- backend.RunResult) {
	cfg := b.getRunConfig(params)

	if b.updater != nil {
		err := b.updater(params, &cfg)
		if err != nil {
			res <- backend.RunResult{Error: err}
			return
		}
	}
	cc, err := b.cli.ContainerCreate(ctx, cfg.ContainerConfig, cfg.HostConfig, cfg.NetConfig, nil, "")
	contID := cc.ID
	if err != nil {
		b.log.Errorf("Container create error: %+v", err)
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

	resultC, errC := b.cli.ContainerWait(ctx, contID, "")
	var exit int64
	select {
	case err = <-errC:
		b.log.Errorf("containerWait err: err.Error(): %s ctx.Err(): %+v", err.Error(), ctx.Err())
		if err.Error() == "" && ctx.Err() != nil {
			err = ctx.Err()
		}
	case result := <-resultC:
		if result.Error == nil {
			exit = result.StatusCode
		} else {
			err = fmt.Errorf("wait error %s", result.Error.Message)
		}
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
		stopErr := b.cli.ContainerStop(context.Background(), contID, container.StopOptions{
			Timeout: &timeout,
		})
		if stopErr != nil {
			b.log.Errorf("Unable to stop container %s, %+v", contID, stopErr)
		}
	}

	out, logErr := b.getContainerlogs(contID)
	if logErr != nil {
		b.log.Errorf("getting logs for the check %s, %+v", params.CheckID, logErr)
	}
	res <- backend.RunResult{Output: out, Error: err}
}

func (b *Docker) getContainerlogs(ID string) ([]byte, error) {
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

func (b *Docker) imageExists(ctx context.Context, image string) (bool, error) {
	domain, path, tag, err := backend.ParseImage(image)
	if err != nil {
		return false, err
	}

	// Build a pattern with the tag to prevent returning all the tags from the image.
	pattern := domain + "/" + path + ":" + tag
	// We remove docker.io because ImageList doesn't find images with prefix docker.io.
	if domain == "docker.io" {
		pattern = path + ":" + tag
	}

	images, err := b.cli.ImageList(ctx, types.ImageListOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "reference",
			Value: pattern,
		}),
	})
	if err != nil {
		return false, err
	}
	if len(images) == 0 {
		return false, nil
	}
	return true, nil
}

func (b *Docker) pull(ctx context.Context, image string) error {
	if b.config.PullPolicy == config.PullPolicyNever {
		return nil
	}
	if b.config.PullPolicy == config.PullPolicyIfNotPresent {
		exists, err := b.imageExists(ctx, image)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
	}
	pullOpts := types.ImagePullOptions{}

	// Image was validated before and ParseImage always return a domain.
	domain, _, _, err := backend.ParseImage(image)
	if err != nil {
		return err
	}

	if auth := b.getRegistryAuth(domain); auth != nil {
		buf, err := json.Marshal(auth)
		if err != nil {
			return err
		}
		pullOpts.RegistryAuth = base64.URLEncoding.EncodeToString(buf)
	}
	b.log.Debugf("pulling image=%s domain=%s auth=%v", image, domain, pullOpts.RegistryAuth != "")
	start := time.Now()
	err = b.retryer.WithRetries("PullDockerImage", func() error {
		respBody, err := b.cli.ImagePull(ctx, image, pullOpts)
		if err != nil {
			return err
		}
		defer respBody.Close()
		if _, err := io.Copy(io.Discard, respBody); err != nil {
			return err
		}
		return nil
	})
	b.log.Infof(
		"pulled image=%s domain=%s auth=%v duration=%f err=%v",
		image,
		domain,
		pullOpts.RegistryAuth != "",
		time.Since(start).Seconds(),
		err,
	)
	return err
}

// getRunConfig will generate a docker.RunConfig for a given job.
// It will inject the check options and target as environment variables.
// It will return the generated docker.RunConfig.
func (b *Docker) getRunConfig(params backend.RunParams) RunConfig {
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
