/*
Copyright 2021 Adevinta
*/

package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
)

func TestIntegrationDockerRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	type args struct {
		ctx    context.Context
		params backend.RunParams
	}
	tests := []struct {
		name       string
		setup      func() *Docker
		tearDown   func(b *Docker)
		args       args
		want       backend.RunResult
		wantRunErr error
		wantErr    bool
	}{
		{
			name: "ExecutesADockerContainer",
			setup: func() *Docker {
				cli, err := client.NewClientWithOpts(client.FromEnv)
				if err != nil {
					panic(err)
				}
				b := &Docker{
					config: config.RegistryConfig{
						PullPolicy: PullPolicyNever,
					},
					agentAddr: "an addr",
					log:       &log.NullLog{},
					cli:       cli,
					checkVars: map[string]string{"VULCAN_CHECK_VAR": "value_var_1"},
				}
				err = buildDockerImage("testdata/DockerfileEnv", "vulcan-check")
				if err != nil {
					panic(err)
				}
				return b
			},
			tearDown: func(b *Docker) {
				removeContainer("CheckID")
			},
			args: args{
				context.Background(),
				backend.RunParams{
					CheckID:          "CheckID",
					Image:            "vulcan-check:latest",
					CheckTypeName:    "type-name",
					ChecktypeVersion: "1",
					Target:           "example.com",
					AssetType:        "hostname",
					Options:          "{'debug'=true}",
					RequiredVars:     []string{"VULCAN_CHECK_VAR"},
				},
			},
			want: backend.RunResult{
				Output: []byte("VULCAN_CHECK_OPTIONS={'debug'=true}\nVULCAN_CHECKTYPE_VERSION=1" +
					"\nVULCAN_CHECK_ASSET_TYPE=hostname\nVULCAN_CHECK_ID=CheckID\n" +
					"VULCAN_CHECKTYPE_NAME=type-name\nVULCAN_CHECK_TARGET=example.com\n" +
					"VULCAN_AGENT_ADDRESS=an addr\nVULCAN_CHECK_VAR=value_var_1\n\n"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.setup()
			defer func() {
				if tt.tearDown != nil {
					tt.tearDown(b)
				}
			}()
			gotChan, err := b.Run(tt.args.ctx, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Docker.Run() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got := <-gotChan
			gotErr := got.Error
			if gotErr != tt.wantRunErr {
				t.Errorf("gotErr != wantErr, gotErr: %v, wantErr %v", gotErr, tt.wantErr)
			}
			diff := cmp.Diff(string(got.Output), string(tt.want.Output))
			if diff != "" {
				t.Errorf("got!=want, diff %s", diff)
			}

		})
	}
}

func TestIntegrationDockerRunKillContainer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	b := &Docker{
		config: config.RegistryConfig{
			PullPolicy: PullPolicyNever,
		},
		agentAddr: "an addr",
		log:       &log.NullLog{},
		cli:       cli,
	}
	err = buildDockerImage("testdata/DockerfileSleep", "vulcan-check")
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := uuid.New()
	params := backend.RunParams{
		CheckID: id.String(),
		Image:   "vulcan-check:latest",
	}
	gotChan, err := b.Run(ctx, params)
	if err != nil {
		t.Error(err)
		return
	}
	go func() {
		time.Sleep(1 * time.Second)
		cancel()
	}()
	got := <-gotChan
	gotErr := got.Error
	if gotErr != context.Canceled {
		t.Errorf("%+v", gotErr)
		return
	}
	// Check the container is killed.
	filter := filters.NewArgs(filters.KeyValuePair{
		Key:   "label",
		Value: fmt.Sprintf("CheckID=%s", id.String()),
	})
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{Filters: filter})
	if err != nil {
		t.Errorf("error listing running containers: %+v", err)
		return
	}
	if len(containers) > 0 {
		t.Errorf("container with id %s was not killed", id.String())
	}
}

func TestIntegrationDockerDetectUnexpectedExit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	b := &Docker{
		config: config.RegistryConfig{
			PullPolicy: PullPolicyNever,
		},
		agentAddr: "an addr",
		log:       &log.NullLog{},
		cli:       cli,
	}
	err = buildDockerImage("testdata/DockerfileSleep", "vulcan-check")
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id := uuid.New()
	params := backend.RunParams{
		CheckID: id.String(),
		Image:   "vulcan-check:latest",
	}
	gotChan, err := b.Run(ctx, params)
	if err != nil {
		t.Error(err)
		return
	}
	// Find the container and kill it.
	contID, err := waitForContainer(b.cli, id.String())
	if err != nil {
		t.Error(err)
		return
	}
	err = cli.ContainerKill(context.Background(), contID, "")
	if err != nil {
		t.Errorf("error killing container: %+v", err)
		return
	}
	got := <-gotChan
	gotErr := got.Error
	if !errors.Is(gotErr, backend.ErrNonZeroExitCode) {
		t.Errorf("wantError!=gotErr, %+v!=%+v", backend.ErrNonZeroExitCode, gotErr)
		return
	}
}

func TestIntegrationDockerRunAbortGracefully(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}
	b := &Docker{
		config: config.RegistryConfig{
			PullPolicy: PullPolicyNever,
		},
		agentAddr: "an addr",
		log:       &log.NullLog{},
		cli:       cli,
	}
	err = buildDockerImage("testdata/DockerfileSleepEcho", "vulcan-check")
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	id := uuid.New()
	params := backend.RunParams{
		CheckID: id.String(),
		Image:   "vulcan-check:latest",
	}
	gotChan, err := b.Run(ctx, params)
	if err != nil {
		t.Error(err)
		return
	}
	got := <-gotChan
	gotErr := got.Error
	if gotErr != context.DeadlineExceeded {
		t.Errorf("got unexpected error %+v", gotErr)
		return
	}

	diff := cmp.Diff(string(got.Output), "ok\n\n")
	if diff != "" {
		t.Errorf("got output != want output, diff %+s", diff)
		return
	}

	// Check the container is killed.
	filter := filters.NewArgs(filters.KeyValuePair{
		Key:   "label",
		Value: fmt.Sprintf("CheckID=%s", id.String()),
	})
	containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{Filters: filter})
	if err != nil {
		t.Errorf("error listing running containers: %+v", err)
		return
	}
	if len(containers) > 0 {
		t.Errorf("container with id %s was not killed", id.String())
	}
}

func TestIntegrationDockerFindImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}
	b := &Docker{
		config: config.RegistryConfig{
			PullPolicy: PullPolicyNever,
		},
		agentAddr: "an addr",
		log:       &log.NullLog{},
		cli:       cli,
	}
	err = buildDockerImage("testdata/DockerfileSleepEcho", "vulcan-check")
	if err != nil {
		panic(err)
	}
	if err != nil {
		panic(err)
	}

	tests := []struct {
		image   string
		exists  []string
		missing []string
	}{
		{
			image:   "check",
			exists:  []string{"check", "check:latest", "docker.io/check", "docker.io/check:latest"},
			missing: []string{"check2", "registry.com/check", "registry.com/check:latest"},
		},
		{
			image:   "check:latest",
			exists:  []string{"check", "check:latest", "docker.io/check", "docker.io/check:latest"},
			missing: []string{"check2", "registry.com/check", "registry.com/check:latest"},
		},
		{
			image:   "check:tag",
			exists:  []string{"check:tag", "docker.io/check:tag"},
			missing: []string{"check", "check:latest", "check2:tag", "registry.com/check", "registry.com/check:latest"},
		},
		{
			image:   "vulcan/check:tag",
			exists:  []string{"vulcan/check:tag", "docker.io/vulcan/check:tag"},
			missing: []string{"vulcan/check", "vulcan/check:latest", "vulcan/check2:tag", "registry.com/vulcan/check", "registry.com/vulcan/check:latest"},
		},
		{
			image:   "registry.com/vulcan/check:tag",
			exists:  []string{"registry.com/vulcan/check:tag"},
			missing: []string{"docker.io/vulcan/check:tag", "vulcan/check:tag", "vulcan/check:latest", "vulcan/check2:tag", "registry.com/vulcan/check", "registry.com/vulcan/check:latest"},
		},
	}
	for _, c := range tests {
		tagDockerImage("vulcan-check", c.image)
		for _, v := range c.exists {
			if exists, _ := b.imageExists(context.Background(), v); !exists {
				t.Errorf("image:%s check:%s should exists", c.image, v)
			}
		}
		for _, v := range c.missing {
			if exists, _ := b.imageExists(context.Background(), v); exists {
				t.Errorf("image:%s check:%s should not exists", c.image, v)
			}
		}
		removeDockerImage(c.image)
	}
}

func buildDockerImage(dockerFile string, tag string) (err error) {
	path, err := filepath.Abs(dockerFile)
	if err != nil {
		return nil
	}
	dir := filepath.Dir(path)
	args := []string{"build", "-t", tag, "-f", path, dir}
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func tagDockerImage(image string, tag string) (err error) {
	args := []string{"tag", image, tag}
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return err
	}
	return nil
}

func removeDockerImage(image string) (err error) {
	args := []string{"rmi", image}
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return err
	}
	return nil
}

func removeContainer(name string) (err error) {
	args := []string{"rm", name}
	cmd := exec.Command("docker", args...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitForContainer(cli *client.Client, id string) (string, error) {
	filter := filters.NewArgs(filters.KeyValuePair{
		Key:   "label",
		Value: fmt.Sprintf("CheckID=%s", id),
	})
	exit := false
	for !exit {
		containers, err := cli.ContainerList(context.Background(), types.ContainerListOptions{Filters: filter})
		if err != nil {
			err = fmt.Errorf("error listing running containers: %+v", err)
			return "", err
		}
		if len(containers) < 1 {
			continue
		}
		return containers[0].ID, nil
	}
	return "", errors.New("unexpected error waiting for container to be up")
}
