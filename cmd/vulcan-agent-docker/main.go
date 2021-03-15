/*
Copyright 2019 Adevinta
*/

package main

import (
	"errors"
	"net"
	"os"

	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/backend/docker"
	"github.com/adevinta/vulcan-agent/cmd"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/retryer"
)

const defaultDockerIfaceName = "docker0"

func main() {
	// NOTE: This is done in order to be able to return custom exit codes
	// while still executing deferred functions as expected.
	// Using os.Exit inside the main function is not an option:
	// https://golang.org/pkg/os/#Exit
	os.Exit(cmd.MainWithExitCode(buildDockerBackend))
}

func buildDockerBackend(l log.Logger, cfg config.Config, vars backend.CheckVars) (backend.Backend, error) {
	var (
		addr string
		err  error
	)
	if cfg.API.Host != "" {
		addr = cfg.API.Host + cfg.API.Port
	} else {
		addr, err = getAgentAddr(cfg.API.Port, cfg.API.IName)
	}
	if err != nil {
		return nil, err
	}
	interval := cfg.Runtime.Docker.Registry.BackoffInterval
	retries := cfg.Runtime.Docker.Registry.BackoffMaxRetries
	re := retryer.NewRetryer(retries, interval, l)

	return docker.New(l, cfg.Runtime.Docker.Registry, re, addr, vars)
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
