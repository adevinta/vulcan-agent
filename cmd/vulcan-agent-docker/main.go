/*
Copyright 2019 Adevinta
*/

package main

import (
	"fmt"
	"os"

	"github.com/adevinta/vulcan-agent/agent"
	"github.com/adevinta/vulcan-agent/backend/docker"
	"github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/storage"
	"github.com/adevinta/vulcan-agent/storage/s3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, "Usage: vulcan-agent config_file")
		os.Exit(1)
	}
	cfg, err := config.ReadConfig(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading configuration file: %v", err)
		os.Exit(1)
	}
	l, err := log.New(cfg.Agent)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading creating log: %v", err)
		os.Exit(1)
	}

	// Build the docker backend.
	b, err := docker.NewBackend(l, cfg, nil)
	if err != nil {
		l.Errorf("error creating the backend to run the checks %v", err)
		os.Exit(1)
	}

	// Build the storage.
	var s storage.Store
	s, err = s3.NewWriter(cfg.S3Writer, l)
	// NOTE: This is done in order to be able to return custom exit codes
	// while still executing deferred functions as expected.
	// Using os.Exit inside the main function is not an option:
	// https://golang.org/pkg/os/#Exit
	os.Exit(agent.Run(cfg, s, b, l))
}
