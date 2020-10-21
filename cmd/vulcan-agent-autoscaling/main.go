package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/DataDog/datadog-go/statsd"
	"github.com/adevinta/vulcan-agent/api"
	"github.com/adevinta/vulcan-agent/persistence"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/autoscaling/autoscalingiface"
)

const (
	ddTag = "vulcan:autoscaling"
)

type Config struct {
	API         apiConfig         `toml:"api"`
	Persistence persistenceConfig `toml:"persistence"`
	AutoScaling asgConfig         `toml:"asg"`
	Statsd      DatadogConfig     `toml:"datadog"`
}

type apiConfig struct {
	Port         string `toml:"port"`
	ExternalHost string `toml:"external_host"`
}

type persistenceConfig struct {
	Endpoint string `toml:"endpoint"`
	Timeout  int    `toml:"timeout"`
}

type asgConfig struct {
	Interval  int    `toml:"interval"`
	AWSRegion string `toml:"region"`
	StateFile string `toml:"state_file"`
}

type DatadogConfig struct {
	Statsd string `toml:"dogstatsd"`
}

func main() {
	// while still executing deferred functions as expected.
	// Using os.Exit inside the main function is not an option:
	// https://golang.org/pkg/os/#Exit
	os.Exit(mainWithExitCode())
}

func mainWithExitCode() int {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %v <config_file>\n", os.Args[0])
		return 1
	}

	config, err := readConfig(os.Args[1])
	if err != nil {
		log.Printf("configuration file can not be read: %v\n", err)
		return 1
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(config.AutoScaling.AWSRegion),
	}))

	// We are using a mock of the AWS autoscaling API when not
	// running in AWS.
	metadataAPI := ec2metadata.New(sess)
	id := "FakeInstanceID_NotRunningInAws"
	var asgAPI autoscalingiface.AutoScalingAPI
	if metadataAPI.Available() {
		// We are in EC2 instance.
		doc, err := metadataAPI.GetInstanceIdentityDocument()
		if err != nil {
			log.Printf("error retrieving instance metadata: %v\n", err)
			return 1
		}

		id = doc.InstanceID
		asgAPI = autoscaling.New(sess)
	} else {
		asgAPI = ASGMock{}
	}

	a := newAgent(config, asgAPI, id)

	cancelDefer := false
	var b bytes.Buffer
	p := &b
	defer func() {
		if !cancelDefer {
			fmt.Println(b.String())
		}
	}()

	if err := a.updateStats(); err != nil {
		log.Printf("error updating stats: %v", err)

		// If the API of the agent is not accessible, kill the agent.
		fmt.Fprint(p, " TERMINATING")

		fmt.Println(b.String())
		cancelDefer = true

		a.verifyState()

		if err := a.terminateAgent(); err != nil {
			log.Printf("agent can not be terminated: %v", err)
			return 1
		}

		return 0
	}

	fmt.Fprintf(p, "%v - ID: %v AgentID: %v LastMessageReceived: %v",
		time.Now(), id, a.stats.AgentID, a.stats.LastMessageReceived)

	// Terminate agent if there are no messages in the queue for some time.
	// Before terminating it, we need to ensure that the agent is paused and
	// that there are not running jobs. Else, wait until the next execution.
	if a.exceededLastMessageReceived() {
		fmt.Fprintf(p, " EXCEEDS")

		s, err := a.agentStatus()
		if err != nil {
			log.Printf("error updating status: %v", err)
			return 1
		}

		fmt.Fprintf(p, " Status: %v", s)

		n, err := a.agentNumRunningJobs()
		if err != nil {
			log.Printf("error getting jobs: %v", err)
			return 1
		}

		fmt.Fprintf(p, " Jobs: %v", n)

		if n > 0 {
			fmt.Fprint(p, " SKIPPING")
			return 0
		}

		switch s {
		case "RUNNING":
			fmt.Fprint(p, " PAUSING")

			if err := a.pauseAgent(); err != nil {
				log.Printf("agent can not be paused: %v", err)
				return 1
			}
		case "PAUSED":
			fmt.Fprint(p, " DISCONNECTING")

			if err := a.disconnectAgent(); err != nil {
				log.Printf("agent can not be terminated: %v", err)
				return 1
			}
		}
	}

	return 0
}

type agent struct {
	config     Config
	stats      api.StatsResponse
	asgAPI     autoscalingiface.AutoScalingAPI
	instanceID string
}

func newAgent(config Config, asgAPI autoscalingiface.AutoScalingAPI, instanceID string) *agent {
	if config.API.ExternalHost == "" {
		// Most of the times this program will run in the same machine than
		// the vulcan-agent.
		config.API.ExternalHost = "localhost"
	}

	return &agent{
		config:     config,
		asgAPI:     asgAPI,
		instanceID: instanceID,
	}
}

func (a *agent) updateStats() error {
	res, err := http.Get(fmt.Sprintf("http://%v%v/stats", a.config.API.ExternalHost, a.config.API.Port))
	if err != nil {
		return err
	}
	defer res.Body.Close()

	s, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var stats api.StatsResponse
	if err := json.Unmarshal(s, &stats); err != nil {
		return err
	}

	a.stats = stats

	// Store AgentID in file for monitoring purposes.
	return ioutil.WriteFile(a.config.AutoScaling.StateFile, []byte(stats.AgentID), 0644)
}

func (a *agent) exceededLastMessageReceived() bool {
	return !a.stats.LastMessageReceived.IsZero() && time.Now().Sub(a.stats.LastMessageReceived) > time.Duration(a.config.AutoScaling.Interval)*time.Second
}

// pauseAgent just tells the vulcan-persistence to pause the agent.
// Then the vulcan-persistence pauses the agent via the vulcan-stream.
func (a *agent) pauseAgent() error {
	resp, err := http.Post(fmt.Sprintf("%v/agents/%v/pause", a.config.Persistence.Endpoint, a.stats.AgentID), "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code when pausing the agent: %v", resp.StatusCode)
	}

	return nil
}

// disconnectAgent just tells the vulcan-persistence to disconnect the agent.
// Then the vulcan-persistence disconnects the agent via the vulcan-stream.
func (a *agent) disconnectAgent() error {
	resp, err := http.Post(fmt.Sprintf("%v/agents/%v/disconnect", a.config.Persistence.Endpoint, a.stats.AgentID), "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code when pausing the agent: %v", resp.StatusCode)
	}

	return nil
}

func (a *agent) agentStatus() (string, error) {
	res, err := http.Get(fmt.Sprintf("http://%v%v/status", a.config.API.ExternalHost, a.config.API.Port))
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	s, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	// The status returned by the agent includes surrounding quotes, and a trailing '\n'.
	return string(s[1 : len(s)-2]), nil
}

type jobsResponse struct {
	Jobs  []interface{} `json:"jobs"`
	Error string        `json:"error,omitempty"`
}

func (a *agent) agentNumRunningJobs() (int, error) {
	res, err := http.Get(fmt.Sprintf("http://%v%v/jobs?terminal=false", a.config.API.ExternalHost, a.config.API.Port))
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	s, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return 0, err
	}

	var jobs jobsResponse
	if err := json.Unmarshal(s, &jobs); err != nil {
		return 0, err
	}

	return len(jobs.Jobs), nil
}

func (a *agent) terminateAgent() error {
	input := &autoscaling.TerminateInstanceInAutoScalingGroupInput{
		InstanceId:                     aws.String(a.instanceID),
		ShouldDecrementDesiredCapacity: aws.Bool(true),
	}

	_, err := a.asgAPI.TerminateInstanceInAutoScalingGroup(input)

	return err
}

func (a *agent) verifyState() {
	agentID, err := ioutil.ReadFile(a.config.AutoScaling.StateFile)
	if err != nil {
		log.Printf("error reading state: %v", err)
		return
	}

	resp, err := http.Get(fmt.Sprintf("%s/agents/%s", a.config.Persistence.Endpoint, agentID))
	if err != nil {
		log.Printf("error contacting persistence: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("error obtaining agent status from persistence: %v", resp.StatusCode)
		return
	}

	s, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error reading response from persistence: %v", err)
		return
	}

	var ad persistence.AgentData
	if err := json.Unmarshal(s, &ad); err != nil {
		log.Printf("error unmarshalling agent from response: %v", err)
		return
	}

	if ad.Agent.Status == "DOWN" {
		return
	}

	log.Printf("sending alert for agent %s, terminated in %s status", ad.Agent.ID, ad.Agent.Status)
	ddClient, err := statsd.New(a.config.Statsd.Statsd)
	if err != nil {
		log.Printf("error creating statsd client: %v", err)
		return
	}
	defer ddClient.Close() //nolint

	ddClient.Tags = append(ddClient.Tags, ddTag)
	eventText := fmt.Sprintf("AgentID: %s\nInstanceID: %s\nStatus: %s\n", ad.Agent.ID, a.instanceID, ad.Agent.Status)
	e := statsd.NewEvent("Agent terminated in wrong status", eventText)

	if err := ddClient.Event(e); err != nil {
		log.Printf("error creating statsd event: %v", err)
		return
	}
	if err := ddClient.Flush(); err != nil {
		log.Printf("error flushing statsd: %v", err)
		return
	}
	// let the flush finish and DogStatsD send the metric
	time.Sleep(10 * time.Second)
}

func readConfig(configFile string) (Config, error) {
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
