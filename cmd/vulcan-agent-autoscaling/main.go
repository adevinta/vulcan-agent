package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/BurntSushi/toml"
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
	AWSRegion string `toml:"region"`
}

func main() {
	// while still executing deferred functions as expected.
	// Using os.Exit inside the main function is not an option:
	// https://golang.org/pkg/os/#Exit
	os.Exit(mainWithExitCode())
}

func mainWithExitCode() int {
	log.Printf("running vulcan-agent-autoscaling to scale down an agent\n")
	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String("eu-west-1"),
	}))

	// We are using a mock of the AWS autoscaling API when not
	// running in AWS.
	metadataAPI := ec2metadata.New(sess)
	id := "FakeInstanceID_NotRunningInAws"
	var asgAPI autoscalingiface.AutoScalingAPI
	asgAPI = ASGMock{}
	if metadataAPI.Available() {
		// We are in EC2 instance.
		doc, err := metadataAPI.GetInstanceIdentityDocument()
		if err != nil {
			log.Printf("error retrieving instance metadata: %v\n", err)
			return 1
		}
		sess = session.Must(session.NewSession(&aws.Config{
			Region: aws.String(doc.Region),
		}))
		id = doc.InstanceID
		asgAPI = autoscaling.New(sess)
	}
	input := &autoscaling.TerminateInstanceInAutoScalingGroupInput{
		InstanceId:                     aws.String(id),
		ShouldDecrementDesiredCapacity: aws.Bool(true),
	}

	_, err := asgAPI.TerminateInstanceInAutoScalingGroup(input)
	if err != nil {
		log.Printf("error terminanting instance %s, err %+v", id, err)
		return 1
	}
	return 0
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
