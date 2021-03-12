/*
Copyright 2021 Adevinta
*/

package main

import (
	"log"

	"github.com/aws/aws-sdk-go/service/autoscaling"
	"github.com/aws/aws-sdk-go/service/autoscaling/autoscalingiface"
)

type ASGMock struct {
	autoscalingiface.AutoScalingAPI
}

func (m ASGMock) TerminateInstanceInAutoScalingGroup(input *autoscaling.TerminateInstanceInAutoScalingGroupInput) (*autoscaling.TerminateInstanceInAutoScalingGroupOutput, error) {
	log.Println("instance terminated")
	return &autoscaling.TerminateInstanceInAutoScalingGroupOutput{}, nil
}
