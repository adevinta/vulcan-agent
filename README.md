[![Build Status](https://travis-ci.org/adevinta/vulcan-agent.svg?branch=master)](https://travis-ci.org/adevinta/vulcan-agent)

# Vulcan Agent

Vulcan Agent is the Vulcan component that runs checks. Check jobs are received
from SQS and executed using al-least-once semantics. The Agent executes the
checks defined in the messages using the local docker service. It will extended
the visibility timeout of the messages as long as the corresponded checks for
those messages are executed.
The configuration parameter "max_no_msgs_interval" controls the number of seconds
that can pass without reading message for the Agent to continue running. A value
of 0 means the agent will wait forever.

Apart from the queue, the Agent interacts with the [vulcan-results
service](https://github.com/adevinta/vulcan-results) in order to store the
reports and the logs of the executed checks and with the [vulcan-stream
service](https://github.com/adevinta/vulcan-stream) in order to abort the
current running checks and to query the checks the must be cancelled before they
start running.


### Integrations

Agent Runtimes

- [x] Docker
- [] Kubernetes

Queues

- [x] AWS SQS
