package metrics

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/config"
	metrics "github.com/adevinta/vulcan-metrics-client"
)

var (
	// PoolTimeInterval defines the period of time used by the Pusher to
	// publish the number of the checks de agent is running.
	PoolTimeInterval = time.Duration(5) * time.Second

	// PoolPeriod defines the time interval for pooling the agent for the
	// current number of checks running.
	PoolPeriod = 5

	componentTag = "component:agent"
)

// Agent defines the functions an agent must expose for the Metrics to be able
// to gather metrics.
type Agent interface {
	AbortCheck(ID string)
	ChecksRunning() int
}

// Metrics sends the defined metrics for an agent to Data Dog.
type Metrics struct {
	Enabled bool
	Client  metrics.Client
	Aborter Agent
	AgentID string
}

// NewMetrics return a new struct which sends the defined metrics for the agent
// to DD.
func NewMetrics(cfg config.DatadogConfig, aborter Agent) *Metrics {
	if !cfg.Enabled {
		return &Metrics{Enabled: false}
	}
	// Parse DataDog config.
	os.Setenv("DOGSTATSD_ENABLED", "true")
	agentID := os.Getenv("instanceID")
	if agentID == "" {
		agentID = "unknown"
	}
	statsdAddr := strings.Split(cfg.Statsd, ":")
	if len(statsdAddr) == 2 {
		os.Setenv("DOGSTATSD_HOST", statsdAddr[0])
		os.Setenv("DOGSTATSD_PORT", statsdAddr[1])
	}
	metricsClient, _ := metrics.NewClient()
	pusher := &Metrics{
		Enabled: true,
		Client:  metricsClient,
		Aborter: aborter,
		AgentID: agentID,
	}
	return pusher
}

// StartPooling pools every PoolIntervalSeconds the current number the agent is
// running and sends the metric to the Data Dog.
func (p *Metrics) StartPooling(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go p.pool(ctx, done)
	return done
}

func (p *Metrics) pool(ctx context.Context, done chan<- struct{}) {
	defer func() {
		done <- struct{}{}
		close(done)
	}()
	if !p.Enabled {
		return
	}
	ticker := time.NewTicker(PoolTimeInterval * time.Second)
	defer ticker.Stop()
LOOP:
	for {
		select {
		case <-ticker.C:
			n := p.Aborter.ChecksRunning()
			metric := metrics.Metric{
				Name:  "vulcan.scan.check.running",
				Typ:   metrics.Gauge,
				Value: float64(n),
				Tags:  []string{componentTag, p.AgentID},
			}
			p.Client.Push(metric)
		case <-ctx.Done():
			break LOOP
		}
	}
}

// AbortCheck just wraps the AbortCheck function of the "actual" check aborter
// in order to push metrics every time a new message has been received.
func (p *Metrics) AbortCheck(ID string) {
	p.Aborter.AbortCheck(ID)
	if !p.Enabled {
		return
	}
	metrics := metrics.Metric{
		Name:  "vulcan.stream.mssgs.received",
		Typ:   metrics.Count,
		Value: 1,
		Tags: []string{
			"component:agent",
			fmt.Sprint("action:", "abort"),
			fmt.Sprint("agentid:", p.AgentID),
		},
	}
	p.Client.Push(metrics)
}
