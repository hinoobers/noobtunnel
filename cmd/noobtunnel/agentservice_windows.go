//go:build windows

package main

import (
	"context"

	"github.com/noobtunnel/noobtunnel/internal/agent"
	"golang.org/x/sys/windows/svc"
)

type agentService struct{ instance *agent.Agent }

func (s agentService) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.instance.Run(ctx) }()
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case <-result:
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-result
				return false, 0
			}
		}
	}
}

func runAgentAsWindowsService(instance *agent.Agent) (bool, error) {
	yes, err := svc.IsWindowsService()
	if err != nil || !yes {
		return false, err
	}
	return true, svc.Run("noobtunnel-agent", agentService{instance: instance})
}
