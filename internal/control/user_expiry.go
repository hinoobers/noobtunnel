package control

import (
	"context"
	"time"

	"github.com/noobtunnel/noobtunnel/internal/store"
)

func (s *Server) cleanupExpiredUnverified(ctx context.Context) {
	users, err := s.auth.ExpireUnverified(s.now())
	if err != nil {
		s.log.Error("could not expire unverified accounts", "error", err)
		return
	}
	if len(users) == 0 {
		return
	}
	for _, user := range users {
		s.purgeUserMesh(ctx, user)
		s.recordEvent("security", "unverified account expired: "+user.Username)
	}
	if s.tenantFirewallReady.Load() {
		if err := s.syncTenantFirewall(ctx); err != nil {
			s.log.Error("could not update private mesh firewall after account expiry", "error", err)
		}
	}
	s.reconcileResources()
	s.broadcastState()
}

func (s *Server) purgeUserMesh(ctx context.Context, user store.User) {
	if user.MeshSlot == 0 {
		return
	}
	for _, resource := range s.store.Resources() {
		if resource.OwnerID == user.ID {
			if err := s.store.RemoveResource(resource.ID); err != nil {
				s.log.Error("could not remove expired account resource", "resource", resource.ID, "error", err)
			}
		}
	}
	for _, domain := range s.store.Domains() {
		if domain.OwnerID == user.ID {
			if err := s.store.RemoveDomain(domain.Hostname); err != nil {
				s.log.Error("could not remove expired account domain", "domain", domain.Hostname, "error", err)
			}
		}
	}
	for _, agent := range s.store.View().Agents {
		if agent.OwnerID == user.ID && agent.MeshSlot == user.MeshSlot {
			if err := s.store.RemoveAgent(agent.ID); err != nil {
				s.log.Error("could not remove expired account agent", "agent", agent.ID, "error", err)
				continue
			}
			s.Revoke(ctx, agent.ID, "unverified account expired")
		}
	}
}

func (s *Server) unverifiedAccountLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredUnverified(ctx)
		}
	}
}
