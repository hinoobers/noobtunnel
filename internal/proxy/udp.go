package proxy

import (
	"net"
	"sync"
	"time"
)

// udpIdleTimeout is how long a client mapping is kept alive without traffic.
const udpIdleTimeout = 60 * time.Second

// serveUDP forwards datagrams, keeping one upstream socket per client so replies
// find their way back to the right place.
func (g *group) serveUDP(pc net.PacketConn, dialTimeout time.Duration) {
	sessions := map[string]*udpSession{}
	var mu sync.Mutex
	done := make(chan struct{})
	defer func() {
		close(done)
		mu.Lock()
		defer mu.Unlock()
		for _, session := range sessions {
			session.close()
		}
	}()

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			now := time.Now()
			mu.Lock()
			for key, session := range sessions {
				if now.Sub(session.lastSeen()) > udpIdleTimeout {
					session.close()
					delete(sessions, key)
				}
			}
			mu.Unlock()
		}
	}()

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if g.isClosed() {
				return
			}
			g.log.Debug("udp read failed", "port", g.port, "error", err)
			return
		}
		target, ok := g.currentSingle()
		if !ok {
			continue
		}
		key := clientAddr.String()
		mu.Lock()
		session, exists := sessions[key]
		if exists && session.isClosed() {
			delete(sessions, key)
			exists = false
		}
		if !exists {
			// Datagrams have no handshake to fail over on, so each session picks
			// one backend: round-robin spreads sessions over the targets.
			candidates := target.candidates()
			if len(candidates) == 0 {
				mu.Unlock()
				continue
			}
			chosen := candidates[0]
			upstream, err := net.DialTimeout("udp", chosen.Address(), dialTimeout)
			if err != nil {
				mu.Unlock()
				target.stat.targetFor(chosen.ID).setError(err)
				target.stat.setError(err)
				continue
			}
			session = &udpSession{
				client:   clientAddr,
				upstream: upstream,
				packet:   pc,
				stat:     target.stat,
				target:   target.stat.targetFor(chosen.ID),
			}
			sessions[key] = session
			target.stat.set.active.Add(1)
			target.stat.set.total.Add(1)
			session.target.set.active.Add(1)
			session.target.set.total.Add(1)
			go session.readLoop()
		}
		mu.Unlock()

		session.touch()
		// Write consumes the datagram synchronously; reuse the receive buffer.
		if _, err := session.upstream.Write(buf[:n]); err != nil {
			target.stat.setError(err)
			session.target.setError(err)
			mu.Lock()
			session.close()
			delete(sessions, key)
			mu.Unlock()
			continue
		}
		target.stat.setError(nil)
		target.stat.set.tx.Add(uint64(n))
		session.target.set.tx.Add(uint64(n))
	}
}

// udpSession is one client's mapping through the tunnel.
type udpSession struct {
	client   net.Addr
	upstream net.Conn
	packet   net.PacketConn
	stat     *resourceStats
	target   *targetStats

	mu        sync.Mutex
	last      time.Time
	closed    bool
	closeOnce sync.Once
}

func (s *udpSession) touch() {
	s.mu.Lock()
	s.last = time.Now()
	s.mu.Unlock()
}

func (s *udpSession) lastSeen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		_ = s.upstream.Close()
		s.stat.set.active.Add(-1)
		if s.target != nil {
			s.target.set.active.Add(-1)
		}
	})
}

func (s *udpSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// readLoop sends replies from the service back to the client that asked.
func (s *udpSession) readLoop() {
	defer s.close()
	buf := make([]byte, 64*1024)
	for {
		n, err := s.upstream.Read(buf)
		if err != nil {
			return
		}
		if _, err := s.packet.WriteTo(buf[:n], s.client); err != nil {
			return
		}
		s.stat.set.rx.Add(uint64(n))
		if s.target != nil {
			s.target.set.rx.Add(uint64(n))
		}
		s.touch()
	}
}
