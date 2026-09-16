package proxy

import (
	"net/netip"
	"time"
)

// RequestEvent describes one request that reached (or was refused by) a resource.
// The control node keeps a bounded log of these for the Logs tab.
type RequestEvent struct {
	Time       time.Time  `json:"time"`
	ResourceID uint32     `json:"resourceId"`
	Resource   string     `json:"resource"`
	Host       string     `json:"host"`
	IP         netip.Addr `json:"-"`
	IPText     string     `json:"ip"`
	Country    string     `json:"country,omitempty"`
	Account    string     `json:"account,omitempty"`
	Protocol   string     `json:"protocol"`
	// Allowed is false when a rule or the identity gate refused the request.
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	Status  int    `json:"status,omitempty"`
	Path    string `json:"path,omitempty"`
}

// observe reports an event when the control node is listening for them.
func (m *Manager) observe(event RequestEvent) {
	if m.OnRequest == nil {
		return
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	event.IPText = event.IP.String()
	m.OnRequest(event)
}
