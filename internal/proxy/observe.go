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
	// Target is the backend this request was sent to.
	Target string `json:"target,omitempty"`
	// DurationMs is how long the request took inside the control node: the
	// dial through the tunnel, the service's answer and the copy back. It is the
	// number to look at when a published service feels slow.
	DurationMs int64 `json:"durationMs,omitempty"`
	// DialMs is how long connecting to the backend took. Comparing it with
	// DurationMs is what separates a slow tunnel from a slow service: a fresh
	// connection to a service that then answers in milliseconds is the tunnel, and
	// a connection made in a millisecond followed by a slow answer is the service.
	DialMs int64 `json:"dialMs,omitempty"`
	// HeaderMs is elapsed time until the backend response headers arrived.
	HeaderMs int64 `json:"headerMs,omitempty"`
	// TransferMs is time spent copying the response body after its headers.
	TransferMs int64 `json:"transferMs,omitempty"`
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
