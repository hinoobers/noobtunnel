package proxy

import (
	"crypto/tls"
	"net"
	"time"
)

// httpsResource terminates TLS on the control node and reverse proxies to the
// service over plain HTTP, the same way the HTTP resource does.
type httpsResource struct {
	group *group
	inner *httpResource
	ln    net.Listener
}

func newHTTPSResource(g *group, dialTimeout time.Duration, provider CertificateProvider) *httpsResource {
	h := &httpsResource{group: g, inner: newHTTPResource(g, dialTimeout)}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Any name gets a certificate (the provider decides what it is allowed to
		// issue): a client asking for an unknown host still completes the
		// handshake and then receives the readable "not published" error.
		GetCertificate: provider.GetCertificate,
	}
	h.inner.server.TLSConfig = tlsConfig
	h.inner.server.Handler = h.inner
	return h
}

func (h *httpsResource) serve(ln net.Listener) error {
	h.ln = ln
	return h.inner.server.ServeTLS(ln, "", "")
}

func (h *httpsResource) close() {
	h.inner.close()
}
