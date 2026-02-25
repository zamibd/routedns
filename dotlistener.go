package rdns

import (
	"crypto/tls"
	"net"

	"github.com/miekg/dns"
	proxyproto "github.com/pires/go-proxyproto"
)

// DoTListener is a DNS listener/server for DNS-over-TLS.
type DoTListener struct {
	*dns.Server
	id      string
	opt     DoTListenerOptions
	addr    string
	network string
}

var _ Listener = &DoTListener{}

// DoTListenerOptions contains options used by the DNS-over-TLS server.
type DoTListenerOptions struct {
	ListenOptions

	TLSConfig *tls.Config
}

// NewDoTListener returns an instance of a DNS-over-TLS listener.
func NewDoTListener(id, addr, network string, opt DoTListenerOptions, resolver Resolver) *DoTListener {
	switch network {
	case "", "tcp":
		network = "tcp"
	case "tcp4":
		network = "tcp4"
	case "tcp6":
		network = "tcp6"
	}
	return &DoTListener{
		id:      id,
		opt:     opt,
		addr:    addr,
		network: network,
		Server: &dns.Server{
			Addr:      addr,
			Net:       network + "-tls",
			TLSConfig: opt.TLSConfig,
			Handler:   listenHandler(id, "dot", addr, resolver, opt.AllowedNet),
		},
	}
}

// Start the DoT server.
func (s DoTListener) Start() error {
	Log.Info("starting listener",
		"id", s.id,
		"protocol", "dot",
		"addr", s.addr)

	// When PROXY protocol is enabled, manually create a TLS listener and wrap it
	if s.opt.ProxyProtocol {
		ln, err := net.Listen(s.network, s.addr)
		if err != nil {
			return err
		}
		// Wrap with PROXY protocol
		proxyLn := &proxyproto.Listener{Listener: ln}
		// Wrap with TLS
		tlsLn := tls.NewListener(proxyLn, s.opt.TLSConfig)
		s.Server.Listener = tlsLn
		Log.Info("PROXY protocol enabled", "id", s.id, "addr", s.addr)
		return s.Server.ActivateAndServe()
	}

	return s.ListenAndServe()
}

// Stop the server.
func (s DoTListener) Stop() error {
	Log.Info("stopping listener",
		"id", s.id,
		"protocol", "dot",
		"addr", s.addr)
	return s.Shutdown()
}

func (s DoTListener) String() string {
	return s.id
}
