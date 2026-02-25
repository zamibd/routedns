package rdns

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/require"
)

// TestDoTListenerProxyProtocolV1 tests that the DoT listener correctly extracts
// the real client IP from a PROXY protocol v1 header.
func TestDoTListenerProxyProtocolV1(t *testing.T) {
	// Track the source IP seen by the resolver
	var seenSourceIP net.IP
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			seenSourceIP = ci.SourceIP
			return q, nil
		},
	}

	// Find a free port
	addr, err := getLnAddress()
	require.NoError(t, err)

	// Create the DoT listener with PROXY protocol enabled
	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	opt := DoTListenerOptions{
		TLSConfig: tlsServerConfig,
		ListenOptions: ListenOptions{
			ProxyProtocol: true,
		},
	}
	s := NewDoTListener("test-proxy-v1", addr, "", opt, upstream)
	go func() {
		err := s.Start()
		if err != nil {
			t.Logf("listener error: %v", err)
		}
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	// Connect with raw TCP, send PROXY protocol v1 header, then do TLS
	rawConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer rawConn.Close()

	// Send PROXY protocol v1 header with a fake source IP 203.0.113.50
	header := &proxyproto.Header{
		Version:           1,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("203.0.113.50"), Port: 12345},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 853},
	}
	_, err = header.WriteTo(rawConn)
	require.NoError(t, err)

	// TLS handshake over the same connection
	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	tlsClientConfig.InsecureSkipVerify = true
	tlsConn := tls.Client(rawConn, tlsClientConfig)
	defer tlsConn.Close()
	err = tlsConn.Handshake()
	require.NoError(t, err)

	// Send a DNS query over the TLS connection
	dnsConn := &dns.Conn{Conn: tlsConn}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	err = dnsConn.WriteMsg(q)
	require.NoError(t, err)

	// Read response
	_, err = dnsConn.ReadMsg()
	require.NoError(t, err)

	// Verify the resolver saw the PROXY protocol source IP, not 127.0.0.1
	require.Equal(t, 1, upstream.HitCount())
	require.Equal(t, "203.0.113.50", seenSourceIP.String(),
		"Expected PROXY protocol source IP 203.0.113.50, got %s", seenSourceIP)
}

// TestDoTListenerProxyProtocolV2 tests PROXY protocol v2 (binary format).
func TestDoTListenerProxyProtocolV2(t *testing.T) {
	var seenSourceIP net.IP
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			seenSourceIP = ci.SourceIP
			return q, nil
		},
	}

	addr, err := getLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	opt := DoTListenerOptions{
		TLSConfig: tlsServerConfig,
		ListenOptions: ListenOptions{
			ProxyProtocol: true,
		},
	}
	s := NewDoTListener("test-proxy-v2", addr, "", opt, upstream)
	go func() {
		err := s.Start()
		if err != nil {
			t.Logf("listener error: %v", err)
		}
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	rawConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer rawConn.Close()

	// Send PROXY protocol v2 header with source IP 198.51.100.42
	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("198.51.100.42"), Port: 54321},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 853},
	}
	_, err = header.WriteTo(rawConn)
	require.NoError(t, err)

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	tlsClientConfig.InsecureSkipVerify = true
	tlsConn := tls.Client(rawConn, tlsClientConfig)
	defer tlsConn.Close()
	err = tlsConn.Handshake()
	require.NoError(t, err)

	dnsConn := &dns.Conn{Conn: tlsConn}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	err = dnsConn.WriteMsg(q)
	require.NoError(t, err)

	_, err = dnsConn.ReadMsg()
	require.NoError(t, err)

	require.Equal(t, 1, upstream.HitCount())
	require.Equal(t, "198.51.100.42", seenSourceIP.String(),
		"Expected PROXY protocol v2 source IP 198.51.100.42, got %s", seenSourceIP)
}

// TestDoTListenerWithoutProxyProtocol tests that the normal DoT listener
// still works correctly without PROXY protocol (regression test).
func TestDoTListenerWithoutProxyProtocol(t *testing.T) {
	upstream := new(TestResolver)

	addr, err := getLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	// No ProxyProtocol set (defaults to false)
	s := NewDoTListener("test-no-proxy", addr, "", DoTListenerOptions{TLSConfig: tlsServerConfig}, upstream)
	go func() {
		err := s.Start()
		require.NoError(t, err)
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	tlsConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	c, _ := NewDoTClient("test-dot", addr, DoTClientOptions{TLSConfig: tlsConfig})

	q := new(dns.Msg)
	q.SetQuestion("cloudflare.com.", dns.TypeA)
	_, err = c.Resolve(q, ClientInfo{})
	require.NoError(t, err)
	require.Equal(t, 1, upstream.HitCount())
}

// TestDNSListenerTCPProxyProtocol tests PROXY protocol on a plain DNS TCP listener.
func TestDNSListenerTCPProxyProtocol(t *testing.T) {
	var seenSourceIP net.IP
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			seenSourceIP = ci.SourceIP
			return q, nil
		},
	}

	addr, err := getLnAddress()
	require.NoError(t, err)

	opt := ListenOptions{ProxyProtocol: true}
	s := NewDNSListener("test-tcp-proxy", addr, "tcp", opt, upstream)
	go func() {
		err := s.Start()
		if err != nil {
			t.Logf("listener error: %v", err)
		}
	}()
	defer s.Shutdown()
	time.Sleep(time.Second)

	// Connect with raw TCP, send PROXY protocol v2 header, then DNS query
	rawConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer rawConn.Close()

	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv4,
		SourceAddr:        &net.TCPAddr{IP: net.ParseIP("10.0.0.50"), Port: 11111},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53},
	}
	_, err = header.WriteTo(rawConn)
	require.NoError(t, err)

	// Send DNS query over the TCP connection
	dnsConn := &dns.Conn{Conn: rawConn}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	err = dnsConn.WriteMsg(q)
	require.NoError(t, err)

	_, err = dnsConn.ReadMsg()
	require.NoError(t, err)

	require.Equal(t, 1, upstream.HitCount())
	require.Equal(t, "10.0.0.50", seenSourceIP.String(),
		"Expected PROXY protocol source IP 10.0.0.50, got %s", seenSourceIP)
}

// TestDoTListenerProxyProtocolIPv6 tests PROXY protocol with IPv6 addresses.
func TestDoTListenerProxyProtocolIPv6(t *testing.T) {
	var seenSourceIP net.IP
	upstream := &TestResolver{
		ResolveFunc: func(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
			seenSourceIP = ci.SourceIP
			return q, nil
		},
	}

	addr, err := getLnAddress()
	require.NoError(t, err)

	tlsServerConfig, err := TLSServerConfig("", "testdata/server.crt", "testdata/server.key", false)
	require.NoError(t, err)

	opt := DoTListenerOptions{
		TLSConfig: tlsServerConfig,
		ListenOptions: ListenOptions{
			ProxyProtocol: true,
		},
	}
	s := NewDoTListener("test-proxy-v6", addr, "", opt, upstream)
	go func() {
		err := s.Start()
		if err != nil {
			t.Logf("listener error: %v", err)
		}
	}()
	defer s.Stop()
	time.Sleep(time.Second)

	rawConn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer rawConn.Close()

	// Send PROXY protocol v2 header with IPv6 source
	srcIP := net.ParseIP("2001:db8::1")
	header := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: proxyproto.TCPv6,
		SourceAddr:        &net.TCPAddr{IP: srcIP, Port: 12345},
		DestinationAddr:   &net.TCPAddr{IP: net.ParseIP("::1"), Port: 853},
	}
	_, err = header.WriteTo(rawConn)
	require.NoError(t, err)

	tlsClientConfig, err := TLSClientConfig("testdata/ca.crt", "", "", "")
	require.NoError(t, err)
	tlsClientConfig.InsecureSkipVerify = true
	tlsConn := tls.Client(rawConn, tlsClientConfig)
	defer tlsConn.Close()
	err = tlsConn.Handshake()
	require.NoError(t, err)

	dnsConn := &dns.Conn{Conn: tlsConn}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	err = dnsConn.WriteMsg(q)
	require.NoError(t, err)

	_, err = dnsConn.ReadMsg()
	require.NoError(t, err)

	require.Equal(t, 1, upstream.HitCount())
	fmt.Printf("Seen source IP: %s\n", seenSourceIP)
	require.Equal(t, "2001:db8::1", seenSourceIP.String(),
		"Expected PROXY protocol IPv6 source IP 2001:db8::1, got %s", seenSourceIP)
}
