// Command grok provides a standalone server that terminates HTTPS connections and proxies
// requests as plain HTTP over reverse SSH tunnels.
//
// Its main use-case is similar to the ngrok tool (https://ngrok.com), allowing developers
// to expose local services through a public HTTPS endpoint.
//
// The server operates by listening on two endpoints:
//
//   - HTTPS: For incoming web requests
//   - SSH: For tunnel establishment
//
// When receiving SSH connections, grok looks for "tcpip-forward" requests ([RFC 4254, Section 7.1]).
// Once received, it establishes a reverse proxy for a domain that is either
// derived from the client's public key fingerprint (hash.base.tld), or
// explicitly defined in the authorized_keys file.
//
// For HTTPS requests, grok matches the request's domain name against active tunnels.
// If a match is found, the request is proxied over the tunnel as a plain HTTP/1.1 request.
// TLS certificates for matched domains are automatically obtained from [Let's Encrypt]
// as needed.
//
// # Domain Configuration
//
// There are two ways to configure domains:
//
// Explicit domain per key in authorized_keys:
//
//	domain=dev1.example.com ssh-ed25519 key1...
//	domain=dev2.example.com ssh-rsa key2...
//
// Auto-derived domain from key hash:
//
//	ssh-ed25519 key3...  # Results in <hash>.example.com
//
// where <hash> is derived from the key's fingerprint and domain
// is set via the -domain flag
//
// # Usage Example
//
// To expose a local development server running on port 8080:
//
//	ssh -N -R 8080:localhost:8080 <SERVER>
//
// Note on SSH -R syntax:
//
//	-R [bind_address:]port:host:hostport
//
// The bind_address and first port are ignored by grok; only the host:hostport
// pair is used to determine where the SSH client will connect for forwarded
// connections.
//
// [Let's Encrypt]: https://letsencrypt.org
// [RFC 4254, Section 7.1]: https://www.rfc-editor.org/rfc/rfc4254#section-7.1
package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

func main() {
	args := runArgs{
		AuthKeysFile: "authorized_keys",
		HostKeyFile:  "id_rsa",
		Timeout:      3 * time.Minute,
		AddrSSH:      ":2022",
		AddrTLS:      ":443",
		AddrHTTP:     ":80",
		Domain:       "example.com",
		DirCache:     "/var/cache/grok",
	}
	flag.StringVar(&args.AuthKeysFile, "auth", args.AuthKeysFile, "`path` to authorized_keys file")
	flag.StringVar(&args.HostKeyFile, "hostKey", args.HostKeyFile, "`path` to private host key file")
	flag.DurationVar(&args.Timeout, "timeout", args.Timeout, "IO timeout on client ssh connections")
	flag.StringVar(&args.AddrSSH, "addr.ssh", args.AddrSSH, "ssh address to listen")
	flag.StringVar(&args.AddrTLS, "addr.https", args.AddrTLS, "https address to listen")
	flag.StringVar(&args.AddrHTTP, "addr.http", args.AddrHTTP, "optional address to serve http-to-https redirects and ACME http-01 challenge responses")
	flag.StringVar(&args.Domain, "domain", args.Domain, "domain to use as the base if the key lacks explicit domain")
	flag.StringVar(&args.DirCache, "cache", args.DirCache, "certificates cache directory `path`")
	flag.StringVar(&args.Email, "email", args.Email, "email to use for Letsencrypt API")
	flag.Parse()
	log.SetFlags(0)
	if err := run(args); err != nil {
		log.Fatal(err)
	}
}

type runArgs struct {
	AuthKeysFile string
	HostKeyFile  string
	Timeout      time.Duration
	AddrSSH      string
	AddrTLS      string
	AddrHTTP     string
	Domain       string
	DirCache     string
	Email        string
}

func run(args runArgs) error {
	if args.Domain == "" || args.Email == "" {
		return errors.New("both domain and email should be set")
	}
	auth, err := authChecker(args.AuthKeysFile)
	if err != nil {
		return fmt.Errorf("authorized keys load: %w", err)
	}
	hostKey, err := loadHostKey(args.HostKeyFile)
	if err != nil {
		return fmt.Errorf("host key load: %w", err)
	}
	config := &ssh.ServerConfig{
		PublicKeyCallback: auth,
		ServerVersion:     "SSH-2.0-generic",
	}
	config.AddHostKey(hostKey)
	ln, err := net.Listen("tcp", args.AddrSSH)
	if err != nil {
		return err
	}
	defer ln.Close()
	g := newGrok(args.Domain)
	manager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(args.DirCache),
		Email:      args.Email,
		HostPolicy: g.HostPolicy,
	}
	srv := &http.Server{
		Handler:           g,
		Addr:              args.AddrTLS,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       30 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: manager.GetCertificate,
		},
	}
	defer srv.Close()
	var group errgroup.Group
	group.Go(func() error { return srv.ListenAndServeTLS("", "") })
	if args.AddrHTTP != "" {
		group.Go(func() error {
			srv := &http.Server{
				Addr:         args.AddrHTTP,
				Handler:      manager.HTTPHandler(nil),
				ReadTimeout:  10 * time.Second,
				WriteTimeout: 10 * time.Second,
			}
			return srv.ListenAndServe()
		})
	}
	group.Go(func() error {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return err
			}
			tc := conn.(*net.TCPConn)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(3 * time.Minute)
			if args.Timeout > 0 {
				conn = timeoutConn{tc, args.Timeout}
			}
			go g.handleConn(conn, config)
		}
	})
	return group.Wait()
}

func handleSession(newChannel ssh.NewChannel, domain string) error {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return err
	}
	defer channel.Close()
	go func(reqs <-chan *ssh.Request) {
		for req := range reqs {
			req.Reply(req.Type == "shell", nil)
		}
	}(requests)
	go sendKeepalives(channel, 90*time.Second)
	fmt.Fprintf(channel, "tunnel address is https://%s\n", domain)
	_, err = io.Copy(io.Discard, channel)
	if err == nil || err == io.EOF {
		// this makes ssh client exit with 0 status on client-initiated
		// disconnect (eg. ^D)
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	}
	return err
}

func sendKeepalives(channel ssh.Channel, d time.Duration) {
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	for range ticker.C {
		if _, err := channel.SendRequest("keepalive@openssh.com", true, nil); err != nil {
			return
		}
	}
}

// timeoutConn extends deadline after successful read or write operations
type timeoutConn struct {
	*net.TCPConn
	d time.Duration
}

func (c timeoutConn) Read(b []byte) (int, error) {
	n, err := c.TCPConn.Read(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}

func (c timeoutConn) Write(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b)
	if err == nil {
		_ = c.TCPConn.SetDeadline(time.Now().Add(c.d))
	}
	return n, err
}

func loadHostKey(name string) (ssh.Signer, error) {
	privateBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(privateBytes)
}

func authChecker(name string) (func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error), error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	pkeys := make(map[string]*ssh.Permissions)
	const prefix = "domain="
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		pk, _, opts, _, err := ssh.ParseAuthorizedKey(sc.Bytes())
		if err != nil {
			return nil, err
		}
		fp := ssh.FingerprintSHA256(pk)
		perms := &ssh.Permissions{
			CriticalOptions: map[string]string{
				"hash": fmt.Sprintf("%x", md5.Sum(pk.Marshal())),
			},
		}
		for _, opt := range opts {
			if strings.HasPrefix(opt, prefix) {
				perms.Extensions = map[string]string{
					"domain": strings.TrimPrefix(opt, prefix),
				}
				break
			}
		}
		pkeys[fp] = perms
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		fp := ssh.FingerprintSHA256(key)
		if perms, ok := pkeys[fp]; ok {
			return perms, nil
		}
		return nil, errors.New("no keys matched")
	}, nil
}

func newGrok(domain string) *grok {
	return &grok{
		defaultDomain: domain,
		proxies:       make(map[string]*httputil.ReverseProxy),
	}
}

type grok struct {
	defaultDomain string
	mu            sync.Mutex
	proxies       map[string]*httputil.ReverseProxy
}

func (g *grok) handleConn(nConn net.Conn, config *ssh.ServerConfig) error {
	defer nConn.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return err
	}
	domain, err := g.domain(sconn.Permissions)
	if err != nil {
		return err
	}
	go func() {
		for newChannel := range chans {
			switch newChannel.ChannelType() {
			default:
				newChannel.Reject(ssh.UnknownChannelType,
					"unsupported channel type")
			case "session":
				go handleSession(newChannel, domain)
			}
		}
	}()
	var proxyEnabled bool
	defer func() {
		if proxyEnabled {
			g.deleteProxy(domain)
		}
	}()
	for req := range reqs {
		switch req.Type {
		case "cancel-tcpip-forward":
			ok := g.deleteProxy(domain)
			if ok {
				proxyEnabled = false
			}
			req.Reply(ok, nil)
		case "tcpip-forward":
			// https://tools.ietf.org/html/rfc4254#section-7.1
			m := struct {
				Addr  string
				Rport uint32
			}{}
			if err := ssh.Unmarshal(req.Payload, &m); err != nil {
				req.Reply(false, nil)
				continue
			}
			proxy := newReverseProxy(sconn, domain, m.Addr, m.Rport)
			ok := g.setProxy(domain, proxy)
			if ok {
				proxyEnabled = true
			}
			req.Reply(ok, nil)
		default:
			req.Reply(false, nil)
		}
	}
	return nil
}

func (g *grok) domain(p *ssh.Permissions) (string, error) {
	if p == nil {
		return "", errors.New("nil *ssh.Permissions")
	}
	if p.Extensions != nil {
		if domain, ok := p.Extensions["domain"]; ok {
			return domain, nil
		}
	}
	if p.CriticalOptions != nil {
		if fp, ok := p.CriticalOptions["hash"]; ok {
			return fp + "." + g.defaultDomain, nil
		}
	}
	return "", errors.New("failed to derive domain from the key")
}

func (g *grok) setProxy(domain string, proxy *httputil.ReverseProxy) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.proxies[domain]; !ok {
		g.proxies[domain] = proxy
		return true
	}
	return false
}

func (g *grok) deleteProxy(domain string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.proxies[domain]
	delete(g.proxies, domain)
	return ok
}

func (g *grok) getProxy(domain string) (http.Handler, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p, ok := g.proxies[domain]
	return p, ok
}

func (g *grok) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if handler, ok := g.getProxy(r.Host); ok {
		handler.ServeHTTP(w, r)
		return
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

// HostPolicy implements autocert.HostPolicy type
func (g *grok) HostPolicy(ctx context.Context, host string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.proxies[host]; ok {
		return nil
	}
	return errors.New("host not configured")
}

// netAddr is a stub implementation of net.Addr
type netAddr string

func (netAddr) Network() string  { return "tcp" }
func (n netAddr) String() string { return string(n) }

// connWrap wraps ssh.Channel in net.Conn-compatible interface
type connWrap struct {
	ssh.Channel
	rAddr net.Addr
}

func (c *connWrap) LocalAddr() net.Addr                { return netAddr("localhost") }
func (c *connWrap) RemoteAddr() net.Addr               { return c.rAddr }
func (c *connWrap) SetDeadline(t time.Time) error      { return errors.ErrUnsupported }
func (c *connWrap) SetReadDeadline(t time.Time) error  { return errors.ErrUnsupported }
func (c *connWrap) SetWriteDeadline(t time.Time) error { return errors.ErrUnsupported }

func newReverseProxy(sconn ssh.Conn, domain, addr string, port uint32) *httputil.ReverseProxy {
	dialFunc := func(network, address string) (net.Conn, error) {
		// https://tools.ietf.org/html/rfc4254#section-7.2
		m := struct {
			ConnAddr string
			ConnPort uint32
			OrigAddr string
			OrigPort uint32
		}{addr, port, "127.0.0.1", 9000}
		conn, reqs, err := sconn.OpenChannel("forwarded-tcpip", ssh.Marshal(&m))
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(reqs)
		return &connWrap{
			Channel: conn,
			rAddr:   netAddr(addr),
		}, nil
	}
	return &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host = domain
		},
		Transport: &http.Transport{
			Dial:                  dialFunc,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
