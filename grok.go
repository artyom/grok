// Command grok provides standalone server terminating https and proxying
// requests in plain http over reverse ssh tunnels.
//
// Its main use-case is the same as of the ngrok tool from <https://ngrok.com>.
//
// Command grok listens https and ssh endpoints. On ssh connections it's looking
// for "tcpip-forward" request (RFC 4254, Section 7.1), once received, it
// establishes reverse proxy for domain derived from public key of the client.
//
// When receiving request over https, grok inspects request domain name, if
// matching active tunnel is found, request is proxied over found tunnel as
// plain HTTP/1.1 request. Certificates for matched domains are automatically
// obtained from https://letsencrypt.org authority as required.
//
// Domains are either derived from public key md5 fingerprint: hash.base.tld
// (where base.tld domain is set with -domain flag) or defined per-key in
// authorized_keys file as key option specification in form of domain=name.tld:
//
//	domain=dev1.example.com ssh-ed25519 key1...
//	domain=dev2.example.com ssh-rsa key2...
//
// Once set, developer may then connect to this service with ssh client setting
// up reverse port forwarding (i.e. to localhost:8080):
//
//	ssh -N -R 8080:localhost:8080 server.example.com
//
// Note the notation for -R used by ssh:
//
//	-R [bind_address:]port:host:hostport
//
// When connecting to grok only host:hostport pair is significant, since they
// specify where ssh client will connect on forwarded connection, the first port
// can be set to arbitrary value and is ignored by the server.
package main

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/artyom/autoflags"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"
)

func main() {
	args := runArgs{
		AuthKeysFile: "authorized_keys",
		HostKeyFile:  "id_rsa",
		Timeout:      3 * time.Minute,
		AddrSSH:      ":2022",
		AddrTLS:      ":443",
		Domain:       "example.com",
		DirCache:     "/var/cache/grok",
	}
	autoflags.Parse(&args)
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type runArgs struct {
	AuthKeysFile string        `flag:"auth,path to authorized_keys file"`
	HostKeyFile  string        `flag:"hostKey,path to private host key file"`
	Timeout      time.Duration `flag:"timeout,IO timeout on client ssh connections"`
	AddrSSH      string        `flag:"addr.ssh,ssh address to listen"`
	AddrTLS      string        `flag:"addr.https,https address to listen"`
	Domain       string        `flag:"domain,domain to use as a base if key lacks explicit domain"`
	DirCache     string        `flag:"cache,certificates cache dir"`
	Email        string        `flag:"email,email to use for letsencrypt API"`
}

func run(args runArgs) error {
	if args.Domain == "" || args.Email == "" {
		return fmt.Errorf("both domain and email should be set")
	}
	auth, err := authChecker(args.AuthKeysFile)
	if err != nil {
		return err
	}
	hostKey, err := loadHostKey(args.HostKeyFile)
	if err != nil {
		return err
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
	errCh := make(chan error, 2)
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
	go func() { errCh <- srv.ListenAndServeTLS("", "") }()
	defer srv.Close()
	go func() {
		errCh <- func() error {
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
		}()
	}()
	return <-errCh
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
	_, err = io.Copy(ioutil.Discard, channel)
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
	privateBytes, err := ioutil.ReadFile(name)
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
		return nil, fmt.Errorf("no keys matched")
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
		return "", fmt.Errorf("nil *ssh.Permissions")
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
	return "", fmt.Errorf("failed to derive domain from the key")
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
	return fmt.Errorf("host not configured")
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
func (c *connWrap) SetDeadline(t time.Time) error      { return fmt.Errorf("not implemented") }
func (c *connWrap) SetReadDeadline(t time.Time) error  { return fmt.Errorf("not implemented") }
func (c *connWrap) SetWriteDeadline(t time.Time) error { return fmt.Errorf("not implemented") }

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
