package gomitmproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"github.com/armon/go-socks5"
	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/zhaozuodong/gomitmproxy/log"
	"github.com/zhaozuodong/gomitmproxy/middlewares"
	"github.com/zhaozuodong/gomitmproxy/mitm"
	"github.com/zhaozuodong/gomitmproxy/nosigpipe"
	"github.com/zhaozuodong/gomitmproxy/proxyutil"
	"io"
	tlog "log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Proxy struct {
	roundTripper http.RoundTripper
	dial         func(string, string) (net.Conn, error)
	timeout      time.Duration
	mitm         *mitm.Config
	proxyURL     *url.URL
	conns        sync.WaitGroup
	connsMu      sync.Mutex
	closing      chan bool
	middlewares  []middlewares.Middleware
	allowTlsUrls []string
	*Auth
}

type Auth struct {
	Username string
	Password string
}

var errClose = errors.New("closing connection")

func isCloseable(err error) bool {
	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		return true
	}

	switch err {
	case io.EOF, io.ErrClosedPipe, errClose:
		return true
	}

	return false
}

func NewProxy() *Proxy {
	proxy := &Proxy{
		roundTripper: &http.Transport{
			TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		timeout:      5 * time.Minute,
		closing:      make(chan bool),
		middlewares:  []middlewares.Middleware{},
		allowTlsUrls: []string{},
	}
	proxy.SetDial((&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial)
	return proxy
}

func (p *Proxy) AllowTlsUrls(urls []string) {
	p.allowTlsUrls = urls
}

func (p *Proxy) GetAllowTlsUrls() []string {
	return p.allowTlsUrls
}

func (p *Proxy) Use(handlers ...middlewares.Middleware) {
	p.middlewares = append(p.middlewares, handlers...)
}

func (p *Proxy) GetRoundTripper() http.RoundTripper {
	return p.roundTripper
}

func (p *Proxy) SetRoundTripper(rt http.RoundTripper) {
	p.roundTripper = rt

	if tr, ok := p.roundTripper.(*http.Transport); ok {
		tr.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
		tr.Proxy = http.ProxyURL(p.proxyURL)
		tr.Dial = p.dial
	}
}

func (p *Proxy) SetDownstreamProxy(proxyURL *url.URL) {
	p.proxyURL = proxyURL

	if tr, ok := p.roundTripper.(*http.Transport); ok {
		tr.Proxy = http.ProxyURL(p.proxyURL)
	}
}

func (p *Proxy) SetTimeout(timeout time.Duration) {
	p.timeout = timeout
}

func (p *Proxy) SetMITM(config *mitm.Config) {
	p.mitm = config
}

func (p *Proxy) SetDial(dial func(string, string) (net.Conn, error)) {
	p.dial = func(a, b string) (net.Conn, error) {
		c, e := dial(a, b)
		nosigpipe.IgnoreSIGPIPE(c)
		return c, e
	}

	if tr, ok := p.roundTripper.(*http.Transport); ok {
		tr.Dial = p.dial
	}
}

func (p *Proxy) Close() {
	log.Infof("gomitmproxy: closing down proxy")

	close(p.closing)

	log.Infof("gomitmproxy: waiting for connections to close")
	p.connsMu.Lock()
	p.conns.Wait()
	p.connsMu.Unlock()
	log.Infof("gomitmproxy: all connections closed")
}

func (p *Proxy) Closing() bool {
	select {
	case <-p.closing:
		return true
	default:
		return false
	}
}

func (p *Proxy) Serve(l net.Listener) error {
	defer l.Close()

	var delay time.Duration
	for {
		if p.Closing() {
			return nil
		}

		conn, err := l.Accept()
		nosigpipe.IgnoreSIGPIPE(conn)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
				}
				if max := time.Second; delay > max {
					delay = max
				}

				log.Debugf("gomitmproxy: temporary error on accept: %v", err)
				time.Sleep(delay)
				continue
			}

			if errors.Is(err, net.ErrClosed) {
				log.Debugf("gomitmproxy: listener closed, returning")
				return err
			}

			log.Errorf("gomitmproxy: failed to accept: %v", err)
			return err
		}
		delay = 0
		log.Debugf("gomitmproxy: accepted connection from %s", conn.RemoteAddr())

		if tconn, ok := conn.(*net.TCPConn); ok {
			tconn.SetKeepAlive(true)
			tconn.SetKeepAlivePeriod(3 * time.Minute)
		}

		go p.handleLoop(conn)
	}
}

func (p *Proxy) handleLoop(conn net.Conn) {
	p.connsMu.Lock()
	p.conns.Add(1)
	p.connsMu.Unlock()
	defer p.conns.Done()
	defer conn.Close()
	if p.Closing() {
		return
	}

	brw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	s, err := newSession(conn, brw)
	if err != nil {
		log.Errorf("gomitmproxy: failed to create session: %v", err)
		return
	}

	ctx, err := withSession(s)
	if err != nil {
		log.Errorf("gomitmproxy: failed to create context: %v", err)
		return
	}

	for {
		start := time.Now()
		deadline := time.Now().Add(p.timeout)
		conn.SetDeadline(deadline)

		if err := p.handle(ctx, conn, brw); isCloseable(err) {
			log.Debugf("gomitmproxy: closing connection: %v, took: %d", conn.RemoteAddr(), time.Since(start).Milliseconds())
			return
		}
	}
}

func (p *Proxy) readRequest(ctx *Context, conn net.Conn, brw *bufio.ReadWriter) (*http.Request, error) {
	var req *http.Request
	reqc := make(chan *http.Request, 1)
	errc := make(chan error, 1)
	go func() {
		r, err := http.ReadRequest(brw.Reader)
		if err != nil {
			errc <- err
			return
		}
		reqc <- r
	}()
	select {
	case err := <-errc:
		if isCloseable(err) {
			log.Debugf("gomitmproxy: connection closed prematurely: %v", err)
		} else {
			log.Errorf("gomitmproxy: failed to read request: %v", err)
		}

		// TODO: TCPConn.WriteClose() to avoid sending an RST to the client.

		return nil, errClose
	case req = <-reqc:
	case <-p.closing:
		return nil, errClose
	}

	return req, nil
}

func (p *Proxy) handleConnectRequest(ctx *Context, req *http.Request, session *Session, brw *bufio.ReadWriter, conn net.Conn) error {
	if p.mitm != nil {
		log.Debugf("gomitmproxy: attempting MITM for connection: %s / %s", req.Host, req.URL.String())

		res := proxyutil.NewResponse(200, nil, req)

		if err := res.Write(brw); err != nil {
			log.Errorf("gomitmproxy: got error while writing response back to client: %v", err)
		}
		if err := brw.Flush(); err != nil {
			log.Errorf("gomitmproxy: got error while flushing response back to client: %v", err)
		}

		log.Debugf("gomitmproxy: completed MITM for connection: %s", req.Host)

		b := make([]byte, 1)
		if _, err := brw.Read(b); err != nil {
			log.Errorf("gomitmproxy: error peeking message through CONNECT tunnel to determine type: %v", err)
		}

		// Drain all of the rest of the buffered data.
		buf := make([]byte, brw.Reader.Buffered())
		brw.Read(buf)

		// 22 is the TLS handshake.
		// https://tools.ietf.org/html/rfc5246#section-6.2.1
		if b[0] == 22 {
			// Prepend the previously read data to be read again by
			// http.ReadRequest.
			tlsconn := tls.Server(&peekedConn{conn, io.MultiReader(bytes.NewReader(b), bytes.NewReader(buf), conn)}, p.mitm.TLSForHost(req.Host))

			if err := tlsconn.Handshake(); err != nil {
				p.mitm.HandshakeErrorCallback(req, err)
				return err
			}

			brw.Writer.Reset(tlsconn)
			brw.Reader.Reset(tlsconn)
			return p.handle(ctx, tlsconn, brw)
		}
		brw.Reader.Reset(io.MultiReader(bytes.NewReader(b), bytes.NewReader(buf), conn))
		return p.handle(ctx, conn, brw)
	}

	log.Debugf("gomitmproxy: attempting to establish CONNECT tunnel: %s", req.URL.Host)
	res, cconn, cerr := p.connect(req)
	if cerr != nil {
		log.Errorf("gomitmproxy: failed to CONNECT: %v", cerr)
		res = proxyutil.NewResponse(502, nil, req)
		proxyutil.Warning(res.Header, cerr)

		if err := res.Write(brw); err != nil {
			log.Errorf("gomitmproxy: got error while writing response back to client: %v", err)
		}
		err := brw.Flush()
		if err != nil {
			log.Errorf("gomitmproxy: got error while flushing response back to client: %v", err)
		}
		return err
	}
	defer res.Body.Close()
	defer cconn.Close()

	res.ContentLength = -1
	if err := res.Write(brw); err != nil {
		log.Errorf("gomitmproxy: got error while writing response back to client: %v", err)
	}
	if err := brw.Flush(); err != nil {
		log.Errorf("gomitmproxy: got error while flushing response back to client: %v", err)
	}

	cbw := bufio.NewWriter(cconn)
	cbr := bufio.NewReader(cconn)
	defer cbw.Flush()

	copySync := func(w io.Writer, r io.Reader, donec chan<- bool) {
		if _, err := io.Copy(w, r); err != nil && err != io.EOF {
			log.Errorf("gomitmproxy: failed to copy CONNECT tunnel: %v", err)
		}

		log.Debugf("gomitmproxy: CONNECT tunnel finished copying")
		donec <- true
	}

	donec := make(chan bool, 2)
	go copySync(cbw, brw, donec)
	go copySync(brw, cbr, donec)

	log.Debugf("gomitmproxy: established CONNECT tunnel, proxying traffic")
	<-donec
	<-donec
	log.Debugf("gomitmproxy: closed CONNECT tunnel")

	return errClose
}

func (p *Proxy) handle(ctx *Context, conn net.Conn, brw *bufio.ReadWriter) error {
	log.Debugf("gomitmproxy: waiting for request: %v", conn.RemoteAddr())

	req, err := p.readRequest(ctx, conn, brw)
	if err != nil {
		return err
	}
	defer req.Body.Close()

	for _, m := range p.middlewares {
		if err := m.MitmRequest(req); err != nil {
			log.Errorf("gomitmproxy: req middlewares error: %v", err)
		}
	}

	session := ctx.Session()
	ctx, err = withSession(session)
	if err != nil {
		log.Errorf("gomitmproxy: failed to build new context: %v", err)
		return err
	}

	link(req, ctx)
	defer unlink(req)

	if tconn, ok := conn.(*tls.Conn); ok {
		session.MarkSecure()

		cs := tconn.ConnectionState()
		req.TLS = &cs
	}

	req.URL.Scheme = "http"
	if session.IsSecure() {
		log.Infof("gomitmproxy: forcing HTTPS inside secure session")
		req.URL.Scheme = "https"
	}

	req.RemoteAddr = conn.RemoteAddr().String()
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	if req.Method == "CONNECT" {
		return p.handleConnectRequest(ctx, req, session, brw, conn)
	}

	res, err := p.roundTrip(ctx, req)
	if err != nil {
		log.Errorf("gomitmproxy: failed to round trip: %v", err)
		res = proxyutil.NewResponse(502, nil, req)
		proxyutil.Warning(res.Header, err)
	}
	defer res.Body.Close()

	res.Request = req

	var closing error
	if req.Close || res.Close || p.Closing() {
		log.Debugf("gomitmproxy: received close request: %v", req.RemoteAddr)
		res.Close = true
		closing = errClose
	}

	for _, m := range p.middlewares {
		if err := m.MitmResponse(res); err != nil {
			log.Errorf("gomitmproxy: res middlewares error: %v", err)
		}
	}

	err = res.Write(brw)
	if err != nil {
		log.Errorf("gomitmproxy: got error while writing response back to client: %v", err)
		closing = errClose
	}
	err = brw.Flush()
	if err != nil {
		closing = errClose
	}
	return closing
}

type peekedConn struct {
	net.Conn
	r io.Reader
}

func (c *peekedConn) Read(buf []byte) (int, error) { return c.r.Read(buf) }

func (p *Proxy) roundTrip(ctx *Context, req *http.Request) (*http.Response, error) {
	if ctx.SkippingRoundTrip() {
		log.Debugf("gomitmproxy: skipping round trip")
		return proxyutil.NewResponse(200, nil, req), nil
	}

	return p.roundTripper.RoundTrip(req)
}

func (p *Proxy) connect(req *http.Request) (*http.Response, net.Conn, error) {
	if p.proxyURL != nil {
		log.Debugf("gomitmproxy: CONNECT with downstream proxy: %s", p.proxyURL.Host)

		conn, err := p.dial("tcp", p.proxyURL.Host)
		if err != nil {
			return nil, nil, err
		}
		pbw := bufio.NewWriter(conn)
		pbr := bufio.NewReader(conn)

		req.Write(pbw)
		pbw.Flush()

		res, err := http.ReadResponse(pbr, req)
		if err != nil {
			return nil, nil, err
		}

		return res, conn, nil
	}

	log.Debugf("gomitmproxy: CONNECT to host directly: %s", req.URL.Host)

	conn, err := p.dial("tcp", req.URL.Host)
	if err != nil {
		return nil, nil, err
	}

	return proxyutil.NewResponse(200, nil, req), conn, nil
}

func (p *Proxy) StartSocks5(httpAddr, socks5Addr string) {
	proxyHost, proxyPort, err := net.SplitHostPort(httpAddr)
	if err != nil {
		log.Errorf("parse proxy addr err:  %v\n", err.Error())
		return
	}
	if proxyHost == "" || strings.Contains(proxyHost, ":") {
		proxyHost = "0.0.0.0"
	}
	port, _ := strconv.ParseInt(proxyPort, 10, 64)
	superProxy, _ := superproxy.NewSuperProxy(proxyHost, uint16(port), superproxy.ProxyTypeHTTP, "", "", "")
	bufioPool := bufiopool.New(4096, 4096)
	conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return superProxy.MakeTunnel(nil, nil, bufioPool, addr)
		},
	}
	if p.Auth != nil && p.Username != "" && p.Password != "" {
		authenticator := socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				p.Username: p.Password,
			},
		}
		conf.AuthMethods = []socks5.Authenticator{authenticator}
		tlog.Printf("gomitmproxy: socks5 use auth username:[%s], password:[%s]", p.Username, p.Password)
	}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}
	if err := server.ListenAndServe("tcp", socks5Addr); err != nil {
		panic(err)
	}
}
