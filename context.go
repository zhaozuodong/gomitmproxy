package gomitmproxy

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// Context provides information and storage for a single request/response pair.
// Contexts are linked to shared session that is used for multiple requests on
// a single connection.
type Context struct {
	session *Session
	id      string

	mu            sync.RWMutex
	vals          map[string]interface{}
	skipRoundTrip bool
	skipLogging   bool
	apiRequest    bool
}

// Session provides information and storage about a connection.
type Session struct {
	mu       sync.RWMutex
	id       string
	secure   bool
	hijacked bool
	conn     net.Conn
	brw      *bufio.ReadWriter
	vals     map[string]interface{}
}

var (
	ctxmu sync.RWMutex
	ctxs  = make(map[*http.Request]*Context)
)

// NewContext returns a context for the in-flight HTTP request.
func NewContext(req *http.Request) *Context {
	ctxmu.RLock()
	defer ctxmu.RUnlock()

	return ctxs[req]
}

// ID returns the session ID.
func (s *Session) ID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.id
}

// IsSecure returns whether the current session is from a secure connection,
// such as when receiving requests from a TLS connection that has been MITM'd.
func (s *Session) IsSecure() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.secure
}

// MarkSecure marks the session as secure.
func (s *Session) MarkSecure() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.secure = true
}

// MarkInsecure marks the session as insecure.
func (s *Session) MarkInsecure() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.secure = false
}

// Hijack takes control of the connection from the proxy. No further action
// will be taken by the proxy and the connection will be closed following the
// return of the hijacker.
func (s *Session) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.hijacked {
		return nil, nil, fmt.Errorf("gomitmproxy: session has already been hijacked")
	}
	s.hijacked = true

	return s.conn, s.brw, nil
}

// Hijacked returns whether the connection has been hijacked.
func (s *Session) Hijacked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.hijacked
}

// setConn resets the underlying connection and bufio.ReadWriter of the
// session. Used by the proxy when the connection is upgraded to TLS.
func (s *Session) setConn(conn net.Conn, brw *bufio.ReadWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.conn = conn
	s.brw = brw
}

// Get takes key and returns the associated value from the session.
func (s *Session) Get(key string) (interface{}, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	val, ok := s.vals[key]

	return val, ok
}

// Set takes a key and associates it with val in the session. The value is
// persisted for the entire session across multiple requests and responses.
func (s *Session) Set(key string, val interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.vals[key] = val
}

// Session returns the session for the context.
func (ctx *Context) Session() *Session {
	return ctx.session
}

// ID returns the context ID.
func (ctx *Context) ID() string {
	return ctx.id
}

// Get takes key and returns the associated value from the context.
func (ctx *Context) Get(key string) (interface{}, bool) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	val, ok := ctx.vals[key]

	return val, ok
}

// Set takes a key and associates it with val in the context. The value is
// persisted for the duration of the request and is removed on the following
// request.
func (ctx *Context) Set(key string, val interface{}) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.vals[key] = val
}

// SkipRoundTrip skips the round trip for the current request.
func (ctx *Context) SkipRoundTrip() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.skipRoundTrip = true
}

// SkippingRoundTrip returns whether the current round trip will be skipped.
func (ctx *Context) SkippingRoundTrip() bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return ctx.skipRoundTrip
}

// SkipLogging skips logging by gomitmproxy loggers for the current request.
func (ctx *Context) SkipLogging() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.skipLogging = true
}

// SkippingLogging returns whether the current request / response pair will be logged.
func (ctx *Context) SkippingLogging() bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return ctx.skipLogging
}

// APIRequest marks the requests as a request to the proxy API.
func (ctx *Context) APIRequest() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	ctx.apiRequest = true
}

// IsAPIRequest returns true when the request patterns matches a pattern in the proxy
// mux. The mux is usually defined as a parameter to the api.Forwarder, which uses
// http.DefaultServeMux by default.
func (ctx *Context) IsAPIRequest() bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()

	return ctx.apiRequest
}

// newID creates a new 16 character random hex ID; note these are not UUIDs.
func newID() (string, error) {
	src := make([]byte, 8)
	if _, err := rand.Read(src); err != nil {
		return "", err
	}

	return hex.EncodeToString(src), nil
}

// link associates the context with request.
func link(req *http.Request, ctx *Context) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	ctxs[req] = ctx
}

// unlink removes the context for request.
func unlink(req *http.Request) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	delete(ctxs, req)
}

// newSession builds a new session.
func newSession(conn net.Conn, brw *bufio.ReadWriter) (*Session, error) {
	sid, err := newID()
	if err != nil {
		return nil, err
	}

	return &Session{
		id:   sid,
		conn: conn,
		brw:  brw,
		vals: make(map[string]interface{}),
	}, nil
}

// withSession builds a new context from an existing session. Session must be
// non-nil.
func withSession(s *Session) (*Context, error) {
	cid, err := newID()
	if err != nil {
		return nil, err
	}

	return &Context{
		session: s,
		id:      cid,
		vals:    make(map[string]interface{}),
	}, nil
}
