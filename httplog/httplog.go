// Package httplog provides the standard HTTP access log for infodancer Go
// services.
//
// net/http gives a server no access log at all, so every service that does not
// wire one in is silently unlogged. This package is the one implementation, so
// the field names mean the same thing everywhere and a single query answers a
// question across every service.
//
// The log stands on its own. Some deployments put a reverse proxy in front that
// keeps its own access log, but nothing here assumes one: a server using this
// package emits a complete conventional access log by itself.
//
// Output goes to the caller's *slog.Logger, so the house format applies
// unchanged (see the parent logging package: logfmt, lowercased levels, which
// Loki's logfmt parser reads).
//
// What it deliberately does not know: who the user is, or where a request id
// comes from. Those arrive through WithIdentity and WithRequestID, supplied by
// whatever middleware owns them, so a richer layer stacks on top without this
// package depending on it.
package httplog

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/felixge/httpsnoop"
)

// Message is the log message every access line carries. Alerts and dashboards
// match on it, so it is part of the contract rather than an implementation
// detail.
const Message = "http_access"

type config struct {
	requestID func(context.Context) string
	identity  func(context.Context) string
	trusted   []netip.Prefix
	skip      map[string]bool
}

// An Option configures the middleware.
type Option func(*config)

// WithRequestID supplies the per-request correlation id, logged as request_id.
// It is read after the handler returns, so the middleware that sets the id must
// run outside this one.
func WithRequestID(f func(context.Context) string) Option {
	return func(c *config) { c.requestID = f }
}

// WithIdentity supplies the authenticated user, logged as identity. Give it
// something stable and non-secret: a user id or login name, never a token.
func WithIdentity(f func(context.Context) string) Option {
	return func(c *config) { c.identity = f }
}

// WithTrustedProxies lists the peers whose X-Forwarded-For header may be
// believed, as CIDR blocks or single addresses.
//
// Without this, the peer address is logged and the header is ignored. That is
// the safe default: X-Forwarded-For is client-supplied, so honouring it from an
// arbitrary peer lets anyone write any address into the log and forge the trail
// an investigation would rely on. Entries that do not parse are dropped.
func WithTrustedProxies(cidrs ...string) Option {
	return func(c *config) {
		for _, s := range cidrs {
			if p, err := netip.ParsePrefix(s); err == nil {
				c.trusted = append(c.trusted, p)
				continue
			}
			if addr, err := netip.ParseAddr(s); err == nil {
				c.trusted = append(c.trusted, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}
	}
}

// WithSkipPaths drops the named paths from the log, matched exactly. Intended
// for health and metrics endpoints, which a monitor hits constantly and which
// say nothing when they succeed.
func WithSkipPaths(paths ...string) Option {
	return func(c *config) {
		if c.skip == nil {
			c.skip = make(map[string]bool, len(paths))
		}
		for _, p := range paths {
			c.skip[p] = true
		}
	}
}

// Middleware returns middleware that logs one line per request to logger.
//
// Wrapping goes through httpsnoop, which reproduces whichever optional
// interfaces the underlying ResponseWriter implements (Flusher, Hijacker,
// ReaderFrom, Pusher). A wrapper that drops one of those does not fail loudly:
// streaming stops flushing, an upgrade stops working, or a file copy quietly
// leaves the fast path.
func Middleware(logger *slog.Logger, opts ...Option) func(http.Handler) http.Handler {
	var cfg config
	for _, o := range opts {
		o(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.skip[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			m := httpsnoop.CaptureMetrics(next, w, r)

			// Path only, never RawQuery: query strings carry tokens, reset
			// codes and search terms, and an access log is the wrong place for
			// any of them.
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("proto", r.Proto),
				slog.Int("status", m.Code),
				slog.Int64("bytes", m.Written),
				slog.Float64("duration_ms", float64(m.Duration.Microseconds())/1000),
				slog.String("remote_addr", clientIP(r, cfg.trusted)),
			}
			attrs = appendIfSet(attrs, "user_agent", r.UserAgent())
			attrs = appendIfSet(attrs, "referer", r.Referer())
			if cfg.requestID != nil {
				attrs = appendIfSet(attrs, "request_id", cfg.requestID(r.Context()))
			}
			if cfg.identity != nil {
				attrs = appendIfSet(attrs, "identity", cfg.identity(r.Context()))
			}

			logger.LogAttrs(r.Context(), slog.LevelInfo, Message, attrs...)
		})
	}
}

// ErrorLog returns the *log.Logger to install as http.Server.ErrorLog, so the
// server's own errors (TLS handshake failures, malformed requests, connection
// faults) are logged at error level through logger.
//
// Left unset, net/http writes them to stderr unstructured, which puts them
// outside every level-based alert and, in a container, often outside the log
// pipeline entirely.
func ErrorLog(logger *slog.Logger) *log.Logger {
	return slog.NewLogLogger(logger.Handler(), slog.LevelError)
}

func appendIfSet(attrs []slog.Attr, key, val string) []slog.Attr {
	if val == "" {
		return attrs
	}
	return append(attrs, slog.String(key, val))
}

// clientIP returns the address to log for r.
//
// The peer address is used unless the peer is a configured proxy. When it is,
// the rightmost X-Forwarded-For entry that is not itself trusted is the closest
// hop we did not supply, and so the least forgeable address available: entries
// to its left were written by hops further out, including the client, and can
// say anything.
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	peer := hostOnly(r.RemoteAddr)
	if len(trusted) == 0 {
		return peer
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || !trustedAddr(addr, trusted) {
		return peer
	}

	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			continue
		}
		if !trustedAddr(hop, trusted) {
			return hop.String()
		}
	}
	return peer
}

func trustedAddr(addr netip.Addr, trusted []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// hostOnly strips the port from a RemoteAddr, tolerating an address that
// carries none.
func hostOnly(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
