package httplog_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/infodancer/logging/httplog"
)

// newTestLogger returns a logger writing JSON to buf. Production uses the
// logfmt TextHandler, but the middleware only emits attributes, so JSON is
// used here purely because it parses back without guesswork.
func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

// logLines parses each line buf holds as one log record.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// oneLine returns the single record the middleware wrote.
func oneLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := logLines(t, buf)
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 log line, got %d: %s", len(lines), buf.String())
	}
	return lines[0]
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// TestLogsTheConventionalFields pins the schema. The log has to stand on its
// own wherever it is deployed: no reverse proxy is assumed, so every field a
// conventional access log carries is present without one.
func TestLogsTheConventionalFields(t *testing.T) {
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))

	r := httptest.NewRequest("GET", "http://example.test/articles/7", nil)
	r.RemoteAddr = "198.51.100.7:44321"
	r.Header.Set("User-Agent", "curl/8.0")
	r.Header.Set("Referer", "http://example.test/index.html")
	serve(h, r)

	line := oneLine(t, &buf)
	if line["msg"] != "http_access" {
		t.Errorf("msg = %v, want http_access", line["msg"])
	}
	for field, want := range map[string]any{
		"method":      "GET",
		"path":        "/articles/7",
		"proto":       "HTTP/1.1",
		"status":      float64(200),
		"bytes":       float64(5),
		"remote_addr": "198.51.100.7",
		"user_agent":  "curl/8.0",
		"referer":     "http://example.test/index.html",
	} {
		if got, ok := line[field]; !ok {
			t.Errorf("field %q missing from the access log: %v", field, line)
		} else if got != want {
			t.Errorf("field %q = %v, want %v", field, got, want)
		}
	}
	if _, ok := line["duration_ms"].(float64); !ok {
		t.Errorf("duration_ms missing or not a number: %v", line["duration_ms"])
	}
	if _, ok := line["time"]; !ok {
		t.Error("record carries no timestamp")
	}
}

// TestNeverLogsCredentials is the security property. A query string carries
// tokens and reset codes often enough that logging it is a credential leak, and
// the same goes for the headers that carry them.
func TestNeverLogsCredentials(t *testing.T) {
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest("GET", "http://example.test/reset?token=s3cr3t-token&next=/home", nil)
	r.Header.Set("Authorization", "Bearer s3cr3t-bearer")
	r.Header.Set("Cookie", "session=s3cr3t-cookie")
	serve(h, r)

	out := buf.String()
	for _, secret := range []string{"s3cr3t-token", "s3cr3t-bearer", "s3cr3t-cookie", "token=", "Authorization", "Cookie"} {
		if strings.Contains(out, secret) {
			t.Errorf("access log leaked %q: %s", secret, out)
		}
	}
	if line := oneLine(t, &buf); line["path"] != "/reset" {
		t.Errorf("path = %v, want /reset with the query dropped", line["path"])
	}
}

func TestStatusAndBytes(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantStatus float64
		wantBytes  float64
	}{
		{
			name:       "explicit status and body",
			handler:    func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(404); _, _ = w.Write([]byte("nope")) },
			wantStatus: 404,
			wantBytes:  4,
		},
		{
			// A handler that writes nothing still answered 200. Recording 0
			// would put a status no server ever sent into the log.
			name:       "implicit 200",
			handler:    func(http.ResponseWriter, *http.Request) {},
			wantStatus: 200,
			wantBytes:  0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := httplog.Middleware(newTestLogger(&buf))(tt.handler)
			serve(h, httptest.NewRequest("GET", "/", nil))

			line := oneLine(t, &buf)
			if line["status"] != tt.wantStatus {
				t.Errorf("status = %v, want %v", line["status"], tt.wantStatus)
			}
			if line["bytes"] != tt.wantBytes {
				t.Errorf("bytes = %v, want %v", line["bytes"], tt.wantBytes)
			}
		})
	}
}

// fullWriter implements the optional interfaces a real ResponseWriter may carry.
type fullWriter struct {
	httptest.ResponseRecorder
	flushed  bool
	hijacked bool
	readFrom bool
}

func (w *fullWriter) Flush() { w.flushed = true }

func (w *fullWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, nil
}

func (w *fullWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFrom = true
	return io.Copy(io.Discard, r)
}

// TestPreservesOptionalInterfaces is why this lives in one shared module. A
// wrapper that hides Flusher breaks SSE and MCP streaming; hiding Hijacker
// breaks WebSocket upgrades; hiding ReaderFrom silently drops the sendfile
// path static sites rely on. Every hand-written wrapper in our repos has got
// at least one of these wrong.
func TestPreservesOptionalInterfaces(t *testing.T) {
	var buf bytes.Buffer
	var sawFlusher, sawHijacker, sawReaderFrom, controllerFlushed bool

	h := httplog.Middleware(newTestLogger(&buf))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, sawFlusher = w.(http.Flusher)
		_, sawHijacker = w.(http.Hijacker)
		_, sawReaderFrom = w.(io.ReaderFrom)
		controllerFlushed = http.NewResponseController(w).Flush() == nil
	}))

	inner := &fullWriter{ResponseRecorder: *httptest.NewRecorder()}
	h.ServeHTTP(inner, httptest.NewRequest("GET", "/stream", nil))

	if !sawFlusher {
		t.Error("handler cannot see http.Flusher through the wrapper; SSE and MCP streaming break")
	}
	if !sawHijacker {
		t.Error("handler cannot see http.Hijacker through the wrapper; WebSocket upgrades break")
	}
	if !sawReaderFrom {
		t.Error("handler cannot see io.ReaderFrom through the wrapper; the sendfile path is lost")
	}
	if !controllerFlushed {
		t.Error("http.ResponseController cannot flush through the wrapper")
	}
	if !inner.flushed {
		t.Error("the flush never reached the underlying ResponseWriter")
	}
}

// TestClientIPTrustsOnlyConfiguredProxies pins that X-Forwarded-For is honoured
// only when the peer is a proxy we configured. Trusting it from anyone lets a
// client write whatever address it likes into our logs, which is how a
// header-spoofing bug becomes a forged audit trail.
func TestClientIPTrustsOnlyConfiguredProxies(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		xff        string
		want       string
	}{
		{
			name:       "no trusted proxies configured",
			remoteAddr: "203.0.113.5:5000",
			xff:        "1.2.3.4",
			want:       "203.0.113.5",
		},
		{
			name:       "peer is not a trusted proxy",
			trusted:    []string{"192.0.2.1/32"},
			remoteAddr: "203.0.113.5:5000",
			xff:        "1.2.3.4",
			want:       "203.0.113.5",
		},
		{
			name:       "peer is a trusted proxy",
			trusted:    []string{"192.0.2.1/32"},
			remoteAddr: "192.0.2.1:5000",
			xff:        "198.51.100.7",
			want:       "198.51.100.7",
		},
		{
			name:       "rightmost untrusted hop wins",
			trusted:    []string{"192.0.2.0/24"},
			remoteAddr: "192.0.2.1:5000",
			xff:        "1.2.3.4, 198.51.100.7, 192.0.2.9",
			want:       "198.51.100.7",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			opts := []httplog.Option{}
			if tt.trusted != nil {
				opts = append(opts, httplog.WithTrustedProxies(tt.trusted...))
			}
			h := httplog.Middleware(newTestLogger(&buf), opts...)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			r.Header.Set("X-Forwarded-For", tt.xff)
			serve(h, r)

			if got := oneLine(t, &buf)["remote_addr"]; got != tt.want {
				t.Errorf("remote_addr = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSkipPaths(t *testing.T) {
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf), httplog.WithSkipPaths("/v1/health", "/metrics"))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	for _, p := range []string{"/v1/health", "/metrics"} {
		serve(h, httptest.NewRequest("GET", p, nil))
	}
	if out := buf.String(); out != "" {
		t.Errorf("skipped paths were logged: %s", out)
	}

	serve(h, httptest.NewRequest("GET", "/articles", nil))
	if line := oneLine(t, &buf); line["path"] != "/articles" {
		t.Errorf("path = %v, want /articles", line["path"])
	}
}

// TestExtractorsSupplyRequestIDAndIdentity pins the layering: this module holds
// no notion of who the user is or where a request id comes from. A caller
// supplies them, so a richer layer can stack on top without this module
// depending on it.
func TestExtractorsSupplyRequestIDAndIdentity(t *testing.T) {
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf),
		httplog.WithRequestID(func(context.Context) string { return "req-42" }),
		httplog.WithIdentity(func(context.Context) string { return "matthew" }),
	)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	serve(h, httptest.NewRequest("GET", "/", nil))

	line := oneLine(t, &buf)
	if line["request_id"] != "req-42" {
		t.Errorf("request_id = %v, want req-42", line["request_id"])
	}
	if line["identity"] != "matthew" {
		t.Errorf("identity = %v, want matthew", line["identity"])
	}
}

// TestOptionalFieldsOmittedWhenEmpty keeps the line clean on the common path:
// a field nobody supplied is absent rather than present and empty.
func TestOptionalFieldsOmittedWhenEmpty(t *testing.T) {
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	serve(h, httptest.NewRequest("GET", "/", nil))

	line := oneLine(t, &buf)
	for _, field := range []string{"request_id", "identity", "referer"} {
		if _, ok := line[field]; ok {
			t.Errorf("field %q present with nothing to report: %v", field, line[field])
		}
	}
}

// TestErrorLog covers the other half of the contract: net/http writes its own
// internal errors (TLS handshake failures, malformed requests) to ErrorLog,
// and unset they go to stderr unstructured, outside every level-based alert.
func TestErrorLog(t *testing.T) {
	var buf bytes.Buffer
	httplog.ErrorLog(newTestLogger(&buf)).Printf("http: TLS handshake error from %s", "198.51.100.7:1234")

	line := oneLine(t, &buf)
	if line["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", line["level"])
	}
	if msg, _ := line["msg"].(string); !strings.Contains(msg, "TLS handshake error") {
		t.Errorf("msg = %v, want the server's error text", line["msg"])
	}
}

// A service has fields of its own worth putting on the request it just
// served -- how long a search spent embedding, which backend answered. Those
// belong on the access line, where they sit beside the status and the total
// duration, rather than on a second record nothing can join to this one.
func TestWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf),
		httplog.WithAttrs(func(ctx context.Context) []slog.Attr {
			return []slog.Attr{
				slog.Float64("embed_ms", 310.5),
				slog.Int("fts_calls", 5),
			}
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))

	serve(h, httptest.NewRequest("GET", "http://example.test/search", nil))

	line := oneLine(t, &buf)
	if got, want := line["embed_ms"], 310.5; got != want {
		t.Errorf("embed_ms = %v, want %v", got, want)
	}
	if got, want := line["fts_calls"], float64(5); got != want {
		t.Errorf("fts_calls = %v, want %v", got, want)
	}
	// The conventional fields are still there: extra attributes add to the
	// schema, they do not replace it.
	if line["method"] != "GET" || line["status"] != float64(200) {
		t.Errorf("standard fields missing: %v", line)
	}
}

// The attributes are gathered after the handler returns, which is what lets a
// handler fill in numbers it only knows once it has done the work.
func TestWithAttrsReadAfterHandler(t *testing.T) {
	type key struct{}
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf),
		httplog.WithAttrs(func(ctx context.Context) []slog.Attr {
			v, _ := ctx.Value(key{}).(*int)
			if v == nil {
				return nil
			}
			return []slog.Attr{slog.Int("work", *v)}
		}),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(key{}).(*int); ok {
			*v = 42
		}
	}))

	counter := 0
	r := httptest.NewRequest("GET", "http://example.test/x", nil).
		WithContext(context.WithValue(context.Background(), key{}, &counter))
	serve(h, r)

	if got := oneLine(t, &buf)["work"]; got != float64(42) {
		t.Errorf("work = %v, want the value the handler set (42)", got)
	}
}

// An empty or nil return adds nothing, so a request with no numbers to report
// logs exactly the conventional line.
func TestWithAttrsEmpty(t *testing.T) {
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf),
		httplog.WithAttrs(func(context.Context) []slog.Attr { return nil }),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))

	serve(h, httptest.NewRequest("GET", "http://example.test/x", nil))
	line := oneLine(t, &buf)
	if line["method"] != "GET" {
		t.Errorf("standard fields missing: %v", line)
	}
}

// Several callers can each contribute, so a service need not funnel every
// field through one function.
func TestWithAttrsAccumulates(t *testing.T) {
	var buf bytes.Buffer
	h := httplog.Middleware(newTestLogger(&buf),
		httplog.WithAttrs(func(context.Context) []slog.Attr { return []slog.Attr{slog.String("a", "1")} }),
		httplog.WithAttrs(func(context.Context) []slog.Attr { return []slog.Attr{slog.String("b", "2")} }),
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))

	serve(h, httptest.NewRequest("GET", "http://example.test/x", nil))
	line := oneLine(t, &buf)
	if line["a"] != "1" || line["b"] != "2" {
		t.Errorf("want both contributions, got: %v", line)
	}
}

// A service often needs the client address for something other than the access
// line -- an audit record, a rate limiter, a notification -- and must not
// reimplement the trust rule to get it. Two hand-rolled versions of this
// resolve differently, and the naive one (leftmost entry, no trust check) hands
// every caller an address the client chose.
func TestProxiesClientIP(t *testing.T) {
	cf := "104.16.0.0/13"
	docker := "172.21.0.0/16"

	tests := []struct {
		name    string
		trusted []string
		peer    string
		xff     string
		want    string
	}{
		{
			name:    "no trusted proxies ignores the header",
			trusted: nil,
			peer:    "198.51.100.4:5000",
			xff:     "10.0.0.1",
			want:    "198.51.100.4",
		},
		{
			name:    "untrusted peer ignores the header",
			trusted: []string{docker},
			peer:    "203.0.113.9:5000",
			xff:     "10.0.0.1",
			want:    "203.0.113.9",
		},
		{
			name:    "one trusted hop yields the client",
			trusted: []string{docker},
			peer:    "172.21.0.9:5000",
			xff:     "203.0.113.7",
			want:    "203.0.113.7",
		},
		{
			name:    "two trusted hops skip past both",
			trusted: []string{docker, cf},
			peer:    "172.21.0.9:5000",
			xff:     "203.0.113.7, 104.16.5.5",
			want:    "203.0.113.7",
		},
		{
			name:    "a client-supplied prefix cannot reach past the trusted hops",
			trusted: []string{docker, cf},
			peer:    "172.21.0.9:5000",
			xff:     "9.9.9.9, 203.0.113.7, 104.16.5.5",
			want:    "203.0.113.7",
		},
		{
			name:    "garbage entries are skipped, not returned",
			trusted: []string{docker},
			peer:    "172.21.0.9:5000",
			xff:     "not-an-ip, 203.0.113.7",
			want:    "203.0.113.7",
		},
		{
			name:    "no header falls back to the peer",
			trusted: []string{docker},
			peer:    "172.21.0.9:5000",
			xff:     "",
			want:    "172.21.0.9",
		},
		{
			name:    "an unparseable CIDR is dropped, so nothing is trusted by accident",
			trusted: []string{"not-a-cidr"},
			peer:    "172.21.0.9:5000",
			xff:     "203.0.113.7",
			want:    "172.21.0.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://example.test/", nil)
			r.RemoteAddr = tt.peer
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := httplog.NewProxies(tt.trusted...).ClientIP(r); got != tt.want {
				t.Errorf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

// The middleware and the exported helper must agree: two answers to "who is the
// client" is the bug this exists to prevent.
func TestProxiesClientIPMatchesTheAccessLine(t *testing.T) {
	var buf bytes.Buffer
	trusted := []string{"172.21.0.0/16", "104.16.0.0/13"}
	h := httplog.Middleware(newTestLogger(&buf), httplog.WithTrustedProxies(trusted...))(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = "172.21.0.9:5000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 104.16.5.5")
	serve(h, r)

	logged, _ := oneLine(t, &buf)["remote_addr"].(string)
	direct := httplog.NewProxies(trusted...).ClientIP(r)
	if logged != direct {
		t.Errorf("access line logged %q but ClientIP returned %q", logged, direct)
	}
}
