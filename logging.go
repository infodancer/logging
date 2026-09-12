// Package logging provides structured logfmt logging for infodancer services.
//
// All output uses slog.TextHandler with lowercased level values
// (info, warn, error, debug) for compatibility with Loki's logfmt parser.
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
)

// contextKey is used for storing loggers in context.
type contextKey struct{}

var loggerKey = contextKey{}

// connectionCounter is used to generate unique connection IDs.
var connectionCounter atomic.Uint64

// NewLogger creates a new slog.Logger writing to stderr with the specified
// level. Level values are case-insensitive: debug, info, warn/warning, error.
// The default level is info.
func NewLogger(level string) *slog.Logger {
	return NewLoggerTo(os.Stderr, level)
}

// NewLoggerTo is NewLogger with an explicit destination. A service whose
// entry point already owns an output writer -- a daemon that hands its tests
// an io.Discard, a command that writes to a buffer -- routes logging through
// that writer instead of reaching past it to stderr. A nil writer means
// stderr, so a zero value behaves like NewLogger rather than panicking on the
// first record.
func NewLoggerTo(w io.Writer, level string) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}

	opts := &slog.HandlerOptions{
		Level: parseLevel(level),
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
			}
			return a
		},
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// parseLevel maps a case-insensitive level name to its slog.Level. Anything
// unrecognized, the empty string included, is info: a typo in a config file
// should not silence a service.
func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithConnection returns a new logger with connection-specific attributes.
// It generates a unique connection ID for log correlation.
func WithConnection(logger *slog.Logger, remoteAddr string) *slog.Logger {
	connID := connectionCounter.Add(1)
	return logger.With(
		slog.Uint64("conn_id", connID),
		slog.String("remote_addr", remoteAddr),
	)
}

// WithListener returns a new logger with listener-specific attributes.
func WithListener(logger *slog.Logger, address string, mode string) *slog.Logger {
	return logger.With(
		slog.String("listener", address),
		slog.String("mode", mode),
	)
}

// FromContext retrieves the logger from the context.
// Returns the default logger if none is found.
func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

// NewContext returns a new context with the logger attached.
func NewContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// TransactionWriter wraps an io.Writer to log all data written.
// Used for debugging protocol transactions at debug level.
type TransactionWriter struct {
	w      io.Writer
	logger *slog.Logger
	prefix string
}

// NewTransactionWriter creates a writer that logs all data.
func NewTransactionWriter(w io.Writer, logger *slog.Logger, prefix string) *TransactionWriter {
	return &TransactionWriter{
		w:      w,
		logger: logger,
		prefix: prefix,
	}
}

// Write writes data and logs it.
func (tw *TransactionWriter) Write(p []byte) (n int, err error) {
	n, err = tw.w.Write(p)
	if n > 0 {
		tw.logger.Debug("transaction",
			slog.String("direction", tw.prefix),
			slog.String("data", string(p[:n])),
		)
	}
	return n, err
}

// TransactionReader wraps an io.Reader to log all data read.
type TransactionReader struct {
	r      io.Reader
	logger *slog.Logger
	prefix string
}

// NewTransactionReader creates a reader that logs all data.
func NewTransactionReader(r io.Reader, logger *slog.Logger, prefix string) *TransactionReader {
	return &TransactionReader{
		r:      r,
		logger: logger,
		prefix: prefix,
	}
}

// Read reads data and logs it.
func (tr *TransactionReader) Read(p []byte) (n int, err error) {
	n, err = tr.r.Read(p)
	if n > 0 {
		tr.logger.Debug("transaction",
			slog.String("direction", tr.prefix),
			slog.String("data", string(p[:n])),
		)
	}
	return n, err
}

// DebugWriter returns an io.Writer that logs each Write call as a debug-level
// message with the given prefix. Useful for routing protocol-level debug output
// (e.g., go-imap's DebugWriter) through structured logging.
func DebugWriter(logger *slog.Logger, prefix string) io.Writer {
	return &debugWriter{logger: logger, prefix: prefix}
}

type debugWriter struct {
	logger *slog.Logger
	prefix string
}

func (dw *debugWriter) Write(p []byte) (int, error) {
	dw.logger.Debug(dw.prefix, slog.String("data", string(p)))
	return len(p), nil
}
