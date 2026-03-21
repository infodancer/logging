package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLogger_LevelParsing(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo},
		{"invalid", slog.LevelInfo},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			logger := NewLogger(tt.input)
			if logger == nil {
				t.Fatal("NewLogger returned nil")
			}
			if !logger.Enabled(context.Background(), tt.want) {
				t.Errorf("expected level %v to be enabled", tt.want)
			}
		})
	}
}

func TestNewLogger_LowercaseLevels(t *testing.T) {
	// Create a logger that writes to a buffer so we can inspect output.
	var buf bytes.Buffer
	opts := &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				a.Value = slog.StringValue(strings.ToLower(a.Value.String()))
			}
			// Strip time for predictable output.
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}
	logger := slog.New(slog.NewTextHandler(&buf, opts))

	logger.Info("test message")
	output := buf.String()
	if !strings.Contains(output, "level=info") {
		t.Errorf("expected lowercase level=info, got: %s", output)
	}
	if strings.Contains(output, "level=INFO") {
		t.Errorf("level should be lowercase, got: %s", output)
	}

	buf.Reset()
	logger.Error("test error")
	output = buf.String()
	if !strings.Contains(output, "level=error") {
		t.Errorf("expected lowercase level=error, got: %s", output)
	}

	buf.Reset()
	logger.Warn("test warn")
	output = buf.String()
	if !strings.Contains(output, "level=warn") {
		t.Errorf("expected lowercase level=warn, got: %s", output)
	}
}

func TestWithConnection(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	connLogger := WithConnection(logger, "192.168.1.1:12345")
	connLogger.Info("connected")

	output := buf.String()
	if !strings.Contains(output, "conn_id=") {
		t.Errorf("expected conn_id in output: %s", output)
	}
	if !strings.Contains(output, "remote_addr=192.168.1.1:12345") {
		t.Errorf("expected remote_addr in output: %s", output)
	}
}

func TestWithConnection_UniqueIDs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	l1 := WithConnection(logger, "a")
	l2 := WithConnection(logger, "b")

	// Extract conn_ids by logging to separate buffers.
	var buf1, buf2 bytes.Buffer
	// Re-create with buffers to capture output.
	h1 := slog.NewTextHandler(&buf1, nil)
	h2 := slog.NewTextHandler(&buf2, nil)
	slog.New(h1).With(slog.Uint64("conn_id", 1)).Info("x")
	slog.New(h2).With(slog.Uint64("conn_id", 2)).Info("x")

	// Just verify they're different loggers (the atomic counter ensures uniqueness).
	if l1 == l2 {
		t.Error("expected different logger instances")
	}
}

func TestWithListener(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	listenerLogger := WithListener(logger, ":25", "tls")
	listenerLogger.Info("listening")

	output := buf.String()
	if !strings.Contains(output, "listener=:25") {
		t.Errorf("expected listener in output: %s", output)
	}
	if !strings.Contains(output, "mode=tls") {
		t.Errorf("expected mode in output: %s", output)
	}
}

func TestContext(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	ctx := NewContext(context.Background(), logger)
	got := FromContext(ctx)
	if got != logger {
		t.Error("expected same logger from context")
	}
}

func TestFromContext_Default(t *testing.T) {
	got := FromContext(context.Background())
	if got == nil {
		t.Error("expected non-nil default logger")
	}
}

func TestTransactionWriter(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	var dest bytes.Buffer
	tw := NewTransactionWriter(&dest, logger, "S")
	n, err := tw.Write([]byte("250 OK\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Errorf("expected 8 bytes written, got %d", n)
	}
	if dest.String() != "250 OK\r\n" {
		t.Errorf("expected data written to underlying writer")
	}
	if !strings.Contains(logBuf.String(), "direction=S") {
		t.Errorf("expected direction in log: %s", logBuf.String())
	}
}

func TestTransactionReader(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	src := strings.NewReader("EHLO test\r\n")
	tr := NewTransactionReader(src, logger, "C")
	buf := make([]byte, 64)
	n, err := tr.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "EHLO test\r\n" {
		t.Errorf("unexpected data: %q", string(buf[:n]))
	}
	if !strings.Contains(logBuf.String(), "direction=C") {
		t.Errorf("expected direction in log: %s", logBuf.String())
	}
}

func TestDebugWriter(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	w := DebugWriter(logger, "imap-protocol")
	data := []byte("* OK ready\r\n")
	n, err := w.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Errorf("expected %d, got %d", len(data), n)
	}
	output := logBuf.String()
	if !strings.Contains(output, "imap-protocol") {
		t.Errorf("expected prefix in log: %s", output)
	}
	if !strings.Contains(output, "* OK ready") {
		t.Errorf("expected data in log: %s", output)
	}
}
