package logging

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// bufferLogger returns a logger writing to a buffer at debug level so every
// record is captured, plus the buffer for assertions.
func bufferLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), &buf
}

func TestStdLogger_Printf_EmitsErrorLevel(t *testing.T) {
	logger, buf := bufferLogger()

	// The exact shape go-imap/go-smtp use before emitting an internal-error
	// response to the client.
	NewStdLogger(logger).Printf("handling %v command: %v", "FETCH", errors.New("boom"))

	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("expected error level, got: %q", out)
	}
	if !strings.Contains(out, "handling FETCH command: boom") {
		t.Errorf("expected formatted message, got: %q", out)
	}
}

func TestStdLogger_Println_EmitsErrorLevel(t *testing.T) {
	logger, buf := bufferLogger()

	NewStdLogger(logger).Println("panic serving", "1.2.3.4", errors.New("boom"))

	out := buf.String()
	if !strings.Contains(out, "level=ERROR") {
		t.Errorf("expected error level, got: %q", out)
	}
	// fmt.Sprintln space-separates operands; the trailing newline must be trimmed
	// so it does not corrupt the single-line logfmt record.
	if !strings.Contains(out, `msg="panic serving 1.2.3.4 boom"`) {
		t.Errorf("expected space-joined message without trailing newline, got: %q", out)
	}
}

func TestNewStdLogger_NilFallsBackToDefault(t *testing.T) {
	// Must not panic with a nil logger.
	NewStdLogger(nil).Printf("no logger set: %d", 1)
}
