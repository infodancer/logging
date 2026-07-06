package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// StdLogger adapts a *slog.Logger to the Printf/Println-style error-log sinks
// that several third-party libraries expose. When such a sink is left unset the
// library falls back to log.Default(), dumping internal faults to stderr
// unstructured, levelless, and outside the slog pipeline. Wrapping a slog logger
// in a StdLogger and assigning it keeps those faults in structured logging.
//
// It satisfies both go-imap's imapserver.Logger (Printf only) and go-smtp's
// Server.ErrorLog (Printf + Println), and any consumer expecting a
// stdlib-log.Logger-shaped sink.
//
// By default every message is emitted at error level, which suits sinks that
// carry only faults. When a sink also carries benign, client-caused events
// (malformed input, disconnects), supply a LevelFunc via NewStdLoggerFunc to
// reclassify per message -- the library's Printf/Println interface has no level,
// so the consumer owns that policy.
//
// Decorate the logger with a component attribute before wrapping so records are
// attributable, e.g. logging.NewStdLogger(logger.With("component", "imapd")).
type StdLogger struct {
	logger *slog.Logger
	level  LevelFunc // nil => always slog.LevelError
}

// LevelFunc maps a formatted log message to the slog.Level it should be emitted
// at. It lets a consumer reclassify messages from libraries whose logger
// interface carries no level -- e.g. demoting benign client-caused protocol
// errors below error while keeping genuine faults at error.
type LevelFunc func(msg string) slog.Level

// NewStdLogger wraps logger in a StdLogger that emits every message at error
// level. A nil logger falls back to slog.Default().
func NewStdLogger(logger *slog.Logger) *StdLogger {
	return NewStdLoggerFunc(logger, nil)
}

// NewStdLoggerFunc wraps logger in a StdLogger that emits each message at the
// level returned by level(msg). A nil level behaves like NewStdLogger (every
// message at error level). A nil logger falls back to slog.Default().
func NewStdLoggerFunc(logger *slog.Logger, level LevelFunc) *StdLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &StdLogger{logger: logger, level: level}
}

// emit logs msg at the classified level (error by default).
func (l *StdLogger) emit(msg string) {
	level := slog.LevelError
	if l.level != nil {
		level = l.level(msg)
	}
	l.logger.Log(context.Background(), level, msg)
}

// Printf formats as fmt.Sprintf and emits the result at the classified level.
func (l *StdLogger) Printf(format string, v ...any) {
	l.emit(fmt.Sprintf(format, v...))
}

// Println formats as fmt.Sprintln (operands space-separated), trims the trailing
// newline, and emits the result at the classified level.
func (l *StdLogger) Println(v ...any) {
	l.emit(strings.TrimSuffix(fmt.Sprintln(v...), "\n"))
}
