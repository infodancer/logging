package logging

import (
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
// stdlib-log.Logger-shaped sink. Every message is emitted at error level, which
// is correct because these libraries route only faults -- panics, connection
// errors, and internal-error responses -- through these interfaces.
//
// Decorate the logger with a component attribute before wrapping so records are
// attributable, e.g. logging.NewStdLogger(logger.With("component", "imapd")).
type StdLogger struct {
	logger *slog.Logger
}

// NewStdLogger wraps logger in a StdLogger. A nil logger falls back to
// slog.Default().
func NewStdLogger(logger *slog.Logger) *StdLogger {
	if logger == nil {
		logger = slog.Default()
	}
	return &StdLogger{logger: logger}
}

// Printf formats as fmt.Sprintf and emits the result at error level.
func (l *StdLogger) Printf(format string, v ...any) {
	l.logger.Error(fmt.Sprintf(format, v...))
}

// Println formats as fmt.Sprintln (operands space-separated), trims the trailing
// newline, and emits the result at error level.
func (l *StdLogger) Println(v ...any) {
	l.logger.Error(strings.TrimSuffix(fmt.Sprintln(v...), "\n"))
}
