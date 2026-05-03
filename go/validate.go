package main

// Plugin-API `validate()` support: compile a directives string via
// `coraza.NewWAF(WithDirectives(...))`, capturing the SecLang parser's
// structured log events (which carry `line` fields) so we can surface
// line/column-precise diagnostics back to the Rust side and ultimately
// HAPTIC's admission webhook.
//
// The Coraza Go API doesn't return line numbers in its error: the
// returned `error` is just a string ("unknown directive 'foo'", "failed
// to compile rule X", etc.). The parser logs each warning/error as a
// structured event with `Int("line", n)` via the WAF's debug logger
// (see `internal/seclang/parser.go`). We attach a custom logger that
// captures those events into a Go slice; on `NewWAF` failure we
// serialise the captured slice plus the wrapped error message and
// return JSON across the FFI for the Rust side to deserialise into
// `Vec<plugin_api::Diagnostic>`.

// #include <stdlib.h>
import "C"

import (
	"encoding/json"
	"fmt"
	"io"
	"unsafe"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
)

// capturedDiagnostic mirrors plugin_api::Diagnostic on the wire.
// Severity is "warning" or "error"; the column is always 0 because
// Coraza's parser only tracks line.
type capturedDiagnostic struct {
	Severity string `json:"severity"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// capturedLogger implements `debuglog.Logger` and forwards every
// Warn/Error call into a slice via `capturedEvent.Msg`. Lower-level
// events (Trace/Debug/Info) are accepted but ignored — the parser
// emits unknown-directive and rule-compile failures at Warn/Error.
type capturedLogger struct {
	diagnostics *[]capturedDiagnostic
}

func (l *capturedLogger) WithOutput(_ io.Writer) debuglog.Logger { return l }
func (l *capturedLogger) WithLevel(_ debuglog.Level) debuglog.Logger {
	return l
}
func (l *capturedLogger) With(_ ...debuglog.ContextField) debuglog.Logger {
	return l
}

func (l *capturedLogger) Trace() debuglog.Event { return noopEvent{} }
func (l *capturedLogger) Debug() debuglog.Event { return noopEvent{} }
func (l *capturedLogger) Info() debuglog.Event  { return noopEvent{} }
func (l *capturedLogger) Warn() debuglog.Event {
	return &capturedEvent{diagnostics: l.diagnostics, severity: "warning"}
}
func (l *capturedLogger) Error() debuglog.Event {
	return &capturedEvent{diagnostics: l.diagnostics, severity: "error"}
}

// capturedEvent collects the line and message fields from a single
// Logger.Warn() / Logger.Error() builder chain. The chain ends with
// `Msg(...)`, at which point we append a `capturedDiagnostic`.
type capturedEvent struct {
	diagnostics *[]capturedDiagnostic
	severity    string
	line        int
}

func (e *capturedEvent) Msg(msg string) {
	*e.diagnostics = append(*e.diagnostics, capturedDiagnostic{
		Severity: e.severity,
		Line:     e.line,
		Message:  msg,
	})
}

func (e *capturedEvent) Str(_, _ string) debuglog.Event       { return e }
func (e *capturedEvent) Err(_ error) debuglog.Event           { return e }
func (e *capturedEvent) Bool(_ string, _ bool) debuglog.Event { return e }
func (e *capturedEvent) Int(key string, i int) debuglog.Event {
	if key == "line" {
		e.line = i
	}
	return e
}
func (e *capturedEvent) Uint(_ string, _ uint) debuglog.Event              { return e }
func (e *capturedEvent) Stringer(_ string, _ fmt.Stringer) debuglog.Event  { return e }
func (e *capturedEvent) IsEnabled() bool                                   { return true }

// noopEvent absorbs Trace/Debug/Info chains without recording anything.
type noopEvent struct{}

func (noopEvent) Msg(_ string)                                        {}
func (n noopEvent) Str(_, _ string) debuglog.Event                    { return n }
func (n noopEvent) Err(_ error) debuglog.Event                        { return n }
func (n noopEvent) Bool(_ string, _ bool) debuglog.Event              { return n }
func (n noopEvent) Int(_ string, _ int) debuglog.Event                { return n }
func (n noopEvent) Uint(_ string, _ uint) debuglog.Event              { return n }
func (n noopEvent) Stringer(_ string, _ fmt.Stringer) debuglog.Event  { return n }
func (n noopEvent) IsEnabled() bool                                   { return false }

// coraza_validate_directives compiles a directives string via Coraza's
// public API and returns captured diagnostics as a JSON-serialised
// `[]capturedDiagnostic`.
//
// The returned C string is heap-allocated and MUST be freed by the
// caller via `coraza_free_string`.
//
//export coraza_validate_directives
func coraza_validate_directives(directives *C.char, directivesLen C.int) *C.char {
	defer recoverPanic("coraza_validate_directives")

	if directives == nil || directivesLen <= 0 {
		// Empty input → empty diagnostics. The validator's caller
		// decides whether to treat empty directives as an error
		// (validate() is just one input source).
		return C.CString("[]")
	}

	goDirectives := C.GoStringN(directives, directivesLen)
	captured := make([]capturedDiagnostic, 0)
	logger := &capturedLogger{diagnostics: &captured}

	cfg := coraza.NewWAFConfig().
		WithDebugLogger(logger).
		WithDirectives(goDirectives)

	_, err := coraza.NewWAF(cfg)
	if err != nil {
		// Build a final error diagnostic carrying the wrapped error
		// message. Use the line of the most recent captured entry as
		// best-effort positioning — the parser logs the
		// per-directive context just before NewWAF returns the
		// wrapped error.
		line := 0
		if len(captured) > 0 {
			line = captured[len(captured)-1].Line
		}
		captured = append(captured, capturedDiagnostic{
			Severity: "error",
			Line:     line,
			Message:  err.Error(),
		})
	}

	body, marshalErr := json.Marshal(captured)
	if marshalErr != nil {
		// Should be unreachable — capturedDiagnostic is plain JSON.
		// On the off chance, return a sentinel error diagnostic.
		fallback := []capturedDiagnostic{{
			Severity: "error",
			Line:     0,
			Message:  fmt.Sprintf("internal: failed to marshal validation diagnostics: %v", marshalErr),
		}}
		body, _ = json.Marshal(fallback)
	}

	return C.CString(string(body))
}

// Free a string that was allocated by coraza_validate_directives or
// any other Go-side allocator using C.CString. The Rust side owns
// the lifetime of these strings; calling free here is just
// `C.free` on the buffer.
//
// (We rely on the existing `coraza_free_string` exported function
// for this — defined alongside `lib.go`'s metric helpers — so no new
// FFI symbol is required for cleanup.)
var _ = unsafe.Pointer(nil) // silence unused-import in some build configs
