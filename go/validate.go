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
	"io/fs"
	"sync"
	"unsafe"

	"github.com/KimMachineGun/automemlimit/memlimit"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/jcchavezs/mergefs"
	osfs "github.com/jcchavezs/mergefs/io"
)

// The host and other native plugins need headroom outside this Go runtime.
var configureValidationMemory = sync.OnceValue(func() error {
	_, err := memlimit.Set(memlimit.WithRatio(0.4))
	return err
})

var validationCompileSlots = make(chan struct{}, 2)
var previousValidationMu sync.Mutex

// One generation keeps shared compiled expressions warm without retaining superseded rules.
var previousValidationWAF experimental.WAFCloser

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
func (e *capturedEvent) Uint(_ string, _ uint) debuglog.Event             { return e }
func (e *capturedEvent) Stringer(_ string, _ fmt.Stringer) debuglog.Event { return e }
func (e *capturedEvent) IsEnabled() bool                                  { return true }

// noopEvent absorbs Trace/Debug/Info chains without recording anything.
type noopEvent struct{}

func (noopEvent) Msg(_ string)                                       {}
func (n noopEvent) Str(_, _ string) debuglog.Event                   { return n }
func (n noopEvent) Err(_ error) debuglog.Event                       { return n }
func (n noopEvent) Bool(_ string, _ bool) debuglog.Event             { return n }
func (n noopEvent) Int(_ string, _ int) debuglog.Event               { return n }
func (n noopEvent) Uint(_ string, _ uint) debuglog.Event             { return n }
func (n noopEvent) Stringer(_ string, _ fmt.Stringer) debuglog.Event { return n }
func (n noopEvent) IsEnabled() bool                                  { return false }

// coraza_validate_directives compiles a directives string via Coraza's
// public API and returns captured diagnostics as a JSON-serialised
// `[]capturedDiagnostic`.
//
// The returned C string is heap-allocated and MUST be freed by the
// caller via `coraza_free_string`.
//
//export coraza_validate_directives
func coraza_validate_directives(
	directives *C.char,
	directivesLen C.int,
	stagedFilesJSON *C.char,
) *C.char {
	defer recoverPanic("coraza_validate_directives")

	if directives == nil || directivesLen <= 0 {
		// Empty input → empty diagnostics. The validator's caller
		// decides whether to treat empty directives as an error
		// (validate() is just one input source).
		return C.CString("[]")
	}

	return marshalDiagnostics(validateDirectives(
		C.GoStringN(directives, directivesLen),
		goStagedFilesJSON(stagedFilesJSON),
	))
}

// validateDirectives is the whole of the validation logic, kept free of cgo
// types so it is reachable from tests — the exported symbol above is only the
// FFI shell.
func validateDirectives(directives, stagedFilesJSON string) []capturedDiagnostic {
	return promoteEmptyGlobs(validateDirectivesRaw(directives, stagedFilesJSON))
}

// validateDirectivesRaw compiles the directives and returns Coraza's
// diagnostics as reported, before any severity promotion. Split out so a test
// can assert the wording the promotion keys on.
func validateDirectivesRaw(directives, stagedFilesJSON string) []capturedDiagnostic {
	if err := configureValidationMemory(); err != nil {
		return []capturedDiagnostic{{Severity: "error", Message: "configure validation memory budget: " + err.Error()}}
	}
	validationCompileSlots <- struct{}{}
	defer func() { <-validationCompileSlots }()

	captured := make([]capturedDiagnostic, 0)
	logger := &capturedLogger{diagnostics: &captured}

	staged, stagedErr := parseStagedFiles(stagedFilesJSON)
	if stagedErr != nil {
		return append(captured, capturedDiagnostic{
			Severity: "error",
			Line:     0,
			Message:  stagedErr.Error(),
		})
	}

	// Mirror the production `createWAF` rootFS setup so directives that
	// reference the embedded CRS (`@coraza.conf-recommended`,
	// `@owasp_crs/*.conf`) resolve identically here. Without this,
	// validating a config that production accepts would synthesize
	// false-positive "no such file or directory" errors.
	//
	// Staged files sit between the embedded CRS and the OS layer, so they
	// shadow the real filesystem: the validator runs in the controller pod,
	// where a path like /etc/haproxy/general/crs/*.conf either does not exist
	// or belongs to something else entirely. What the request carries is the
	// content about to be deployed, and that is what must be compiled. The OS
	// layer stays last so a genuinely on-disk include still resolves.
	filesystems := []fs.FS{coreruleset.FS}
	if len(staged) > 0 {
		filesystems = append(filesystems, newStagedFS(staged))
	}
	filesystems = append(filesystems, osfs.OSFS)

	cfg := coraza.NewWAFConfig().
		WithDebugLogger(logger).
		WithRootFS(mergefs.Merge(filesystems...)).
		WithDirectives(directives)

	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		// Build a final error diagnostic carrying the wrapped error
		// message. Use the line of the most recent captured entry as
		// best-effort positioning — the parser logs the per-directive
		// context just before NewWAF returns the wrapped error.
		line := 0
		if len(captured) > 0 {
			line = captured[len(captured)-1].Line
		}
		captured = append(captured, capturedDiagnostic{
			Severity: "error",
			Line:     line,
			Message:  err.Error(),
		})
	} else {
		previousValidationMu.Lock()
		previous := previousValidationWAF
		previousValidationWAF = waf.(experimental.WAFCloser)
		previousValidationMu.Unlock()
		if previous != nil {
			if err := previous.Close(); err != nil {
				captured = append(captured, capturedDiagnostic{
					Severity: "warning",
					Message:  "release previous validation resources: " + err.Error(),
				})
			}
		}
	}

	return captured
}

// corazaEmptyGlobMessage is what Coraza logs when an `Include` pattern matches
// no files (internal/seclang/parser.go). It is matched by text because Coraza
// attaches no structured field naming the pattern — only a line number.
const corazaEmptyGlobMessage = "empty glob result"

// promoteEmptyGlobs turns "this Include matched nothing" from a warning into an
// error.
//
// Coraza only warns, which means a ruleset that never reached the pod compiles
// to whatever the OTHER includes contributed and validates clean. That is
// indistinguishable from the ruleset having arrived, and it is silent: the WAF
// runs with rules missing and nothing says so. A rule-count check does not
// catch it either — `@coraza.conf-recommended` alone contributes rules, so the
// count is non-zero with the entire ruleset absent.
//
// Deliberately validate-only. Admission refuses a config whose files are not
// all there; the runtime path keeps its warning, so an already-running fleet is
// not taken down by an upstream that went away after it was admitted.
//
// The message coupling is pinned by TestPromoteEmptyGlobs_MatchesCorazaWording,
// which fails if a Coraza upgrade changes the text — the alternative to
// coupling is fail-open, which is not a trade worth making.
func promoteEmptyGlobs(captured []capturedDiagnostic) []capturedDiagnostic {
	for i := range captured {
		if captured[i].Severity == "warning" && captured[i].Message == corazaEmptyGlobMessage {
			captured[i].Severity = "error"
			captured[i].Message = corazaEmptyGlobMessage +
				": an Include matched no files, so those rules are missing from the compiled WAF"
		}
	}
	return captured
}

// goStagedFilesJSON reads the optional staged-files payload. A nil pointer is
// the ordinary case: a config that includes nothing off disk.
func goStagedFilesJSON(payload *C.char) string {
	if payload == nil {
		return ""
	}
	return C.GoString(payload)
}

// marshalDiagnostics renders the captured diagnostics as the JSON array the
// Rust side parses.
func marshalDiagnostics(captured []capturedDiagnostic) *C.char {
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
