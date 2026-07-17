package main

import (
	"strings"
	"testing"
)

func TestRecoveredPanicNeverExposesPanicPayload(t *testing.T) {
	func() {
		defer recoverPanic("test-secret-panic")
		panic("request-body-secret")
	}()

	lastErrorMu.Lock()
	err := lastError
	lastError = ""
	lastErrorMu.Unlock()
	if strings.Contains(err, "request-body-secret") {
		t.Fatalf("panic payload leaked through last error: %q", err)
	}
	if err != "panic in test-secret-panic" {
		t.Fatalf("unexpected sanitized panic error: %q", err)
	}
}

func TestUnknownInterruptionActionFailsClosed(t *testing.T) {
	if got := actionToCString("future-disruptive-action"); got != actionDeny {
		t.Fatal("unknown interruption action must map to deny")
	}
	if got := actionToCString("allow"); got != actionAllow {
		t.Fatal("explicit allow action must remain allow")
	}
}
