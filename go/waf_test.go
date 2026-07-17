package main

import (
	"strings"
	"testing"
)

func TestCreateWAF_EmbeddedCRS(t *testing.T) {
	directives := `SecRuleEngine On
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf`

	handle, rulesCount, err := createWAF(directives, "", "", 4096, 4096, 4096, false, matchedDataNone, 128)
	if err != nil {
		t.Fatalf("createWAF failed: %v", err)
	}
	defer destroyWAF(handle)

	if handle == 0 {
		t.Fatal("expected non-zero handle")
	}
	if rulesCount == 0 {
		t.Fatal("expected non-zero rules count with embedded CRS")
	}
	t.Logf("Loaded %d rules", rulesCount)
}

func TestCreateWAF_InvalidDirectives(t *testing.T) {
	directives := `SecRuleEngine On
Include /nonexistent/path/rules.conf`

	handle, _, err := createWAF(directives, "", "", 4096, 4096, 4096, false, matchedDataNone, 128)
	if err == nil {
		destroyWAF(handle)
		t.Fatal("expected error for invalid directives")
	}
	t.Logf("Got expected error: %v", err)
}

func TestCreateWAF_MinimalDirectives(t *testing.T) {
	directives := "SecRuleEngine On"
	handle, rulesCount, err := createWAF(directives, "", "", 4096, 4096, 4096, false, matchedDataNone, 128)
	if err != nil {
		t.Fatalf("createWAF failed: %v", err)
	}
	defer destroyWAF(handle)

	if handle == 0 {
		t.Fatal("expected non-zero handle")
	}
	// Minimal directives = no CRS rules loaded
	t.Logf("Loaded %d rules with minimal directives", rulesCount)
}

func TestDestroyWAF_NonexistentHandle(t *testing.T) {
	// Should not panic
	destroyWAF(999999)
}

func TestRetiredWAFClosesAfterLastTransactionLease(t *testing.T) {
	handle, _, err := createWAF("SecRuleEngine On", "", "", 4096, 4096, 4096, false, matchedDataNone, 128)
	if err != nil {
		t.Fatalf("createWAF failed: %v", err)
	}
	if !retainWAF(handle) {
		t.Fatal("expected to retain live WAF")
	}

	destroyWAF(handle)
	if _, err := getWAF(handle); err == nil {
		t.Fatal("retired WAF must reject new transactions")
	}
	if activeWAFCount() == 0 {
		t.Fatal("leased WAF must remain allocated while transaction is cached")
	}

	releaseWAF(handle)
	if _, err := getWAF(handle); err == nil {
		t.Fatal("released retired WAF must be removed")
	}
}

func TestMatchedDataLoggingIsBoundedAndSafeByDefault(t *testing.T) {
	secret := "password=super-secret\nsecond-line"
	if got := matchedDataForLog(secret, matchedDataNone, 128); got != "" {
		t.Fatalf("default mode must omit matched data, got %q", got)
	}
	if got := matchedDataForLog(secret, matchedDataHash, 128); !strings.HasPrefix(got, "sha256:") || strings.Contains(got, "super-secret") {
		t.Fatalf("hash mode must not expose payload, got %q", got)
	}
	if got := matchedDataForLog(secret, matchedDataTruncate, 12); got != "password=sup..." {
		t.Fatalf("truncate mode must sanitize and bound output, got %q", got)
	}
}
