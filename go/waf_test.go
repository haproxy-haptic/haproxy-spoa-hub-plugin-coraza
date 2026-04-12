package main

import (
	"testing"
)

func TestCreateWAF_EmbeddedCRS(t *testing.T) {
	directives := `SecRuleEngine On
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf`

	handle, rulesCount, err := createWAF(directives, "", "", 4096, 4096, 4096)
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

	handle, _, err := createWAF(directives, "", "", 4096, 4096, 4096)
	if err == nil {
		destroyWAF(handle)
		t.Fatal("expected error for invalid directives")
	}
	t.Logf("Got expected error: %v", err)
}

func TestCreateWAF_MinimalDirectives(t *testing.T) {
	directives := "SecRuleEngine On"
	handle, rulesCount, err := createWAF(directives, "", "", 4096, 4096, 4096)
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
