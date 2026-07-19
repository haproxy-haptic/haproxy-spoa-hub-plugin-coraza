package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// setupTestWAF creates a WAF instance with embedded CRS for testing.
func setupTestWAF(t *testing.T) uint64 {
	t.Helper()
	directives := `SecRuleEngine On
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf`

	handle, _, err := createWAF(directives, "", "", 4096, 4096, 4096, false, matchedDataNone, 128)
	if err != nil {
		t.Fatalf("setupTestWAF: %v", err)
	}
	return handle
}

func TestParseHeaders(t *testing.T) {
	// Validate the null-separated key-value format used by the FFI layer.
	// This mirrors the logic in parseHeaders() but without CGo types.
	input := "Host\x00example.com\x00User-Agent\x00Mozilla/5.0\x00"
	parts := strings.Split(input, "\x00")

	var pairs []headerPair
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] != "" {
			pairs = append(pairs, headerPair{key: parts[i], value: parts[i+1]})
		}
	}

	if len(pairs) != 2 {
		t.Fatalf("expected 2 header pairs, got %d", len(pairs))
	}
	if pairs[0].key != "Host" || pairs[0].value != "example.com" {
		t.Errorf("unexpected first header: %v", pairs[0])
	}
	if pairs[1].key != "User-Agent" || pairs[1].value != "Mozilla/5.0" {
		t.Errorf("unexpected second header: %v", pairs[1])
	}
}

func TestProcessRequestGo_BenignRequest(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, err := getWAF(handle)
	if err != nil {
		t.Fatalf("getWAF: %v", err)
	}

	tx := inst.waf.NewTransactionWithID("test-benign")
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessConnection("192.168.1.1", 12345, "10.0.0.1", 80)
	tx.ProcessURI("/index.html", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddRequestHeader("User-Agent", "Mozilla/5.0")

	it := tx.ProcessRequestHeaders()
	if it != nil {
		t.Errorf("expected no interruption for benign request, got rule %d", it.RuleID)
	}
}

func TestProcessRequestGo_SQLInjection(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, err := getWAF(handle)
	if err != nil {
		t.Fatalf("getWAF: %v", err)
	}

	tx := inst.waf.NewTransactionWithID("test-sqli")
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessConnection("192.168.1.1", 12345, "10.0.0.1", 80)
	tx.ProcessURI("/search?id=1'+OR+1=1+--", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")

	// CRS uses anomaly scoring: rules accumulate score during header
	// processing, but the blocking decision happens at ProcessRequestBody.
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	// Check for CRS anomaly scoring detection.
	// CRS v4 rule 949110 fires when the inbound anomaly score exceeds
	// the configured threshold. Our buildResult() checks for this rule
	// to generate a deny decision.
	hasAnomalyExceeded := false
	for _, mr := range tx.MatchedRules() {
		ruleID := mr.Rule().ID()
		if ruleID == 949110 || ruleID == 949111 {
			hasAnomalyExceeded = true
			t.Logf("SQL injection blocked by CRS anomaly scoring: rule=%d msg=%s",
				ruleID, mr.Message())
			break
		}
	}
	if !hasAnomalyExceeded && !tx.IsInterrupted() {
		t.Error("expected SQL injection to be blocked by CRS anomaly scoring")
	}
}

func TestProcessRequestGo_EmptyBody(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, err := getWAF(handle)
	if err != nil {
		t.Fatalf("getWAF: %v", err)
	}

	tx := inst.waf.NewTransactionWithID("test-empty-body")
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessConnection("192.168.1.1", 12345, "10.0.0.1", 80)
	tx.ProcessURI("/api/data", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.AddRequestHeader("Content-Type", "application/json")

	it := tx.ProcessRequestHeaders()
	if it != nil {
		t.Errorf("expected no interruption for empty body POST, got rule %d", it.RuleID)
		return
	}

	bodyIt, err := tx.ProcessRequestBody()
	if err != nil {
		t.Logf("ProcessRequestBody error (expected for empty body): %v", err)
	}
	if bodyIt != nil {
		t.Errorf("expected no interruption for empty body, got rule %d", bodyIt.RuleID)
	}
}

func TestProcessResponseGo_CachedTransaction(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, _ := getWAF(handle)

	// Create and process request phase, cache the transaction
	tx := inst.waf.NewTransactionWithID("resp-test-1")
	tx.ProcessConnection("192.168.1.1", 12345, "10.0.0.1", 80)
	tx.ProcessURI("/api/data", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	if !cacheTransaction("resp-test-1", tx, handle, 10_000_000_000, 10) {
		t.Fatal("expected transaction to be cached")
	}

	// Retrieve and process response phase
	entry := takeCachedTransaction("resp-test-1")
	if entry == nil {
		t.Fatal("expected cached transaction")
	}
	defer releaseWAF(entry.wafHandle)
	cached := entry.tx

	cached.AddResponseHeader("Content-Type", "text/html")
	it := cached.ProcessResponseHeaders(200, "HTTP/1.1")
	if it != nil {
		t.Logf("Response headers interrupted: rule=%d", it.RuleID)
	}

	_, _, _ = cached.WriteResponseBody([]byte("<html>OK</html>"))
	respIt, _ := cached.ProcessResponseBody()
	if respIt != nil {
		t.Logf("Response body interrupted: rule=%d", respIt.RuleID)
	}

	cached.ProcessLogging()
	cached.Close()
}

func TestDetectOnlyResponseProcessingRemainsSynchronous(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, _ := getWAF(handle)

	// Create and process request phase, cache the transaction
	tx := inst.waf.NewTransactionWithID("detect-only-test")
	tx.ProcessConnection("192.168.1.1", 12345, "10.0.0.1", 80)
	tx.ProcessURI("/api/data", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	if !cacheTransaction("detect-only-test", tx, handle, 10_000_000_000, 10) {
		t.Fatal("expected transaction to be cached")
	}

	// Detect-only changes the verdict, not the execution boundary: response
	// inspection must stay inside the hub's bounded plugin call.
	hdrs := []headerPair{{key: "Content-Type", value: "text/html"}}
	body := []byte("<html>response</html>")

	entry := takeCachedTransaction("detect-only-test")
	if entry == nil {
		t.Fatal("expected cached transaction")
	}
	defer releaseWAF(entry.wafHandle)
	interrupted, processingError := processResponsePhases(entry.tx, 200, "HTTP/1.1", hdrs, body)
	if interrupted || processingError {
		t.Fatalf("benign response should process cleanly: interrupted=%v error=%v", interrupted, processingError)
	}
	entry.tx.ProcessLogging()
	entry.tx.Close()
}

func TestMatchedRulesJSON(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, err := getWAF(handle)
	if err != nil {
		t.Fatalf("getWAF: %v", err)
	}

	tx := inst.waf.NewTransactionWithID("test-matched-json")
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessConnection("192.168.1.1", 12345, "10.0.0.1", 80)
	tx.ProcessURI("/search?id=1'+OR+1=1+--", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	raw := matchedRulesJSONString(tx.MatchedRules())
	if raw == "" {
		t.Fatal("expected matched_rules JSON for a SQLi transaction, got empty")
	}

	var hits []struct {
		I int `json:"i"`
		S int `json:"s"`
	}
	if err := json.Unmarshal([]byte(raw), &hits); err != nil {
		t.Fatalf("matched_rules is not valid JSON: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("expected at least one rule hit")
	}
	sawSQLi := false
	for _, h := range hits {
		if h.I == 0 {
			t.Errorf("administrative rule with id 0 must be skipped, got %+v", h)
		}
		if h.I >= 942000 && h.I < 943000 {
			sawSQLi = true
		}
		// -1 = rule declares no severity (CRS reporting rules); the
		// metrics consumer labels those "none".
		if h.S < -1 || h.S > 7 {
			t.Errorf("severity out of range: %+v", h)
		}
	}
	if !sawSQLi {
		t.Errorf("expected a 942xxx SQLi rule among hits: %+v", hits)
	}
}

func TestMatchedRulesJSON_NoHitsIsEmpty(t *testing.T) {
	if got := matchedRulesJSONString(nil); got != "" {
		t.Errorf("expected empty string for no matched rules, got %q", got)
	}
}
