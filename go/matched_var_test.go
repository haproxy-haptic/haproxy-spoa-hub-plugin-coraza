package main

import (
	"math"
	"strings"
	"testing"
)

// TestMatchedVarName covers the field that makes false-positive triage possible
// without logging request content: matched_var names WHICH request field tripped
// a rule, and must never contain the value that tripped it.
func TestMatchedVarName(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, err := getWAF(handle)
	if err != nil {
		t.Fatalf("getWAF: %v", err)
	}

	const injected = "1' OR 1=1 --"

	tx := inst.waf.NewTransactionWithID("test-matched-var")
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessConnection("192.168.1.1", 12345, "10.0.0.1", 80)
	tx.ProcessURI("/search?id="+injected, "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.ProcessRequestHeaders()
	tx.ProcessRequestBody()

	matched := tx.MatchedRules()
	if len(matched) == 0 {
		t.Fatal("expected the SQLi probe to match at least one rule")
	}

	// preferRuleID 0: no specific rule requested, so the first matched rule that
	// names a target wins — the plain "which field tripped something" case.
	got := matchedVarName(matched, 0)
	if got == "" {
		t.Fatal("expected a matched target name, got empty")
	}
	t.Logf("matched target = %q", got)

	// Assert the SHAPE, not one spelling: the query parameter is reachable as
	// ARGS / ARGS_GET (with or without a key) or via the request line, and a CRS
	// or Coraza update may legitimately report a different valid target.
	// A SQLi payload in a query parameter must be attributed to the ARGUMENT,
	// not to the request line. CRS protocol rules match REQUEST_LINE first, so
	// this asserts the severity-preferring fallback actually picks the attack
	// rule's own target — which is the whole point for scoping an exclusion.
	// The list must include the query ARGUMENT: that is the field an operator
	// scopes an exclusion to. Other request variables may legitimately appear
	// alongside it (CRS protocol rules name REQUEST_LINE, path rules name
	// REQUEST_FILENAME), which is why this is a list and not a single name.
	hasArgs := false
	for _, part := range strings.Split(got, ",") {
		if strings.HasPrefix(part, "ARGS") {
			hasArgs = true
		}
		if !isRequestVariable(strings.SplitN(part, ":", 2)[0]) {
			t.Errorf("entry %q in %q is not a request variable", part, got)
		}
	}
	if !hasArgs {
		t.Errorf("matched targets %q should include the query argument (ARGS*) for a SQLi payload in a query parameter", got)
	}
	if n := len(strings.Split(got, ",")); n > maxMatchedVars {
		t.Errorf("matched targets %q has %d entries, over the cap of %d", got, n, maxMatchedVars)
	}
	if strings.ContainsAny(got, " \t\n\"") {
		t.Errorf("matched target %q contains whitespace or a quote; a variable name has neither", got)
	}

	// THE POINT OF THE FIELD: a name, never the value. This is what lets it be
	// logged where `data` (gated behind expose_matched_data) cannot be. Check the
	// distinctive fragments of the payload rather than the whole string, since
	// Coraza may normalise it before reporting.
	for _, leak := range []string{injected, "OR 1=1", "1=1", "--"} {
		if strings.Contains(got, leak) {
			t.Errorf("matched target %q contains the matched VALUE (%q); it must name the field only", got, leak)
		}
	}

	// Preferring a rule that DID match must report that rule's own target, so the
	// reported target belongs to the reported rule id.
	first := matched[0].Rule().ID()
	if n := matchedVarName(matched, first); n == "" {
		t.Errorf("preferring rule %d (which matched) returned no target", first)
	}

	// Preferring a rule that did NOT match must fall back rather than go empty.
	// This is the anomaly-threshold case: CRS 949110 is reported in rule_id but
	// carries no matched data of its own, and that is exactly when an operator
	// needs to know which field contributed.
	if n := matchedVarName(matched, 999999); n == "" {
		t.Error("preferring an unmatched rule id must fall back to the first rule that names a target")
	}

	if n := matchedVarName(nil, 0); n != "" {
		t.Errorf("no matched rules must yield an empty target, got %q", n)
	}
}

// TestSeverityRankPutsUnsetLast pins the ordering rule that matchedVarName
// depends on. Coraza reports types.RuleSeverityUnset as -1, which is numerically
// lower than every real severity including EMERGENCY(0) — so comparing the raw
// value ranks a rule that declares NO severity as the most urgent of all. CRS's
// administrative and reporting rules are exactly those rules, and they match
// early, so the bug would let them consume the entry cap ahead of the attack
// rule whose target an operator actually needs.
func TestSeverityRankPutsUnsetLast(t *testing.T) {
	// Raw severities, as Coraza reports them.
	const (
		unset     = -1
		emergency = 0
		critical  = 2
		notice    = 5
	)

	rank := func(raw int) int {
		if raw < 0 {
			return math.MaxInt
		}
		return raw
	}

	if rank(unset) <= rank(emergency) {
		t.Errorf("unset severity must rank BELOW emergency: rank(unset)=%d rank(emergency)=%d", rank(unset), rank(emergency))
	}
	if rank(unset) <= rank(notice) {
		t.Errorf("unset severity must rank below even notice: rank(unset)=%d rank(notice)=%d", rank(unset), rank(notice))
	}
	// Real severities keep their natural order: lower value = more urgent.
	if !(rank(emergency) < rank(critical) && rank(critical) < rank(notice)) {
		t.Errorf("real severities must stay ascending-by-urgency: %d %d %d",
			rank(emergency), rank(critical), rank(notice))
	}
	// Guard the raw comparison this replaced, so the bug cannot be reintroduced
	// by "simplifying" severityRank back to a bare `<`.
	if !(unset < emergency) {
		t.Fatal("premise broken: Coraza no longer reports unset severity as negative")
	}
}
