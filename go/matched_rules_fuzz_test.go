package main

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
)

type fuzzRule struct {
	types.RuleMetadata
	id       int
	severity types.RuleSeverity
}

func (r fuzzRule) ID() int                      { return r.id }
func (r fuzzRule) Severity() types.RuleSeverity { return r.severity }

type fuzzMatch struct {
	types.MatchedRule
	rule fuzzRule
}

func (m fuzzMatch) Rule() types.RuleMetadata { return m.rule }

// FuzzAppendMatchedRulesJSON pins the hand-written encoder to encoding/json for
// any rule ID and severity, so a change to either side fails here.
func FuzzAppendMatchedRulesJSON(f *testing.F) {
	pair := func(id, severity int64) []byte {
		b := binary.LittleEndian.AppendUint64(nil, uint64(id))
		return binary.LittleEndian.AppendUint64(b, uint64(severity))
	}
	f.Add([]byte{})
	f.Add(pair(930130, 2))
	f.Add(append(pair(0, 2), pair(-5, -1)...))
	f.Add(append(pair(949110, -1), pair(math.MaxInt64, math.MinInt64)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		var rules []types.MatchedRule
		for len(data) >= 16 {
			id := int(int64(binary.LittleEndian.Uint64(data)))
			severity := types.RuleSeverity(int64(binary.LittleEndian.Uint64(data[8:])))
			rules = append(rules, fuzzMatch{rule: fuzzRule{id: id, severity: severity}})
			data = data[16:]
		}
		got := string(appendMatchedRulesJSON(nil, rules, true, 0))
		if want := legacyMatchedRulesJSON(rules); got != want {
			t.Fatalf("encoder %q, encoding/json %q", got, want)
		}
	})
}
