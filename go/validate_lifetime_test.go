package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type validationLifetimeOperator struct{}

func (validationLifetimeOperator) Evaluate(plugintypes.TransactionState, string) bool { return true }

func TestValidationRetainsOnlyCurrentCompiledResources(t *testing.T) {
	compilations := map[string]int{}
	plugins.RegisterOperator("validation-lifetime", func(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
		_, err := options.Memoizer.Do(t.Name()+options.Arguments, func() (any, error) {
			compilations[options.Arguments]++
			return struct{}{}, nil
		})
		return validationLifetimeOperator{}, err
	})
	warm := `SecRule ARGS "@validation-lifetime warm" "id:1,phase:1,deny"`
	if diagnostics := validateDirectives(warm, ""); len(diagnostics) != 0 {
		t.Fatalf("warm validation: %+v", diagnostics)
	}
	for i := 0; i < 100; i++ {
		directives := warm + fmt.Sprintf("\nSecRule ARGS \"@validation-lifetime candidate%d\" \"id:2,phase:1,deny\"", i%2)
		if diagnostics := validateDirectives(directives, ""); len(diagnostics) != 0 {
			t.Fatalf("unexpected diagnostics: %+v", diagnostics)
		}
	}
	if compilations["warm"] != 1 {
		t.Fatalf("shared expressions were recompiled %d times", compilations["warm"])
	}
	if compilations["candidate0"] != 50 || compilations["candidate1"] != 50 {
		t.Fatalf("obsolete validation retained resources: %v", compilations)
	}
	if diagnostics := validateDirectives("", ""); len(diagnostics) != 0 {
		t.Fatalf("empty replacement: %+v", diagnostics)
	}
	if diagnostics := validateDirectives(warm, ""); len(diagnostics) != 0 {
		t.Fatalf("final validation: %+v", diagnostics)
	}
	if compilations["warm"] != 2 {
		t.Fatalf("replacement did not release the last shared expression: %v", compilations)
	}
}

// countRuleBuilds registers an operator that counts how often a rule using it is
// built, which is once per WAF construction that reaches the rule.
func countRuleBuilds(t *testing.T) (string, map[string]int) {
	name := "count-" + strings.ReplaceAll(t.Name(), "/", "-")
	builds := map[string]int{}
	plugins.RegisterOperator(name, func(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
		builds[options.Arguments]++
		return validationLifetimeOperator{}, nil
	})
	return name, builds
}

func TestRejectedValidationIsNotRebuilt(t *testing.T) {
	operator, builds := countRuleBuilds(t)
	for i := 0; i < 100; i++ {
		directives := fmt.Sprintf("SecRule ARGS \"@%s candidate%d\" \"id:1,phase:1,deny\"\nNotARealDirective yes", operator, i%2)
		diagnostics := validateDirectives(directives, "")
		if len(diagnostics) == 0 || diagnostics[len(diagnostics)-1].Severity != "error" {
			t.Fatalf("invalid rules must still fail: %+v", diagnostics)
		}
	}
	if builds["candidate0"] != 1 || builds["candidate1"] != 1 {
		t.Fatalf("rejected input was rebuilt: %v", builds)
	}
}

func TestRejectedValidationReplaysItsDiagnostics(t *testing.T) {
	operator, _ := countRuleBuilds(t)
	directives := fmt.Sprintf("Include /missing/%s/*.conf\nSecRule ARGS \"@%s x\" \"id:1\"\nNotARealDirective yes", operator, operator)
	first := validateDirectives(directives, "")
	second := validateDirectives(directives, "")
	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Fatalf("replayed diagnostics differ:\n%+v\n%+v", first, second)
	}
	if first[0].Severity != "error" || first[0].Message == corazaEmptyGlobMessage {
		t.Fatalf("empty glob was not promoted on the first validation: %+v", first)
	}
}

func TestRejectedWAFIsRebuiltOnlyWhenItsFilesChange(t *testing.T) {
	operator, builds := countRuleBuilds(t)
	rules := filepath.Join(t.TempDir(), "rules.conf")
	broken := fmt.Sprintf("SecRule ARGS \"@%s x\" \"id:1\"\nNotARealDirective yes\n", operator)
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(rules, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	create := func() error {
		t.Helper()
		handle, _, err := createWAF("Include "+rules, "", "", 0, 0, 0, false, matchedDataNone, 0)
		if err == nil {
			destroyWAF(handle)
		}
		return err
	}

	write(broken)
	for i := 0; i < 10; i++ {
		if create() == nil {
			t.Fatal("broken rules compiled")
		}
	}
	write(broken)
	if create() == nil || builds["x"] != 1 {
		t.Fatalf("identical rejected input was rebuilt: %v", builds)
	}

	write(fmt.Sprintf("SecRule ARGS \"@%s x\" \"id:1\"\n", operator))
	if err := create(); err != nil {
		t.Fatalf("fixed rules were not rebuilt: %v", err)
	}
	if builds["x"] != 2 {
		t.Fatalf("expected one rebuild after the fix: %v", builds)
	}
}

func TestRejectedBuildsAreBounded(t *testing.T) {
	builds := newRejectedBuilds[int]()
	for i := 0; i < 3*maxRejectedBuilds; i++ {
		_, _ = builds.build(inputKey(strconv.Itoa(i)), fstest.MapFS{}, func(fs.FS) (int, error) {
			return 0, errors.New("rejected")
		})
	}
	if got := builds.remembered(); got != maxRejectedBuilds {
		t.Fatalf("remembered %d rejected builds, want %d", got, maxRejectedBuilds)
	}
}

type failingValidationCloser struct{}

func (failingValidationCloser) Close() error { return errors.New("cleanup failed") }

func TestPreviousCleanupFailureDoesNotRejectValidRules(t *testing.T) {
	previousValidationMu.Lock()
	previous := previousValidationWAF
	previousValidationWAF = failingValidationCloser{}
	previousValidationMu.Unlock()
	t.Cleanup(func() {
		previousValidationMu.Lock()
		current := previousValidationWAF
		previousValidationWAF = previous
		previousValidationMu.Unlock()
		if current != nil {
			if err := current.Close(); err != nil {
				t.Fatal(err)
			}
		}
	})
	diagnostics := validateDirectives(`SecRule ARGS "@rx safe" "id:1,phase:1,deny"`, "")
	if len(diagnostics) != 1 || diagnostics[0].Severity != "warning" || diagnostics[0].Message != "release previous validation resources: cleanup failed" {
		t.Fatalf("unexpected cleanup diagnostics: %+v", diagnostics)
	}
	if diagnostics := validateDirectives("NotARealDirective yes", ""); len(diagnostics) == 0 || diagnostics[len(diagnostics)-1].Severity != "error" {
		t.Fatalf("invalid rules must still fail: %+v", diagnostics)
	}
}
