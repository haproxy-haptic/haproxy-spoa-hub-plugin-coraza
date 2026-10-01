package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

type validationLifetimeOperator struct{}

func (validationLifetimeOperator) Evaluate(plugintypes.TransactionState, string) bool { return true }

func TestValidationRetainsOnlyCurrentCompiledResources(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid=%t", invalid), func(t *testing.T) {
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
				if invalid {
					directives += "\nNotARealDirective yes"
				}
				diagnostics := validateDirectives(directives, "")
				if invalid != (len(diagnostics) > 0) {
					t.Fatalf("unexpected diagnostics: %+v", diagnostics)
				}
			}
			if compilations["warm"] != 1 {
				t.Fatalf("shared expressions were recompiled %d times", compilations["warm"])
			}
			if compilations["candidate0"] != 50 || compilations["candidate1"] != 50 {
				t.Fatalf("obsolete or failed validation retained resources: %v", compilations)
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
		})
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
