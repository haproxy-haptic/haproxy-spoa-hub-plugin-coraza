package main

import (
	"errors"
	"runtime/debug"
	"testing"

	"github.com/KimMachineGun/automemlimit/memlimit"
)

func TestValidationMemoryFailureDoesNotRejectRules(t *testing.T) {
	for _, failure := range []error{memlimit.ErrNoCgroup, errors.New("unsupported cgroups"), errors.New("invalid memory ratio")} {
		t.Run(failure.Error(), func(t *testing.T) {
			var budget validationMemoryBudget
			attempts := 0
			budget.configure(func() (int64, error) { attempts++; return 0, failure })
			if diagnostics := validateDirectives("SecRuleEngine On", ""); len(diagnostics) != 0 {
				t.Fatalf("valid rules rejected after budget failure: %+v", diagnostics)
			}
			if diagnostics := validateDirectives("NotARealDirective yes", ""); len(diagnostics) == 0 || diagnostics[len(diagnostics)-1].Severity != "error" {
				t.Fatalf("invalid rules accepted after budget failure: %+v", diagnostics)
			}
			budget.configure(func() (int64, error) { attempts++; return 100, nil })
			budget.configure(func() (int64, error) { t.Fatal("successful budget was not cached"); return 0, nil })
			if attempts != 2 {
				t.Fatalf("failed budget was not retried: %d attempts", attempts)
			}
		})
	}
}

func TestOrdinaryValidationPreservesRuntimeMemoryBudget(t *testing.T) {
	previous := debug.SetMemoryLimit(1 << 30)
	t.Cleanup(func() { debug.SetMemoryLimit(previous) })
	if diagnostics := validateDirectives("SecRuleEngine On", ""); len(diagnostics) != 0 {
		t.Fatalf("valid rules rejected: %+v", diagnostics)
	}
	if got := debug.SetMemoryLimit(-1); got != 1<<30 {
		t.Fatalf("runtime validation changed memory budget to %d", got)
	}
}
