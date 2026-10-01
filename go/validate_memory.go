package main

import "C"

import (
	"sync"

	"github.com/KimMachineGun/automemlimit/memlimit"
	"github.com/rs/zerolog/log"
)

var validationMemory validationMemoryBudget

type validationMemoryBudget struct {
	mu         sync.Mutex
	configured bool
	warned     bool
}

func (b *validationMemoryBudget) configure(set func() (int64, error)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.configured {
		return
	}
	if _, err := set(); err != nil {
		if !b.warned {
			log.Warn().Err(err).Msg("automatic validation memory budget unavailable; retaining runtime defaults")
			b.warned = true
		}
		return
	}
	b.configured = true
}

//export coraza_configure_validation_memory
func coraza_configure_validation_memory() {
	validationMemory.configure(func() (int64, error) {
		// The dedicated validator shares its cgroup with the native host and plugins.
		return memlimit.Set(memlimit.WithRatio(0.4))
	})
}
