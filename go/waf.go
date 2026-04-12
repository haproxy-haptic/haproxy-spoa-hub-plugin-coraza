package main

import (
	"fmt"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	osfs "github.com/jcchavezs/mergefs/io"
	"github.com/rs/zerolog/log"
)

// wafInstance holds a compiled WAF and its metadata.
type wafInstance struct {
	waf        coraza.WAF
	rulesCount int
}

var (
	wafMu       sync.RWMutex
	wafHandles  = make(map[uint64]*wafInstance)
	wafNextID   atomic.Uint64
	appWAFs     = make(map[string]uint64) // app name → waf handle
	defaultWAF  uint64
	appWAFsMu   sync.RWMutex
)

// createWAF builds a new Coraza WAF instance from directives and optional config.
func createWAF(directives string, directivesFile string, rootFSPath string, reqBodyLimit, reqBodyMemLimit, respBodyLimit int) (uint64, int, error) {
	config := coraza.NewWAFConfig()

	// Merge embedded CRS with OS filesystem (or custom path)
	var rootFS fs.FS
	if rootFSPath != "" {
		rootFS = mergefs.Merge(coreruleset.FS, os.DirFS(rootFSPath))
	} else {
		rootFS = mergefs.Merge(coreruleset.FS, osfs.OSFS)
	}
	config = config.WithRootFS(rootFS)

	// Load directives
	if directives != "" {
		config = config.WithDirectives(directives)
	}

	// Load additional directives from file
	if directivesFile != "" {
		config = config.WithDirectivesFromFile(directivesFile)
	}

	// Body access and limits
	// Note: RequestBodyLimit must be >= RequestBodyInMemoryLimit (Coraza panics otherwise)
	config = config.WithRequestBodyAccess()
	if reqBodyLimit > 0 {
		memLimit := reqBodyMemLimit
		if memLimit <= 0 {
			memLimit = reqBodyLimit
		}
		if memLimit > reqBodyLimit {
			memLimit = reqBodyLimit
		}
		config = config.WithRequestBodyLimit(reqBodyLimit)
		config = config.WithRequestBodyInMemoryLimit(memLimit)
	}
	config = config.WithResponseBodyAccess()
	if respBodyLimit > 0 {
		config = config.WithResponseBodyLimit(respBodyLimit)
	}

	// Error callback for matched rules logging
	config = config.WithErrorCallback(func(mr types.MatchedRule) {
		log.Warn().
			Int("rule_id", mr.Rule().ID()).
			Str("msg", mr.Message()).
			Str("data", mr.Data()).
			Msg("WAF rule matched")
	})

	waf, err := coraza.NewWAF(config)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create WAF: %w", err)
	}

	// Get rules count via experimental interface
	rulesCount := 0
	if rc, ok := waf.(experimental.WAFWithRules); ok {
		rulesCount = rc.RulesCount()
	}

	id := wafNextID.Add(1)

	wafMu.Lock()
	wafHandles[id] = &wafInstance{
		waf:        waf,
		rulesCount: rulesCount,
	}
	wafMu.Unlock()

	return id, rulesCount, nil
}

// getWAF retrieves a WAF instance by handle.
func getWAF(handle uint64) (*wafInstance, error) {
	wafMu.RLock()
	inst, ok := wafHandles[handle]
	wafMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("WAF handle %d not found", handle)
	}
	return inst, nil
}

// getWAFForApp retrieves the WAF handle for a given app name.
func getWAFForApp(appName string) uint64 {
	if appName == "" {
		return defaultWAF
	}
	appWAFsMu.RLock()
	handle, ok := appWAFs[appName]
	appWAFsMu.RUnlock()
	if !ok {
		return defaultWAF
	}
	return handle
}

// destroyWAF destroys a WAF instance and releases its resources.
func destroyWAF(handle uint64) {
	wafMu.Lock()
	inst, ok := wafHandles[handle]
	if ok {
		delete(wafHandles, handle)
	}
	wafMu.Unlock()

	if ok && inst.waf != nil {
		if closer, ok := inst.waf.(experimental.WAFCloser); ok {
			closer.Close()
		}
	}
}

// destroyAllWAFs cleans up all WAF instances.
func destroyAllWAFs() {
	wafMu.Lock()
	handles := make([]uint64, 0, len(wafHandles))
	for id := range wafHandles {
		handles = append(handles, id)
	}
	wafMu.Unlock()

	for _, id := range handles {
		destroyWAF(id)
	}
}
