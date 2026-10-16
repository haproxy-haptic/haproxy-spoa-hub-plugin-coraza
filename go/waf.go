package main

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"strconv"
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
	waf                coraza.WAF
	rulesCount         int
	activeTransactions int
	retiring           bool
}

var (
	wafMu      sync.RWMutex
	wafHandles = make(map[uint64]*wafInstance)
	wafNextID  atomic.Uint64

	rejectedWAFs = newRejectedBuilds[coraza.WAF]()
)

const (
	matchedDataNone = iota
	matchedDataHash
	matchedDataTruncate
)

func boundedLogValue(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	bytes := []byte(value)
	truncated := len(bytes) > limit
	if truncated {
		bytes = bytes[:limit]
	}
	for i, b := range bytes {
		if b < 0x20 || b == 0x7f || b >= 0x80 {
			bytes[i] = '.'
		}
	}
	result := string(bytes)
	if truncated {
		result += "..."
	}
	return result
}

func matchedDataForLog(data string, mode, limit int) string {
	switch mode {
	case matchedDataHash:
		return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(data)))
	case matchedDataTruncate:
		return boundedLogValue(data, limit)
	default:
		return ""
	}
}

// createWAF builds a new Coraza WAF instance from directives and optional config.
func createWAF(
	directives string,
	directivesFile string,
	rootFSPath string,
	reqBodyLimit, reqBodyMemLimit, respBodyLimit int,
	ruleMatchLog bool,
	matchedDataLogMode, matchedDataMaxBytes int,
) (uint64, int, error) {
	config := coraza.NewWAFConfig()

	// Merge embedded CRS with OS filesystem (or custom path)
	var rootFS fs.FS
	if rootFSPath != "" {
		rootFS = mergefs.Merge(coreruleset.FS, os.DirFS(rootFSPath))
	} else {
		rootFS = mergefs.Merge(coreruleset.FS, osfs.OSFS)
	}

	// Load directives
	if directives != "" {
		config = config.WithDirectives(directives)
	}

	// Load additional directives from file
	if directivesFile != "" {
		config = config.WithDirectivesFromFile(directivesFile)
	}

	// Body limits are integration safety rails; body access itself is controlled
	// by SecRequestBodyAccess/SecResponseBodyAccess in each compiled policy. This
	// is what allows HAPTIC to use header-only profiles without Coraza buffering
	// an opaque Git or package payload.
	// Note: RequestBodyLimit must be >= RequestBodyInMemoryLimit (Coraza panics otherwise)
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
	if respBodyLimit > 0 {
		config = config.WithResponseBodyLimit(respBodyLimit)
	}

	// Matched-rule logging is deliberately opt-in. Logging every rule match on
	// hostile traffic is a log-amplification vector, and MatchedRule.Data may
	// contain credentials or arbitrary request bodies.
	config = config.WithErrorCallback(func(mr types.MatchedRule) {
		if !ruleMatchLog {
			return
		}
		event := log.Warn().
			Int("rule_id", mr.Rule().ID()).
			Str("msg", boundedLogValue(mr.Message(), 512))
		if data := matchedDataForLog(mr.Data(), matchedDataLogMode, matchedDataMaxBytes); data != "" {
			event = event.Str("data", data)
		}
		event.Msg("WAF rule matched")
	})

	key := inputKey(directives, directivesFile, rootFSPath,
		strconv.Itoa(reqBodyLimit), strconv.Itoa(reqBodyMemLimit), strconv.Itoa(respBodyLimit))
	waf, err := rejectedWAFs.build(key, rootFS, func(root fs.FS) (coraza.WAF, error) {
		return coraza.NewWAF(config.WithRootFS(root))
	})
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
	if ok && inst.retiring {
		ok = false
	}
	wafMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("WAF handle %d not found", handle)
	}
	return inst, nil
}

// retainWAF pins a handle while a request transaction waits for its response.
func retainWAF(handle uint64) bool {
	wafMu.Lock()
	defer wafMu.Unlock()
	inst, ok := wafHandles[handle]
	if !ok || inst.retiring {
		return false
	}
	inst.activeTransactions++
	return true
}

func closeWAF(inst *wafInstance) {
	if inst != nil && inst.waf != nil {
		if closer, ok := inst.waf.(experimental.WAFCloser); ok {
			closer.Close()
		}
	}
}

// releaseWAF drops a cached-transaction lease and completes deferred
// destruction once the last transaction from a retired generation closes.
func releaseWAF(handle uint64) {
	var closing *wafInstance
	wafMu.Lock()
	if inst, ok := wafHandles[handle]; ok {
		if inst.activeTransactions > 0 {
			inst.activeTransactions--
		}
		if inst.retiring && inst.activeTransactions == 0 {
			delete(wafHandles, handle)
			closing = inst
		}
	}
	wafMu.Unlock()
	closeWAF(closing)
}

// destroyWAF destroys a WAF instance and releases its resources.
func destroyWAF(handle uint64) {
	var closing *wafInstance
	wafMu.Lock()
	inst, ok := wafHandles[handle]
	if ok {
		if inst.activeTransactions == 0 {
			delete(wafHandles, handle)
			closing = inst
		} else {
			inst.retiring = true
		}
	}
	wafMu.Unlock()
	closeWAF(closing)
}

func activeWAFCount() int {
	wafMu.RLock()
	defer wafMu.RUnlock()
	return len(wafHandles)
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
