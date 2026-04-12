package main

import (
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/rs/zerolog/log"
)

type cachedTx struct {
	tx        types.Transaction
	createdAt time.Time
}

var (
	txCache   = make(map[string]*cachedTx)
	txCacheMu sync.RWMutex
	cacheTTL  = 10 * time.Second
	cacheWg   sync.WaitGroup // tracks background detect-only goroutines
	cacheStop chan struct{}
	cacheOnce sync.Once
)

// setCacheTTL updates the cache TTL.
func setCacheTTL(ttlMs int) {
	if ttlMs > 0 {
		cacheTTL = time.Duration(ttlMs) * time.Millisecond
	}
}

// startCacheEvictor starts the background eviction goroutine.
func startCacheEvictor() {
	cacheOnce.Do(func() {
		cacheStop = make(chan struct{})
		go cacheEvictLoop()
	})
}

func cacheEvictLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			evictExpired()
		case <-cacheStop:
			return
		}
	}
}

func evictExpired() {
	now := time.Now()
	var expired []string

	txCacheMu.RLock()
	for id, entry := range txCache {
		if now.Sub(entry.createdAt) > cacheTTL {
			expired = append(expired, id)
		}
	}
	txCacheMu.RUnlock()

	for _, id := range expired {
		txCacheMu.Lock()
		entry, ok := txCache[id]
		if ok {
			delete(txCache, id)
		}
		txCacheMu.Unlock()

		if ok && entry.tx != nil {
			log.Debug().Str("tx_id", id).Msg("Evicting expired transaction from cache")
			entry.tx.ProcessLogging()
			entry.tx.Close()
		}
	}
}

// cacheTransaction stores a transaction for later response processing.
func cacheTransaction(id string, tx types.Transaction) {
	startCacheEvictor()

	txCacheMu.Lock()
	txCache[id] = &cachedTx{
		tx:        tx,
		createdAt: time.Now(),
	}
	txCacheMu.Unlock()
}

// getCachedTransaction retrieves a cached transaction by ID.
func getCachedTransaction(id string) types.Transaction {
	txCacheMu.RLock()
	entry, ok := txCache[id]
	txCacheMu.RUnlock()
	if !ok {
		return nil
	}
	return entry.tx
}

// removeCachedTransaction removes a transaction from the cache without closing it.
func removeCachedTransaction(id string) {
	txCacheMu.Lock()
	delete(txCache, id)
	txCacheMu.Unlock()
}

// drainCache closes all cached transactions and waits for background goroutines.
func drainCache() {
	// Stop evictor
	if cacheStop != nil {
		select {
		case <-cacheStop:
		default:
			close(cacheStop)
		}
	}

	// Wait for detect-only background goroutines
	cacheWg.Wait()

	// Close all remaining cached transactions
	txCacheMu.Lock()
	for id, entry := range txCache {
		if entry.tx != nil {
			entry.tx.ProcessLogging()
			entry.tx.Close()
		}
		delete(txCache, id)
	}
	txCacheMu.Unlock()
}
