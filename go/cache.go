package main

import (
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/rs/zerolog/log"
)

type cachedTx struct {
	tx        types.Transaction
	wafHandle uint64
	expiresAt time.Time
}

var (
	txCache   = make(map[string]*cachedTx)
	txCacheMu sync.RWMutex
	cacheStop chan struct{}
	cacheOnce sync.Once
)

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
	txCacheMu.Lock()
	expired := removeExpiredLocked(time.Now())
	txCacheMu.Unlock()

	closeCachedTransactions(expired)
}

func removeExpiredLocked(now time.Time) []*cachedTx {
	var expired []*cachedTx
	for id, entry := range txCache {
		if !now.Before(entry.expiresAt) {
			expired = append(expired, entry)
			delete(txCache, id)
		}
	}
	return expired
}

func closeCachedTransactions(entries []*cachedTx) {
	for _, entry := range entries {
		if entry.tx != nil {
			log.Debug().Msg("Evicting expired transaction from cache")
			entry.tx.ProcessLogging()
			entry.tx.Close()
		}
		releaseWAF(entry.wafHandle)
	}
}

// cacheTransaction stores a transaction for later response processing while
// retaining its originating WAF generation. The global cache is hard-capped;
// callers fail closed if capacity is exhausted.
func cacheTransaction(id string, tx types.Transaction, wafHandle uint64, ttl time.Duration, maxEntries int) bool {
	if ttl <= 0 || maxEntries <= 0 || !retainWAF(wafHandle) {
		return false
	}
	startCacheEvictor()

	var replaced *cachedTx
	var expired []*cachedTx
	txCacheMu.Lock()
	if len(txCache) >= maxEntries {
		// Under pressure, reclaim leases that are already expired before
		// deciding the cache is full. Waiting for the one-second background
		// sweep would create an avoidable fail-closed outage after a short burst.
		expired = removeExpiredLocked(time.Now())
	}
	if _, exists := txCache[id]; !exists && len(txCache) >= maxEntries {
		txCacheMu.Unlock()
		closeCachedTransactions(expired)
		releaseWAF(wafHandle)
		return false
	}
	replaced = txCache[id]
	txCache[id] = &cachedTx{
		tx:        tx,
		wafHandle: wafHandle,
		expiresAt: time.Now().Add(ttl),
	}
	txCacheMu.Unlock()

	closeCachedTransactions(expired)
	if replaced != nil {
		replaced.tx.ProcessLogging()
		replaced.tx.Close()
		releaseWAF(replaced.wafHandle)
	}
	return true
}

// takeCachedTransaction atomically removes and returns one transaction. This
// prevents duplicate response messages from processing the same Coraza
// transaction concurrently.
func takeCachedTransaction(id string) *cachedTx {
	txCacheMu.Lock()
	entry, ok := txCache[id]
	if ok {
		delete(txCache, id)
	}
	txCacheMu.Unlock()
	if !ok {
		return nil
	}
	return entry
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

	// Close all remaining cached transactions
	txCacheMu.Lock()
	entries := make([]*cachedTx, 0, len(txCache))
	for id, entry := range txCache {
		entries = append(entries, entry)
		delete(txCache, id)
	}
	txCacheMu.Unlock()

	closeCachedTransactions(entries)
}
