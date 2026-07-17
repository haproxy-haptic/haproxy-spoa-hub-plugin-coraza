package main

import (
	"testing"
	"time"
)

func TestCacheStoreAndRetrieve(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, _ := getWAF(handle)
	tx := inst.waf.NewTransactionWithID("cache-test-1")

	if !cacheTransaction("cache-test-1", tx, handle, time.Second, 10) {
		t.Fatal("expected transaction to be cached")
	}

	retrieved := takeCachedTransaction("cache-test-1")
	if retrieved == nil {
		t.Fatal("expected to retrieve cached transaction")
	}
	defer releaseWAF(retrieved.wafHandle)
	defer retrieved.tx.Close()
	if retrieved.tx.ID() != "cache-test-1" {
		t.Errorf("expected ID=cache-test-1, got %s", retrieved.tx.ID())
	}
}

func TestCacheRetrieveNonexistent(t *testing.T) {
	retrieved := takeCachedTransaction("nonexistent")
	if retrieved != nil {
		t.Error("expected nil for nonexistent transaction")
	}
}

func TestCacheTTLEviction(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	inst, _ := getWAF(handle)
	tx := inst.waf.NewTransactionWithID("evict-test")
	tx.ProcessConnection("1.1.1.1", 1, "2.2.2.2", 80)

	if !cacheTransaction("evict-test", tx, handle, 100*time.Millisecond, 10) {
		t.Fatal("expected transaction to be cached")
	}

	// Verify it's in the cache
	txCacheMu.RLock()
	_, cached := txCache["evict-test"]
	txCacheMu.RUnlock()
	if !cached {
		t.Fatal("expected transaction to be in cache")
	}

	// Wait for eviction
	time.Sleep(200 * time.Millisecond)
	evictExpired()

	// Should be evicted now
	if takeCachedTransaction("evict-test") != nil {
		t.Error("expected transaction to be evicted after TTL")
	}
}

func TestCacheRejectsBeyondConfiguredCapacity(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)
	inst, _ := getWAF(handle)
	first := inst.waf.NewTransactionWithID("cache-cap-first")
	second := inst.waf.NewTransactionWithID("cache-cap-second")

	if !cacheTransaction("cache-cap-first", first, handle, time.Second, 1) {
		t.Fatal("first transaction should fit")
	}
	if cacheTransaction("cache-cap-second", second, handle, time.Second, 1) {
		t.Fatal("second transaction must be rejected at the hard cap")
	}
	second.Close()

	entry := takeCachedTransaction("cache-cap-first")
	if entry == nil {
		t.Fatal("first transaction should remain cached")
	}
	entry.tx.Close()
	releaseWAF(entry.wafHandle)
}

func TestCacheReclaimsExpiredEntryBeforeRejectingAtCapacity(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)
	inst, _ := getWAF(handle)
	first := inst.waf.NewTransactionWithID("cache-expired-first")
	second := inst.waf.NewTransactionWithID("cache-expired-second")

	if !cacheTransaction("cache-expired-first", first, handle, time.Second, 1) {
		t.Fatal("first transaction should fit")
	}
	txCacheMu.Lock()
	txCache["cache-expired-first"].expiresAt = time.Now().Add(-time.Second)
	txCacheMu.Unlock()

	if !cacheTransaction("cache-expired-second", second, handle, time.Second, 1) {
		second.Close()
		t.Fatal("an already-expired lease must be reclaimed before rejecting at capacity")
	}
	if takeCachedTransaction("cache-expired-first") != nil {
		t.Fatal("expired transaction must have been removed")
	}
	entry := takeCachedTransaction("cache-expired-second")
	if entry == nil {
		t.Fatal("second transaction should be cached")
	}
	entry.tx.Close()
	releaseWAF(entry.wafHandle)
}
