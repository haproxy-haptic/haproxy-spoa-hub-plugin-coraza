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

	cacheTransaction("cache-test-1", tx)
	defer removeCachedTransaction("cache-test-1")

	retrieved := getCachedTransaction("cache-test-1")
	if retrieved == nil {
		t.Fatal("expected to retrieve cached transaction")
	}
	if retrieved.ID() != "cache-test-1" {
		t.Errorf("expected ID=cache-test-1, got %s", retrieved.ID())
	}
}

func TestCacheRetrieveNonexistent(t *testing.T) {
	retrieved := getCachedTransaction("nonexistent")
	if retrieved != nil {
		t.Error("expected nil for nonexistent transaction")
	}
}

func TestCacheTTLEviction(t *testing.T) {
	handle := setupTestWAF(t)
	defer destroyWAF(handle)

	// Set a very short TTL
	oldTTL := cacheTTL
	setCacheTTL(100) // 100ms
	defer func() { cacheTTL = oldTTL }()

	inst, _ := getWAF(handle)
	tx := inst.waf.NewTransactionWithID("evict-test")
	tx.ProcessConnection("1.1.1.1", 1, "2.2.2.2", 80)

	cacheTransaction("evict-test", tx)

	// Verify it's in the cache
	if getCachedTransaction("evict-test") == nil {
		t.Fatal("expected transaction to be in cache")
	}

	// Wait for eviction
	time.Sleep(200 * time.Millisecond)
	evictExpired()

	// Should be evicted now
	if getCachedTransaction("evict-test") != nil {
		t.Error("expected transaction to be evicted after TTL")
	}
}
