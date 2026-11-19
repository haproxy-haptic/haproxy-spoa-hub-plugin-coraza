use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::{Evaluation, Lease};

struct Entry {
    lease: Lease,
    expires: Instant,
}

#[derive(Default)]
struct Entries {
    leases: HashMap<String, Entry>,
    worker: Option<JoinHandle<()>>,
    stopping: bool,
}

impl Entries {
    fn expire(&mut self, now: Instant) -> Vec<Entry> {
        let expired: Vec<_> = self
            .leases
            .iter()
            .filter(|(_, entry)| entry.expires <= now)
            .map(|(key, _)| key.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.leases.remove(&key))
            .collect()
    }
}

#[derive(Default)]
struct Queue {
    state: Mutex<Entries>,
    wake: Condvar,
}

impl Queue {
    fn run(&self) {
        loop {
            let state = self.state.lock().unwrap();
            let (mut state, _) = self
                .wake
                .wait_timeout_while(state, Duration::from_secs(1), |state| !state.stopping)
                .unwrap();
            if state.stopping {
                return;
            }
            let expired = state.expire(Instant::now());
            drop(state);
            // Finishing phase 5 can run rules and log, so do it outside the lock.
            drop(expired);
        }
    }
}

#[derive(Default)]
struct Cache {
    queue: Arc<Queue>,
    allowed: AtomicU64,
    blocked: AtomicU64,
    hits: AtomicU64,
    errors: AtomicU64,
}

impl Drop for Cache {
    fn drop(&mut self) {
        let mut state = self.queue.state.lock().unwrap();
        state.stopping = true;
        let worker = state.worker.take();
        let remaining = std::mem::take(&mut state.leases);
        self.queue.wake.notify_all();
        drop(state);
        if let Some(thread) = worker {
            let _ = thread.join();
        }
        drop(remaining);
    }
}

/// All live plugin instances share one bounded cache, including old and new
/// generations during a hub reload. The final owner joins the eviction thread.
#[derive(Clone)]
pub(crate) struct TransactionCache(Arc<Cache>);

impl Default for TransactionCache {
    fn default() -> Self {
        static LIVE: OnceLock<Mutex<Weak<Cache>>> = OnceLock::new();
        let mut current = LIVE.get_or_init(Default::default).lock().unwrap();
        if let Some(cache) = current.upgrade() {
            return Self(cache);
        }
        let cache = Arc::new(Cache::default());
        *current = Arc::downgrade(&cache);
        Self(cache)
    }
}

impl std::fmt::Debug for TransactionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionCache").finish_non_exhaustive()
    }
}

impl TransactionCache {
    pub(super) fn insert(&self, id: &str, lease: Lease, ttl: Duration, max: usize) -> bool {
        let queue = &self.0.queue;
        let mut state = queue.state.lock().unwrap();
        let now = Instant::now();
        let expired = if state.leases.len() >= max {
            state.expire(now)
        } else {
            Vec::new()
        };
        let accepted = max > 0 && (state.leases.len() < max || state.leases.contains_key(id));
        if !accepted {
            drop(state);
            drop(expired);
            return false;
        }
        if state.worker.is_none() {
            let worker_queue = Arc::clone(queue);
            let Ok(worker) = thread::Builder::new()
                .name("waf-tx-expiry".into())
                .spawn(move || worker_queue.run())
            else {
                drop(state);
                drop(expired);
                return false;
            };
            state.worker = Some(worker);
        }
        let old = state.leases.insert(
            id.to_owned(),
            Entry {
                lease,
                expires: now + ttl,
            },
        );
        drop(state);
        drop(expired);
        drop(old);
        true
    }

    pub(super) fn take(&self, id: &str) -> Option<Lease> {
        let entry = self.0.queue.state.lock().unwrap().leases.remove(id)?;
        if entry.expires <= Instant::now() {
            return None;
        }
        Some(entry.lease)
    }

    pub(super) fn record(&self, verdict: &Evaluation, request: bool, failed: bool) {
        if failed {
            self.0.errors.fetch_add(1, Ordering::Relaxed);
        }
        if request {
            self.0
                .hits
                .fetch_add(verdict.rules_hit as u64, Ordering::Relaxed);
        }
        let denied = if request {
            verdict.denied()
        } else {
            verdict.status != 0
        };
        let counter = if denied {
            &self.0.blocked
        } else {
            &self.0.allowed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn missing_response(&self) {
        self.0.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn summary(&self) -> (u64, u64, u64, u64) {
        let count = |value: &AtomicU64| value.load(Ordering::Relaxed);
        (
            count(&self.0.allowed),
            count(&self.0.blocked),
            count(&self.0.hits),
            count(&self.0.errors),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginConfig;
    use crate::rust_backend::transaction::RuleCatalog;

    fn lease(engine: &zentinel_modsec::ModSecurity, marker: &str) -> Lease {
        Lease {
            tx: engine.new_transaction_with_id(marker),
            catalog: Arc::new(RuleCatalog::new(engine, &PluginConfig::default())),
            logged: 0,
        }
    }

    #[test]
    fn bounded_cache_replaces_consumes_and_reclaims_expired_leases() {
        let cache = TransactionCache(Arc::new(Cache::default()));
        let engine = zentinel_modsec::ModSecurity::from_string("SecRuleEngine On").unwrap();
        let ttl = Duration::from_secs(60);
        assert!(cache.insert("key", lease(&engine, "old"), ttl, 1));
        assert!(!cache.insert("other", lease(&engine, "other"), ttl, 1));
        assert!(cache.insert("key", lease(&engine, "new"), ttl, 1));
        assert_eq!(cache.take("key").unwrap().tx.id(), "new");
        assert!(cache.take("key").is_none());
        assert!(cache.insert("expired", lease(&engine, "expired"), Duration::ZERO, 1));
        assert!(cache.insert("live", lease(&engine, "live"), ttl, 1));
        assert!(cache.take("expired").is_none());
        assert!(cache.take("live").is_some());
    }

    #[test]
    fn invalid_response_status_fails_closed_and_consumes_the_lease() {
        use crate::backend::Response;
        use crate::rust_backend::transaction::evaluate_response;
        let cache = TransactionCache(Arc::new(Cache::default()));
        let engine = zentinel_modsec::ModSecurity::from_string("SecRuleEngine On").unwrap();
        assert!(cache.insert("id", lease(&engine, "id"), Duration::from_secs(30), 1));
        let response = |status| Response {
            tx_id: "id",
            version: "HTTP/1.1",
            status,
            headers: &[],
            body: &[],
        };
        let malformed = evaluate_response(&cache, response(-1), true).unwrap();
        assert_eq!((malformed.action, malformed.status), ("deny", 502));
        let replay = evaluate_response(&cache, response(200), true).unwrap();
        assert_eq!((replay.action, replay.status), ("deny", 503));
        assert_eq!(cache.summary(), (0, 1, 0, 2));
    }

    #[test]
    fn reloads_share_inflight_transactions() {
        let retiring = TransactionCache::default();
        let active = TransactionCache::default();
        assert!(Arc::ptr_eq(&retiring.0, &active.0));
    }
}
