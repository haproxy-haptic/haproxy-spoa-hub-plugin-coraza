//! Rule-file watcher: recompiles this plugin's WAF when the files its
//! directives include change on disk, without a hub reload.
//!
//! The hub reloads on its config file changing. A rule set delivered as
//! separate files does not change that file — an `Include` of a glob is the
//! same string whatever the glob matches — so nothing would otherwise notice a
//! refreshed rule set, and the WAF would keep serving the previous rules until
//! an unrelated config change happened to reload it.
//!
//! Reloading the hub instead would rebuild every plugin's generation to pick up
//! a change that concerns one of them. This stays local: the plugin swaps its
//! own generation and nothing else is disturbed.
//!
//! **Polling, not inotify.** inotify would work — watching the parent directory
//! survives the atomic renames the writer uses, which is what the hub's own
//! config watcher does. Polling is chosen for three properties inotify does not
//! have, none of which matter for a config file but all of which matter for a
//! rule set:
//!
//! 1. **It cannot miss a change.** A full inotify queue drops events and reports
//!    `IN_Q_OVERFLOW`, after which recovery is a rescan you have to implement
//!    anyway; `notify` documents its Linux backend as not fully reliable and
//!    ships a polling watcher for this reason. A missed event here is permanent:
//!    the files stay as they are, so nothing fires again and the WAF serves the
//!    old rules indefinitely.
//! 2. **A batch settles for free.** The rule set arrives as one write per file,
//!    so inotify reports dozens of events per refresh and would need a debouncer
//!    to avoid recompiling once per file. Polling coalesces by construction, and
//!    "unchanged since the last poll" is the settle check below.
//! 3. **A missing directory is not fatal.** Adding an inotify watch on a
//!    directory that does not exist yet fails and never retries; a glob that
//!    matches nothing is just an empty fingerprint that fills in later.
//!
//! A few dozen `stat` calls per interval cost nothing against a rule set that
//! changes hourly at most.

use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime},
};

/// How finely the poll loop checks whether it has been asked to stop. The
/// watcher must be gone before the plugin generation that owns it is dropped,
/// so the sleep is sliced rather than waiting out a whole interval.
const STOP_CHECK_SLICE: Duration = Duration::from_millis(250);

/// One observation of the watched files: which existed, how big they were, and
/// when they last changed.
///
/// Size and mtime together rather than content hashes — reading every rule file
/// on every poll to detect a change that happens hourly would be the expensive
/// way round. A same-size same-mtime edit is missed, which for a published rule
/// set fetched over HTTP does not occur; the next genuine change is picked up.
pub type Fingerprint = Vec<(PathBuf, u64, Option<SystemTime>)>;

/// Watches a set of globs and calls back when their fingerprint changes.
pub struct RuleWatcher {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl RuleWatcher {
    /// Start watching. `on_change` runs on the watcher thread, so it must not
    /// take a lock the request path holds across a long operation.
    ///
    /// `baseline` is what the caller last compiled, and the caller must take it
    /// with [`fingerprint`] *before* reading the files. Letting the thread take
    /// its own baseline loses every write that lands between the caller's read
    /// and the thread's first run — and because the fingerprint then already
    /// matches the new files, nothing ever fires again and the stale rules are
    /// served forever. A baseline that is too old only costs one redundant
    /// rebuild, so err in that direction.
    ///
    /// A change must hold still for one interval before it fires. The rule set
    /// is delivered as one write per file, so a poll can land mid-batch, and a
    /// partial rule set compiles perfectly well — the WAF would come up short of
    /// rules while looking healthy. Waiting for quiescence costs one interval on
    /// a rule set that changes hourly.
    pub fn spawn<F>(
        globs: Vec<String>,
        interval: Duration,
        baseline: Fingerprint,
        on_change: F,
    ) -> Self
    where
        F: Fn() + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);

        let handle = thread::Builder::new()
            .name("coraza-rule-watcher".to_owned())
            .spawn(move || {
                let mut compiled = baseline;
                let mut last_seen = compiled.clone();
                while !thread_stop.load(Ordering::Relaxed) {
                    if !sleep_interruptibly(interval, &thread_stop) {
                        return;
                    }
                    let current = fingerprint(&globs);
                    let settled = current == last_seen;
                    last_seen.clone_from(&current);
                    if settled && current != compiled {
                        compiled = current;
                        on_change();
                    }
                }
            })
            .ok();

        Self { stop, handle }
    }

    /// Stop the watcher and wait for it. Called from `Drop`, and directly when
    /// a reconfigure replaces the watcher — without the wait, two threads could
    /// briefly rebuild the same plugin's generation.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RuleWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

impl std::fmt::Debug for RuleWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleWatcher")
            .field("running", &self.handle.is_some())
            .finish()
    }
}

/// Sleep for `total`, waking every [`STOP_CHECK_SLICE`] to observe `stop`.
/// Returns false when asked to stop.
fn sleep_interruptibly(total: Duration, stop: &AtomicBool) -> bool {
    let mut remaining = total;
    while !remaining.is_zero() {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let slice = remaining.min(STOP_CHECK_SLICE);
        thread::sleep(slice);
        remaining -= slice;
    }
    !stop.load(Ordering::Relaxed)
}

/// Observe every file the globs currently match.
///
/// Sorted, so the fingerprint depends on the file set rather than on the order
/// the filesystem happened to return it in. An unreadable entry is skipped: it
/// contributes nothing now and reappears in a later poll once it is readable,
/// which is what a partially-written batch looks like from here.
pub fn fingerprint(globs: &[String]) -> Fingerprint {
    let mut out: Fingerprint = Vec::new();
    for pattern in globs {
        let Ok(paths) = glob::glob(pattern) else {
            continue;
        };
        for path in paths.flatten() {
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            out.push((path, meta.len(), meta.modified().ok()));
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn write(dir: &std::path::Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write");
    }

    #[test]
    fn fingerprint_tracks_the_file_set_not_its_order() {
        let dir = tempdir();
        write(dir.path(), "b.conf", "b");
        write(dir.path(), "a.conf", "a");
        let pattern = format!("{}/*.conf", dir.path().display());

        let first = fingerprint(std::slice::from_ref(&pattern));
        let second = fingerprint(std::slice::from_ref(&pattern));

        assert_eq!(first, second, "fingerprint must be order-independent");
        assert_eq!(first.len(), 2);
    }

    #[test]
    fn fingerprint_changes_when_a_file_is_added_or_removed() {
        let dir = tempdir();
        write(dir.path(), "a.conf", "a");
        let pattern = format!("{}/*.conf", dir.path().display());

        let before = fingerprint(std::slice::from_ref(&pattern));
        write(dir.path(), "b.conf", "b");
        let added = fingerprint(std::slice::from_ref(&pattern));
        assert_ne!(before, added, "a new rule file must be noticed");

        std::fs::remove_file(dir.path().join("b.conf")).expect("remove");
        let removed = fingerprint(std::slice::from_ref(&pattern));
        assert_eq!(before, removed, "removing it must return to the prior set");
    }

    #[test]
    fn fingerprint_changes_when_content_size_changes() {
        let dir = tempdir();
        write(dir.path(), "a.conf", "a");
        let pattern = format!("{}/*.conf", dir.path().display());

        let before = fingerprint(std::slice::from_ref(&pattern));
        write(dir.path(), "a.conf", "much longer content");
        assert_ne!(before, fingerprint(std::slice::from_ref(&pattern)));
    }

    // The baseline poll must not fire: init already compiled these files, and
    // rebuilding there would discard a generation that is serving traffic.
    #[test]
    fn does_not_fire_on_the_first_observation() {
        let dir = tempdir();
        write(dir.path(), "a.conf", "a");
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);

        let globs = vec![format!("{}/*.conf", dir.path().display())];
        let mut watcher = RuleWatcher::spawn(
            globs.clone(),
            Duration::from_millis(50),
            fingerprint(&globs),
            move || {
                seen.fetch_add(1, Ordering::Relaxed);
            },
        );
        thread::sleep(Duration::from_millis(250));
        watcher.stop();

        assert_eq!(
            calls.load(Ordering::Relaxed),
            0,
            "an unchanged rule set must not trigger a rebuild"
        );
    }

    #[test]
    fn fires_once_when_the_rule_set_changes() {
        let dir = tempdir();
        write(dir.path(), "a.conf", "a");
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);

        let globs = vec![format!("{}/*.conf", dir.path().display())];
        let mut watcher = RuleWatcher::spawn(
            globs.clone(),
            Duration::from_millis(50),
            fingerprint(&globs),
            move || {
                seen.fetch_add(1, Ordering::Relaxed);
            },
        );
        thread::sleep(Duration::from_millis(150));
        write(dir.path(), "b.conf", "b");
        thread::sleep(Duration::from_millis(300));
        watcher.stop();

        let n = calls.load(Ordering::Relaxed);
        assert_eq!(n, 1, "one change must rebuild exactly once, got {n}");
    }

    // The race that made an earlier version silently serve stale rules forever:
    // a write landing between the caller's read and the thread's first poll was
    // absorbed into a thread-taken baseline and never seen again.
    #[test]
    fn fires_for_a_change_that_lands_before_the_thread_starts() {
        let dir = tempdir();
        write(dir.path(), "a.conf", "a");
        let globs = vec![format!("{}/*.conf", dir.path().display())];
        let baseline = fingerprint(&globs);

        write(dir.path(), "a.conf", "a much longer rule set");

        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let mut watcher =
            RuleWatcher::spawn(globs, Duration::from_millis(50), baseline, move || {
                seen.fetch_add(1, Ordering::Relaxed);
            });
        thread::sleep(Duration::from_millis(300));
        watcher.stop();

        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "a change written before the watcher thread ran must still rebuild"
        );
    }

    // The rule set arrives as one write per file. Rebuilding on the first poll
    // that differs would compile whatever subset had landed — a partial rule set
    // compiles fine, so the WAF would run short of rules and look healthy.
    #[test]
    fn does_not_rebuild_while_a_batch_is_still_arriving() {
        let dir = tempdir();
        let globs = vec![format!("{}/*.conf", dir.path().display())];
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);

        let mut watcher = RuleWatcher::spawn(
            globs.clone(),
            Duration::from_millis(200),
            fingerprint(&globs),
            move || {
                seen.fetch_add(1, Ordering::Relaxed);
            },
        );

        // Files land far faster than the poll interval, as they do in
        // production: the whole rule set is pushed concurrently in well under
        // the default 15s.
        for i in 0..8 {
            write(dir.path(), &format!("rule{i}.conf"), "rule");
            thread::sleep(Duration::from_millis(30));
        }
        let during_batch = calls.load(Ordering::Relaxed);
        thread::sleep(Duration::from_millis(700));
        watcher.stop();

        assert_eq!(
            during_batch, 0,
            "a rule set still being written must not be compiled yet"
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "the settled batch must be compiled exactly once"
        );
    }

    // The watcher must be gone before the generation it rebuilds is dropped, so
    // stopping cannot wait out a whole interval.
    #[test]
    fn stops_promptly_even_with_a_long_interval() {
        let dir = tempdir();
        let mut watcher = RuleWatcher::spawn(
            vec![format!("{}/*.conf", dir.path().display())],
            Duration::from_secs(3600),
            Fingerprint::new(),
            || {},
        );

        let start = std::time::Instant::now();
        watcher.stop();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "stop took {:?}; a shutdown must not wait out the poll interval",
            start.elapsed()
        );
    }

    fn tempdir() -> TempDir {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "coraza-watcher-test-{}-{:?}",
            std::process::id(),
            thread::current().id()
        ));
        std::fs::create_dir_all(&path).expect("mkdir");
        TempDir { path }
    }

    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
