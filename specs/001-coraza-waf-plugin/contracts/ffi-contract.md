# FFI Contract: Go Coraza Wrapper → Rust Plugin

This document defines the C-compatible FFI boundary between the Go-based
Coraza WAF wrapper (compiled as `c-archive`) and the Rust cdylib plugin.

## Type Definitions

```c
// Opaque handles
typedef uint64_t coraza_waf_t;

// Result of WAF evaluation
typedef struct {
    int rule_id;        // 0 if no interruption
    const char *action; // "allow", "deny", "drop", "redirect" (pre-allocated, do NOT free)
    int status;         // HTTP status code (0 for allow)
    const char *data;   // Optional bounded interruption data (free via coraza_free_string when non-empty)
    int anomaly_score;  // CRS anomaly score (sum of matched rule severities)
    int rules_hit;      // Number of matched rules
} coraza_result_t;
```

## Functions

### WAF Lifecycle

```c
// Create a new WAF instance with embedded CRS and optional overrides.
// directives: SecLang directives (UTF-8, not necessarily null-terminated)
// directives_len: length in bytes
// directives_file: optional path to additional directives file (null = none)
// root_fs_path: optional filesystem root for rule loading (null = embedded + OS)
// Returns: WAF handle (>0) or 0 on error. Check coraza_last_error().
coraza_waf_t coraza_waf_new(
    const char *directives,
    int directives_len,
    const char *directives_file,
    const char *root_fs_path,
    int req_body_limit,
    int req_body_mem_limit,
    int resp_body_limit,
    int rule_match_log,
    int matched_data_log_mode,
    int matched_data_max_bytes
);

int coraza_waf_rules_count(coraza_waf_t waf);
void coraza_waf_free(coraza_waf_t waf);
int coraza_waf_active_count(void);
```

Application routing is owned by the Rust plugin generation. It selects a WAF
handle before crossing the FFI boundary; the Go archive has no process-global
application map.

### Request Processing (batched)

```c
// Process a complete HTTP request in a single FFI call.
// Headers format: "Key1\0Value1\0Key2\0Value2\0" (null-separated pairs)
coraza_result_t coraza_process_request(
    coraza_waf_t waf_handle,
    const char *tx_id,
    const char *src_ip,
    int src_port,
    const char *dst_ip,
    int dst_port,
    const char *method,
    const char *path,
    const char *query,
    const char *http_version,
    const char *headers,
    int headers_len,
    const char *body,
    int body_len,
    int cache_ttl_ms,
    int max_cached_transactions,
    int detect_only,
    int expose_matched_data,
    int matched_data_max_bytes
);
```

### Response Processing (batched)

```c
// Process a complete HTTP response for a previously cached transaction.
coraza_result_t coraza_process_response(
    const char *tx_id,
    int status_code,
    const char *http_version,
    const char *headers,
    int headers_len,
    const char *body,
    int body_len,
    int detect_only
);
```

Cache TTL and capacity are passed with each request. This keeps concurrently
live reload generations from overwriting process-global cache settings.

### Metrics

```c
int64_t coraza_metrics_allowed(void);
int64_t coraza_metrics_blocked(void);
int64_t coraza_metrics_rules_hit(void);
int64_t coraza_metrics_errors(void);
```

### Utilities

```c
// Free a dynamically allocated string from the Go side.
// Do NOT call on pre-allocated action strings ("allow", "deny", etc.).
void coraza_free_string(char *s);

// Get the last error message. Returns NULL if no error.
// Caller must free the returned string via coraza_free_string().
char *coraza_last_error(void);

// Graceful shutdown: close cached transactions, stop the evictor, and retire
// all WAF instances.
void coraza_shutdown(void);
```

## Memory Ownership Rules

1. **`action` field**: Points to pre-allocated Go-side constants. MUST NOT
   be freed.
2. **`data` field**: Dynamically allocated via `C.CString` when non-empty.
   Free via `coraza_free_string()`.
3. **`coraza_last_error()` return**: Dynamically allocated. Caller must
   free via `coraza_free_string()`.
4. **Rust-allocated buffers** (`headers`, `body`): Owned by Rust. Go copies
   data during the call; Rust can free after return.

## Thread Safety

- `coraza_waf_new` and `coraza_waf_free`: thread-safe. A freed handle is
  retired after its last cached transaction releases its lease.
- `coraza_process_request`, `coraza_process_response`: Thread-safe.
- `coraza_metrics_*`: Thread-safe (atomic counters).
- `coraza_shutdown`: NOT thread-safe. Call once after all processing stops.

## Error Handling

- Functions that can fail return 0/NULL or an explicit deny result (FR-008).
- `coraza_last_error()` returns the most recent error message.
- Go panics are recovered via `defer recover()` and converted to generic errors
  without logging or returning the panic payload.
- The Rust side defaults `action_str()` to "deny" if the action pointer
  is null (deny-by-default per FR-008).
