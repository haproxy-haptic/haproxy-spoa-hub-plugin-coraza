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
    const char *data;   // Redirect URL or empty (dynamically allocated if non-empty, free via coraza_free_string)
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
    int resp_body_limit
);

int coraza_waf_rules_count(coraza_waf_t waf);
void coraza_waf_free(coraza_waf_t waf);
```

### WAF Application Routing

```c
// Set the default WAF used when no app name is specified.
void coraza_set_default_waf(coraza_waf_t waf);

// Map an application name to a specific WAF instance.
void coraza_set_app_waf(const char *app_name, coraza_waf_t waf);
```

### Request Processing (batched)

```c
// Process a complete HTTP request in a single FFI call.
// Headers format: "Key1\0Value1\0Key2\0Value2\0" (null-separated pairs)
// app_name: optional application name for multi-app routing (null = default)
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
    int cache_tx,
    const char *app_name
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

### Cache Configuration

```c
void coraza_set_cache_ttl(int ttl_ms);
```

### Metrics

```c
int64_t coraza_metrics_allowed(void);
int64_t coraza_metrics_blocked(void);
int64_t coraza_metrics_rules_hit(void);
int64_t coraza_metrics_errors(void);
void coraza_metrics_reset(void);
```

### Utilities

```c
// Free a dynamically allocated string from the Go side.
// Do NOT call on pre-allocated action strings ("allow", "deny", etc.).
void coraza_free_string(char *s);

// Get the last error message. Returns NULL if no error.
// Caller must free the returned string via coraza_free_string().
char *coraza_last_error(void);

// Graceful shutdown: drain pending async evaluations, close all cached
// transactions, stop background goroutines, destroy all WAF instances.
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

- `coraza_waf_new`, `coraza_waf_free`, `coraza_set_default_waf`,
  `coraza_set_app_waf`: NOT thread-safe. Call during init/shutdown only.
- `coraza_process_request`, `coraza_process_response`: Thread-safe.
- `coraza_metrics_*`: Thread-safe (atomic counters).
- `coraza_shutdown`: NOT thread-safe. Call once after all processing stops.

## Error Handling

- Functions that can fail return 0/NULL or set action to "deny" (FR-008).
- `coraza_last_error()` returns the most recent error message.
- Go panics are recovered via `defer recover()` and converted to errors.
- The Rust side defaults `action_str()` to "deny" if the action pointer
  is null (deny-by-default per FR-008).
