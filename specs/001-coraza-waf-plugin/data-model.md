# Data Model: Coraza WAF Plugin

## Entities

### WAFHandle

A compiled Coraza WAF instance. Created once per application configuration at startup.

| Field | Type | Description |
|-------|------|-------------|
| id | uint64 | Opaque handle for FFI reference |
| application_name | string | Application identifier from hub config |
| rules_count | int | Number of loaded WAF rules |

**Lifecycle**: Created during `init()` → shared across all requests → destroyed during `shutdown()`.

**Cardinality**: One per configured application (typically 1, up to N for multi-app deployments).

### TransactionHandle

A short-lived WAF evaluation context for a single HTTP request/response pair.

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique transaction ID (UUID or HAProxy stream ID) |
| waf_handle | uint64 | Reference to parent WAF instance |
| created_at | timestamp | Creation time (for TTL cache eviction) |
| interrupted | bool | Whether a rule triggered an interruption |

**Lifecycle**: Created at request arrival → processes request phases → optionally cached for response → closed after processing or on TTL eviction.

**Cardinality**: One per active HTTP request. Pooled via `sync.Pool` internally by Coraza.

### Interruption

The result of a WAF rule evaluation that triggers a blocking action.

| Field | Type | Description |
|-------|------|-------------|
| rule_id | int | ID of the rule that triggered the interruption |
| action | string | "deny", "drop", or "redirect" |
| status | int | HTTP status code to return (e.g., 403) |
| data | string | Auxiliary data (redirect URL for "redirect" action) |

**Lifecycle**: Created during rule evaluation → returned to Rust via FFI → converted to SPOE transaction variables → discarded.

### ProcessingDecision

The Rust-side result of WAF evaluation, converted to SPOE variables.

| Field | Type | Description |
|-------|------|-------------|
| action | string | "allow" or "deny" |
| status_code | int | HTTP status code (0 for allow, 403/etc. for deny) |
| rule_id | int | Matched rule ID (0 for allow) |
| anomaly_score | int | Accumulated anomaly score |
| rules_hit | int | Number of rules that matched |

**Lifecycle**: Created from Interruption + MatchedRules → serialized as SPOE `TxnVariable`s → returned to hub.

### PluginConfig (Rust side)

Configuration parsed from hub TOML `[plugins.params]`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| directives | string | (embedded CRS) | SecLang directives for WAF rules |
| directives_file | string | none | Path to additional directives file |
| request_body_limit | int | 4096 | Max request body bytes to buffer |
| request_body_in_memory_limit | int | 4096 | Max body bytes kept in memory |
| response_body_limit | int | 4096 | Max response body bytes to buffer |
| response_check | bool | false | Enable response-phase inspection |
| detect_only | bool | false | Log-only mode for response inspection |
| transaction_ttl_ms | int | 10000 | TTL for cached transactions (ms) |
| applications | table | none | Per-app WAF configurations |

### TransactionCache (Go side)

In-memory cache correlating request and response SPOE messages.

| Field | Type | Description |
|-------|------|-------------|
| entries | map[string]*CachedTransaction | Transaction ID → cached transaction |
| ttl | duration | Eviction timeout |
| mu | sync.RWMutex | Concurrent access protection |

**Eviction**: Background goroutine periodically scans for expired entries. Evicted transactions have `ProcessLogging()` and `Close()` called automatically.

## Relationships

```
PluginConfig (1) ──creates──> (1..N) WAFHandle
WAFHandle (1) ──creates──> (0..*) TransactionHandle
TransactionHandle (1) ──produces──> (0..1) Interruption
TransactionHandle (1) ──cached in──> (0..1) TransactionCache entry
Interruption (1) ──maps to──> (1) ProcessingDecision
ProcessingDecision (1) ──serialized as──> (1..*) TxnVariable
```

## State Transitions

### Transaction Lifecycle

```
Created → Processing Request → [Interrupted | Request Complete]
  → If response_check: Cached → Processing Response → [Interrupted | Response Complete] → Closed
  → If !response_check: Closed
  → If TTL expires while Cached: Evicted → Closed
```
