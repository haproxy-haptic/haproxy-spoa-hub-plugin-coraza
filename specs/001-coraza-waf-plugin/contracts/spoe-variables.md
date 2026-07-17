# SPOE Variable Contract

## SPOE Message: `check-request`

**Event**: `on-frontend-http-request`

### Input Arguments (from HAProxy)

| Argument | Type | Source | Description |
|----------|------|--------|-------------|
| `src-ip` | string | `src` | Client source IP address |
| `src-port` | int | `src_port` | Client source port |
| `dst-ip` | string | `dst` | Destination IP address |
| `dst-port` | int | `dst_port` | Destination port |
| `method` | string | `method` | HTTP method (GET, POST, etc.) |
| `path` | string | `path` | Request path |
| `query` | string | `query` | Query string |
| `version` | string | `req.ver` | HTTP version (HTTP/1.1, HTTP/2.0) |
| `headers` | binary | `req.hdrs` | Raw request headers |
| `body` | binary | `req.body` | Request body |
| `app` | string | (optional) | Application name for multi-app routing |
| `detect-only` | bool | (optional) | Per-message override: when `true`, the WAF evaluates rules normally but coerces the verdict to `action=allow`; matched `rule_id`, `anomaly_score`, `rules_hit`, and `data` are still populated. Falls back to the hub-global `detect_only` config when malformed or absent. See `specs/002-detect-only-request/`. |
| `body-mode` | string | (optional) | `none` ignores body bytes; `buffered` inspects them and requires `body-complete=true`. Absent defaults safely to `none`. |
| `body-complete` | bool | (required with buffered mode) | Integration assertion that HAProxy supplied the complete bounded body. Missing/false fails closed. |

### Output Variables (set by plugin)

All variables are scoped to `txn` and namespaced by the hub as `hub.<plugin_name>.<var>`.

| Variable | Type | Description |
|----------|------|-------------|
| `id` | string | Transaction ID (for response correlation) |
| `action` | string | `allow`, `deny`, `drop`, or `redirect` |
| `status` | int | HTTP status code; a `drop` action is disruptive despite status 0 |
| `rule_id` | int | ID of the rule that triggered deny (0=allow) |
| `anomaly_score` | int | Accumulated anomaly score |
| `rules_hit` | int | Number of rules that matched |
| `data` | string | Bounded interruption data; omitted unless `expose_matched_data=true` |

## SPOE Message: `check-response`

**Event**: `on-http-response`

### Input Arguments (from HAProxy)

| Argument | Type | Source | Description |
|----------|------|--------|-------------|
| `id` | string | `var(txn.hub.coraza.id)` | Transaction ID from request phase |
| `version` | string | `res.ver` | HTTP response version |
| `status` | int | `status` | HTTP response status code |
| `headers` | binary | `res.hdrs` | Raw response headers |
| `body` | binary | `res.body` | Response body |
| `detect-only` | bool | (optional) | If true, coerce a completed WAF deny to allow; evaluation remains synchronous inside the hub admission permit |

### Output Variables (set by plugin)

| Variable | Type | Description |
|----------|------|-------------|
| `resp_action` | string | "allow" or "deny" (always "allow" in detect-only) |
| `resp_status` | int | HTTP status code from response-phase rule |
| `resp_rule_id` | int | ID of the response-phase rule that triggered |

## Migration from standalone coraza-spoa

| coraza-spoa variable | Hub equivalent (plugin name: `coraza`) |
|---------------------|----------------------------------------|
| `txn.coraza.action` | `var(txn.hub.coraza.action)` |
| `txn.coraza.status` | `var(txn.hub.coraza.status)` |
| `txn.coraza.data` | `var(txn.hub.coraza.data)` |
| `txn.coraza.ruleid` | `var(txn.hub.coraza.rule_id)` |
| `txn.coraza.id` | `var(txn.hub.coraza.id)` |
| `txn.coraza.anomaly_score` | `var(txn.hub.coraza.anomaly_score)` |
| `txn.coraza.rules_hit` | `var(txn.hub.coraza.rules_hit)` |

## Example HAProxy SPOE Configuration

```
[coraza-waf]
spoe-agent coraza_agent
    messages check-request check-response
    option var-prefix hub
    use-backend spoa-hub
    timeout hello      100ms
    timeout idle       30s
    timeout processing 15ms

spoe-message check-request
    args src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs body=req.body body-mode=var(txn.coraza_body_mode) body-complete=var(txn.coraza_body_complete) detect-only=var(txn.coraza_detect_only) app=var(txn.coraza_app)
    event on-frontend-http-request

spoe-message check-response
    args id=var(txn.hub.coraza.id) version=res.ver status=status headers=res.hdrs body=res.body
    event on-http-response
```
