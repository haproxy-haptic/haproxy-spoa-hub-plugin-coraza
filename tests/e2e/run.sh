#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLUSTER_NAME="e2e-coraza-$$"
HOST_PORT="${E2E_PORT:-$(( (RANDOM % 30000) + 20000 ))}"
NAMESPACE="e2e-coraza"

# Docker-in-Docker support: node host may differ from localhost
if [ -n "${DOCKER_HOST:-}" ]; then
    NODE_HOST=$(echo "$DOCKER_HOST" | sed -E 's|tcp://([^:]+):.*|\1|')
else
    NODE_HOST="localhost"
fi

TMPDIR=$(mktemp -d)
PASS=0
FAIL=0

# --- Cleanup ---
cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# --- Assertion helpers ---
assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected '$expected', got '$actual')"
        FAIL=$((FAIL + 1))
    fi
}

assert_contains() {
    local desc="$1" expected="$2" actual="$3"
    # Match in-shell: with `| grep -q`, grep exits on first match, the
    # producer takes SIGPIPE, and pipefail reports 141 -- a match read as a miss.
    if [[ "$actual" == *"$expected"* ]]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (expected to contain '$expected')"
        FAIL=$((FAIL + 1))
    fi
}

assert_not_eq() {
    local desc="$1" unexpected="$2" actual="$3"
    if [ "$unexpected" != "$actual" ]; then
        echo "  PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $desc (did not expect '$unexpected')"
        FAIL=$((FAIL + 1))
    fi
}

# --- Prerequisites ---
echo "=== Checking prerequisites ==="
for cmd in kind kubectl docker curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found"
        exit 1
    fi
done

# --- Create kind cluster ---
echo "=== Creating kind cluster: $CLUSTER_NAME ==="

API_SERVER_ADDR="127.0.0.1"
if [ -n "${DOCKER_HOST:-}" ]; then
    API_SERVER_ADDR="0.0.0.0"
fi

cat > "$TMPDIR/kind-config.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "$API_SERVER_ADDR"
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: $HOST_PORT
        protocol: TCP
EOF

kind create cluster --name "$CLUSTER_NAME" --config "$TMPDIR/kind-config.yaml" --wait 60s

# Docker-in-Docker: patch kubeconfig
if [ -n "${DOCKER_HOST:-}" ]; then
    API_PORT=$(docker port "${CLUSTER_NAME}-control-plane" 6443/tcp | head -1 | cut -d: -f2)
    kubectl config set-cluster "kind-${CLUSTER_NAME}" \
        --server="https://${NODE_HOST}:${API_PORT}" \
        --insecure-skip-tls-verify=true
fi

# --- Build and load hub+plugin image ---
echo "=== Building hub+plugin image ==="
docker build -t e2e-hub:latest -f "$SCRIPT_DIR/Dockerfile.hub" "$REPO_ROOT"
kind load docker-image e2e-hub:latest --name "$CLUSTER_NAME"

# --- Deploy manifests ---
echo "=== Deploying manifests ==="
kubectl apply -f "$SCRIPT_DIR/manifests/namespace.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/configmaps.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/backend.yaml"
kubectl apply -f "$SCRIPT_DIR/manifests/haproxy-hub.yaml"

# --- Wait for pods ---
echo "=== Waiting for pods ==="
kubectl wait --for=condition=ready pod -l app=backend -n "$NAMESPACE" --timeout=120s

if ! kubectl wait --for=condition=ready pod -l app=haproxy-hub -n "$NAMESPACE" --timeout=120s; then
    echo "ERROR: haproxy-hub pod not ready"
    kubectl describe pod -l app=haproxy-hub -n "$NAMESPACE"
    kubectl logs -l app=haproxy-hub -n "$NAMESPACE" --all-containers --tail=50 || true
    exit 1
fi

BASE_URL="http://${NODE_HOST}:${HOST_PORT}"
echo "HAProxy URL: $BASE_URL"

# Wait for HAProxy to accept connections
echo "Waiting for HAProxy..."
for i in $(seq 1 30); do
    if curl -sf "$BASE_URL/" > /dev/null 2>&1; then
        echo "HAProxy ready after ${i}s"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: HAProxy not ready after 30s"
        echo "--- haproxy-hub pod logs ---"
        kubectl logs -l app=haproxy-hub -n "$NAMESPACE" --all-containers --tail=50 || true
        exit 1
    fi
    sleep 1
done

# --- Tests ---
echo ""
echo "=== Running tests ==="

# Test 1: Benign request returns 200
echo ""
echo "--- Test 1: Benign GET request ---"
RESP=$(curl -s -o "$TMPDIR/body1.txt" -w '%{http_code}' "$BASE_URL/index.html")
assert_eq "Benign request returns 200" "200" "$RESP"

# Test 2: SQL injection returns 403
echo ""
echo "--- Test 2: SQL injection blocked ---"
RESP=$(curl -s -o "$TMPDIR/body2.txt" -w '%{http_code}' "$BASE_URL/search?id=1'+OR+1%3D1+--")
assert_eq "SQL injection returns 403" "403" "$RESP"

# Test 3: XSS returns 403
echo ""
echo "--- Test 3: XSS blocked ---"
RESP=$(curl -s -o "$TMPDIR/body3.txt" -w '%{http_code}' "$BASE_URL/page?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
assert_eq "XSS returns 403" "403" "$RESP"

# Test 4: Large body does not crash (non-5xx response)
echo ""
echo "--- Test 4: Large body handling ---"
head -c 262144 /dev/urandom > "$TMPDIR/large_body.bin"
RESP=$(curl -s -o "$TMPDIR/body4.txt" -w '%{http_code}' -X POST --data-binary @"$TMPDIR/large_body.bin" -H "Content-Type: application/octet-stream" "$BASE_URL/upload")
assert_not_eq "Large body does not return 500" "500" "$RESP"
assert_not_eq "Large body does not return 502" "502" "$RESP"
assert_not_eq "Large body does not return 503" "503" "$RESP"

# Test 5: Hub logs show plugin processing
echo ""
echo "--- Test 5: Hub logs ---"
HUB_LOGS=$(kubectl logs -l app=haproxy-hub -n "$NAMESPACE" -c hub --tail=100 2>/dev/null || echo "")
assert_contains "Hub logs contain plugin activity" "coraza" "$HUB_LOGS"

# --- Summary ---
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "=== Debug: Pod logs ==="
    kubectl logs -l app=haproxy-hub -n "$NAMESPACE" --all-containers --tail=50 || true
    exit 1
fi
