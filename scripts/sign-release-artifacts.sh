#!/bin/sh
# Keyless cosign signing of every release artifact under ./artifacts, using
# the CI's ambient OIDC identity. Writes <file>.cosign.bundle next to each.
set -eu

cd artifacts

for f in *; do
    [ -f "$f" ] || continue
    case "$f" in
        *.sha256 | *.cosign.bundle | SHA256SUMS) continue ;;
    esac
    cosign sign-blob --yes "$f" --bundle "$f.cosign.bundle"
done
