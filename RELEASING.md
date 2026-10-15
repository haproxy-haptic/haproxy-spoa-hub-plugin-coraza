# Release Process

This project produces multi-arch plugin shared libraries on every version
tag, published as a GitHub release alongside per-file `.sha256` sidecars,
a combined `SHA256SUMS`, and `.cosign.bundle` signatures.

All artifacts are published automatically by CI when you push a version tag.

## Prerequisites

- Permission to push tags to the repository.

## Release process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`: move items from `[Unreleased]` into a new
   `## [x.y.z]` section
3. Commit: `git commit -am "chore: release vx.y.z"`
4. Tag: `git tag vx.y.z`
5. Push: `git push origin vx.y.z`

`.github/workflows/release.yml` handles the rest:

- Cross-compiles for amd64, arm64, and armv7 with `cargo auditable`
  (binaries embed a compressed `Cargo.lock`-equivalent so SBOM tools can
  enumerate Rust deps without source access)
- Cosign keyless-signs every `.so` using the GitHub Actions OIDC token,
  producing `.cosign.bundle` files, and verifies each signature against the
  release workflow identity
- Generates per-file `.sha256` sidecars and a combined `SHA256SUMS`
- Creates a GitHub release with all artifacts attached

To exercise build, signing, and verification without publishing, run the
`release` workflow manually with `dry_run` enabled.

## Verifying a release

After CI finishes, verify the release end-to-end from a clean machine:

```sh
make verify-release VERSION=v0.1.1
```

This downloads `SHA256SUMS`, every artifact named in it, and every artifact's
cosign bundle from the GitHub release, then runs `sha256sum -c` and
`cosign verify-blob` against the project's tag identity. Tags released
before the move to GitHub verify against the GitLab CI identity.
