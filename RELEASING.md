# Release Process

This project produces multi-arch plugin shared libraries on every version
tag, uploaded to the GitLab Generic Package Registry alongside per-file
`.sha256` sidecars and `.cosign.bundle` signatures.

All artifacts are published automatically by CI when you push a version tag.

## Prerequisites

- Permission to push tags to the repository.
- **Generic packages "Reject duplicates" enabled** under
  Settings > Packages and Registries > Generic packages. Without this, a
  re-run of the release pipeline on the same tag silently overwrites the
  bytes uploaded earlier.

## Release process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`: move items from `[Unreleased]` into a new
   `## [x.y.z]` section
3. Commit: `git commit -am "chore: release vx.y.z"`
4. Tag: `git tag vx.y.z`
5. Push: `git push origin vx.y.z`

CI handles the rest:

- Cross-compiles for amd64, arm64, and armv7 with `cargo auditable`
  (binaries embed a compressed `Cargo.lock`-equivalent so SBOM tools can
  enumerate Rust deps without source access)
- Generates per-file `.sha256` sidecars and a combined `SHA256SUMS`
- Cosign keyless-signs every `.so` using the GitLab OIDC id token,
  producing `.cosign.bundle` files
- Uploads everything to the Generic Package Registry under
  `packages/generic/coraza/<tag>/`
- Creates a GitLab release with all artifacts linked as release assets

## Verifying a release

After CI finishes, verify the release end-to-end from a clean machine:

```sh
make verify-release VERSION=v0.1.1
```

This downloads `SHA256SUMS`, every artifact named in it, and every artifact's
cosign bundle from the package registry, then runs `sha256sum -c` and
`cosign verify-blob` against the project's tag identity.
