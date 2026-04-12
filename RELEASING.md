# Release Process

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` with new `## [x.y.z]` section
3. Commit: `git commit -am "chore: release vx.y.z"`
4. Tag: `git tag vx.y.z`
5. Push: `git push origin vx.y.z`

The CI pipeline automatically:
- Builds multi-arch binaries (amd64, arm64, armv7)
- Creates a GitLab release with binary assets
- Attaches `.so` files named `libcoraza_plugin-{arch}-glibc2.36.so`
