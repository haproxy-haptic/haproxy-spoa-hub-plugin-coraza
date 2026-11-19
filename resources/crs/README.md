The pure Rust build embeds the rule and data files from the same Coraza Core Rule
Set v4.25.0 module as the Go build. The archive contains only the module's
`rules/` subtree, including the recommended connector policy and CRS setup.
The files are licensed under Apache-2.0. [Source module](https://github.com/corazawaf/coraza-coreruleset/tree/v4.25.0)

To reproduce the archive from the repository root, run the following commands.

```sh
curl -fL https://proxy.golang.org/github.com/corazawaf/coraza-coreruleset/v4/@v/v4.25.0.zip -o /tmp/coraza-crs.zip
python3 scripts/package-crs.py /tmp/coraza-crs.zip
```
