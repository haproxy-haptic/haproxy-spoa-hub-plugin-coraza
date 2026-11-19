"""Rebuild the Rust backend's embedded CRS assets from the pinned Go module zip."""
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import zipfile

VERSION = "v4.25.0"
MODULE = "github.com/corazawaf/coraza-coreruleset/v4"
PREFIX = f"{MODULE}@{VERSION}/rules/"
ZIP_SHA256 = "ca9f35410c39be69d0b2cb9536c2b19212295886e9f5709fce0b4bbbb2c43981"
source = Path(sys.argv[1]).read_bytes()
if hashlib.sha256(source).hexdigest() != ZIP_SHA256:
    sys.exit(f"expected {MODULE} {VERSION} from proxy.golang.org")
root = Path(__file__).resolve().parents[1] / "resources/crs"
with zipfile.ZipFile(io.BytesIO(source)) as files:
    root.joinpath("LICENSE").write_bytes(files.read(PREFIX + "LICENSE"))
    with (root / "rules.tar.gz").open("wb") as bundle, gzip.GzipFile(
        fileobj=bundle, mode="wb", filename="", mtime=0
    ) as gz, tarfile.open(fileobj=gz, mode="w") as archive:
        for filename in sorted(files.namelist()):
            if not filename.startswith(PREFIX) or filename.endswith("/"):
                continue
            data = files.read(filename)
            info = tarfile.TarInfo(filename[len(PREFIX):])
            info.mode = 0o600
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
