"""Check license bytes in a source archive or an extracted container filesystem."""

import argparse
from pathlib import Path
import tarfile

FILES = ("LICENSE", "NOTICE.md", "licenses/JEP-CORE-BSD-3-Clause.txt")
parser = argparse.ArgumentParser(description=__doc__)
target = parser.add_mutually_exclusive_group(required=True)
target.add_argument("--source", type=Path)
target.add_argument("--directory", type=Path)
args = parser.parse_args()
if args.source:
    with tarfile.open(args.source) as archive:
        for name in FILES:
            assert archive.extractfile(name).read() == Path(name).read_bytes(), name
else:
    for name in FILES:
        assert (args.directory / name).read_bytes() == Path(name).read_bytes(), name
print("Distributed license texts and scope notices match the reviewed source")
