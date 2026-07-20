#!/usr/bin/env python3
"""Download + extract the CodeQL bundle (CLI + prebuilt query packs) into .codeql/.

The CodeQL bundle is self-contained: no query-pack download at analysis time.
It is large (~670 MB win64) so this is a one-time setup step, kept out of git.

Usage:
    python scripts/setup_codeql.py            # download (if needed) + extract
    python scripts/setup_codeql.py --check    # just report whether codeql is ready
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CODEQL_DIR = ROOT / ".codeql"
BINARY = CODEQL_DIR / "codeql" / ("codeql.exe" if os.name == "nt" else "codeql")

BUNDLE_TAG = "codeql-bundle-v2.26.1"
ASSET_BY_SYSTEM = {
    "Windows": "codeql-bundle-win64.tar.gz",
    "Linux": "codeql-bundle-linux64.tar.gz",
    "Darwin": "codeql-bundle-osx64.tar.gz",
}


def asset_name() -> str:
    system = platform.system()
    try:
        return ASSET_BY_SYSTEM[system]
    except KeyError as exc:
        raise SystemExit(f"Unsupported platform for CodeQL bundle: {system}") from exc


def download(dest: Path) -> None:
    if dest.exists():
        print(f"bundle already downloaded: {dest} ({dest.stat().st_size/1e6:.0f} MB)")
        return
    print(f"downloading {BUNDLE_TAG} / {dest.name} via gh ...")
    subprocess.run(
        [
            "gh", "release", "download", BUNDLE_TAG,
            "--repo", "github/codeql-action",
            "--pattern", dest.name,
            "--dir", str(CODEQL_DIR),
            "--clobber",
        ],
        check=True,
    )


def extract(archive: Path) -> None:
    print(f"extracting {archive.name} -> {CODEQL_DIR} ...")
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(CODEQL_DIR)  # noqa: S202 (trusted GitHub release)


def main() -> int:
    check_only = "--check" in sys.argv
    if BINARY.exists():
        print(f"CodeQL ready: {BINARY}")
        return 0
    if check_only:
        print("CodeQL not set up. Run: python scripts/setup_codeql.py")
        return 1

    CODEQL_DIR.mkdir(parents=True, exist_ok=True)
    archive = CODEQL_DIR / asset_name()
    download(archive)
    extract(archive)
    if not BINARY.exists():
        raise SystemExit(f"extraction finished but {BINARY} not found")
    print(f"CodeQL ready: {BINARY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
