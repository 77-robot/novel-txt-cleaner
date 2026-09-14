#!/usr/bin/env python3
"""Static privacy/release gate for the public package."""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
FORBIDDEN = (
    "ME" + "AT",
    "看" + "文记录",
    "library" + "_class",
    "file" + "Id",
    "Reading" + "o",
    "/" + "Users/",
    "Desk" + "top/",
    "真实" + "语料",
    "批" + "次",
)
PRIVATE_NAMES = ("_user_meta.json", "__pycache__")


def main() -> int:
    failures: list[str] = []
    for path in ROOT.rglob("*"):
        if path == SELF or not path.is_file():
            continue
        if any(part in PRIVATE_NAMES for part in path.parts):
            failures.append(f"private path: {path.relative_to(ROOT)}")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            failures.append(f"non-UTF8 release text: {path.relative_to(ROOT)}")
            continue
        for marker in FORBIDDEN:
            if marker in text:
                failures.append(f"sensitive marker {marker!r}: {path.relative_to(ROOT)}")
    if failures:
        print("PUBLIC RELEASE CHECK: FAIL")
        print("\n".join(failures))
        return 1
    print("PUBLIC RELEASE CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
