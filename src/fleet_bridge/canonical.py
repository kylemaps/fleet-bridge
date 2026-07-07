"""Canonical JSON serialisation, identical convention to rating-bridge and
veriseal's manifest spec (SPEC-manifest.md ss1): sorted keys, no insignificant
whitespace, non-ASCII left as-is, NaN/Infinity forbidden, UTF-8, one trailing
newline so the canonical bytes double as a diff-friendly text file.

Floats are rounded upstream (aggregate.py) before they reach this function,
so re-running the pipeline on the same fleet directory reproduces the same
canonical bytes for every metric field.
"""

from __future__ import annotations

import json


def canonical_bytes(obj: object) -> bytes:
    """Return the canonical UTF-8 byte encoding of *obj*, plus a trailing newline."""
    text = json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return (text + "\n").encode("utf-8")
