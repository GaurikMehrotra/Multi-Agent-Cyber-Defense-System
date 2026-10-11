"""Streaming Zeek JSON and ASCII parsing with malformed-row accounting."""

import json
from collections.abc import Iterator
from pathlib import Path


class ParseStats:
    def __init__(self):
        self.accepted = 0
        self.rejected = 0


def records(path: str | Path, stats: ParseStats | None = None) -> Iterator[dict]:
    stats = stats or ParseStats()
    columns = []
    separator = "\t"
    with Path(path).open(errors="replace") as stream:
        for line in stream:
            if line.startswith("#separator"):
                try:
                    candidate = bytes(line.rstrip("\n").split(" ", 1)[1], "ascii").decode(
                        "unicode_escape"
                    )
                    if len(candidate) != 1:
                        raise ValueError("single separator required")
                    separator = candidate
                except (ValueError, UnicodeError, IndexError):
                    stats.rejected += 1
                continue
            if line.startswith("#fields"):
                columns = line.rstrip().split(separator)[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            try:
                if line.lstrip().startswith("{"):
                    row = json.loads(line)
                else:
                    values = line.rstrip("\n").split(separator)
                    if len(values) != len(columns) or not columns:
                        raise ValueError("truncated or missing header")
                    row = {
                        key: None if val in ("-", "(empty)") else val
                        for key, val in zip(columns, values, strict=True)
                    }
                if not isinstance(row, dict):
                    raise ValueError("object required")
            except (ValueError, UnicodeError, RecursionError):
                stats.rejected += 1
                continue
            stats.accepted += 1
            yield row
