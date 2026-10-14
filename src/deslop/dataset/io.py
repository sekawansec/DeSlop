"""Read/write helpers for synthetic datasets (JSONL)."""

from __future__ import annotations

import json
from pathlib import Path

from .schema import DatasetManifest, SyntheticReport


def write_jsonl(reports: list[SyntheticReport], path: str | Path, *, seed: int = 0) -> Path:
    """Write reports to a JSONL file plus a companion manifest."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [r.model_dump_json() for r in reports]
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    by_label: dict[str, int] = {}
    for r in reports:
        by_label[r.label.value] = by_label.get(r.label.value, 0) + 1
    manifest = DatasetManifest(program_id="lab", seed=seed, count=len(reports), by_label=by_label)
    p.with_suffix(".manifest.json").write_text(
        manifest.model_dump_json(indent=2), encoding="utf-8"
    )
    return p


def read_jsonl(path: str | Path) -> list[SyntheticReport]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(p)
    reports: list[SyntheticReport] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        reports.append(SyntheticReport.model_validate(json.loads(line)))
    return reports
