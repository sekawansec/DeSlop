"""Evidence pack generation.

Produces a downloadable bundle: summary.md, requests.har, request/response log,
repro.sh, repro_test.py, verifier_log.json, and the reply draft. Credentials are
never included.
"""

from __future__ import annotations

import io
import json
import zipfile

from ..db.models import Report

REDACT = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}


def _summary_md(report: Report, triage: dict | None) -> str:
    lines = [
        f"# {report.title}",
        "",
        f"- Report ID: {report.id}",
        f"- Program: {report.program_id}",
        f"- Asset: {report.asset or 'unknown'}",
        f"- Endpoint: {report.endpoint or 'unknown'}",
        f"- Vuln class: {report.vuln_class or 'unknown'}",
        f"- Internal status: {report.status}",
        f"- Claimed severity: {report.claimed_severity or 'unknown'}",
    ]
    if triage:
        lines.append(f"- Suggested CVSS: {triage.get('suggested_cvss') or 'n/a'}")
        lines.append(f"- Routing category: {triage.get('routing_category') or 'n/a'}")
    lines += ["", "## Report body", "", report.body[:4000], ""]
    return "\n".join(lines)


def _repro_sh(steps: list[dict]) -> str:
    lines = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    for step in steps:
        req = step.get("request", {})
        method = req.get("method", "GET")
        url = req.get("url", "")
        lines.append(f"# step {step.get('index')}: {step.get('description', '')}")
        curl = f"curl -sS -X {method} '{url}'"
        for name, value in (req.get("headers") or {}).items():
            if name.lower() in REDACT:
                value = "<redacted>"
            curl += f" -H '{name}: {value}'"
        if req.get("body"):
            curl += f" --data '{req['body']}'"
        lines.append(curl)
        lines.append("")
    return "\n".join(lines)


def _repro_test_py(steps: list[dict], bug_class: str) -> str:
    return (
        '"""Retest script. Re-run after a fix to check whether the bug is still present."""\n'
        "import httpx\n\n"
        f"STEPS = {steps!r}\n"
        f"BUG_CLASS = {bug_class!r}\n\n\n"
        "def run(base_url=None):\n"
        "    results = []\n"
        "    with httpx.Client(follow_redirects=False, timeout=20.0) as c:\n"
        "        for step in STEPS:\n"
        "            req = step.get('request', {})\n"
        "            url = req.get('url', '')\n"
        "            if base_url and url.startswith('http'):\n"
        "                url = base_url.rstrip('/') + '/' + url.split('/', 3)[-1]\n"
        "            r = c.request(req.get('method', 'GET'), url,\n"
        "                          headers=req.get('headers') or {},\n"
        "                          content=req.get('body'))\n"
        "            results.append({'index': step.get('index'), 'status': r.status_code,\n"
        "                            'body': r.text[:4096]})\n"
        "    return results\n\n\n"
        "if __name__ == '__main__':\n"
        "    for row in run():\n"
        "        print(row['index'], row['status'])\n"
    )


def _har(steps: list[dict]) -> str:
    entries = []
    for step in steps:
        req = step.get("request", {})
        entries.append(
            {
                "startedDateTime": "",
                "request": {
                    "method": req.get("method", "GET"),
                    "url": req.get("url", ""),
                    "headers": [
                        {"name": n, "value": ("<redacted>" if n.lower() in REDACT else v)}
                        for n, v in (req.get("headers") or {}).items()
                    ],
                },
                "response": {"status": 0, "content": {"text": ""}},
            }
        )
    return json.dumps({"log": {"version": "1.2", "entries": entries}}, indent=2)


def build_evidence_pack(report: Report, triage: dict | None = None) -> bytes:
    """Build a zip bundle of the evidence pack for a report."""
    plans = report.repro_plans or []
    steps: list[dict] = []
    if plans:
        steps = plans[-1].steps or []
    runs = [r for plan in plans for r in plan.runs]
    verifier_log = [
        {
            "run_id": r.run_id,
            "status": r.status,
            "verdict": r.verdict,
            "evidence": r.evidence,
            "duration_ms": r.duration_ms,
        }
        for r in runs
    ]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("summary.md", _summary_md(report, triage))
        z.writestr("requests.har", _har(steps))
        z.writestr("repro.sh", _repro_sh(steps))
        z.writestr("repro_test.py", _repro_test_py(steps, report.vuln_class or "unknown"))
        z.writestr("verifier_log.json", json.dumps(verifier_log, indent=2))
        draft = (triage or {}).get("reply_draft") or ""
        z.writestr("reply_draft.txt", draft)
    return buf.getvalue()

