"""Shared helpers for verifiers.

Verifiers are deterministic: they only read the recorded request/response log
and, when needed, talk to the OOB listener. They never ask an LLM anything.
"""

from __future__ import annotations

from ..repro.interfaces import ExecutionResult, StepResult


def last_response(execution: ExecutionResult) -> StepResult | None:
    for r in reversed(execution.step_results):
        if r.response is not None:
            return r
    return None


def all_bodies(execution: ExecutionResult) -> list[str]:
    return [r.response["body"] for r in execution.step_results if r.response is not None]


def response_body_for_step(execution: ExecutionResult, index: int) -> str | None:
    for r in execution.step_results:
        if r.index == index and r.response is not None:
            return r.response["body"]
    return None


def find_step_by_marker(execution: ExecutionResult, marker: str) -> StepResult | None:
    for r in execution.step_results:
        if r.response is None:
            continue
        body = r.response.get("body", "")
        if marker and marker in body:
            return r
    return None


def status_of(step: StepResult) -> int | None:
    if step.response is None:
        return None
    return step.response.get("status_code")


def header_of(step: StepResult, name: str) -> str | None:
    if step.response is None:
        return None
    headers = step.response.get("headers", {})
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None
