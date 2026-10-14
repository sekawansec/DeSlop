"""Deterministic scope matching against a program's in/out-of-scope assets.

This is security-critical: it decides whether a reproduction step may target a
host at all. It must be conservative — when in doubt, deny.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from ..config.schema import ProgramConfig, ScopeEntry


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    matched: ScopeEntry | None = None
    reason: str = ""


def _host_of(url_or_host: str) -> str:
    value = url_or_host.strip()
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
    else:
        # A bare host possibly with a path or port.
        host = value.split("/", 1)[0].split(":", 1)[0]
    return host.lower().strip(".")


def _domain_matches(host: str, domain: str) -> bool:
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def _wildcard_matches(host: str, pattern: str) -> bool:
    # pattern looks like "*.example.com"; matches any subdomain (not the apex).
    pattern = pattern.lower().strip(".")
    if not pattern.startswith("*."):
        return False
    base = pattern[2:]
    return host.endswith("." + base) and host != base


def _ip_in_range(host: str, cidr: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr in net


def _entry_matches(host: str, url_or_host: str, entry: ScopeEntry) -> bool:
    if entry.kind == "domain":
        return _domain_matches(host, entry.value)
    if entry.kind == "wildcard":
        return _wildcard_matches(host, entry.value)
    if entry.kind == "ip_range":
        return _ip_in_range(host, entry.value)
    if entry.kind in {"url", "app_id"}:
        # For a URL scope, compare the host of the scope to the target host.
        scope_host = _host_of(entry.value) if entry.kind == "url" else entry.value.lower()
        return host == scope_host
    return False


def check_scope(target: str, program: ProgramConfig) -> ScopeDecision:
    """Return whether ``target`` (a URL or host) is in scope for ``program``.

    Out-of-scope entries always win over in-scope entries.
    """
    host = _host_of(target)
    if not host:
        return ScopeDecision(False, None, "could not determine a host from the target")

    for entry in program.out_of_scope:
        if _entry_matches(host, target, entry):
            return ScopeDecision(False, entry, f"host {host!r} explicitly out of scope")

    for entry in program.in_scope:
        if _entry_matches(host, target, entry):
            return ScopeDecision(True, entry, f"host {host!r} matched in-scope rule")

    return ScopeDecision(False, None, f"host {host!r} is not in any in-scope rule")


def is_allowed_egress_host(host: str, program: ProgramConfig) -> bool:
    """Whether the sandbox may open a raw connection to ``host``.

    Staging hosts (base URL host + host_map values) are always allowed in
    addition to configured ``allowed_egress_hosts``.
    """
    host = host.lower().strip(".")
    allowed = {h.lower().strip(".") for h in program.allowed_egress_hosts}
    staging_host = _host_of(program.staging.base_url)
    if staging_host:
        allowed.add(staging_host)
    for value in program.staging.host_map.values():
        allowed.add(_host_of(value))
    return host in allowed
