"""Sandbox configuration builders and egress policy helpers.

The sandbox is a single-use container per run. v1 does not yet launch real
containers from Python (that is wired in a later stage); this module defines the
policy the sandbox must enforce and the egress allowlist derived from a program
plus the OOB listener. The web executor enforces the same policy in-process so
the guarantee holds either way:

* staging-side hosts (staging base URL, ``host_map`` targets,
  ``allowed_egress_hosts``, the OOB listener) are always reachable;
* in-scope **production** hosts are only reachable when production
  reproduction was approved (``allow_production`` setting/program flag or a
  per-report ``approve_production`` decision);
* everything else is denied.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..config.schema import ProgramConfig
from ..repro.scope import _domain_matches, _wildcard_matches, check_scope


def host_of(url: str) -> str:
    if "://" in url:
        return (urlparse(url).hostname or "").lower()
    return url.split("/", 1)[0].split(":", 1)[0].lower()


def _host_only(netloc_or_host: str) -> str:
    return netloc_or_host.split(":", 1)[0].lower().strip(".")


def _pattern_matches(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        return _wildcard_matches(host, pattern)
    return _domain_matches(host, pattern)


@dataclass(frozen=True)
class EgressPolicy:
    """What the sandbox/executor may connect to.

    ``allowed_hosts`` holds staging-side patterns (bare host = host plus
    subdomains, ``*.domain`` = wildcard incl. apex). Production hosts —
    in-scope hosts that were not mapped onto staging — are additionally gated
    behind ``production_approved``.
    """

    allowed_hosts: frozenset[str]
    oob_host: str
    staging_hosts: frozenset[str]
    program: ProgramConfig
    production_approved: bool = False

    def is_staging(self, host: str) -> bool:
        host = host.lower().strip(".")
        return any(_pattern_matches(host, s) for s in self.staging_hosts)

    def is_production(self, host: str) -> bool:
        """In-scope, but not mapped onto staging — i.e. the real target."""
        host = host.lower().strip(".")
        if self.is_staging(host):
            return False
        return check_scope(host, self.program).allowed

    def permits(self, host: str) -> bool:
        host = host.lower().strip(".")
        if self.is_production(host):
            return self.production_approved
        if host == self.oob_host:
            return True
        return any(_pattern_matches(host, e) for e in self.allowed_hosts)


def build_egress_policy(
    program: ProgramConfig,
    oob_base_url: str,
    *,
    production_approved: bool = False,
) -> EgressPolicy:
    staging_hosts: set[str] = set()
    base_host = host_of(program.staging.base_url)
    if base_host:
        staging_hosts.add(base_host)
    for v in program.staging.host_map.values():
        staging_hosts.add(_host_only(v))

    allowed = set(program.allowed_egress_hosts) | staging_hosts
    return EgressPolicy(
        allowed_hosts=frozenset(allowed),
        oob_host=host_of(oob_base_url),
        staging_hosts=frozenset(staging_hosts),
        program=program,
        production_approved=production_approved,
    )


@dataclass
class SandboxSpec:
    image: str
    network: str
    env: dict[str, str]
    egress: EgressPolicy
    max_requests: int
    max_seconds: int

    def docker_run_args(self) -> list[str]:
        """Return the ``docker run`` arguments enforcing this spec.

        ``--network none`` plus a proxy is the portable way to enforce egress;
        the proxy only forwards to ``egress.allowed_hosts`` and the OOB host.
        """
        args = ["run", "--rm", "--network", self.network]
        for k, v in self.env.items():
            args += ["-e", f"{k}={v}"]
        return args


def build_sandbox_spec(program: ProgramConfig, oob_base_url: str, *, image: str = "deslop/sandbox:latest") -> SandboxSpec:
    return SandboxSpec(
        image=image,
        network="deslop-sandbox",
        env={"DESLOP_STAGING_BASE": program.staging.base_url},
        egress=build_egress_policy(program, oob_base_url),
        max_requests=program.max_requests_per_run or 50,
        max_seconds=120,
    )
