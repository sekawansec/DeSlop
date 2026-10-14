"""Sandbox configuration builders and egress policy helpers.

The sandbox is a single-use container per run. v1 does not yet launch real
containers from Python (that is wired in a later stage); this module defines the
policy the sandbox must enforce and the egress allowlist derived from a program
plus the OOB listener.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from ..config.schema import ProgramConfig


def host_of(url: str) -> str:
    if "://" in url:
        return (urlparse(url).hostname or "").lower()
    return url.split("/", 1)[0].split(":", 1)[0].lower()


@dataclass(frozen=True)
class EgressPolicy:
    allowed_hosts: frozenset[str]
    oob_host: str

    def permits(self, host: str) -> bool:
        host = host.lower().strip(".")
        return host in self.allowed_hosts or host == self.oob_host


def build_egress_policy(program: ProgramConfig, oob_base_url: str) -> EgressPolicy:
    allowed = {h.lower().strip(".") for h in program.allowed_egress_hosts}
    staging_host = host_of(program.staging.base_url)
    if staging_host:
        allowed.add(staging_host)
    for v in program.staging.host_map.values():
        allowed.add(host_of(v))
    return EgressPolicy(allowed_hosts=frozenset(allowed), oob_host=host_of(oob_base_url))


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
