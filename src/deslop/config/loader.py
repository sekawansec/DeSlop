"""Load and validate per-program YAML configuration files.

Layout::

    config/programs/<anything>.yaml   # one program per file

The filename is irrelevant; the ``id`` field inside the file is authoritative.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import yaml
from pydantic import ValidationError

from .schema import ProgramConfig


class ConfigError(Exception):
    """Raised when a program config file is missing, unreadable, or invalid."""


def load_program_file(path: str | Path) -> ProgramConfig:
    """Load and validate a single program YAML file."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - passthrough
        raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{p}: top-level document must be a mapping")
    try:
        return ProgramConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"{p}: {exc}") from exc


def iter_program_files(config_dir: str | Path) -> Iterator[Path]:
    d = Path(config_dir)
    if not d.is_dir():
        return
    yield from sorted(d.glob("*.yaml"))
    yield from sorted(d.glob("*.yml"))


def load_programs(config_dir: str | Path) -> dict[str, ProgramConfig]:
    """Load every program file in a directory, keyed by program id.

    Raises :class:`ConfigError` on duplicate ids.
    """
    programs: dict[str, ProgramConfig] = {}
    for path in iter_program_files(config_dir):
        program = load_program_file(path)
        if program.id in programs:
            raise ConfigError(f"duplicate program id {program.id!r} in {path}")
        programs[program.id] = program
    return programs


class ProgramRegistry:
    """In-memory registry of loaded programs."""

    def __init__(self, programs: dict[str, ProgramConfig] | None = None) -> None:
        self._programs: dict[str, ProgramConfig] = programs or {}

    @classmethod
    def from_dir(cls, config_dir: str | Path) -> ProgramRegistry:
        return cls(load_programs(config_dir))

    def get(self, program_id: str) -> ProgramConfig:
        try:
            return self._programs[program_id]
        except KeyError as exc:
            raise ConfigError(f"unknown program id: {program_id!r}") from exc

    def __contains__(self, program_id: object) -> bool:
        return program_id in self._programs

    def __iter__(self) -> Iterator[ProgramConfig]:
        return iter(self._programs.values())

    def __len__(self) -> int:
        return len(self._programs)

    def ids(self) -> list[str]:
        return sorted(self._programs)
