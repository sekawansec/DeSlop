# Security Policy

## Reporting a vulnerability

Please report security issues in DeSlop privately through GitHub Security
Advisories ("Report a vulnerability" on the repository's Security tab).

Please include:

- a description of the issue and its impact,
- reproduction steps or a minimal proof of concept,
- the version / commit you tested.

We aim to acknowledge reports within 3 business days.

## Scope

This policy covers the DeSlop codebase itself. It does **not** cover the
infrastructure you run DeSlop against; that is your responsibility.

## Safety note

DeSlop executes HTTP requests and drives a headless browser against configured
targets. Never point it at systems you do not own or have written authorization
to test.
