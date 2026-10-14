# Architecture

This document evolves with the build. Stage 1 covers the data model and config
loader; later stages fill in the pipeline.

## High-level pipeline

```mermaid
flowchart LR
    A[Intake\nform / adapter] --> B[Filtering\nscope, dup, injection]
    B --> C[Parsing\nLLM -> locked steps]
    C --> D[Validator\ndeterministic policy]
    D -->|reject| X[blocked_by_policy]
    D -->|ok| E[Executor\nsandbox, staging]
    E --> F[Verifier\nper bug class]
    F --> G[Routing\ncategorize + queue]
    G --> H[Triage Dashboard\nhuman decides]
    H --> I[Retest\nre-run after fix]
```

## Trust boundaries

```mermaid
flowchart TB
    subgraph Untrusted
        R[Report text\n+ attachments]
    end
    subgraph Trusted
        P[Parser LLM]
        V[Validator\ndeterministic]
        E[Executor\nsandbox]
        VF[Verifier\ndeterministic]
    end
    R -->|wrapped as data| P
    P -->|structured steps only| V
    V -->|approved steps only| E
    E -->|request/response logs| VF
    VF -->|technical evidence| OUT[Verdict]
```

Key rule: the **executor never reads raw report text**, and the **LLM never
decides whether a bug is proven**.

## Data model (Stage 1)

```mermaid
erDiagram
    REPORT ||--o{ MESSAGE : has
    REPORT ||--o{ REPRO_PLAN : has
    REPORT ||--o{ DUPLICATE_CANDIDATE : has
    REPORT ||--|| TRIAGE_RESULT : has
    REPRO_PLAN ||--o{ REPRO_RUN : has
    REPORT ||--o{ AUDIT_LOG : referenced_by

    REPORT {
        string id PK
        string program_id
        string status
        string public_status
        string status_token_hash
        string duplicate_of FK
        vector embedding
    }
    MESSAGE {
        int id PK
        string report_id FK
        string direction
        string body
    }
    REPRO_PLAN {
        int id PK
        string report_id FK
        json steps
        json substitutions
    }
    REPRO_RUN {
        int id PK
        int plan_id FK
        string run_id
        string status
        string verdict
        json evidence
    }
    DUPLICATE_CANDIDATE {
        int id PK
        string report_id FK
        string candidate_report_id FK
        float similarity
        string verdict
    }
    TRIAGE_RESULT {
        int id PK
        string report_id FK
        string routing_category
        json suggested_cvss
        bool injection_flag
    }
    AUDIT_LOG {
        int id PK
        string report_id
        string actor
        string action
    }
```

The `embedding` column maps to `pgvector` on PostgreSQL and to JSON on SQLite,
so the same models run in production and in tests.

## Configuration model

- **Environment** (`DESLOP_*`, see `.env.example`) — infrastructure concerns:
  database URL, LLM/embedding provider, sandbox limits, SMTP, OOB listener.
- **Per-program YAML** (`config/programs/*.yaml`) — all policy: scope, excluded
  classes, staging host map, test accounts, bounty table, reply templates,
  status-page settings.

No company names, scopes, or rules are hardcoded.

## Executor / verifier plugin interfaces

The core (intake, dedup, parsing, validator, routing, evidence) is independent of
how a plan is executed or verified.

```python
class Executor(Protocol):
    name: str
    def execute(self, plan, program, *, run_id) -> ExecutionResult: ...

class Verifier(Protocol):
    bug_class: str
    def verify(self, plan, execution, program) -> VerificationResult: ...
```

v1 ships `WebExecutor` (httpx). A recipe bundles state setup, execution (via an
executor), and a verifier. Adding a bug class means writing a verifier and
registering a recipe; adding an executor (Android on-device, desktop) means
implementing `Executor` without touching the core.

## Routing categories

| Category | Meaning |
|---|---|
| `reproduced` | Proven by a verifier; high-priority human review. |
| `reproduced_with_deviation` | Proven after triager-approved deviations. |
| `needs_info` | Steps incomplete; a draft question for the researcher is prepared. |
| `failed_replay` | Failed at a specific step; low-priority queue, still human-reviewed. |
| `manual_reproduction_required` | No recipe for the bug class yet. |
| `out_of_scope` / `excluded_class` / `duplicate` | With reasoning and references. |
| `blocked_by_policy` | Steps violate policy or injection was detected. |

No status automatically rejects or closes a report. Internal statuses are never
shown to researchers.

## Status-page token flow

```mermaid
sequenceDiagram
    participant R as Researcher
    participant W as DeSlop web
    participant DB as Database
    R->>W: POST /submit (evidence required)
    W->>DB: store report + SHA-256(token hash)
    W-->>R: report id + secret status link
    R->>W: GET /status/<token>
    W->>DB: look up by hash, check expiry/revocation
    W-->>R: public fields only (id, title, status, messages)
```

Tokens are random (>=128 bits), stored hashed, expiring, and revocable. The
public status only changes when a triager makes a decision or sends a message.
