# Contributing to DeSlop

Thanks for helping! DeSlop filters and reproduces vulnerability reports so
security teams only review evidence-backed submissions.

## Ground rules

- Reproduction is **locked** to the steps in the report. Never add heuristics
  that improvise or try alternative approaches.
- Verifiers must be **deterministic** and read only technical evidence. An LLM
  must never decide whether a bug is proven.
- Report content is untrusted input. Never execute it outside the sandbox, and
  never write credentials to logs or evidence packs.
- Generic by default: no company names, scopes, or rules hardcoded. Use config.

## Development

```bash
python -m venv .venv
. .venv/Scripts/activate     # Windows;   . .venv/bin/activate on Linux/macOS
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e . --no-deps
pytest
ruff check .
```

## Writing a new recipe (bug class)

A recipe bundles three things: **state setup**, **execution** (the executor does
this), and a **deterministic verifier**. Recipes live in
`src/deslop/recipes/`.

1. **Write the verifier.** It receives the locked `plan`, the `ExecutionResult`
   (the recorded request/response log), and the `ProgramConfig`. It returns a
   `VerificationResult(verdict, evidence, reason)`. Use only evidence from the
   execution (and, for blind bugs, the OOB listener). Return one of:

   - `Verdict.PROVEN` — technical evidence proves the bug.
   - `Verdict.NOT_PROVEN` — evidence shows the bug did not occur.
   - `Verdict.INCONCLUSIVE` — not enough evidence to decide.
   - `Verdict.ERROR` — the check itself could not run.

   ```python
   # src/deslop/recipes/mybug.py
   from ..db.enums import Verdict
   from ..repro.interfaces import VerificationResult

   class MyBugVerifier:
       bug_class = "my_bug"

       def verify(self, plan, execution, program) -> VerificationResult:
           for step in execution.step_results:
               if step.response and "THE_PROOF" in step.response["body"]:
                   return VerificationResult(Verdict.PROVEN, {"step": step.index})
           return VerificationResult(Verdict.NOT_PROVEN, {})
   ```

2. **Add a recipe** in `concrete.py` (or a program-specific module) wiring the
   verifier, and any `setup()` needed to bring staging into a known state.

3. **Register it** in `register_default_recipes()`.

4. **Add tests.** Use `httpx.MockTransport` for HTTP and the injectable
   `Browser` (`recipes.browser.set_browser`) for client-side bugs. Cover both a
   proven and a not-proven case, and prove the false-positive case returns
   `NOT_PROVEN`.

5. **Document the proof criteria** for your bug class in this file and in
   `docs/architecture.md`.

### Verifier checklist

- [ ] Reads only technical evidence (execution log / OOB listener).
- [ ] No LLM call.
- [ ] Returns `NOT_PROVEN` when the evidence is absent or ambiguous.
- [ ] Never writes secrets to evidence.
- [ ] Has a false-positive test.

## Writing an intake adapter

Adapters translate an external source into a `Report` and the pipeline entry
point. Provide an `intake(program, payload) -> Report` function. Stubs (email,
GitHub Private Vulnerability Reporting) live in `src/deslop/intake/`. An adapter
must collect the mandatory evidence fields (raw HTTP request, HAR, or runnable
PoC) or reject the submission at intake.

## Pull requests

- Keep changes focused; one bug class or one adapter per PR.
- Run `ruff check .` and `pytest` before opening a PR.
- Never commit real report data, secrets, or `.env` files.
