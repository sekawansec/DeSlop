from deslop.config.schema import (
    LoginConfig,
    ProgramConfig,
    ScopeEntry,
    StagingConfig,
    TestAccount,
)
from deslop.config.settings import Settings
from deslop.repro.steps import ReproPlanModel, ReproStep, StructuredRequest
from deslop.repro.validator import validate_plan

PROGRAM = ProgramConfig(
    id="demo",
    name="Demo",
    in_scope=[ScopeEntry(kind="wildcard", value="*.demo.test")],
    staging=StagingConfig(base_url="https://staging.demo.test"),
    test_accounts=[
        TestAccount(id="user_a", role="user", username="a", password="a"),
        TestAccount(id="user_b", role="user", username="b", password="b"),
    ],
    login=LoginConfig(kind="none"),
)


def _step(index: int, url: str, *, method: str = "GET", account: str | None = None) -> ReproStep:
    return ReproStep(
        index=index,
        description="x",
        request=StructuredRequest(method=method, url=url),
        as_account=account,
    )


def _plan(*steps: ReproStep) -> ReproPlanModel:
    return ReproPlanModel(bug_class="idor", steps=list(steps))


def test_valid_plan_approved():
    plan = _plan(_step(0, "https://api.demo.test/a", account="user_b"))
    result = validate_plan(plan, PROGRAM, Settings(_env_file=None))
    assert result.approved
    assert result.issues == []


def test_out_of_scope_step_blocked():
    plan = _plan(_step(0, "https://evil.test/a"))
    result = validate_plan(plan, PROGRAM, Settings(_env_file=None))
    assert not result.approved
    assert any(i.code == "out_of_scope" for i in result.issues)


def test_delete_method_blocked():
    plan = _plan(_step(0, "https://api.demo.test/a", method="DELETE"))
    result = validate_plan(plan, PROGRAM, Settings(_env_file=None))
    assert not result.approved
    assert any(i.code == "destructive" for i in result.issues)


def test_destructive_path_pattern_blocked():
    plan = _plan(_step(0, "https://api.demo.test/v1/users/delete"))
    result = validate_plan(plan, PROGRAM, Settings(_env_file=None))
    assert any(i.code == "destructive" for i in result.issues)


def test_unknown_account_blocked():
    plan = _plan(_step(0, "https://api.demo.test/a", account="user_z"))
    result = validate_plan(plan, PROGRAM, Settings(_env_file=None))
    assert any(i.code == "unknown_account" for i in result.issues)


def test_empty_plan_blocked():
    result = validate_plan(_plan(), PROGRAM, Settings(_env_file=None))
    assert not result.approved
    assert any(i.code == "empty_plan" for i in result.issues)


def test_too_many_steps_blocked():
    settings = Settings(_env_file=None, max_requests_per_run=2)
    plan = _plan(*[_step(i, "https://api.demo.test/x") for i in range(3)])
    result = validate_plan(plan, PROGRAM, settings)
    assert any(i.code == "too_many_steps" for i in result.issues)


def test_program_limit_overrides_settings():
    program = PROGRAM.model_copy(update={"max_requests_per_run": 1})
    plan = _plan(*[_step(i, "https://api.demo.test/x") for i in range(2)])
    result = validate_plan(plan, program, Settings(_env_file=None))
    assert any(i.code == "too_many_steps" for i in result.issues)


def test_validator_is_deterministic():
    plan = _plan(_step(0, "https://evil.test/a"))
    a = validate_plan(plan, PROGRAM, Settings(_env_file=None))
    b = validate_plan(plan, PROGRAM, Settings(_env_file=None))
    assert a.approved == b.approved
    assert [i.code for i in a.issues] == [i.code for i in b.issues]
