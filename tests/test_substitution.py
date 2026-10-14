from deslop.config.schema import (
    ProgramConfig,
    StagingConfig,
    TestAccount,
)
from deslop.repro.steps import ReproPlanModel, ReproStep, StructuredRequest
from deslop.repro.substitution import apply_substitutions

PROGRAM = ProgramConfig(
    id="demo",
    name="Demo",
    staging=StagingConfig(
        base_url="https://staging.demo.test",
        host_map={"app.demo.test": "staging.demo.test"},
    ),
    test_accounts=[
        TestAccount(id="user_a", role="user", username="a", password="a"),
        TestAccount(id="user_b", role="user", username="b", password="b"),
    ],
)


def _step(index, url, *, cookies=None, headers=None, body=None, account=None):
    return ReproStep(
        index=index,
        description="x",
        request=StructuredRequest(
            method="GET", url=url, cookies=cookies or {}, headers=headers or {}, body=body
        ),
        as_account=account,
    )


def test_host_rewrite_to_staging():
    plan = ReproPlanModel(bug_class="idor", steps=[_step(0, "https://app.demo.test/api/invoices/1")])
    result = apply_substitutions(plan, PROGRAM)
    assert result.steps[0].request.url == "https://staging.demo.test/api/invoices/1"
    assert any(s.kind == "host" for s in result.substitutions)


def test_credentials_recorded_not_replaced_inline():
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[
            _step(
                0,
                "https://app.demo.test/api/invoices/1",
                cookies={"session": "researcher-real-session-value"},
                account="user_b",
            )
        ],
    )
    result = apply_substitutions(plan, PROGRAM)
    kinds = [s.kind for s in result.substitutions]
    assert "credential" in kinds
    # The recorded substitution must not leak the full secret.
    cred = next(s for s in result.substitutions if s.kind == "credential")
    assert "researcher-real-session-value" not in cred.original


def test_dynamic_placeholder_recorded():
    plan = ReproPlanModel(
        bug_class="xss_reflected",
        steps=[_step(0, "https://app.demo.test/x?n={{nonce}}")],
    )
    result = apply_substitutions(plan, PROGRAM)
    assert any(s.kind == "dynamic" for s in result.substitutions)


def test_step_order_and_count_preserved():
    plan = ReproPlanModel(
        bug_class="idor",
        steps=[
            _step(0, "https://app.demo.test/a"),
            _step(1, "https://app.demo.test/b"),
            _step(2, "https://app.demo.test/c"),
        ],
    )
    result = apply_substitutions(plan, PROGRAM)
    assert [s.index for s in result.steps] == [0, 1, 2]
    assert [s.request.url for s in result.steps] == [
        "https://staging.demo.test/a",
        "https://staging.demo.test/b",
        "https://staging.demo.test/c",
    ]


def test_payload_and_query_untouched():
    url = "https://app.demo.test/search?q=<script>x</script>&page=2"
    plan = ReproPlanModel(bug_class="xss_reflected", steps=[_step(0, url)])
    result = apply_substitutions(plan, PROGRAM)
    assert result.steps[0].request.url.endswith("/search?q=<script>x</script>&page=2")
