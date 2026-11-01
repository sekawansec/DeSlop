from deslop.config.schema import (
    ProgramConfig,
    ScopeEntry,
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


def test_host_rewrite_uses_staging_scheme():
    """Staging is authoritative for the scheme — an http:// raw request must
    land on https staging, not silently downgrade."""
    plan = ReproPlanModel(bug_class="idor", steps=[_step(0, "http://app.demo.test/api/x")])
    result = apply_substitutions(plan, PROGRAM)
    assert result.steps[0].request.url == "https://staging.demo.test/api/x"


def test_oob_test_host_rewritten_to_listener():
    url = "http://app.demo.test/api/fetch?url=http://abc123.oob.test/ping"
    plan = ReproPlanModel(bug_class="ssrf", steps=[_step(0, url)])
    result = apply_substitutions(
        plan, PROGRAM, oob_base_url="http://127.0.0.1:18080", run_token="RUNTOKEN"
    )
    out = result.steps[0].request.url
    assert "127.0.0.1:18080/cb/RUNTOKEN" in out
    assert "oob.test" not in out


def test_known_oob_services_rewritten_to_listener():
    """interactsh / Burp Collaborator style callbacks are redirected to the
    program's own OOB listener — never contacted for real."""
    for host in ("x1.oast.fun", "x1.interact.sh", "x1.burpcollaborator.net", "x1.oastify.com"):
        url = f"http://app.demo.test/api/fetch?url=http://{host}/"
        plan = ReproPlanModel(bug_class="ssrf", steps=[_step(0, url)])
        result = apply_substitutions(
            plan, PROGRAM, oob_base_url="http://127.0.0.1:18080", run_token="RUNTOKEN"
        )
        out = result.steps[0].request.url
        assert "127.0.0.1:18080/cb/RUNTOKEN" in out, (host, out)
        assert host not in out
        assert any(s.kind == "oob_host" for s in result.substitutions)


def test_non_oob_host_not_rewritten():
    url = "http://app.demo.test/api/fetch?url=http://attacker.example.com/"
    plan = ReproPlanModel(bug_class="ssrf", steps=[_step(0, url)])
    result = apply_substitutions(plan, PROGRAM, oob_base_url="http://127.0.0.1:18080")
    assert "attacker.example.com" in result.steps[0].request.url


def test_open_redirect_target_pointed_at_marker_domain():
    for url, expected in (
        (
            "https://app.demo.test/redirect?next=https://evil.example/landing",
            "https://staging.demo.test/redirect?next=https://marker.deslop.test/landing",
        ),
        (
            "https://app.demo.test/r?a=1&url=https%3A%2F%2Fevil.example%2Fx",
            "https://staging.demo.test/r?a=1&url=https%3A%2F%2Fmarker.deslop.test%2Fx",
        ),
        (
            "https://app.demo.test/r?to=//evil.example/p",
            "https://staging.demo.test/r?to=https://marker.deslop.test/p",
        ),
    ):
        plan = ReproPlanModel(bug_class="open_redirect", steps=[_step(0, url)])
        result = apply_substitutions(plan, PROGRAM)
        assert result.steps[0].request.url == expected, url
        assert any(s.kind == "redirect_target" for s in result.substitutions)


def test_redirect_rewrite_only_for_open_redirect_and_external_hosts():
    url = "https://app.demo.test/redirect?next=https://evil.example/landing"
    plan = ReproPlanModel(bug_class="ssrf", steps=[_step(0, url)])
    assert "evil.example" in apply_substitutions(plan, PROGRAM).steps[0].request.url

    program = PROGRAM.model_copy(
        update={"in_scope": [ScopeEntry(kind="domain", value="demo.test")]}
    )
    url = "https://app.demo.test/redirect?next=https://app.demo.test/home"
    plan = ReproPlanModel(bug_class="open_redirect", steps=[_step(0, url)])
    assert apply_substitutions(plan, program).steps[0].request.url.endswith(
        "next=https://app.demo.test/home"
    )


def test_payload_and_query_untouched():
    url = "https://app.demo.test/search?q=<script>x</script>&page=2"
    plan = ReproPlanModel(bug_class="xss_reflected", steps=[_step(0, url)])
    result = apply_substitutions(plan, PROGRAM)
    assert result.steps[0].request.url.endswith("/search?q=<script>x</script>&page=2")
