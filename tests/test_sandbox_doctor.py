from deslop.config.schema import ProgramConfig, StagingConfig, TestAccount
from deslop.doctor import CheckResult, CheckStatus, run_doctor
from deslop.sandbox.policy import build_egress_policy, host_of


def _program(**overrides):
    base = dict(
        id="demo",
        name="Demo",
        staging=StagingConfig(
            base_url="https://staging.demo.test",
            host_map={"app.demo.test": "staging.demo.test"},
        ),
        test_accounts=[
            TestAccount(id="user_a", role="user", username="a", password="a"),
            TestAccount(id="user_b", role="user", username="b", password="b"),
            TestAccount(id="admin", role="admin", username="admin", password="x"),
        ],
        allowed_egress_hosts=["staging.demo.test"],
    )
    base.update(overrides)
    return ProgramConfig(**base)


def test_host_of():
    assert host_of("https://x.test/path") == "x.test"
    assert host_of("x.test:8080/path") == "x.test"


def test_egress_policy_includes_staging_and_oob():
    policy = build_egress_policy(_program(), "http://oob:8080")
    assert policy.permits("staging.demo.test")
    assert policy.permits("oob")
    assert not policy.permits("evil.test")


def test_doctor_ok_with_network_skipped():
    report = run_doctor(_program(), skip_network=True)
    # Network checks are skipped; account checks still run against kind=none login.
    assert all(r.status != CheckStatus.FAIL for r in report.results if r.required)
    assert report.ok


def test_doctor_flags_single_same_role_account():
    program = _program(
        test_accounts=[TestAccount(id="solo", role="user", username="solo", password="x")]
    )
    report = run_doctor(program, skip_network=True)
    assert not report.ok
    assert any("distinct same-role" in r.name and r.status == CheckStatus.FAIL for r in report.results)


def test_doctor_detects_duplicate_usernames():
    program = _program(
        test_accounts=[
            TestAccount(id="a", role="user", username="same", password="x"),
            TestAccount(id="b", role="user", username="same", password="y"),
            TestAccount(id="c", role="admin", username="adm", password="z"),
        ]
    )
    report = run_doctor(program, skip_network=True)
    assert any("distinct identities" in r.name and r.status == CheckStatus.FAIL for r in report.results)


def test_doctor_egress_probe_detects_open_egress():
    # Point the probe at a host we pretend is reachable by choosing an allowed host.
    def fake_oob(settings):
        return CheckResult("OOB listener", CheckStatus.PASS, "fake")

    report = run_doctor(
        _program(),
        probe_host="staging.demo.test",  # in allowlist -> doctor should FAIL this check
        oob_probe=fake_oob,
    )
    assert any("egress blocked" in r.name and r.status == CheckStatus.FAIL for r in report.results)


def test_doctor_render_contains_result_line():
    report = run_doctor(_program(), skip_network=True)
    text = report.render()
    assert "RESULT:" in text
