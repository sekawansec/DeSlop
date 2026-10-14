from deslop.config.schema import ProgramConfig, ScopeEntry, StagingConfig
from deslop.repro.scope import check_scope, is_allowed_egress_host

PROGRAM = ProgramConfig(
    id="demo",
    name="Demo",
    in_scope=[
        ScopeEntry(kind="wildcard", value="*.demo.test"),
        ScopeEntry(kind="domain", value="api.demo.test"),
        ScopeEntry(kind="ip_range", value="10.0.0.0/24"),
        ScopeEntry(kind="url", value="https://app.demo.test"),
    ],
    out_of_scope=[
        ScopeEntry(kind="domain", value="status.demo.test"),
        ScopeEntry(kind="wildcard", value="*.internal.demo.test"),
    ],
    staging=StagingConfig(
        base_url="https://staging.demo.test",
        host_map={"app.demo.test": "staging.demo.test"},
    ),
    allowed_egress_hosts=["staging.demo.test"],
)


def test_wildcard_matches_subdomain_not_apex():
    assert check_scope("https://shop.demo.test/x", PROGRAM).allowed
    assert check_scope("shop.demo.test", PROGRAM).allowed
    assert not check_scope("https://demo.test", PROGRAM).allowed


def test_exact_domain_in_scope():
    assert check_scope("https://api.demo.test/v1", PROGRAM).allowed


def test_out_of_scope_wins_over_in_scope():
    # status.demo.test is not covered by any in-scope rule, but also explicitly out.
    d = check_scope("https://status.demo.test", PROGRAM)
    assert not d.allowed
    assert d.matched is not None
    # A host matching both a broad wildcard and an out-of-scope rule must be denied.
    d2 = check_scope("https://x.internal.demo.test", PROGRAM)
    assert not d2.allowed


def test_ip_range():
    assert check_scope("10.0.0.5", PROGRAM).allowed
    assert not check_scope("10.0.1.5", PROGRAM).allowed


def test_url_scope_matches_host():
    assert check_scope("https://app.demo.test/login", PROGRAM).allowed


def test_unknown_host_denied():
    assert not check_scope("https://evil.test", PROGRAM).allowed


def test_empty_target_denied():
    assert not check_scope("", PROGRAM).allowed


def test_egress_allowed_hosts():
    assert is_allowed_egress_host("staging.demo.test", PROGRAM)
    assert not is_allowed_egress_host("evil.test", PROGRAM)
