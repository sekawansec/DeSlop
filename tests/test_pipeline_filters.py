from deslop.config.schema import ExcludedClass, ProgramConfig, ScopeEntry, StagingConfig
from deslop.db.enums import Verdict
from deslop.pipeline.filters import check_excluded_class, check_scope_for_report
from deslop.pipeline.routing import route_needs_info, route_no_recipe, route_verdict

PROGRAM = ProgramConfig(
    id="lab",
    name="Lab",
    in_scope=[ScopeEntry(kind="domain", value="api.lab.test")],
    out_of_scope=[ScopeEntry(kind="domain", value="blog.lab.test")],
    excluded_classes=[
        ExcludedClass(id="self-xss", match=["self-xss", "missing header"], reason="not accepted"),
    ],
    staging=StagingConfig(base_url="http://127.0.0.1:18000"),
)


def test_scope_pass():
    assert check_scope_for_report("api.lab.test", None, PROGRAM).passed


def test_scope_fail_out_of_scope_host():
    d = check_scope_for_report("blog.lab.test", None, PROGRAM)
    assert not d.passed
    assert d.category == "out_of_scope"


def test_scope_fail_without_asset():
    d = check_scope_for_report(None, None, PROGRAM)
    assert not d.passed
    assert "asset" in d.reason


def test_excluded_class_match():
    d = check_excluded_class("missing header", PROGRAM)
    assert not d.passed
    assert d.category == "excluded_class"


def test_excluded_class_no_match():
    assert check_excluded_class("idor", PROGRAM).passed


def test_excluded_class_with_cwe_keyword():
    d = check_excluded_class("self-xss via console", PROGRAM)
    assert not d.passed


def test_route_verdicts():
    assert route_verdict(Verdict.PROVEN).category == "reproduced"
    assert route_verdict(Verdict.PROVEN, deviation=True).category == "reproduced_with_deviation"
    assert route_verdict(Verdict.NOT_PROVEN).category == "failed_replay"
    assert route_verdict(Verdict.ERROR).category == "needs_human_review"


def test_route_no_recipe():
    d = route_no_recipe("graphql_introspection")
    assert d.category == "manual_reproduction_required"


def test_route_needs_info():
    d = route_needs_info(["no request block", "no account specified"])
    assert d.category == "needs_info"
    assert "no request block" in d.reason


def test_priorities_order():
    from deslop.pipeline.routing import PRIORITY

    assert PRIORITY["reproduced"] > PRIORITY["failed_replay"]
