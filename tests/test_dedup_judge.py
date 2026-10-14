from deslop.config.schema import ProgramConfig, StagingConfig
from deslop.dedup.detector import build_normalized, retrieve_candidates
from deslop.dedup.judge import classify_for_routing, judge_candidates
from deslop.llm.embeddings import HashingEmbedder

PROGRAM = ProgramConfig(id="lab", name="Lab", staging=StagingConfig(base_url="http://x"))
EMB = HashingEmbedder(256)


def _norm(rid, asset, endpoint, cls, summary):
    return build_normalized(
        rid, asset=asset, endpoint=endpoint, vuln_class=cls,
        root_cause_summary=summary, embedding=EMB.embed([summary])[0],
    )


def test_deterministic_judge_same_root_cause():
    target = _norm("N", "api.lab.test", "/api/invoices/1001", "idor", "idor invoice access control cross account")
    other = _norm("V", "api.lab.test", "/api/invoices/1001", "idor", "idor invoice access control cross account leak")
    cands = retrieve_candidates(target, [target, other], PROGRAM.duplicates)
    cands = judge_candidates(target, cands, {"V": other}, PROGRAM, client=None)
    assert cands[0].verdict == "same_root_cause"
    category, reason = classify_for_routing(cands)
    assert category == "duplicate"
    assert "V" in reason


def test_deterministic_judge_same_asset_different_bug():
    target = _norm("N", "api.lab.test", "/api/invoices/1001", "idor", "idor invoice access control")
    other = _norm("V", "api.lab.test", "/search", "xss_reflected", "reflected xss search parameter")
    cands = retrieve_candidates(target, [target, other], PROGRAM.duplicates)
    cands = judge_candidates(target, cands, {"V": other}, PROGRAM, client=None)
    if cands:
        assert cands[0].verdict in {"same_asset_different_bug", "unrelated"}
        category, _ = classify_for_routing(cands)
        assert category == ""


def test_classify_empty_when_no_same_root_cause():
    assert classify_for_routing([]) == ("", "")


def test_judge_no_candidates_returns_empty():
    target = _norm("N", "api.lab.test", "/a", "idor", "idor")
    assert judge_candidates(target, [], {}, PROGRAM, client=None) == []
