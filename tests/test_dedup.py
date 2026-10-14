from deslop.config.schema import DuplicateRules, ProgramConfig, StagingConfig
from deslop.dedup.detector import build_normalized, retrieve_candidates
from deslop.llm.embeddings import HashingEmbedder

PROGRAM = ProgramConfig(id="lab", name="Lab", staging=StagingConfig(base_url="http://x"))
EMB = HashingEmbedder(256)


def _norm(rid, asset, endpoint, summary):
    return build_normalized(
        rid, asset=asset, endpoint=endpoint, vuln_class=None,
        root_cause_summary=summary, embedding=EMB.embed([summary])[0],
    )


def test_retrieval_finds_paraphrase():
    original = _norm("V1", "api.lab.test", "/api/invoices/1001", "idor invoice access control cross account")
    paraphrase = _norm("D1", "api.lab.test", "/api/invoices/1001", "idor invoice access control cross account leak")
    unrelated = _norm("U1", "www.lab.test", "/search", "reflected xss search parameter script injection")
    cands = retrieve_candidates(paraphrase, [original, paraphrase, unrelated], PROGRAM.duplicates)
    assert cands
    assert cands[0].report_id == "V1"


def test_asset_and_endpoint_boost_applied():
    orig = _norm("V1", "api.lab.test", "/api/invoices/1001", "idor invoice access control")
    other = _norm("D1", "other.test", "/other", "idor invoice access control")
    rules = DuplicateRules(similarity_threshold=0.1, same_asset_boost=0.5, same_endpoint_boost=0.5)
    cands = retrieve_candidates(other, [orig, other], rules)
    # Without matching asset/endpoint, the boosted score equals raw similarity.
    assert cands[0].boosted == cands[0].similarity


def test_threshold_filters_low_similarity():
    a = _norm("A", "x.test", "/a", "completely unrelated topic about birds")
    b = _norm("B", "y.test", "/b", "sql injection in login form parameter")
    rules = DuplicateRules(similarity_threshold=0.9)
    assert retrieve_candidates(b, [a, b], rules) == []


def test_self_excluded_from_candidates():
    a = _norm("A", "x.test", "/a", "idor invoice")
    assert all(c.report_id != "A" for c in retrieve_candidates(a, [a], PROGRAM.duplicates))