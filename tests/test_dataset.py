import json
from collections import Counter

import pytest

from deslop.dataset import Label, generate_dataset
from deslop.dataset.builders import VALID_BUILDERS, build_valid
from deslop.dataset.io import read_jsonl, write_jsonl
from deslop.dataset.lab import INVOICES, SUPPORTED


def test_generate_is_deterministic():
    a = generate_dataset(seed=42)
    b = generate_dataset(seed=42)
    assert [r.id for r in a] == [r.id for r in b]
    assert [r.label for r in a] == [r.label for r in b]


def test_dataset_covers_every_label():
    reports = generate_dataset(seed=1)
    labels = {r.label for r in reports}
    assert labels == set(Label)


def test_no_real_data_and_all_lab_assets():
    for r in generate_dataset(seed=7):
        assert ".test" in r.asset or "lab.test" in r.asset
        assert "example.com" not in r.body.lower()


def test_valid_reports_have_evidence():
    for r in generate_dataset(seed=3):
        if r.label == Label.VALID:
            assert r.reproducible is True
            assert r.attachments, f"{r.id} has no evidence attachment"


def test_duplicates_reference_an_earlier_valid_report():
    reports = generate_dataset(seed=5)
    by_id = {r.id: r for r in reports}
    dups = [r for r in reports if r.label == Label.DUPLICATE]
    assert dups
    for d in dups:
        assert d.duplicate_of is not None
        original = by_id[d.duplicate_of]
        assert original.label == Label.VALID
        assert original.vuln_class == d.vuln_class
        assert original.asset == d.asset


def test_injection_reports_flagged():
    reports = generate_dataset(seed=9)
    injections = [r for r in reports if r.label == Label.INJECTION]
    assert injections
    for inj in injections:
        assert inj.injection_attempt is True
        text = (inj.body + " ".join(a.content for a in inj.attachments)).lower()
        assert any(k in text for k in ("ignore", "system", "assistant"))


def test_every_supported_bug_class_has_a_baseline_and_builder():
    reports = generate_dataset(seed=11)
    valid_classes = {r.vuln_class for r in reports if r.label == Label.VALID}
    for bug in SUPPORTED:
        assert bug in valid_classes
        assert bug in VALID_BUILDERS


def test_idor_builder_embeds_owner_secret():
    report = build_valid("idor", "X-1")
    for inv in INVOICES.values():
        if inv["secret"] in report.body:
            break
    else:
        pytest.fail("IDOR report does not embed an owner secret")


def test_write_and_read_jsonl(tmp_path):
    reports = generate_dataset(seed=2, per_category=2)
    out = write_jsonl(reports, tmp_path / "ds.jsonl", seed=2)
    assert out.is_file()
    assert out.with_suffix(".manifest.json").is_file()
    manifest = json.loads(out.with_suffix(".manifest.json").read_text(encoding="utf-8"))
    assert manifest["count"] == len(reports)
    assert manifest["seed"] == 2

    loaded = read_jsonl(out)
    assert len(loaded) == len(reports)
    assert Counter(r.label for r in loaded) == Counter(r.label for r in reports)


def test_read_jsonl_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_jsonl(tmp_path / "nope.jsonl")
