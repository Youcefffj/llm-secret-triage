import json

import pytest

from secret_triage.models import (
    Candidate,
    Run,
    Verdict,
    append_verdict,
    digest,
    mask,
    read_jsonl,
    read_run,
    write_jsonl,
    write_run,
)


# a throwaway candidate to test on. pass any field to override it
def make_candidate(**overrides) -> Candidate:
    fields = {
        "id": "0123456789abcdef",
        "detector": "gitleaks",
        "source": "git",
        "path": "config/settings.py",
        "line": 42,
        "rule": "aws-secret-access-key",
        "match": "Bu8IkJ9GtnAsutfahETpNzi2WZlzxUBhFmLOKPLf",
        "context": 'AWS_SECRET_ACCESS_KEY = "Bu8IkJ9GtnAsutfahETpNzi2WZlzxUBhFmLOKPLf"',
        "label": "secret",
        "label_source": "synthetic",
        "difficulty": None,
    }
    fields.update(overrides)
    return Candidate(**fields)


# the mask must not shrink the value: length is a hint too
def test_mask_keeps_length_and_reveals_three_plus_two():
    masked = mask("Bu8IkJ9GtnAsutfahETpNzi2WZlzxUBhFmLOKPLf")
    assert masked == "Bu8***********************************Lf"
    assert len(masked) == len("Bu8IkJ9GtnAsutfahETpNzi2WZlzxUBhFmLOKPLf")


def test_mask_hides_short_values_entirely():
    assert mask("null") == "****"
    assert mask("Welcome1!") == "*********"
    assert mask("a" * 19) == "*" * 19
    assert mask("a" * 20) == "aaa" + "*" * 15 + "aa"


def test_digest_is_the_sha256_of_the_value():
    assert digest("hello") == (
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )


def test_derived_fields_follow_the_raw_value():
    candidate = make_candidate(match="CHANGEME")
    assert candidate.match_masked == mask("CHANGEME")
    assert candidate.match_sha256 == digest("CHANGEME")


def test_jsonl_roundtrip(tmp_path):
    candidates = [make_candidate(), make_candidate(id="f" * 16, line=7)]
    out = tmp_path / "corpus.jsonl"

    assert write_jsonl(out, candidates) == 2
    assert list(read_jsonl(out)) == candidates


# someone hand-edits the file and lies about the mask -> we ignore what's written
def test_read_recomputes_derived_fields_instead_of_trusting_them(tmp_path):
    out = tmp_path / "corpus.jsonl"
    record = make_candidate().to_dict()
    record["match_masked"] = "wrong"
    record["match_sha256"] = "wrong"
    out.write_text(json.dumps(record) + "\n", encoding="utf-8")

    candidate = next(iter(read_jsonl(out)))
    assert candidate.match_masked == mask(candidate.match)
    assert candidate.match_sha256 == digest(candidate.match)


# the big one: this is what stops a live key ending up in a shared report
def test_public_export_carries_no_raw_value_anywhere():
    candidate = make_candidate()
    exported = json.dumps(candidate.to_public_dict())

    assert "match" not in candidate.to_public_dict()
    assert candidate.match not in exported
    assert candidate.match_masked in exported
    assert candidate.match_sha256 in exported


def test_public_export_masks_the_value_inside_the_context():
    candidate = make_candidate(
        context="line before\nTOKEN = \"ghp_realvaluehere0000\"\nline after",
        match="ghp_realvaluehere0000",
    )
    exported = candidate.to_public_dict()

    assert "ghp_realvaluehere0000" not in exported["context"]
    assert mask("ghp_realvaluehere0000") in exported["context"]
    assert "line before" in exported["context"]


def make_verdict(candidate_id: str, **overrides) -> Verdict:
    fields = {
        "candidate_id": candidate_id,
        "verdict": "secret",
        "confidence": 0.9,
        "reason": "a password in a script",
        "error": None,
        "replied": True,
        "tokens_in": 420,
        "tokens_out": 38,
        "cost_usd": None,
        "latency": 5.2,
        "at": 5.3,
    }
    fields.update(overrides)
    return Verdict(**fields)


def test_a_run_file_reads_back_as_written(tmp_path):
    run = Run(
        started_at="2026-10-14T00:10:00",
        provider="local",
        model="google/gemma-4-12b-qat",
        prompt_version="v1",
        source="data/corpus/synthetic-42-400.jsonl",
        source_sha256="0930448045c3dc2849958ee7b3b20779da2881a538e1dd7718ace3d1ec1c7a93",
        masked=False,
        include_dropped=False,
        limit=50,
        concurrency=1,
    )
    path = tmp_path / "runs" / "run.jsonl"
    write_run(path, run)
    first = make_verdict("a")
    failed = make_verdict("b", verdict=None, confidence=None, error="HTTP 503", replied=False)
    append_verdict(path, first)
    append_verdict(path, failed)

    assert read_run(path) == (run, [first, failed])


def test_a_file_that_is_no_run_is_refused(tmp_path):
    path = tmp_path / "scan.jsonl"
    write_jsonl(path, [make_candidate()])
    with pytest.raises(ValueError, match="not a run file"):
        read_run(path)
