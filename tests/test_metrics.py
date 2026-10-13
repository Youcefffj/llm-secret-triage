import hashlib

import pytest

from secret_triage import metrics, prefilter
from secret_triage.models import LABEL_NOT_SECRET, LABEL_SECRET, Candidate, Verdict
from secret_triage.synthetic import generate


def candidate(match: str, label: str | None, difficulty: str | None = None) -> Candidate:
    return Candidate(
        id=hashlib.sha256(match.encode()).hexdigest()[:16],
        detector="test",
        source="test",
        path="config/settings.py",
        line=1,
        rule="test",
        match=match,
        context=f'KEY = "{match}"',
        label=label,
        label_source="test" if label else None,
        difficulty=difficulty,
    )


# twenty corpora pooled, built once for the whole file
@pytest.fixture(scope="module")
def twenty_seeds() -> list[Candidate]:
    return [c for seed in range(20) for c in generate(seed=seed, count=400)]


# invariant 4, the test the phase hangs on: not one secret in 2400 is dropped
def test_recall_is_one_across_twenty_seeds(twenty_seeds):
    (point,) = metrics.sweep(twenty_seeds, [prefilter.DEFAULT_MIN_ENTROPY])
    assert point.secrets == 2400
    assert point.secrets_dropped == 0
    assert point.recall == 1.0


def test_kill_rules_alone_never_drop_a_secret(twenty_seeds):
    (point,) = metrics.sweep(twenty_seeds, [0.0])
    assert point.secrets_dropped == 0


def test_a_higher_floor_never_drops_less():
    points = metrics.sweep(generate(seed=3, count=400), [0.0, 1.0, 2.0, 3.0, 4.0, 5.0])
    drops = [p.secrets_dropped + p.false_positives_dropped for p in points]
    assert drops == sorted(drops)


def test_contributions_list_every_rule_and_add_up():
    corpus = generate(seed=3, count=400)
    rows = metrics.contributions(corpus, prefilter.DEFAULT_MIN_ENTROPY)
    (point,) = metrics.sweep(corpus, [prefilter.DEFAULT_MIN_ENTROPY])

    assert [row.rule for row in rows] == list(prefilter.RULES)
    assert sum(row.first_match for row in rows) == (
        point.secrets_dropped + point.false_positives_dropped
    )


def test_only_rule_counts_drops_no_other_rule_would_make():
    corpus = [
        candidate("${API_KEY}", LABEL_NOT_SECRET),  # template, nothing else
        candidate("CHANGEME", LABEL_NOT_SECRET),  # placeholder, nothing else
        candidate("xxxx", LABEL_NOT_SECRET),  # too few distinct AND under the floor
    ]
    rows = {row.rule: row for row in metrics.contributions(corpus, 2.0)}

    assert rows["template_expression"].only_rule == 1
    assert rows["placeholder_token"].only_rule == 1
    assert rows["too_few_distinct"].first_match == 1
    assert rows["too_few_distinct"].only_rule == 0
    assert rows["low_entropy"].only_rule == 0


def test_unlabelled_candidates_are_left_out():
    corpus = [candidate("CHANGEME", None), candidate("a1B2c3D4e5F6g7H8", LABEL_SECRET)]
    (point,) = metrics.sweep(corpus, [0.0])
    assert point.secrets == 1
    assert point.false_positives == 0
    assert sum(row.first_match for row in metrics.contributions(corpus, 0.0)) == 0


def test_drops_by_difficulty_skip_what_is_absent():
    commit_sha = hashlib.sha1(b"a commit").hexdigest()
    corpus = [
        candidate("CHANGEME", LABEL_NOT_SECRET, "easy"),
        candidate(commit_sha, LABEL_NOT_SECRET, "hard"),
        candidate("a1B2c3D4e5F6g7H8", LABEL_SECRET),
    ]
    rows = {row.difficulty: row for row in metrics.drops_by_difficulty(corpus, 1.5)}

    assert set(rows) == {"easy", "hard"}
    assert (rows["easy"].total, rows["easy"].dropped) == (1, 1)
    assert (rows["hard"].total, rows["hard"].dropped) == (1, 0)


def test_lowest_secret_entropy_ignores_vendor_prefixed_secrets():
    corpus = [
        candidate("ghp_" + "a" * 20, LABEL_SECRET),  # low, but the floor never sees it
        candidate("a1B2c3D4e5F6g7H8", LABEL_SECRET),  # 16 distinct chars: 4.0 bits
        candidate("CHANGEME", LABEL_NOT_SECRET),
    ]
    assert metrics.lowest_secret_entropy(corpus) == 4.0
    assert metrics.lowest_secret_entropy([]) is None


def verdict(candidate_id: str, answer: str | None, *, latency=1.0, at=1.0, **fields) -> Verdict:
    values = {
        "candidate_id": candidate_id,
        "verdict": answer,
        "confidence": 0.9 if answer else None,
        "reason": "",
        "error": None if answer else "HTTP 503",
        "replied": answer is not None,
        "tokens_in": 400,
        "tokens_out": 40,
        "cost_usd": None,
        "latency": latency,
        "at": at,
    }
    values.update(fields)
    return Verdict(**values)


def test_precision_recall_and_f1():
    scores = metrics.Scores(
        true_positives=8, false_positives=2, false_negatives=2, true_negatives=88
    )
    assert (scores.precision, scores.recall) == (0.8, 0.8)
    assert scores.f1 == pytest.approx(0.8)


def test_nothing_flagged_or_nothing_to_find_does_not_divide_by_zero():
    assert metrics.Scores().precision == 0.0
    assert metrics.Scores().recall == 1.0
    assert metrics.Scores().f1 == 0.0


def test_the_scanner_alone_flags_everything():
    corpus = [
        candidate("Welcome1!", LABEL_SECRET),
        candidate("CHANGEME", LABEL_NOT_SECRET),
        candidate("Soleil2024", None),  # unlabelled: left out
    ]
    assert metrics.scanner_alone(corpus) == metrics.Scores(true_positives=1, false_positives=1)


def test_with_triage_each_candidate_ends_where_the_layers_put_it():
    secret, sha, placeholder, failed, unsent = (
        candidate("Welcome1!", LABEL_SECRET),
        candidate("4f9c2a1e7b3d5f8a0c6e9b2d4f7a1c3e5b8d0f2a", LABEL_NOT_SECRET),
        candidate("CHANGEME", LABEL_NOT_SECRET),  # dropped by the prefilter
        candidate("Hiver-2023", LABEL_SECRET),  # sent, the call failed
        candidate("Bonjour2025", LABEL_SECRET),  # sent, the run stopped before it
    )
    sent = {secret.id, sha.id, failed.id, unsent.id}
    verdicts = [
        verdict(secret.id, LABEL_SECRET),
        verdict(sha.id, LABEL_NOT_SECRET),
        verdict(failed.id, None),  # no answer: kept for a human, so counted as flagged
    ]
    scores = metrics.with_triage([secret, sha, placeholder, failed, unsent], sent, verdicts)
    assert scores == metrics.Scores(true_positives=2, true_negatives=2)


def test_latency_is_read_on_the_second_half_of_the_batch():
    verdicts = [verdict(str(n), LABEL_SECRET, latency=float(n), at=float(n)) for n in range(1, 11)]
    verdicts.reverse()  # written in the order they came, read in the order of `at`
    timing = metrics.timing(verdicts)
    assert timing.tail == 5
    assert (timing.latency_p50, timing.latency_p95) == (8.0, 10.0)
    assert (timing.wall_seconds, timing.tokens_out) == (10.0, 400)
    assert timing.tokens_per_second == 40.0
    assert timing.cost_usd is None


def test_failed_calls_count_in_the_tokens_but_not_in_the_latency():
    verdicts = [
        verdict("a", LABEL_SECRET, latency=3.0, at=3.0, cost_usd=0.002),
        verdict("b", None, latency=0.0, at=9.0, tokens_in=None, tokens_out=None),
    ]
    timing = metrics.timing(verdicts)
    assert (timing.calls, timing.replied, timing.tail) == (2, 1, 1)
    assert timing.latency_p95 == 3.0
    assert timing.cost_usd == 0.002
