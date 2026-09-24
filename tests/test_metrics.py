import hashlib

import pytest

from secret_triage import metrics, prefilter
from secret_triage.models import LABEL_NOT_SECRET, LABEL_SECRET, Candidate
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
        candidate("xxxx", LABEL_NOT_SECRET),  # too short AND too few distinct
    ]
    rows = {row.rule: row for row in metrics.contributions(corpus, 0.0)}

    assert rows["template_expression"].only_rule == 1
    assert rows["placeholder_token"].only_rule == 1
    assert rows["too_short"].first_match == 1
    assert rows["too_short"].only_rule == 0
    assert rows["too_few_distinct"].only_rule == 0


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
