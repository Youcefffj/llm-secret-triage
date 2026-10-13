import collections
import hashlib
import json
import os
import subprocess
import sys

import pytest

from secret_triage.models import LABEL_NOT_SECRET, LABEL_SECRET, write_jsonl
from secret_triage.synthetic import generate

# run in a separate python below, prints the corpus to stdout
_CHILD_SCRIPT = """
import json, sys
from secret_triage.synthetic import generate
for candidate in generate(seed=11, count=120):
    sys.stdout.write(json.dumps(candidate.to_dict(), ensure_ascii=False) + "\\n")
"""


# the whole point of P1: same seed in, same file out
def test_same_seed_produces_the_same_bytes(tmp_path):
    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    write_jsonl(first, generate(seed=42, count=400))
    write_jsonl(second, generate(seed=42, count=400))

    assert first.read_bytes() == second.read_bytes()


# pins the corpus itself, not just two runs agreeing with each other. a change in
# draw order, or in python's `random` between versions, moves this hash. changing
# the generator on purpose means updating it on purpose
def test_seed_42_still_gives_the_same_corpus(tmp_path):
    out = tmp_path / "corpus.jsonl"
    write_jsonl(out, generate(seed=42, count=400))

    assert hashlib.sha256(out.read_bytes()).hexdigest() == (
        "0930448045c3dc2849958ee7b3b20779da2881a538e1dd7718ace3d1ec1c7a93"
    )


def test_a_different_seed_produces_a_different_corpus():
    assert generate(seed=42, count=400) != generate(seed=43, count=400)


# PYTHONHASHSEED changes on every run, so a stray set() in the generator shows up here
def test_same_seed_survives_a_fresh_interpreter():
    """Catches any dependence on hash ordering, which varies per process."""
    runs = []
    for hash_seed in ("0", "12345"):
        env = {**os.environ, "PYTHONHASHSEED": hash_seed}
        result = subprocess.run(
            [sys.executable, "-c", _CHILD_SCRIPT],
            env=env,
            capture_output=True,
            check=True,
        )
        runs.append(result.stdout)

    assert runs[0] == runs[1]
    assert runs[0].count(b"\n") == 120


@pytest.mark.parametrize(
    ("count", "secrets", "hard", "medium", "easy"),
    [(400, 120, 140, 56, 84), (1000, 300, 350, 140, 210)],
)
# 400 -> 120/140/56/84 and 1000 -> 300/350/140/210, on the nose
def test_distribution_holds_exactly(count, secrets, hard, medium, easy):
    candidates = generate(seed=1, count=count)
    labels = collections.Counter(c.label for c in candidates)
    difficulties = collections.Counter(
        c.difficulty for c in candidates if c.label == LABEL_NOT_SECRET
    )

    assert len(candidates) == count
    assert labels[LABEL_SECRET] == secrets
    assert labels[LABEL_NOT_SECRET] == count - secrets
    assert difficulties["hard"] == hard
    assert difficulties["medium"] == medium
    assert difficulties["easy"] == easy


@pytest.mark.parametrize("seed", [0, 7, 42, 1337])
def test_every_candidate_is_well_formed(seed):
    candidates = generate(seed=seed, count=400)

    assert len({c.id for c in candidates}) == len(candidates)
    for candidate in candidates:
        assert candidate.match in candidate.context
        assert candidate.detector == "synthetic"
        assert candidate.line >= 3
        if candidate.label == LABEL_SECRET:
            assert candidate.difficulty is None
        else:
            assert candidate.difficulty in {"easy", "medium", "hard"}


# keeps the hard cases hard. without it a sloppy edit makes the scores look great
def test_hard_false_positives_are_not_given_away_by_their_value():
    """A hard FP must be distinguishable only in context: no placeholder wording."""
    giveaways = ("changeme", "example", "your-", "todo", "redacted", "${", "{{")
    hard = [c for c in generate(seed=5, count=1000) if c.difficulty == "hard"]

    assert hard
    for candidate in hard:
        lowered = candidate.match.lower()
        assert not any(word in lowered for word in giveaways)


def test_count_below_the_floor_is_refused():
    with pytest.raises(ValueError, match="at least"):
        generate(seed=1, count=3)


def test_corpus_serialises_to_the_documented_schema(tmp_path):
    out = tmp_path / "corpus.jsonl"
    write_jsonl(out, generate(seed=3, count=50))
    record = json.loads(out.read_text(encoding="utf-8").splitlines()[0])

    assert list(record) == [
        "id",
        "detector",
        "source",
        "path",
        "line",
        "rule",
        "match",
        "context",
        "match_masked",
        "match_sha256",
        "label",
        "label_source",
        "difficulty",
    ]
