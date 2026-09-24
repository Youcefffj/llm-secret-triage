"""Measure how a filtering layer splits labelled secrets from false positives.

Only labelled candidates count. An unlabelled one says nothing about recall or
drop rate, so it is skipped rather than guessed at.
"""

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from . import prefilter
from .models import (
    DIFFICULTY_EASY,
    DIFFICULTY_HARD,
    DIFFICULTY_MEDIUM,
    LABEL_NOT_SECRET,
    LABEL_SECRET,
    Candidate,
)


@dataclass(frozen=True)
class SweepPoint:
    """The prefilter's result over a corpus, at one entropy floor."""

    min_entropy: float
    secrets: int
    secrets_dropped: int
    false_positives: int
    false_positives_dropped: int
    entropy_only: int  # false positives nothing but the entropy floor would drop

    @property
    def recall(self) -> float:
        # share of real secrets that get through. invariant 4 wants exactly 1.0
        if not self.secrets:
            return 1.0
        return (self.secrets - self.secrets_dropped) / self.secrets

    @property
    def fp_drop_rate(self) -> float:
        if not self.false_positives:
            return 0.0
        return self.false_positives_dropped / self.false_positives


@dataclass(frozen=True)
class RuleContribution:
    """How much one prefilter rule actually does."""

    rule: str
    first_match: int  # drops logged under this rule, because it fired first
    only_rule: int  # drops no other rule would have made. 0 = the rule adds nothing


@dataclass(frozen=True)
class DifficultyDrop:
    """How many false positives of one difficulty the prefilter removes."""

    difficulty: str
    total: int
    dropped: int


def sweep(candidates: Sequence[Candidate], thresholds: Iterable[float]) -> list[SweepPoint]:
    """Run the prefilter over `candidates` once per entropy floor."""
    points = []
    for threshold in thresholds:
        secrets = secrets_dropped = false_positives = fp_dropped = entropy_only = 0
        for candidate in candidates:
            decision = prefilter.decide(candidate.match, min_entropy=threshold)
            if candidate.label == LABEL_SECRET:
                secrets += 1
                secrets_dropped += not decision.kept
            elif candidate.label == LABEL_NOT_SECRET:
                false_positives += 1
                fp_dropped += not decision.kept
                entropy_only += decision.fired == ("low_entropy",)
        points.append(
            SweepPoint(
                min_entropy=threshold,
                secrets=secrets,
                secrets_dropped=secrets_dropped,
                false_positives=false_positives,
                false_positives_dropped=fp_dropped,
                entropy_only=entropy_only,
            )
        )
    return points


def contributions(candidates: Iterable[Candidate], min_entropy: float) -> list[RuleContribution]:
    """Per rule: drops credited to it, and drops only it makes. Every rule is listed."""
    first_match: Counter[str] = Counter()
    only_rule: Counter[str] = Counter()
    for candidate in candidates:
        if candidate.label is None:
            continue
        fired = prefilter.decide(candidate.match, min_entropy=min_entropy).fired
        if fired:
            first_match[fired[0]] += 1
            if len(fired) == 1:
                only_rule[fired[0]] += 1
    return [RuleContribution(rule, first_match[rule], only_rule[rule]) for rule in prefilter.RULES]


def drops_by_difficulty(
    candidates: Iterable[Candidate], min_entropy: float
) -> list[DifficultyDrop]:
    """False positives removed per difficulty. Difficulties absent from the corpus are left out."""
    total: Counter[str] = Counter()
    dropped: Counter[str] = Counter()
    for candidate in candidates:
        if candidate.label != LABEL_NOT_SECRET or candidate.difficulty is None:
            continue
        total[candidate.difficulty] += 1
        dropped[candidate.difficulty] += not prefilter.decide(
            candidate.match, min_entropy=min_entropy
        ).kept
    return [
        DifficultyDrop(difficulty, total[difficulty], dropped[difficulty])
        for difficulty in (DIFFICULTY_EASY, DIFFICULTY_MEDIUM, DIFFICULTY_HARD)
        if total[difficulty]
    ]


def lowest_secret_entropy(candidates: Iterable[Candidate]) -> float | None:
    """Lowest entropy among the secrets the floor applies to: the room left under it."""
    values = [
        prefilter.entropy(candidate.match)
        for candidate in candidates
        if candidate.label == LABEL_SECRET and not prefilter.has_vendor_prefix(candidate.match)
    ]
    return min(values, default=None)
