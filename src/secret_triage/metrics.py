"""Measure how each layer splits labelled secrets from false positives, and what a run costs.

Only labelled candidates count. An unlabelled one says nothing about recall or
drop rate, so it is skipped rather than guessed at.
"""

import math
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
    Verdict,
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


@dataclass(frozen=True)
class Scores:
    """Calls against labels: real secrets flagged and missed, false positives flagged and not."""

    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0

    @property
    def precision(self) -> float:
        # of what was flagged, the share that is a real secret
        flagged = self.true_positives + self.false_positives
        return self.true_positives / flagged if flagged else 0.0

    @property
    def recall(self) -> float:
        # of the real secrets, the share that was flagged
        secrets = self.true_positives + self.false_negatives
        return self.true_positives / secrets if secrets else 1.0

    @property
    def f1(self) -> float:
        total = self.precision + self.recall
        return 2 * self.precision * self.recall / total if total else 0.0


def score(calls: Iterable[tuple[str, str]]) -> Scores:
    """Count (predicted, label) pairs, both secret or not_secret."""
    counts: Counter[tuple[str, str]] = Counter(calls)
    return Scores(
        true_positives=counts[LABEL_SECRET, LABEL_SECRET],
        false_positives=counts[LABEL_SECRET, LABEL_NOT_SECRET],
        false_negatives=counts[LABEL_NOT_SECRET, LABEL_SECRET],
        true_negatives=counts[LABEL_NOT_SECRET, LABEL_NOT_SECRET],
    )


def scanner_alone(candidates: Iterable[Candidate]) -> Scores:
    """The baseline: everything the scanner reports is taken for a secret."""
    return score((LABEL_SECRET, c.label) for c in candidates if c.label is not None)


def with_triage(
    candidates: Iterable[Candidate], sent: set[str], verdicts: Iterable[Verdict]
) -> Scores:
    """The scanner, then the prefilter, then the model: what each labelled candidate becomes.

    Not sent to the model, it was dropped by the prefilter: not_secret. Sent with no
    usable answer: secret, since a failed call never hides a finding from a human.
    Sent with no verdict at all (the run was cut short): left out.
    """
    answers = {verdict.candidate_id: verdict for verdict in verdicts}
    calls = []
    for candidate in candidates:
        if candidate.label is None:
            continue
        if candidate.id not in sent:
            calls.append((LABEL_NOT_SECRET, candidate.label))
        elif candidate.id in answers:
            calls.append((answers[candidate.id].verdict or LABEL_SECRET, candidate.label))
    return score(calls)


@dataclass(frozen=True)
class Timing:
    """What a run took. Latency is read on the tail of the batch: a fanless machine slows down."""

    calls: int
    replied: int
    wall_seconds: float
    tokens_in: int
    tokens_out: int
    cost_usd: float | None      # None: no provider put a price on its calls
    tail: int                   # how many of the last answers the latency is read on
    latency_p50: float
    latency_p95: float

    @property
    def tokens_per_second(self) -> float:
        return self.tokens_out / self.wall_seconds if self.wall_seconds else 0.0


def timing(verdicts: Sequence[Verdict]) -> Timing:
    replied = sorted((v for v in verdicts if v.replied), key=lambda verdict: verdict.at)
    tail = [verdict.latency for verdict in replied[len(replied) // 2 :]]
    costs = [verdict.cost_usd for verdict in verdicts if verdict.cost_usd is not None]
    return Timing(
        calls=len(verdicts),
        replied=len(replied),
        wall_seconds=max((verdict.at for verdict in verdicts), default=0.0),
        tokens_in=sum(verdict.tokens_in or 0 for verdict in verdicts),
        tokens_out=sum(verdict.tokens_out or 0 for verdict in verdicts),
        cost_usd=sum(costs) if costs else None,
        tail=len(tail),
        latency_p50=_percentile(tail, 0.50),
        latency_p95=_percentile(tail, 0.95),
    )


def _percentile(values: Sequence[float], share: float) -> float:
    """Nearest rank: the smallest value with at least `share` of them at or below it."""
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(math.ceil(share * len(ordered)) - 1, 0)]
