"""The terminal review: one candidate at a time, a human says whether it is a real secret.

Labels are written back into the scan file after every answer, so a review can
stop anywhere and resume where it left off.
"""

import random
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from . import prefilter
from .models import LABEL_NOT_SECRET, LABEL_SECRET, Candidate, read_jsonl, write_jsonl

# fixed, so a review stopped and resumed audits the same dropped candidates
_AUDIT_SEED = 0

PROMPT = "real secret? [y]es [n]o [?] not sure [q]uit: "
_LABELS = {"y": LABEL_SECRET, "n": LABEL_NOT_SECRET}


def queue(candidates: Sequence[Candidate], audit_dropped: int = 0) -> list[int]:
    """Positions of the candidates still to review, in file order.

    What the prefilter drops is left out, except `audit_dropped` of those drawn at
    random and mixed in. Nothing on screen tells them apart, so their labels
    measure what the prefilter throws away (invariant 4).
    """
    kept: list[int] = []
    dropped: list[int] = []
    for index, candidate in enumerate(candidates):
        (kept if prefilter.decide(candidate.match).kept else dropped).append(index)
    audited = random.Random(_AUDIT_SEED).sample(dropped, min(audit_dropped, len(dropped)))
    return sorted(index for index in kept + audited if candidates[index].label is None)


def review(
    path: Path,
    *,
    audit_dropped: int = 0,
    ask: Callable[[str], str] = input,
    show: Callable[[str], None] = print,
) -> None:
    """Ask about every candidate of the scan file still to review, until done or told to quit."""
    candidates = list(read_jsonl(path))
    positions = queue(candidates, audit_dropped)
    for number, index in enumerate(positions, start=1):
        show(card(candidates[index], number, len(positions)))
        answer = _answer(ask, show)
        if answer == "q":
            return
        if answer in _LABELS:
            candidates[index] = replace(
                candidates[index], label=_LABELS[answer], label_source="human"
            )
            _save(path, candidates)


def card(candidate: Candidate, number: int, total: int) -> str:
    """What the reviewer sees: where it is, and the lines around it, the value's marked."""
    lines = [f"\n[{number}/{total}] {candidate.path}:{candidate.line}  ({candidate.rule})"]
    for text in candidate.context.splitlines():
        lines.append(f"  {'>>' if candidate.match in text else '  '}  {text}")
    return "\n".join(lines)


def _answer(ask: Callable[[str], str], show: Callable[[str], None]) -> str:
    while True:
        try:
            answer = ask(PROMPT).strip().lower()
        except EOFError:  # ctrl-d, or input ran out: same as quitting
            return "q"
        if answer in ("y", "n", "?", "q"):
            return answer
        show("y, n, ? or q")


def _save(path: Path, candidates: list[Candidate]) -> None:
    # written aside then swapped in: a crash mid-write never eats the labels
    temporary = path.with_name(path.name + ".tmp")
    write_jsonl(temporary, candidates)
    temporary.replace(path)
