"""The candidate schema: one scanner finding, its masking and its JSONL form."""

import hashlib
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

# the only two answers a candidate can get. None means nobody labelled it yet
LABEL_SECRET = "secret"
LABEL_NOT_SECRET = "not_secret"

# how hard a false positive is to spot. only ever set on false positives
DIFFICULTY_EASY = "easy"
DIFFICULTY_MEDIUM = "medium"
DIFFICULTY_HARD = "hard"

# Below this length a value has too little to reveal: mask it whole.
_MASK_MIN_LENGTH = 8
_MASK_PREFIX = 3
_MASK_SUFFIX = 2


def mask(value: str) -> str:
    """Return `value` with its middle replaced by stars, keeping its length."""
    if len(value) < _MASK_MIN_LENGTH:   # too short to show anything safely
        return "*" * len(value)
    # keep the first 3 and last 2 chars, stars in between
    stars = len(value) - _MASK_PREFIX - _MASK_SUFFIX
    return f"{value[:_MASK_PREFIX]}{'*' * stars}{value[-_MASK_SUFFIX:]}"


def digest(value: str) -> str:
    """Return the SHA-256 of `value`, which identifies it without carrying it."""
    # one way street: same val always gives the same fingerprint,
    # but you can't get the val back out of it
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Candidate:
    """A single finding: where it was seen, what was matched, and how it is labelled.

    `match` is the raw value and stays on the host. The masked form and the digest
    are derived from it on serialisation rather than stored, so the two can never
    drift apart from the value they describe.
    """

    id: str                             # short unique id for this finding
    detector: str                       # who found it: gitleaks, synthetic...
    source: str                         # where it came from: git, filesystem, synthetic
    path: str                           # file the value sits in
    line: int                           # line number inside that file
    rule: str                           # which rule fired, e.g. aws-secret-access-key
    match: str                          # the raw val. stays local, never exported
    context: str                        # the lines around it. this is what the llm reads
    label: str | None = None            # the truth: secret / not_secret
    label_source: str | None = None     # who said so: synthetic, human
    difficulty: str | None = None       # easy / medium / hard, false positives only

    # safe to print in a report
    @property
    def match_masked(self) -> str:
        return mask(self.match)

    # safe to store and compare, can't be reversed
    @property
    def match_sha256(self) -> str:
        return digest(self.match)

    @property
    def context_masked(self) -> str:
        """`context` with every occurrence of the raw value replaced by its mask."""
        # the raw val shows up inside context too, so swap it out there as well
        return self.context.replace(self.match, self.match_masked)

    # full record, raw val included. goes to a local file only
    def to_dict(self) -> dict:
        """The local record, raw value included. Never leaves the host."""
        return {
            "id": self.id,
            "detector": self.detector,
            "source": self.source,
            "path": self.path,
            "line": self.line,
            "rule": self.rule,
            "match": self.match,
            "context": self.context,
            "match_masked": self.match_masked,
            "match_sha256": self.match_sha256,
            "label": self.label,
            "label_source": self.label_source,
            "difficulty": self.difficulty,
        }

    # same record minus the secret bits. this one can be shared
    def to_public_dict(self) -> dict:
        """The exportable record: no raw value, in the context either (invariant 2)."""
        record = self.to_dict()
        # drop the raw val, then clean the context
        del record["match"]
        record["context"] = self.context_masked
        return record

    # note: match_masked / match_sha256 in the file are ignored on purpose,
    # we recompute them from match so they can never be stale
    @classmethod
    def from_dict(cls, record: dict) -> "Candidate":
        """Read a local record. Derived fields are recomputed, not trusted."""
        return cls(
            id=record["id"],
            detector=record["detector"],
            source=record["source"],
            path=record["path"],
            line=record["line"],
            rule=record["rule"],
            match=record["match"],
            context=record["context"],
            # .get() not [] here: a fresh scan has no label yet, so these can be missing
            label=record.get("label"),
            label_source=record.get("label_source"),
            difficulty=record.get("difficulty"),
        )


def write_jsonl(path: Path, candidates: Iterable[Candidate]) -> int:
    """Write candidates as one JSON object per line. Returns how many were written."""
    # data/corpus/ may not exist yet
    path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for candidate in candidates:
            handle.write(json.dumps(candidate.to_dict(), ensure_ascii=False))
            handle.write("\n")
            written += 1
    return written


def read_jsonl(path: Path) -> Iterator[Candidate]:
    """Read back a file written by `write_jsonl`."""
    with path.open(encoding="utf-8") as handle:
        # one line at a time, so a huge file never lands in memory whole
        for line in handle:
            line = line.strip()
            # skip blank lines
            if line:
                yield Candidate.from_dict(json.loads(line))
