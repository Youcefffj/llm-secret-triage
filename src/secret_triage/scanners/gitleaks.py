"""Run gitleaks on a folder and turn what it reports into Candidates.

The candidate's value is gitleaks' `Secret` (the value alone), never its `Match`,
which carries the label too: the prefilter must not see the label (invariant 3).
Author, email and commit fields of the report are not kept.
"""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from ..models import Candidate

# lines kept on each side of a finding, so the reviewer sees what the value belongs to
CONTEXT_LINES = 5

# a minified file is one huge line: keep this much of each line, around the value
_MAX_LINE = 300

# a share also holds videos and disk images. nobody types a password into those
_MAX_FILE_MEGABYTES = 50

# the password rule, on top of gitleaks' own (see the file for why)
_CONFIG = Path(__file__).with_name("gitleaks.toml")


class GitleaksError(RuntimeError):
    """gitleaks is missing, or it failed."""


def scan(folder: Path) -> list[Candidate]:
    """Every finding in `folder`, in file order, one Candidate per value and place."""
    if not folder.is_dir():
        raise ValueError(f"not a folder: {folder}")
    binary = shutil.which("gitleaks")
    if binary is None:
        raise GitleaksError(
            "gitleaks not found on PATH, get it from https://github.com/gitleaks/gitleaks/releases"
        )
    result = subprocess.run(
        [
            binary, "dir", str(folder),
            "--config", str(_CONFIG),
            "--report-format", "json",
            "--report-path", "-",  # report on stdout: no file of raw values left behind
            "--exit-code", "0",  # finding something is not a failure
            "--max-target-megabytes", str(_MAX_FILE_MEGABYTES),
            "--no-banner",
            "--log-level", "error",
        ],
        capture_output=True,
        encoding="utf-8",
    )
    if result.returncode != 0:
        raise GitleaksError(result.stderr.strip() or f"gitleaks exited with {result.returncode}")
    return parse_report(result.stdout)


def parse_report(report: str) -> list[Candidate]:
    """Turn gitleaks' JSON report into Candidates, reading each file for the context."""
    candidates: dict[tuple[str, int, str], Candidate] = {}
    for finding in json.loads(report):
        path, line, secret = finding["File"], finding["StartLine"], finding["Secret"]
        # two rules on the same value at the same place: one thing to review
        if (path, line, secret) in candidates:
            continue
        context = _context(Path(path), line, finding["EndLine"], secret)
        candidates[path, line, secret] = Candidate(
            id=hashlib.sha256(f"{path}:{line}:{secret}".encode()).hexdigest()[:16],
            detector="gitleaks",
            source="filesystem",
            path=path,
            line=line,
            rule=finding["RuleID"],
            match=secret,
            # the file moved since the scan: what gitleaks matched is all there is
            context=context if context is not None else finding["Match"],
        )
    # gitleaks reports in whatever order its workers finish
    return sorted(candidates.values(), key=lambda candidate: (candidate.path, candidate.line))


def _context(path: Path, start: int, end: int, secret: str) -> str | None:
    """Lines `start`..`end` of `path` (1-based) plus CONTEXT_LINES on each side."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    window = lines[max(start - 1 - CONTEXT_LINES, 0) : end + CONTEXT_LINES]
    return "\n".join(_clip(text, secret) for text in window)


def _clip(text: str, secret: str) -> str:
    """Cut a long line down to _MAX_LINE chars, centred on the value when it is there."""
    # never cut through the value: a partial copy would escape the mask (invariant 2)
    width = max(_MAX_LINE, len(secret))
    if len(text) <= width:
        return text
    found = text.find(secret)
    if found < 0:
        return text[:width]
    start = max(0, min(found - (width - len(secret)) // 2, len(text) - width))
    return text[start : start + width]
