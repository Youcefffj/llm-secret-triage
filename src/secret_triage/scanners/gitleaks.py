"""Run gitleaks over extracted texts and turn what it reports into Candidates.

The candidate's value is gitleaks' `Secret` (the value alone), never its `Match`,
which carries the label too: the prefilter must not see the label (invariant 3).

gitleaks reads files, so each text is written to a private temporary folder for
the run, and the folder is deleted as soon as gitleaks is done with it.
"""

import hashlib
import json
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path

from ..models import Candidate

# chars kept on each side of a finding, so the reviewer sees what the value belongs to
CONTEXT_CHARS = 100

# the password rules, on top of gitleaks' own (see the file for why)
_CONFIG = Path(__file__).with_name("gitleaks.toml")


class GitleaksError(RuntimeError):
    """gitleaks is missing, or it failed."""


def find_binary() -> str:
    """Where gitleaks is. Raises GitleaksError, with where to get it, when it isn't there."""
    binary = shutil.which("gitleaks")
    if binary is None:
        raise GitleaksError(
            "gitleaks not found on PATH, get it from https://github.com/gitleaks/gitleaks/releases"
        )
    return binary


def scan(documents: Sequence[tuple[str, str]]) -> list[Candidate]:
    """Every finding in the (path, text) pairs, in path order, one per value and place."""
    binary = find_binary()
    with tempfile.TemporaryDirectory(prefix="secret-triage-") as folder:
        # named by position, not after the file: gitleaks skips some names (*.pdf, vendor/...)
        for index, (_, content) in enumerate(documents):
            (Path(folder) / f"{index}.txt").write_text(content, encoding="utf-8")
        result = subprocess.run(
            [
                binary, "dir", folder,
                "--config", str(_CONFIG),
                "--report-format", "json",
                "--report-path", "-",  # report on stdout: no file of raw values left behind
                "--exit-code", "0",  # finding something is not a failure
                "--no-banner",
                "--log-level", "error",
            ],
            capture_output=True,
            encoding="utf-8",
        )
    if result.returncode != 0:
        raise GitleaksError(result.stderr.strip() or f"gitleaks exited with {result.returncode}")
    return parse_report(result.stdout, documents)


def parse_report(report: str, documents: Sequence[tuple[str, str]]) -> list[Candidate]:
    """Turn gitleaks' JSON report on `documents`, written as <index>.txt, into Candidates."""
    candidates: dict[tuple[str, int, str], Candidate] = {}
    line_starts: dict[int, list[int]] = {}
    for finding in json.loads(report):
        index = int(Path(finding["File"]).stem)
        path, content = documents[index]
        line, secret = finding["StartLine"], finding["Secret"]
        # two rules on the same value at the same place: one thing to review
        if (path, line, secret) in candidates:
            continue
        if index not in line_starts:
            line_starts[index] = _line_starts(content)
        context = _context(content, line_starts[index], line, secret)
        candidates[path, line, secret] = Candidate(
            id=hashlib.sha256(f"{path}:{line}:{secret}".encode()).hexdigest()[:16],
            detector="gitleaks",
            source="filesystem",
            path=path,
            line=line,
            rule=finding["RuleID"],
            match=secret,
            context=context if context is not None else finding["Match"],
        )
    # gitleaks reports in whatever order its workers finish
    return sorted(candidates.values(), key=lambda candidate: (candidate.path, candidate.line))


def _line_starts(content: str) -> list[int]:
    starts = [0]
    found = content.find("\n")
    while found >= 0:
        starts.append(found + 1)
        found = content.find("\n", found + 1)
    return starts


def _context(content: str, starts: list[int], line: int, secret: str) -> str | None:
    """CONTEXT_CHARS before the value on `line` (1-based), the value, CONTEXT_CHARS after."""
    offset = starts[min(line, len(starts)) - 1]
    at = content.find(secret, offset)
    if at < 0:  # gitleaks counted lines differently: take the first one in the text
        at = content.find(secret)
    if at < 0:
        return None
    return content[max(0, at - CONTEXT_CHARS) : at + len(secret) + CONTEXT_CHARS]
