"""The scan, file by file: open it, extract its text, run gitleaks over it, keep the findings.

A file's text is held in memory until its batch goes through gitleaks, then
dropped. Nothing of a file survives the scan but its findings, and its path in
the list of files that could not be read.
"""

import zipfile
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from functools import partial

from . import extract
from .models import Candidate
from .scanners import gitleaks
from .sources import SourceFile

# a share also holds videos and disk images. nobody types a password into those
MAX_FILE_BYTES = 50 * 1024 * 1024

# gitleaks costs about 0.2 s to start: one run per file would take hours on a big share
_BATCH_FILES = 500
_BATCH_CHARS = 64 * 1024 * 1024

# why a file was not read, on top of the reasons in `extract`
TOO_LARGE = "over 50 MB"
CANNOT_OPEN = "cannot open"
DAMAGED = "damaged"


@dataclass(frozen=True)
class Unread:
    """A file the scan could not read, so a password in it would go unseen."""

    path: str
    reason: str
    detail: str = ""


@dataclass(frozen=True)
class Scan:
    candidates: list[Candidate]
    read: int               # files whose text went through gitleaks
    unread: list[Unread]


def run(files: Iterable[SourceFile], progress: Callable[[int], None] = lambda done: None) -> Scan:
    """Scan every file, the ones inside .zip archives included."""
    gitleaks.find_binary()  # missing gitleaks: say so now, not after the first 500 files
    candidates: list[Candidate] = []
    unread: list[Unread] = []
    batch: list[tuple[str, str]] = []
    read = chars = 0
    for done, outcome in enumerate(_texts(files), start=1):
        progress(done)
        if isinstance(outcome, Unread):
            unread.append(outcome)
            continue
        read += 1
        batch.append(outcome)
        chars += len(outcome[1])
        if len(batch) >= _BATCH_FILES or chars >= _BATCH_CHARS:
            candidates += gitleaks.scan(batch)
            batch, chars = [], 0
    if batch:
        candidates += gitleaks.scan(batch)
    candidates.sort(key=lambda candidate: (candidate.path, candidate.line))
    return Scan(candidates, read, unread)


def _texts(files: Iterable[SourceFile]) -> Iterator[tuple[str, str] | Unread]:
    """(path, text) for every file that reads, an Unread for every one that doesn't."""
    for file in files:
        if file.path.lower().endswith(".zip"):
            yield from _archive(file)
            continue
        if file.size > MAX_FILE_BYTES:
            yield Unread(file.path, TOO_LARGE)
            continue
        try:
            with file.open() as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
        except OSError as error:
            yield Unread(file.path, CANNOT_OPEN, error.strerror or str(error))
            continue
        if len(data) > MAX_FILE_BYTES:  # grew since it was listed
            yield Unread(file.path, TOO_LARGE)
            continue
        try:
            yield file.path, extract.text(file.path, data)
        except extract.Unreadable as error:
            yield Unread(file.path, error.reason)
        # a parser choking on one broken file must not end a scan hours in
        except Exception as error:
            yield Unread(file.path, DAMAGED, f"{type(error).__name__}: {error}")


def _archive(file: SourceFile) -> Iterator[tuple[str, str] | Unread]:
    """The files inside a .zip, as if it were a folder, nested .zip included."""
    try:
        with file.open() as handle, zipfile.ZipFile(handle) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member = SourceFile(
                    f"{file.path}/{info.filename}", info.file_size, partial(archive.open, info)
                )
                if info.flag_bits & 0x1:  # bit 0: encrypted, it would ask for a password
                    yield Unread(member.path, extract.ENCRYPTED)
                    continue
                yield from _texts([member])
    except OSError as error:
        yield Unread(file.path, CANNOT_OPEN, error.strerror or str(error))
    except zipfile.BadZipFile as error:
        yield Unread(file.path, DAMAGED, str(error))
