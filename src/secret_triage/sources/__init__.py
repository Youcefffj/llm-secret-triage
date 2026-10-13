"""Where files come from. A source hands them over one at a time, as SourceFiles."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import BinaryIO


@dataclass(frozen=True)
class SourceFile:
    """One file of a source, not read yet: the scan decides whether to open it."""

    path: str                       # what a finding points at, e.g. share/it/acces.txt
    size: int                       # bytes, known before opening
    open: Callable[[], BinaryIO]    # the content. raises OSError when it can't be read
