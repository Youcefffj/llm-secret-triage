"""A folder as a source: every file under it, a mounted share or a synced library."""

import os
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from typing import NoReturn

from . import SourceFile


def walk(folder: Path) -> Iterator[SourceFile]:
    """Every file under `folder`, in name order, subfolders included."""
    if not folder.is_dir():
        raise ValueError(f"not a folder: {folder}")
    return _walk(str(folder))


def _walk(directory: str) -> Iterator[SourceFile]:
    try:
        entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except OSError as error:
        # a folder we may not list still shows up, as one file that can't be opened
        yield SourceFile(directory, 0, partial(_fail, error))
        return
    for entry in entries:
        # a linked folder can point back up the tree: never followed
        if entry.is_dir(follow_symlinks=False):
            yield from _walk(entry.path)
        elif entry.is_file():
            try:
                size = entry.stat().st_size
            except OSError as error:
                yield SourceFile(entry.path, 0, partial(_fail, error))
                continue
            yield SourceFile(entry.path, size, partial(open, entry.path, "rb"))


def _fail(error: OSError) -> NoReturn:
    raise error
