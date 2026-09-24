"""Filesystem locations the project writes to."""

import os
from pathlib import Path

# Everything under this directory is gitignored: it holds corpora and findings
# that may contain live credentials (invariant 1).
# point it elsewhere with SECRET_TRIAGE_DATA_DIR=/some/path
DATA_DIR = Path(os.environ.get("SECRET_TRIAGE_DATA_DIR", "data"))

# generated corpora land here, e.g. data/corpus/synthetic-42-400.jsonl
CORPUS_DIR = DATA_DIR / "corpus"
