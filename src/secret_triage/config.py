"""Filesystem locations the project writes to."""

import os
from pathlib import Path

# Everything under this directory is gitignored: it holds corpora and findings
# that may contain live credentials (invariant 1).
# point it elsewhere with SECRET_TRIAGE_DATA_DIR=/some/path
DATA_DIR = Path(os.environ.get("SECRET_TRIAGE_DATA_DIR", "data"))

# generated corpora land here, e.g. data/corpus/synthetic-42-400.jsonl
CORPUS_DIR = DATA_DIR / "corpus"

# one file per scan, raw values and labels included, e.g. data/scans/share-20261013-142501.jsonl
SCANS_DIR = DATA_DIR / "scans"

# one file per triage run: its settings, then a verdict per line
RUNS_DIR = DATA_DIR / "runs"

# where `--provider local` sends its requests: LM Studio's default.
# Ollama listens on http://localhost:11434/v1, llama.cpp's server on http://localhost:8080/v1
LOCAL_BASE_URL = "http://localhost:1234/v1"

# the model each provider gets when --model is not given. local: the one model the
# pipeline is built and measured with. codex: None, the account's own default
DEFAULT_MODELS: dict[str, str | None] = {
    "local": "google/gemma-4-12b-qat",
    "claude-code": "haiku",
    "codex": None,
}
