"""Command-line entry point. Argument parsing and printing, nothing else."""

import argparse
import collections
import sys
from pathlib import Path

from . import __version__, synthetic
from .config import CORPUS_DIR
from .models import LABEL_SECRET, write_jsonl


# runs when you type: secret-triage corpus --seed 42 --count 400
def _corpus(args: argparse.Namespace) -> int:
    candidates = synthetic.generate(seed=args.seed, count=args.count)
    # no --out given? build the name from the seed and count
    out = args.out or CORPUS_DIR / f"synthetic-{args.seed}-{args.count}.jsonl"
    written = write_jsonl(out, candidates)

    # just for the summary below, nothing depends on it
    labels = collections.Counter(c.label for c in candidates)
    difficulties = collections.Counter(
        c.difficulty for c in candidates if c.label != LABEL_SECRET
    )
    secrets = labels[LABEL_SECRET]
    # summary goes to stderr: it's for you, not for whatever pipes the output
    print(f"{written} candidates, seed {args.seed}", file=sys.stderr)
    print(f"  secret      {secrets:>5}  ({secrets / written:.1%})", file=sys.stderr)
    false_positives = written - secrets
    print(f"  not_secret  {false_positives:>5}  ({false_positives / written:.1%})", file=sys.stderr)
    for difficulty in ("hard", "medium", "easy"):
        share = difficulties[difficulty] / false_positives
        print(
            f"    {difficulty:<9} {difficulties[difficulty]:>5}  ({share:.1%} of false positives)",
            file=sys.stderr,
        )
    # stdout gets the path and nothing else, so this works:
    # OUT=$(secret-triage corpus --seed 42)
    print(out)
    return 0


# every `secret-triage ...` call lands here first
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secret-triage",
        description="Triage secret-scanner findings with the model of your choice.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    # one subcommand per job. only `corpus` exists so far, more land in later phases
    subcommands = parser.add_subparsers(dest="command", required=True)

    corpus = subcommands.add_parser(
        "corpus",
        help="generate a labelled synthetic corpus, reproducibly, from a seed",
    )
    corpus.add_argument("--seed", type=int, required=True, help="seed the corpus is derived from")
    corpus.add_argument("--count", type=int, default=400, help="how many candidates (default: 400)")
    corpus.add_argument(
        "--out",
        type=Path,
        default=None,
        help=f"output path (default: {CORPUS_DIR}/synthetic-<seed>-<count>.jsonl)",
    )
    # remember which function runs this subcommand
    corpus.set_defaults(handler=_corpus)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except ValueError as error:
        # a bad --count lands here: clean `error: ...` line, not a python traceback
        parser.error(str(error))
