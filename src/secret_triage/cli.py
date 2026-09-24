"""Command-line entry point. Argument parsing and printing, nothing else."""

import argparse
import collections
import sys
from pathlib import Path

from . import __version__, metrics, prefilter, synthetic
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


# runs when you type: secret-triage prefilter-sweep --seeds 20
def _prefilter_sweep(args: argparse.Namespace) -> int:
    if args.seeds < 1:
        raise ValueError(f"--seeds must be at least 1, got {args.seeds}")
    # seeds 0..N-1 pooled into one corpus, so the numbers aren't one seed's luck
    corpus = [
        candidate
        for seed in range(args.seeds)
        for candidate in synthetic.generate(seed=seed, count=args.count)
    ]
    # 0.00 to 5.00 in quarter-bit steps, plus the default. i / 4 keeps every step exact
    default = prefilter.DEFAULT_MIN_ENTROPY
    thresholds = sorted({i / 4 for i in range(21)} | {default})
    points = metrics.sweep(corpus, thresholds)

    first = points[0]
    print(
        f"{len(corpus)} candidates over {args.seeds} seeds: "
        f"{first.secrets} secrets, {first.false_positives} false positives"
    )
    print()
    print("  floor  recall  secrets lost  fp dropped  entropy only")
    for point in points:
        marker = "   <- default" if point.min_entropy == default else ""
        print(
            f"  {point.min_entropy:5.2f}  {point.recall:6.3f}  {point.secrets_dropped:12}"
            f"  {point.fp_drop_rate:10.1%}  {point.entropy_only:12}{marker}"
        )
    print()

    # recall only ever goes down as the floor rises, so the last safe row is the ceiling
    safe = [point.min_entropy for point in points if point.secrets_dropped == 0]
    if safe:
        print(f"highest floor that keeps every secret: {max(safe):.2f}")
    else:
        print("no floor keeps every secret: a kill rule drops real ones")
    lowest = metrics.lowest_secret_entropy(corpus)
    if lowest is not None:
        print(f"lowest entropy among secrets without a vendor prefix: {lowest:.2f} bits/char")
    print()

    print(f"at the default floor ({default:.2f}):")
    print("  rule                  first match  only rule")
    for row in metrics.contributions(corpus, default):
        print(f"  {row.rule:<20}  {row.first_match:11}  {row.only_rule:9}")
    print()
    print("  false positives dropped")
    for row in metrics.drops_by_difficulty(corpus, default):
        share = row.dropped / row.total
        print(f"  {row.difficulty:<8} {row.dropped:5} / {row.total:<5} {share:7.1%}")
    return 0


# every `secret-triage ...` call lands here first
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secret-triage",
        description="Triage secret-scanner findings with the model of your choice.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    # one subcommand per job, more land in later phases
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

    prefilter_sweep = subcommands.add_parser(
        "prefilter-sweep",
        help="measure the prefilter's recall and drop rate across entropy floors",
    )
    prefilter_sweep.add_argument(
        "--seeds", type=int, default=20, help="corpora to pool, seeds 0..N-1 (default: 20)"
    )
    prefilter_sweep.add_argument(
        "--count", type=int, default=400, help="candidates per corpus (default: 400)"
    )
    prefilter_sweep.set_defaults(handler=_prefilter_sweep)

    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except ValueError as error:
        # a bad --count or --seeds lands here: clean `error: ...` line, not a traceback
        parser.error(str(error))
