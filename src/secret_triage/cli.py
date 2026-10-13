"""Command-line entry point. Argument parsing and printing, nothing else."""

import argparse
import collections
import hashlib
import re
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from . import __version__, labeler, metrics, pipeline, prefilter, prompts, synthetic, triage
from .config import CORPUS_DIR, DEFAULT_MODELS, LOCAL_BASE_URL, RUNS_DIR, SCANS_DIR
from .models import (
    LABEL_NOT_SECRET,
    LABEL_SECRET,
    Candidate,
    Run,
    Verdict,
    append_verdict,
    read_jsonl,
    read_run,
    write_jsonl,
    write_run,
)
from .scanners import gitleaks
from .sources import folder


# runs when you type: secret-triage scan /Volumes/share
def _scan(args: argparse.Namespace) -> int:
    print(f"scanning {args.folder}...", file=sys.stderr)
    try:
        scan = pipeline.run(folder.walk(args.folder), progress=_progress)
    except gitleaks.GitleaksError as error:
        print(f"\nerror: {error}", file=sys.stderr)
        return 1
    # timestamped, so a second scan never overwrites the labels of the first
    out = SCANS_DIR / f"{args.folder.resolve().name}-{datetime.now():%Y%m%d-%H%M%S}.jsonl"
    write_jsonl(out, scan.candidates)

    print(f"\r{scan.read} files read, {len(scan.unread)} not read", file=sys.stderr)
    decisions = [prefilter.decide(candidate.match) for candidate in scan.candidates]
    dropped = collections.Counter(d.reason for d in decisions if not d.kept)
    print(f"{len(scan.candidates)} findings", file=sys.stderr)
    print(f"  to review  {sum(d.kept for d in decisions):>5}", file=sys.stderr)
    for reason, count in dropped.most_common():
        print(f"  dropped    {count:>5}  ({reason})", file=sys.stderr)
    if scan.unread:
        # a password in one of these went unseen: the list says which ones to open by hand
        unread_list = out.with_name(f"{out.stem}-unread.txt")
        unread_list.write_text(
            "".join(
                f"{u.reason}\t{u.path}" + (f"\t{u.detail}" if u.detail else "") + "\n"
                for u in sorted(scan.unread, key=lambda u: (u.reason, u.path))
            ),
            encoding="utf-8",
        )
        print("not read", file=sys.stderr)
        reasons = collections.Counter(u.reason for u in scan.unread)
        for reason, count in reasons.most_common():
            print(f"  {count:>5}  {reason}", file=sys.stderr)
        print(f"  list: {unread_list}", file=sys.stderr)
    # stdout gets the path alone, so this works: secret-triage review $(secret-triage scan X)
    print(out)
    return 0


def _progress(done: int) -> None:
    if done % 100 == 0:
        print(f"\r{done} files...", end="", file=sys.stderr, flush=True)


# runs when you type: secret-triage review data/scans/share-20261013-142501.jsonl
def _review(args: argparse.Namespace) -> int:
    if not args.scan.is_file():
        raise ValueError(f"no such scan file: {args.scan}")
    if args.audit_dropped < 0:
        raise ValueError(f"--audit-dropped must be 0 or more, got {args.audit_dropped}")
    try:
        labeler.review(args.scan, audit_dropped=args.audit_dropped)
    except KeyboardInterrupt:  # every answer is already saved, ctrl-c just stops
        print()

    candidates = list(read_jsonl(args.scan))
    labels = collections.Counter(candidate.label for candidate in candidates)
    left = len(labeler.queue(candidates, args.audit_dropped))
    print(
        f"\n{labels[LABEL_SECRET]} real, {labels[LABEL_NOT_SECRET]} not real, "
        f"{left} still to review"
    )
    to_fix = [candidate for candidate in candidates if candidate.label == LABEL_SECRET]
    if to_fix:
        print("to fix:")
        for candidate in to_fix:
            print(f"  {candidate.path}:{candidate.line}  ({candidate.rule})")
    # labelled candidates the prefilter drops: only an audit puts them in front of you
    audited = [c for c in candidates if c.label and not prefilter.decide(c.match).kept]
    if audited:
        missed = sum(candidate.label == LABEL_SECRET for candidate in audited)
        print(f"prefilter: {missed} real secret(s) among the {len(audited)} drops reviewed")
    return 0


# runs when you type: secret-triage triage data/scans/share-20261013-142501.jsonl
def _triage(args: argparse.Namespace) -> int:
    if not args.file.is_file():
        raise ValueError(f"no such file: {args.file}")
    if args.limit is not None and args.limit < 1:
        raise ValueError(f"--limit must be at least 1, got {args.limit}")
    if args.concurrency < 1:
        raise ValueError(f"--concurrency must be at least 1, got {args.concurrency}")
    everything = list(read_jsonl(args.file))
    candidates = everything[: args.limit]
    # the prefilter decides here: triage itself never knows it exists
    to_send = [c for c in candidates if args.include_dropped or prefilter.decide(c.match).kept]
    provider = _provider(args)
    prompt = prompts.CURRENT

    started = datetime.now()
    model = re.sub(r"[^\w.-]+", "-", provider.model)
    name = f"{args.file.stem}-{provider.name}-{model}-{prompt.version}-{started:%Y%m%d-%H%M%S}"
    out = RUNS_DIR / f"{name}.jsonl"
    write_run(
        out,
        Run(
            started_at=started.isoformat(timespec="seconds"),
            provider=provider.name,
            model=provider.model,
            prompt_version=prompt.version,
            source=str(args.file),
            source_sha256=hashlib.sha256(args.file.read_bytes()).hexdigest(),
            masked=provider.masked,
            include_dropped=args.include_dropped,
            limit=args.limit,
            concurrency=args.concurrency,
        ),
    )
    shown = "masked values" if provider.masked else "raw values, they stay on this machine"
    print(
        f"{len(candidates)} candidates, {len(to_send)} sent to {provider.model} "
        f"({provider.name}, prompt {prompt.version}, {shown})",
        file=sys.stderr,
    )

    done = 0

    def save(verdict: Verdict) -> None:
        nonlocal done
        append_verdict(out, verdict)
        done += 1
        print(f"\r{done}/{len(to_send)}", end="", file=sys.stderr, flush=True)

    status = 0
    try:
        triage.run(to_send, provider, prompt, concurrency=args.concurrency, on_verdict=save)
    except triage.RunAborted as error:
        print(f"\nstopped: {error}", file=sys.stderr)
        status = 1
    except KeyboardInterrupt:
        print("\nstopped, the answers so far are saved", file=sys.stderr)
    _print_run(everything, candidates, to_send, read_run(out)[1], args.include_dropped)
    print(out)
    return status


def _provider(args: argparse.Namespace) -> triage.Provider:
    model = args.model or DEFAULT_MODELS[args.provider]
    if args.provider == "local":
        return triage.local(model, args.base_url)
    if args.provider == "claude-code":
        return triage.claude_code(model)
    return triage.codex(model)


def _print_run(
    everything: Sequence[Candidate],
    candidates: Sequence[Candidate],
    to_send: Sequence[Candidate],
    verdicts: Sequence[Verdict],
    include_dropped: bool,
) -> None:
    timing = metrics.timing(verdicts)
    unusable = sum(verdict.replied and verdict.verdict is None for verdict in verdicts)
    print(
        f"\r{timing.replied} answered ({unusable} unusable), "
        f"{timing.calls - timing.replied} calls failed",
        file=sys.stderr,
    )
    print(
        f"  {timing.tokens_in} tokens in, {timing.tokens_out} out, "
        f"{_duration(timing.wall_seconds)}, {timing.tokens_per_second:.1f} tok/s",
        file=sys.stderr,
    )
    print(
        f"  latency p50 {timing.latency_p50:.1f}s, p95 {timing.latency_p95:.1f}s, "
        f"on the last {timing.tail} answers",
        file=sys.stderr,
    )
    if timing.cost_usd is not None:
        print(f"  ${timing.cost_usd:.4f} at API prices", file=sys.stderr)
    if len(candidates) < len(everything) and verdicts:
        # a smoke run: what the whole file would take at the same pace
        whole = sum(include_dropped or prefilter.decide(c.match).kept for c in everything)
        estimate = timing.wall_seconds * whole / len(verdicts)
        print(f"  the whole file: {whole} to send, about {_duration(estimate)}", file=sys.stderr)
    if any(candidate.label is not None for candidate in candidates):
        sent = {candidate.id for candidate in to_send}
        rows = [
            ("scanner alone", metrics.scanner_alone(candidates)),
            ("+ prefilter + model", metrics.with_triage(candidates, sent, verdicts)),
        ]
        print("                          precision  recall     f1", file=sys.stderr)
        for label, scores in rows:
            print(
                f"  {label:<22} {scores.precision:10.3f} {scores.recall:7.3f} {scores.f1:6.3f}",
                file=sys.stderr,
            )


def _duration(seconds: float) -> str:
    minutes, seconds = divmod(round(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    return f"{minutes}m{seconds:02d}s" if minutes else f"{seconds}s"


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

    scan = subcommands.add_parser(
        "scan",
        help="read every file of a folder (a mounted share, a synced library, .zip included) "
        "and save the passwords and keys found",
    )
    scan.add_argument("folder", type=Path, help="folder to scan")
    scan.set_defaults(handler=_scan)

    review = subcommands.add_parser(
        "review",
        help="go through a scan's findings one by one and say which are real secrets",
    )
    review.add_argument("scan", type=Path, help="scan file written by `secret-triage scan`")
    review.add_argument(
        "--audit-dropped",
        type=int,
        default=0,
        help="mix in this many findings the prefilter dropped, to check it drops no real "
        "secret (default: 0)",
    )
    review.set_defaults(handler=_review)

    triage_command = subcommands.add_parser(
        "triage",
        help="ask a model, finding by finding, whether it is a real secret",
    )
    triage_command.add_argument("file", type=Path, help="a scan file, or a labelled corpus")
    triage_command.add_argument(
        "--provider",
        choices=list(DEFAULT_MODELS),
        default="local",
        help="local: a model server on this machine, it sees the raw values. claude-code, "
        "codex: that subscription's CLI, it sees masked values only (default: local)",
    )
    triage_command.add_argument(
        "--model",
        help="the model, named as the provider names it (default: "
        + ", ".join(f"{name} {model or 'its own'}" for name, model in DEFAULT_MODELS.items())
        + ")",
    )
    triage_command.add_argument(
        "--base-url",
        default=LOCAL_BASE_URL,
        help=f"OpenAI-compatible endpoint of --provider local (default: {LOCAL_BASE_URL})",
    )
    triage_command.add_argument(
        "--limit", type=int, help="only the first N candidates: a smoke run before the real one"
    )
    triage_command.add_argument(
        "--include-dropped", action="store_true", help="send the prefilter's drops to the model too"
    )
    triage_command.add_argument(
        "--concurrency", type=int, default=1, help="calls in flight at once (default: 1)"
    )
    triage_command.set_defaults(handler=_triage)

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
