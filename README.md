# llm-secret-triage

Secret scanners find candidates. They cannot tell a live AWS key from a commit
SHA, a documentation example or a test fixture, so the queue fills up with false
positives, nobody works through it, and the pre-commit hook gets bypassed.

This project puts a language model between the scanner and you. It reads each
finding in context and says whether it is a real credential, with a one-line
reason you can check. The model is your choice: local on your laptop, a hosted
API, or any OpenAI-compatible endpoint.

## Status

Early. One phase out of six is finished. Nothing triages anything yet.

- [x] **P1** — candidate schema, JSONL storage, masking, reproducible synthetic corpus
- [ ] **P2** — deterministic prefilter, recall held at 1.0
- [ ] **P3** — real corpus from public repositories, labelled by hand
- [ ] **P4** — triage against a local model
- [ ] **P5** — multi-model benchmark, cost and latency
- [ ] **P6** — SARIF output, GitHub Action, container image

## Requirements

Python 3.10 or later, and [uv](https://docs.astral.sh/uv/). No other
dependencies: the tool itself is standard library only.

## Install

```bash
git clone <this repo>
cd llm-secret-triage
uv sync
```

## What works today

Generate a labelled benchmark corpus:

```bash
$ uv run secret-triage corpus --seed 42 --count 400
400 candidates, seed 42
  secret        120  (30.0%)
  not_secret    280  (70.0%)
    hard        140  (50.0% of false positives)
    medium       56  (20.0% of false positives)
    easy         84  (30.0% of false positives)
data/corpus/synthetic-42-400.jsonl
```

Same seed, same bytes, on any machine. That is how the benchmark stays
reproducible without shipping a dataset. The file lands under `data/`, which is
gitignored.

Each line is one candidate: where it was found, the value, the few lines around
it, and the true label (abridged here, the real record has 13 fields).

```json
{"id": "a3b99ce2e3a9ea3c", "path": ".env.production", "line": 20,
 "rule": "db-password", "match": "dwQ0FIunWe8Cz6SNDCdyZQ",
 "context": "NODE_ENV=production\nPOSTGRES_PASSWORD=dwQ0FIunWe8Cz6SNDCdyZQ\nLOG_LEVEL=info",
 "match_masked": "dwQ*****************ZQ", "match_sha256": "2d685c95...",
 "label": "secret", "difficulty": null}
```

## The corpus

30% real credentials. The false positives are graded, because a corpus made of
`CHANGEME` and `${VAR}` gives any model a 99% score that means nothing.

| Grade | Share of false positives | Examples |
|---|---|---|
| hard | 50% | commit SHA, artifact checksum, resource UUID, base64-encoded plaintext |
| medium | 20% | vendor documentation key, published test key, rotated key |
| easy | 30% | `CHANGEME`, `${API_KEY}`, `REDACTED` |

The hard ones are the point. A commit SHA and an AWS secret key are the same
object seen from the value alone: same length, same randomness, no threshold
separates them. Only the variable name above them settles it — and that is
exactly what the model layer is measured on.

Every value carries a plausible variable name for that reason: `GIT_COMMIT=`
against `AWS_SECRET_ACCESS_KEY=` is the signal under test.

## Tests

```bash
uv run pytest        # 20 tests
uv run ruff check .
```

## Security rules

This project handles live credentials once it runs against real repositories.
The rules are enforced by the layout, not by good intentions.

- **No dataset in git.** `data/` is gitignored in full. The synthetic corpus is
  reproduced from its seed, never committed.
- **Raw values stay local.** Anything exported carries a masked value and a
  SHA-256 digest, and the raw string is stripped out of the surrounding context
  too.
- **Credentials are never verified.** The tool does not authenticate a
  discovered key against its provider.

## Where this is going

One triage layer, any model. Local and hosted providers differ by base URL and
auth, nothing else, so switching is a flag rather than a code change. The
published numbers will come from a local model on a consumer laptop, with no
network egress — an air-gapped setup is meant to be the default path, not a
footnote.

## License

MIT.
