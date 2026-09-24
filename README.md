# llm-secret-triage

Secret scanners find candidates. They cannot tell a live AWS key from a commit
SHA, a documentation example or a test fixture, so the queue fills up with false
positives, nobody works through it, and the pre-commit hook gets bypassed.

This project puts a language model between the scanner and you. It reads each
finding in context and says whether it is a real credential, with a one-line
reason you can check. The model is your choice: local on your laptop, a hosted
API, or any OpenAI-compatible endpoint.

## Status

Early. Two phases out of six are finished. Nothing triages anything yet.

- [x] **P1** — candidate schema, JSONL storage, masking, reproducible synthetic corpus
- [x] **P2** — deterministic prefilter, recall held at 1.0
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

## The prefilter

A first, free pass that drops candidates which cannot be a credential. It reads
**only the value** — never the variable name, the file path or the surrounding
lines, since that context is what the model layer is measured on. A candidate it
drops never reaches the model, so its recall has to stay at 1.0.

Four explicit rules — unresolved template expression, placeholder word, fewer
than 8 characters, 3 distinct characters or fewer — plus an entropy floor that
vendor token prefixes (`AKIA`, `ghp_`, `sk_live_`...) skip.

```bash
$ uv run secret-triage prefilter-sweep
8000 candidates over 20 seeds: 2400 secrets, 5600 false positives

  floor  recall  secrets lost  fp dropped  entropy only
   1.50   1.000             0       36.8%             0   <- default
   2.00   1.000             0       39.2%           140
   3.50   1.000             0       41.3%           255
   3.75   0.989            27       53.2%           924

at the default floor (1.50):
  rule                  first match  only rule
  template_expression           556        556
  placeholder_token            1079       1079
  too_short                     347          0
  too_few_distinct               76          0
  low_entropy                     0          0

  false positives dropped
  easy      1680 / 1680   100.0%
  medium     378 / 1120    33.8%
  hard         0 / 2800     0.0%
```

*(excerpt — the command prints every floor from 0 to 5)*

What this says:

- **Recall 1.0 over 2400 secrets**, while over a third of the false positives go:
  every easy one, a third of the medium ones, none of the hard ones — which is
  the intended split. The hard cases are for the model.
- **Template expressions and placeholder words do most of the work.** The
  length and distinct-character rules overlap: neither is needed alone, but
  together they remove 423 false positives the other two miss (`null`, `TODO`,
  `N/A`, `xxxx…`). The *only rule* column shows the first part, not the second.
- **The entropy floor adds nothing at its default.** Everything it catches, the
  distinct-character rule already catches. Raising it looks free up to 3.5, but
  it is not: the 140 extra drops at 2.0 are a single zero-padded test
  key from the generator, and above 3 the floor starts eating cache ETags,
  commit SHAs and UUIDs, the hard cases that only context should settle.
- **Why the default stays at 1.5.** Entropy per character can't exceed
  log2(length): an 8-character password scores at most 3.0 however random it is.
  A floor at 3 would silently drop real short passwords — and none exist in this
  corpus, where every secret is 20 characters or more, so the sweep cannot show
  that risk. The floor sits just under the least random 8-character value the
  length and distinct rules let through.
- **Both numbers flatter the rules.** Synthetic secrets are long random strings
  no rule can match, so recall 1.0 here guards against regressions more than it
  proves anything. And the placeholder vocabulary and the easy false positives
  come from the same hands. The real recall and drop rate come from
  hand-labelled findings in P3.

## Tests

```bash
uv run pytest
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
