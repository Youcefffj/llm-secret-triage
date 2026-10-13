# llm-secret-triage

Secret scanners flag anything shaped like a credential. A live AWS key comes out
next to commit SHAs, documentation examples and test fixtures, and from the value
alone they look the same.

This repository contains:

- a generator for a labelled synthetic corpus of such findings, reproducible
  from a seed;
- a deterministic prefilter that drops the findings which cannot be a
  credential, reading the value alone, and a command that measures what it drops.

## Requirements

Python 3.10 or later, and [uv](https://docs.astral.sh/uv/). No other
dependencies: the tool itself is standard library only.

## Install

```bash
git clone https://github.com/Youcefffj/llm-secret-triage.git
cd llm-secret-triage
uv sync
```

## Synthetic corpus

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

Same seed, same bytes: a test pins the SHA-256 of the seed-42 corpus, so the
corpus is regenerated rather than shipped. The file lands under `data/`, which is
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

30% real credentials: the shape of the real thing, random contents, so none of
them has ever worked anywhere. The false positives are graded, because a corpus
made only of `CHANGEME` and `${VAR}` would be trivial to sort.

| Grade | Share of false positives | Examples |
|---|---|---|
| hard | 50% | commit SHA, artifact checksum, resource UUID, base64-encoded plaintext |
| medium | 20% | vendor documentation key, published test key, rotated key |
| easy | 30% | `CHANGEME`, `${API_KEY}`, `REDACTED` |

The hard ones are the point. A commit SHA and an AWS secret key are the same
object seen from the value alone: same length, same randomness, no threshold
separates them. Only the variable name next to them settles it, so every value
is placed under a plausible one: `GIT_COMMIT=` against `AWS_SECRET_ACCESS_KEY=`.

## Prefilter

Drops the candidates which cannot be a credential. It reads **only the value**,
never the variable name, the file path or the surrounding lines; a test checks
that the module imports nothing else from the package. A dropped candidate is
gone for good, so recall has to stay at 1.0: not one real secret dropped.

Three explicit rules — unresolved template expression, placeholder word, 3
distinct characters or fewer — plus an entropy floor that vendor token prefixes
(`AKIA`, `ghp_`, `sk_live_`...) skip.

In doubt, a value is kept. A template expression drops a value only when it is
the whole value, and a placeholder word never drops a value made of several
fields (`user:pass`, a URL, a connection string): in
`postgres://admin:…@${DB_HOST}`, the password next to the template may be real.
There is no length rule either: `root12` is short, and still a password.

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
  too_few_distinct              423        347
  low_entropy                     0          0

  false positives dropped
  easy      1680 / 1680   100.0%
  medium     378 / 1120    33.8%
  hard         0 / 2800     0.0%
```

*(excerpt — the command prints every floor from 0 to 5)*

What this says:

- **Recall 1.0 over 2400 secrets**, while over a third of the false positives go:
  every easy one, a third of the medium ones, none of the hard ones. The hard
  ones are left alone on purpose: only their context settles them.
- **Template expressions and placeholder words do most of the work.** The
  distinct-character rule takes the 423 false positives they miss (`null`,
  `TODO`, `N/A`, `xxxx…`); 76 of them, the `xxxx…` kind, sit under the entropy
  floor too, hence 347 in the *only rule* column.
- **The entropy floor adds nothing at its default.** Everything it catches, the
  distinct-character rule already catches. Raising it looks free up to 3.5, but
  it is not: the 140 extra drops at 2.0 are a single zero-padded test
  key from the generator, and above 3 the floor starts eating cache ETags,
  commit SHAs and UUIDs, the hard cases that only context should settle.
- **Why the default stays at 1.5.** Entropy per character can't exceed
  log2(length): an 8-character password scores at most 3.0 however random it is.
  A floor at 3 would silently drop real short passwords — and none exist in this
  corpus, where every secret is 20 characters or more, so the sweep cannot show
  that risk. The floor sits just under `aaaaabcd`, the least random value of 8
  characters or fewer the distinct rule lets through, so it never decides a
  short value on its own.
- **Both numbers flatter the rules.** Synthetic secrets are long random strings
  no rule can match, so recall 1.0 here guards against regressions more than it
  proves anything. And the placeholder vocabulary and the easy false positives
  come from the same hands. Nothing here measures either number on real
  findings.

## Tests

```bash
uv run pytest
uv run ruff check .
```

## Security

- **No dataset in git.** `data/` is gitignored in full: corpora are regenerated
  from their seed, never committed.
- **No network.** The tool makes no network call, so nothing it handles is ever
  tested against a provider.

## License

MIT, see [LICENSE](LICENSE).
