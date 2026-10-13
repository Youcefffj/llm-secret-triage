# llm-secret-triage

Secret scanners flag anything shaped like a credential. A live AWS key comes out
next to commit SHAs, documentation examples and test fixtures, and from the value
alone they look the same.

This repository contains:

- `scan` and `review`: find the passwords and keys lying in a folder — a mounted
  file share, a synced library — inside its Word, Excel, PDF and zip files too,
  then go through them one by one and get the list of what needs fixing;
- a generator for a labelled synthetic corpus of such findings, reproducible
  from a seed;
- a deterministic prefilter that drops the findings which cannot be a
  credential, reading the value alone, and a command that measures what it drops;
- `triage`: a model reads each remaining finding in its context and says whether
  it is a real secret, with its precision and recall measured against the
  scanner alone.

## Requirements

Python 3.10 or later, [uv](https://docs.astral.sh/uv/), and, for `scan`,
[gitleaks](https://github.com/gitleaks/gitleaks/releases) on the `PATH` (tested
with 8.30.1). One Python dependency, [pypdf](https://pypi.org/project/pypdf/),
for PDFs; everything else is the standard library.

For `triage`, a model: a local server speaking the OpenAI chat API
([LM Studio](https://lmstudio.ai), Ollama, llama.cpp), or the `claude` or `codex`
CLI of a subscription. No API key is needed.

## Install

```bash
git clone https://github.com/Youcefffj/llm-secret-triage.git
cd llm-secret-triage
uv sync
```

## Scan a folder

```bash
$ uv run secret-triage scan share
scanning share...
5 files read, 2 not read
5 findings
  to review      4
  dropped        1  (placeholder_token)
not read
      1  binary
      1  encrypted
  list: data/scans/share-20261013-232532-unread.txt
data/scans/share-20261013-232532.jsonl
```

Every file is opened once: its text is extracted, scanned, and let go. Nothing
of it is kept but its findings.

| Files | Read |
|---|---|
| any text: `.txt` `.ps1` `.sh` `.ini` `.env` `.config` `.json` `.xml` `.html`… | as is, UTF-8, UTF-16 or Windows' cp1252 |
| Word, Excel, PowerPoint (`.docx` `.xlsx` `.pptx`, macro and template variants) | body, headers, footers, comments, notes, and text deleted with track changes on |
| Word, Excel, PowerPoint 97-2003 (`.doc` `.xls` `.ppt`) | text, every cell, every slide, without Office installed |
| Outlook messages (`.msg`) | subject, body, recipients |
| OpenDocument (`.odt` `.ods` `.odp`) | body |
| PDF | its text layer |
| CSV, TSV | as a table |
| `.zip` | like a folder, zips inside it included |

A table (Word, Excel, OpenDocument, CSV) comes out row by row, then each row
again cell by cell under its column name: a password in a column headed
*Mot de passe* reads `Mot de passe: …`, like one written by hand.

gitleaks runs over that text with its own rules plus two: a password next to its
label (`password=`, `pwd:`, `mot de passe :`, `MDP wifi:`, `Password | …` in a
table) and a password inside a URL (`postgres://user:…@host`). Its defaults look
for high-entropy keys and miss both. The prefilter then sets aside what cannot
be a secret, `changeme` here. Each finding keeps the 100 characters before and
after the value; in a document, its line number is the one in the extracted
text.

What could not be read is listed with the reason in `…-unread.txt`, next to the
scan, so it can be opened by hand: Office files saved with a password,
encrypted PDFs and zip entries, PDFs without a text layer
(scans), files over 50 MB, damaged files, files the account may not open, and
binaries.

The scan file lands in `data/scans/` under the current directory and holds the
raw values: keep it there. The text goes to gitleaks through a private
temporary folder, deleted after each batch.

```bash
$ uv run secret-triage review data/scans/share-20261013-232532.jsonl
...
[2/4] share/compta/comptes.xlsx:5  (password-assignment)
       Mot de passe
  >>  intranet | admin | Soleil2024!
      Application: intranet
      Identifiant: admin
  >>  Mot de passe: Soleil2024!
real secret? [y]es [n]o [?] not sure [q]uit: y
...
3 real, 1 not real, 0 still to review
to fix:
  share/archives.zip/migration/notes.txt:1  (url-credentials)
  share/compta/comptes.xlsx:5  (password-assignment)
  share/it/procedure-2009.doc:3  (password-assignment)
```

Every answer is written to the scan file at once: `q` or Ctrl-C stops, and the
next `review` picks up where it left off. `--audit-dropped N` mixes in, unmarked,
N findings the prefilter set aside; the summary then says how many of them were
real secrets.

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

## Triage

```bash
$ uv run secret-triage triage data/corpus/synthetic-42-400.jsonl
400 candidates, 292 sent to google/gemma-4-12b-qat (local, prompt v1, raw values, they stay on this machine)
292 answered (0 unusable), 0 calls failed
  131704 tokens in, 14130 out, 27m36s, 8.5 tok/s
  latency p50 5.3s, p95 6.3s, on the last 146 answers
                          precision  recall     f1
  scanner alone               0.300   1.000  0.462
  + prefilter + model         0.682   1.000  0.811
data/runs/synthetic-42-400-local-google-gemma-4-12b-qat-v1-20261014-000136.jsonl
```

What the prefilter drops stays out, 108 candidates here. Every other one goes to
the model with its file, its rule and the 100 characters around it, under a
versioned prompt: `v1`, pinned by a test, so a better wording becomes `v2` and
never changes what an earlier run meant. The answer must be
`{"verdict", "confidence", "reason"}`, and the local provider constrains the
model to that JSON schema. An answer that doesn't parse is kept as it came and
counted as unusable, never turned into a verdict. A failed call is tried three
times, and five failures in a row stop the run. A finding left without a verdict
counts as flagged: it goes to a human.

| Provider | What answers | Sees |
|---|---|---|
| `local` (default) | any server speaking the OpenAI chat API, at `--base-url` (default: LM Studio, `http://localhost:1234/v1`) | raw values |
| `claude-code` | the `claude` CLI on its own login, tools off, run from an empty folder | masked values |
| `codex` | the `codex` CLI on its own login | masked values |

Running a batch on a subscription is up to you and that subscription's terms.
`--limit 50` takes the first 50 candidates and estimates how long the whole file
would take: a smoke run before a long one. `--include-dropped` sends the
prefilter's drops to the model as well. `--concurrency N` keeps N calls in
flight.

The run file in `data/runs/` holds the settings on its first line (provider,
model, prompt version, source file and its SHA-256), then one line per answer as
it arrives: verdict, confidence, reason, tokens, latency, and cost when the
provider gives one. A run cut short keeps what it got.

What this says, for Gemma 4 12B QAT (Q4_0, in LM Studio, on a MacBook Air M5
with 24 GB):

- **No real secret lost.** All 120 kept, while precision goes from 0.30 to 0.68:
  56 of the 280 false positives are still flagged.
- **Hard cases read from their name.** No commit SHA, checksum or UUID is
  flagged, one cache ETag and one SSH public key are. What gets through: test
  fixture signatures (13 of 18), base64-encoded plaintext (13 of 19), request
  nonces (6 of 14). Random-looking, under a name that doesn't settle it.
- **Medium cases are the weak spot.** A key marked as rotated in a changelog is
  flagged every time (12 of 12), a vendor test key 10 times out of 12. They have
  the exact shape of a live key, and nothing in 100 characters says they are
  dead. Published sample tokens: 0 of 8.
- **The confidence says nothing.** 1.0 on 213 answers, 0.9 on the other 79: no
  threshold can be swept on it.
- **No thinking.** Gemma 4 reasons before answering by default, about 300 tokens
  and 30 s a call here. The local provider sends `reasoning_effort: "none"`: 5 s
  a call.
- **Same caveat as the prefilter.** The corpus and the prompt come from the same
  hands. Numbers on real findings will come from reviewed scans.

## Tests

```bash
uv run pytest
uv run ruff check .
```

## Security

- **No dataset in git.** `data/` is gitignored in full: corpora are regenerated
  from their seed, never committed.
- **No credential is ever tried.** Nothing the tool finds is tested against the
  service it belongs to.
- **Raw values stay on the machine.** `scan` and `review` make no network call.
  `triage` sends raw values to a local model server only; the `claude` and
  `codex` CLIs, which send what they get to a hosted model, are given masked
  values and masked context.

## License

MIT, see [LICENSE](LICENSE).
