"""Generate a labelled synthetic corpus, reproducibly, from a seed.

Determinism is the point of this module: the same seed and count must produce the
same bytes on any machine. Every draw therefore goes through one `random.Random`
in a fixed order, the tables below are literals, and nothing here touches
`uuid4`, the clock, or the built-in `hash` (which varies with PYTHONHASHSEED).

The composition follows the brief: 30% real secrets, and of the false positives
50% hard, 20% medium, 30% easy. Hard means a value carrying the same entropy as a
credential -- a commit SHA, a checksum, a resource UUID, base64-encoded plaintext
-- where only the surrounding context settles it. Every value is placed under a
plausible variable name, because `GIT_COMMIT=` against `AWS_SECRET_ACCESS_KEY=`
is the signal the model layer is measured on.
"""

import base64
import hashlib
import random
import string
from collections.abc import Callable
from dataclasses import dataclass

from .models import (
    DIFFICULTY_EASY,
    DIFFICULTY_HARD,
    DIFFICULTY_MEDIUM,
    LABEL_NOT_SECRET,
    LABEL_SECRET,
    Candidate,
)

# the mix we want: 30% real secrets, and of the fakes 50% hard / 20% medium / 30% easy
SECRET_SHARE = 0.30
HARD_SHARE = 0.50
MEDIUM_SHARE = 0.20

_MIN_COUNT = 10                             # below this the percentages stop meaning anything

# alphabets the fake values are drawn from. a real aws key is base64-ish,
# a commit sha is hex only, a url-safe token swaps +/ for -_ ...
_B64 = string.ascii_letters + string.digits + "+/"
_ALNUM = string.ascii_letters + string.digits
_UPPER_ALNUM = string.ascii_uppercase + string.digits
_URLSAFE = string.ascii_letters + string.digits + "-_"
_HEX = "0123456789abcdef"
_PASSWORD = string.ascii_letters + string.digits + "!@#$%&*?"


# pick `length` random chars out of `alphabet`
def _chars(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


# random bytes, base64'd. that's what a real encryption key looks like
def _b64_bytes(rng: random.Random, length: int) -> str:
    return base64.b64encode(bytes(rng.randrange(256) for _ in range(length))).decode("ascii")


@dataclass(frozen=True)
class _Spec:
    """One kind of value: its scanner rule, the names it appears under, how to build it."""

    rule: str                               # the scanner rule name this value would trip
    names: tuple[str, ...]                  # var names it can appear under, one is picked at random
    make: Callable[[random.Random], str]    # the function that builds one value


# --- real credentials -------------------------------------------------------

# the 30%: values that really are credentials. shapes copied from the real thing,
# contents random, so nothing here has ever worked anywhere
_SECRETS: tuple[_Spec, ...] = (
    _Spec(
        "aws-access-key-id",
        ("AWS_ACCESS_KEY_ID", "accessKeyId", "AWS_KEY"),
        lambda rng: "AKIA" + _chars(rng, _UPPER_ALNUM, 16),
    ),
    _Spec(
        "aws-secret-access-key",
        ("AWS_SECRET_ACCESS_KEY", "secretAccessKey", "AWS_SECRET"),
        lambda rng: _chars(rng, _B64, 40),
    ),
    _Spec(
        "db-password",
        ("DB_PASSWORD", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD"),
        lambda rng: _chars(rng, _PASSWORD, 22),
    ),
    _Spec(
        "encryption-key",
        ("ENCRYPTION_KEY", "APP_SECRET", "DATA_KEY"),
        lambda rng: _b64_bytes(rng, 32),
    ),
    _Spec(
        "github-pat",
        ("GITHUB_TOKEN", "GH_PAT", "GITHUB_ACCESS_TOKEN"),
        lambda rng: "ghp_" + _chars(rng, _ALNUM, 36),
    ),
    _Spec(
        "gitlab-pat",
        ("GITLAB_TOKEN", "CI_JOB_TOKEN", "GITLAB_PAT"),
        lambda rng: "glpat-" + _chars(rng, _URLSAFE, 20),
    ),
    _Spec(
        "google-api-key",
        ("GOOGLE_API_KEY", "MAPS_KEY", "GCP_API_KEY"),
        lambda rng: "AIza" + _chars(rng, _URLSAFE, 35),
    ),
    _Spec(
        "jwt-signing-key",
        ("JWT_SIGNING_KEY", "SESSION_SECRET", "TOKEN_SIGNING_KEY"),
        lambda rng: _chars(rng, _HEX, 64),
    ),
    _Spec(
        "npm-token",
        ("NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_AUTH_TOKEN"),
        lambda rng: "npm_" + _chars(rng, _ALNUM, 36),
    ),
    _Spec(
        "sendgrid-key",
        ("SENDGRID_API_KEY", "MAIL_API_KEY"),
        lambda rng: f"SG.{_chars(rng, _URLSAFE, 22)}.{_chars(rng, _URLSAFE, 43)}",
    ),
    _Spec(
        "slack-bot-token",
        ("SLACK_BOT_TOKEN", "SLACK_TOKEN"),
        lambda rng: f"xoxb-{_chars(rng, string.digits, 12)}-{_chars(rng, _ALNUM, 24)}",
    ),
    _Spec(
        "stripe-live-key",
        ("STRIPE_SECRET_KEY", "STRIPE_API_KEY", "PAYMENTS_KEY"),
        lambda rng: "sk_live_" + _chars(rng, _ALNUM, 24),
    ),
)

# --- hard false positives ---------------------------------------------------
# Same entropy as a credential. Only the variable name and the file settle them.

# plain english, base64'd. looks like a key, is a sentence
_PLAINTEXTS: tuple[str, ...] = (
    "the quick brown fox jumps over the lazy dog",
    "application/json; charset=utf-8; profile=v2",
    "Deployment succeeded, no action required.",
    "username=service-account&scope=read-only",
    "Welcome to the platform. Start with the quickstart guide.",
    "report generated nightly at 02:00 UTC by the scheduler",
)

_HARD: tuple[_Spec, ...] = (
    _Spec(
        "git-commit-sha",
        ("GIT_COMMIT", "SOURCE_COMMIT", "VCS_REF", "COMMIT_SHA"),
        lambda rng: _chars(rng, _HEX, 40),
    ),
    _Spec(
        "artifact-checksum",
        ("SHA256_CHECKSUM", "ARTIFACT_DIGEST", "BUNDLE_INTEGRITY"),
        lambda rng: _chars(rng, _HEX, 64),
    ),
    _Spec(
        "cache-etag",
        ("ETAG", "CACHE_KEY", "BUILD_FINGERPRINT"),
        lambda rng: _chars(rng, _HEX, 32),
    ),
    _Spec(
        "resource-uuid",
        ("TENANT_ID", "CORRELATION_ID", "DEVICE_ID", "RESOURCE_ID"),
        lambda rng: "-".join(
            _chars(rng, _HEX, size) for size in (8, 4, 4, 4, 12)
        ),
    ),
    _Spec(
        "request-nonce",
        ("NONCE", "REQUEST_ID", "IDEMPOTENCY_KEY"),
        lambda rng: _chars(rng, _ALNUM, 32),
    ),
    _Spec(
        "encoded-plaintext",
        ("BANNER_MESSAGE", "DEFAULT_PAYLOAD", "ENCODED_TEMPLATE"),
        lambda rng: base64.b64encode(rng.choice(_PLAINTEXTS).encode("utf-8")).decode("ascii"),
    ),
    _Spec(
        "ssh-public-key",
        ("SSH_PUBLIC_KEY", "DEPLOY_PUBKEY", "AUTHORIZED_KEY"),
        lambda rng: "AAAAB3NzaC1yc2EAAAADAQABAAABgQ" + _chars(rng, _B64, 30),
    ),
    _Spec(
        "test-fixture-signature",
        ("FIXTURE_TOKEN", "SAMPLE_SIGNATURE", "EXPECTED_SIGNATURE"),
        lambda rng: _chars(rng, _B64, 32),
    ),
)

# --- medium false positives -------------------------------------------------
# Credential-shaped, but published by the vendor or retired by its owner.

# tokens vendors publish in their own docs. all zeros, dead on arrival.
# keep them synthetic: a real vendor sample string trips github push protection,
# which blocks the push for everyone who forks this repo
_SAMPLE_TOKENS: tuple[str, ...] = (
    "ghp_000000000000000000000000000000000000",
    "sk_test_00000000000000000000000000",
    "AIzaSyDUMMYKEYDUMMYKEYDUMMYKEYDUMMYKEY0",
)

_VENDOR_DOC_EXAMPLES: tuple[str, ...] = (
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "EXAMPLEKEYEXAMPLEKEYEXAMPLEKEYEXAMPLEKEY",
)

_VENDOR_TEST_KEYS: tuple[str, ...] = (
    "pk_test_TYooMQauvdEDq54NiTphI7jx",
    "pk_test_51H0000000000000000000000",
)

_MEDIUM: tuple[_Spec, ...] = (
    _Spec(
        "sample-token",
        ("SLACK_BOT_TOKEN", "GITHUB_TOKEN", "EXAMPLE_TOKEN"),
        lambda rng: rng.choice(_SAMPLE_TOKENS),
    ),
    _Spec(
        "vendor-doc-example",
        ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DOC_EXAMPLE_KEY"),
        lambda rng: rng.choice(_VENDOR_DOC_EXAMPLES),
    ),
    _Spec(
        "vendor-test-key",
        ("STRIPE_API_KEY", "STRIPE_SECRET_KEY", "TEST_PUBLISHABLE_KEY"),
        lambda rng: rng.choice(_VENDOR_TEST_KEYS),
    ),
    _Spec(
        "rotated-key-in-changelog",
        ("ROTATED_KEY", "OLD_API_KEY", "DEPRECATED_TOKEN"),
        lambda rng: "sk_live_" + _chars(rng, _ALNUM, 24),
    ),
)

# --- easy false positives ---------------------------------------------------

# the easy ones: nobody needs context to call these fake
_PLACEHOLDERS: tuple[str, ...] = (
    "CHANGEME",
    "not-a-real-key",
    "your-api-key-here",
    "xxxxxxxxxxxxxxxx",
    "<your-token>",
    "replace-with-your-secret",
)

# a var that was never filled in, so the real val is elsewhere
_TEMPLATE_EXPRESSIONS: tuple[str, ...] = (
    "${API_KEY}",
    "{{ vault_db_password }}",
    "%(api_key)s",
    "$(SECRET_TOKEN)",
    "<%= ENV['TOKEN'] %>",
    "${{ secrets.DEPLOY_KEY }}",
)

# the field exists but holds nothing
_STUBS: tuple[str, ...] = (
    "null",
    "REDACTED",
    "TODO",
    "none",
    "undefined",
    "N/A",
)

_EASY: tuple[_Spec, ...] = (
    _Spec(
        "placeholder",
        ("API_KEY", "SECRET_KEY", "TOKEN", "PASSWORD"),
        lambda rng: rng.choice(_PLACEHOLDERS),
    ),
    _Spec(
        "template-expression",
        ("APP_SECRET", "DB_PASSWORD", "TOKEN", "CLIENT_SECRET"),
        lambda rng: rng.choice(_TEMPLATE_EXPRESSIONS),
    ),
    _Spec(
        "empty-or-stub",
        ("CLIENT_SECRET", "PRIVATE_KEY", "API_KEY", "AUTH_TOKEN"),
        lambda rng: rng.choice(_STUBS),
    ),
)

# --- surrounding code -------------------------------------------------------
# `__NAME__` and `__VALUE__` rather than str.format: half of these contain braces.

_FILE_TEMPLATES: tuple[tuple[str, str], ...] = (
    (
        "config/settings.py",
        'DEBUG = False\nDATABASE_URL = os.environ["DATABASE_URL"]\n'
        '__NAME__ = "__VALUE__"\nREQUEST_TIMEOUT = 30',
    ),
    (
        "tests/test_config.py",
        'def test_parses_configuration():\n    __NAME__ = "__VALUE__"\n'
        '    cfg = load_config({"__NAME__": __NAME__})\n    assert cfg.is_valid()',
    ),
    (
        "infra/main.tf",
        'locals {\n  region = "eu-west-1"\n  __NAME__ = "__VALUE__"\n}',
    ),
    (
        "scripts/build.sh",
        '#!/usr/bin/env bash\nset -euo pipefail\n__NAME__="__VALUE__"\n'
        "docker build --build-arg __NAME__ -t registry.internal/app:latest .",
    ),
    (
        ".env.production",
        "NODE_ENV=production\n__NAME__=__VALUE__\nLOG_LEVEL=info",
    ),
    (
        "deploy/deployment.yaml",
        'env:\n  - name: __NAME__\n    value: "__VALUE__"\n'
        "  - name: APP_ENV\n    value: production",
    ),
    (
        "src/api/client.js",
        'const client = new Client({\n  region: "eu-west-3",\n'
        '  __NAME__: "__VALUE__",\n  retries: 3,\n});',
    ),
    (
        "docs/quickstart.md",
        "Configure the service before the first run:\n\n```\nexport __NAME__=__VALUE__\n```\n\n"
        "Restart the daemon afterwards.",
    ),
)

# fake line numbers. just needs to look plausible
_MIN_LINE = 3
_MAX_LINE = 200


def _plan(count: int) -> list[tuple[tuple[_Spec, ...], str, str | None]]:
    """Fixed counts per bucket, so the distribution holds exactly rather than on average."""
    # counted, not rolled: 400 -> exactly 120 secrets, never 118 or 123
    secrets = round(count * SECRET_SHARE)
    false_positives = count - secrets
    hard = round(false_positives * HARD_SHARE)
    medium = round(false_positives * MEDIUM_SHARE)
    easy = false_positives - hard - medium

    # one entry per candidate to build: which pool to draw from, and the answer key
    entries: list[tuple[tuple[_Spec, ...], str, str | None]] = []
    entries += [(_SECRETS, LABEL_SECRET, None)] * secrets
    entries += [(_HARD, LABEL_NOT_SECRET, DIFFICULTY_HARD)] * hard
    entries += [(_MEDIUM, LABEL_NOT_SECRET, DIFFICULTY_MEDIUM)] * medium
    entries += [(_EASY, LABEL_NOT_SECRET, DIFFICULTY_EASY)] * easy
    return entries


# short id built from the row itself. same row -> same id, and no uuid4
# (which would break byte-for-byte reproducibility)
def _identifier(index: int, path: str, line: int, rule: str, value: str) -> str:
    raw = f"{index}|{path}|{line}|{rule}|{value}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def generate(seed: int, count: int) -> list[Candidate]:
    """Build `count` labelled candidates. The same seed always yields the same list."""
    if count < _MIN_COUNT:
        raise ValueError(f"count must be at least {_MIN_COUNT}, got {count}")

    # one rng for the whole run. same seed -> same draws, in the same order, forever
    rng = random.Random(seed)
    entries = _plan(count)
    # shuffle so secrets aren't all bunched at the top
    rng.shuffle(entries)

    candidates: list[Candidate] = []
    for index, (pool, label, difficulty) in enumerate(entries):
        # draw order matters here: change it and every corpus after this line changes
        spec = rng.choice(pool)
        name = rng.choice(spec.names)
        value = spec.make(rng)
        # drop the value into a believable bit of code
        path, template = rng.choice(_FILE_TEMPLATES)
        line = rng.randrange(_MIN_LINE, _MAX_LINE)
        # plain .replace, not .format: half these templates are full of { } already
        context = template.replace("__NAME__", name).replace("__VALUE__", value)
        candidates.append(
            Candidate(
                id=_identifier(index, path, line, spec.rule, value),
                detector="synthetic",
                source="synthetic",
                path=path,
                line=line,
                rule=spec.rule,
                match=value,
                context=context,
                label=label,
                label_source="synthetic",
                difficulty=difficulty,
            )
        )
    return candidates
