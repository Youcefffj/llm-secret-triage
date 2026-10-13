"""Layer 1: drop the candidates that cannot be a credential, from the value alone.

Invariant 3: this module never sees the variable name, the file path or the
surrounding lines. That context is what the model layer is measured on, so
`decide` takes a bare string, and nothing here imports from the rest of the
package.

Invariant 4: a dropped candidate never reaches the model, so a false drop is a
miss nothing downstream can recover. Every rule is narrow and justifiable in one
line, and the entropy floor is the only knob. In doubt, a value is kept: the
model is there to decide it.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass

# no length rule: a short password (root12) is still a password, the model decides.
# 3 distinct chars or fewer is a pattern (xxxx, 0000, abab), not a secret.
# a random 8-char string looks like that about once in a million
MIN_DISTINCT = 4

# bits per char. set just under "aaaaabcd" (1.55 bits), the least random value
# of 8 chars or fewer the rule above lets through, so the floor never decides a
# short value on its own. see `entropy` for why a higher floor is a trap
DEFAULT_MIN_ENTROPY = 1.5

# every rule, in the order they're checked. the first one to fire is the
# reason logged for the drop
RULES = (
    "template_expression",
    "placeholder_token",
    "too_few_distinct",
    "low_entropy",
)

# a variable that was never filled in: the real value lives somewhere else.
# matched against the whole value only. with literal text around the template,
# as in postgres://admin:pw@${DB_HOST}, that text may be the real secret
_TEMPLATE_PATTERNS = (
    re.compile(r"\$\{[^{}]+\}"),  # ${API_KEY}
    re.compile(r"\$?\{\{[^{}]+\}\}"),  # {{ vault_pass }}, ${{ secrets.X }}
    re.compile(r"%\([A-Za-z_]\w*\)s"),  # %(api_key)s
    re.compile(r"\$\([^()]+\)"),  # $(SECRET_TOKEN), $(cat /run/secrets/token)
    re.compile(r"<%=?[^%]+%>"),  # <%= ENV['TOKEN'] %>
)

# words people type to mean "no real value here", matched with case and
# separators ignored, so CHANGE_ME and change-me both hit "changeme".
# every token is 7+ chars on purpose: a short word like "test" or "fake" turns
# up by chance inside random secrets, and each hit would be a lost key
_PLACEHOLDER_TOKENS = (
    "changeme",
    "replaceme",
    "example",
    "placeholder",
    "redacted",
    "undefined",
    "notareal",
    "dummykey",
    "dummytoken",
    "yourapi",
    "yourkey",
    "yourtoken",
    "yoursecret",
    "yourpassword",
)
_SEPARATORS = str.maketrans("", "", "-_ .")

# what joins several fields into one value: user@host, user:pass, key=v;key=v.
# a placeholder in one field says nothing about the others, so the model decides
_COMPOSITE = re.compile(r"[@:;]")

# prefixes of real secret token formats. a value carrying one skips the entropy
# floor: AKIA + 16 random chars measures low and is just as live.
# missing a prefix risks a lost key, an extra one only costs a few drops
_VENDOR_PREFIXES = (
    "AKIA", "ASIA",  # aws
    "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",  # github
    "glpat-",  # gitlab
    "xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-",  # slack
    "sk_live_", "sk_test_", "rk_live_", "rk_test_",  # stripe secret keys
    "SG.",  # sendgrid
    "npm_",  # npm
    "AIza",  # google
)


@dataclass(frozen=True)
class Decision:
    """What the prefilter made of one value."""

    fired: tuple[str, ...]  # every rule that matched, in RULES order. empty = kept

    @property
    def kept(self) -> bool:
        return not self.fired

    @property
    def reason(self) -> str | None:
        return self.fired[0] if self.fired else None


def entropy(value: str) -> float:
    """Shannon entropy of `value`, in bits per character.

    Capped at log2(len(value)): an 8-char string can't score above 3.0 however
    random it is. So a floor of f bits quietly drops every string shorter than
    2**f chars, and short ones with a repeated char, whatever they hold.
    """
    length = len(value)
    if not length:
        return 0.0
    # -p*log2(p) summed this way round so a one-symbol string gives 0.0, not -0.0
    return sum(-count / length * math.log2(count / length) for count in Counter(value).values())


def has_vendor_prefix(value: str) -> bool:
    return value.startswith(_VENDOR_PREFIXES)


def decide(value: str, *, min_entropy: float = DEFAULT_MIN_ENTROPY) -> Decision:
    """Run every rule on `value`. It is kept only if none of them fires."""
    normalized = value.lower().translate(_SEPARATORS)
    placeholder = not _COMPOSITE.search(value) and any(
        token in normalized for token in _PLACEHOLDER_TOKENS
    )
    # all checks run, no short-circuit: knowing every rule that fired is what
    # lets us measure which rule catches something no other one would
    checks = (
        ("template_expression", any(p.fullmatch(value) for p in _TEMPLATE_PATTERNS)),
        ("placeholder_token", placeholder),
        ("too_few_distinct", len(set(value)) < MIN_DISTINCT),
        ("low_entropy", not has_vendor_prefix(value) and entropy(value) < min_entropy),
    )
    return Decision(fired=tuple(rule for rule, hit in checks if hit))
