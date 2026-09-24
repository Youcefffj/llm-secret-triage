import ast
import inspect
import random
import string

import pytest

from secret_triage import prefilter
from secret_triage.prefilter import decide, entropy


def test_entropy_of_one_repeated_char_is_zero():
    assert entropy("aaaaaaaa") == 0.0
    assert entropy("") == 0.0


def test_entropy_counts_bits_per_char():
    assert entropy("ab") == 1.0
    assert entropy("abcd") == 2.0


# the trap behind the low default: 8 distinct chars is as random as 8 chars get
def test_entropy_is_capped_by_length():
    assert entropy("a1B2c3D4") == 3.0


@pytest.mark.parametrize(
    "value",
    [
        "${API_KEY}",
        "{{ vault_db_password }}",
        "${{ secrets.DEPLOY_KEY }}",
        "%(api_key)s",
        "$(SECRET_TOKEN)",
        "$(cat /run/secrets/token)",
        "<%= ENV['TOKEN'] %>",
    ],
)
def test_template_expressions_are_dropped(value):
    assert decide(value).reason == "template_expression"


@pytest.mark.parametrize(
    "value",
    [
        "CHANGEME",
        "change_me_please",
        "your-api-key-here",
        "<your-token>",
        "not-a-real-key",
        "REDACTED",
        "undefined",
        "AKIAIOSFODNN7EXAMPLE",
    ],
)
def test_placeholder_tokens_are_dropped(value):
    assert "placeholder_token" in decide(value).fired


@pytest.mark.parametrize("value", ["null", "TODO", "none", "N/A", "-"])
def test_short_values_are_dropped(value):
    assert decide(value).reason == "too_short"


@pytest.mark.parametrize("value", ["xxxxxxxxxxxxxxxx", "0000000000000000", "abababababababab"])
def test_repeated_patterns_are_dropped(value):
    assert "too_few_distinct" in decide(value).fired


def test_low_entropy_is_dropped_once_the_floor_is_raised():
    value = "aaaaaaaaaaaaaaaaabcd"  # 4 distinct, 20 chars, 17 of them the same
    assert decide(value, min_entropy=2.0).fired == ("low_entropy",)


def test_a_vendor_prefix_skips_the_entropy_floor():
    value = "ghp_" + "a" * 20 + "bcd"  # short and repetitive on purpose
    assert entropy(value) < 2.0
    assert decide(value, min_entropy=4.0).kept


def test_a_vendor_prefix_does_not_skip_the_other_rules():
    assert decide("AKIAIOSFODNN7EXAMPLE").reason == "placeholder_token"


# the least random 8-char value the length and distinct rules let through.
# the default floor must never be what drops it
def test_default_floor_sits_under_the_other_rules():
    assert entropy("aaaaabcd") > prefilter.DEFAULT_MIN_ENTROPY
    assert decide("aaaaabcd").kept


# 8 chars only over the full alphanumeric range: a random 8-char hex value has
# 3 distinct chars or fewer about once in a thousand, and that is a real drop
def test_random_secrets_survive_the_default():
    rng = random.Random(0)
    cases = (
        (string.ascii_letters + string.digits, (8, 12, 20, 40, 64)),
        ("0123456789abcdef", (12, 20, 40, 64)),
        (string.ascii_letters + string.digits + "!@#$%&*?", (12, 20, 40)),
    )
    for alphabet, lengths in cases:
        for length in lengths:
            for _ in range(100):
                value = "".join(rng.choice(alphabet) for _ in range(length))
                assert decide(value).kept, value


# "test", "fake", "demo" turn up by chance in random secrets. they must not be tokens
def test_short_words_inside_a_random_value_do_not_count():
    for value in ("q9TESTr7Lm2Vx8Kp", "fAkE7x2Qm9Lr4Vp8", "8xDemo4Kq9Lm2Vr7"):
        assert decide(value).kept, value


def test_every_placeholder_token_is_long_enough_to_never_match_by_chance():
    assert all(len(token) >= 7 for token in prefilter._PLACEHOLDER_TOKENS)


def test_every_rule_can_fire():
    fired = set()
    for value in ("${X}", "CHANGEME", "null", "xxxxxxxxxxxxxxxx", "aaaaaaaaaaaaaaaaabcd"):
        fired.update(decide(value, min_entropy=2.0).fired)
    assert fired == set(prefilter.RULES)


# invariant 3, checked on the source: no import from the package, so no road to
# the variable name, the path or the context
def test_prefilter_imports_nothing_from_the_package():
    tree = ast.parse(inspect.getsource(prefilter))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert not (node.module or "").startswith("secret_triage")
        elif isinstance(node, ast.Import):
            assert not any(alias.name.startswith("secret_triage") for alias in node.names)
