import hashlib

from secret_triage import prompts
from secret_triage.models import Candidate


def candidate(match: str) -> Candidate:
    return Candidate(
        id="0123456789abcdef",
        detector="gitleaks",
        source="filesystem",
        path="share/it/deploy.ps1",
        line=3,
        rule="password-assignment",
        match=match,
        context=f'$user = "svc_backup"\n$password = "{match}"\nInvoke-Backup',
    )


# a published prompt never changes (invariant 5). editing v1 breaks this on purpose:
# the edit belongs in a v2, and every run made with v1 keeps meaning what it meant
def test_v1_is_frozen():
    text = prompts.V1.system + "\n" + prompts.V1.user
    assert hashlib.sha256(text.encode()).hexdigest() == (
        "adbd5dba6d5f47c20eb0e54f2f4769ff991b1ce16927118625f776e1c8fbe233"
    )


def test_every_version_is_listed_under_its_own_name():
    assert all(name == prompt.version for name, prompt in prompts.VERSIONS.items())
    assert prompts.VERSIONS[prompts.CURRENT.version] is prompts.CURRENT


def test_the_finding_is_given_in_full_to_a_local_model():
    text = prompts.render(prompts.V1, candidate("Welcome1!"), masked=False)
    assert "File: share/it/deploy.ps1" in text
    assert "Rule: password-assignment" in text
    assert "Value: Welcome1!" in text
    assert '$password = "Welcome1!"' in text


# a hosted model gets the shape of the value, never the value
def test_masked_the_raw_value_appears_nowhere():
    text = prompts.render(prompts.V1, candidate("Welcome1!"), masked=True)
    assert "Welcome1!" not in text
    assert "Value: *********" in text
    assert '$password = "*********"' in text


def test_the_schema_allows_exactly_the_two_labels():
    assert prompts.SCHEMA["properties"]["verdict"]["enum"] == ["secret", "not_secret"]
    assert set(prompts.SCHEMA["required"]) == {"verdict", "confidence", "reason"}
