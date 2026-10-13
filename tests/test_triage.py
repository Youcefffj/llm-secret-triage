import json
import subprocess
from pathlib import Path

import pytest

from secret_triage import prompts, triage
from secret_triage.models import Candidate


def candidate(number: int, match: str = "Welcome1!") -> Candidate:
    return Candidate(
        id=f"{number:016d}",
        detector="gitleaks",
        source="filesystem",
        path=f"share/{number}.txt",
        line=1,
        rule="password-assignment",
        match=match,
        context=f"password = {match}",
    )


def answer(verdict="secret", confidence=0.9, reason="a password in a script") -> str:
    return json.dumps({"verdict": verdict, "confidence": confidence, "reason": reason})


def provider(ask, masked=False) -> triage.Provider:
    return triage.Provider("fake", "fake-model", masked=masked, ask=ask)


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    monkeypatch.setattr(triage.time, "sleep", lambda seconds: None)


# parse: strict, but not fussy about prose around the JSON


def test_a_plain_answer_parses():
    assert triage.parse(answer()) == ("secret", 0.9, "a password in a script")


def test_json_wrapped_in_prose_or_after_thinking_is_taken_out():
    text = "<think>it says password = {x}</think>Here you go: " + answer("not_secret", 1)
    assert triage.parse(text) == ("not_secret", 1.0, "a password in a script")


@pytest.mark.parametrize(
    "text, problem",
    [
        ("I think it's a secret", "no JSON"),
        (answer(verdict="maybe"), "verdict"),
        (answer(confidence="high"), "confidence"),
        (answer(confidence=True), "confidence"),
        (answer(confidence=1.5), "outside"),
        ("[1, 2]", "not a JSON object"),
    ],
)
def test_anything_else_is_an_error_not_a_guess(text, problem):
    with pytest.raises(ValueError, match=problem):
        triage.parse(text)


# judge: one candidate


def test_a_verdict_carries_what_it_cost():
    reply = triage.Reply(answer(), tokens_in=400, tokens_out=40, cost_usd=0.001)
    verdict = triage.judge(provider(lambda s, u: reply), prompts.V1, candidate(1), 0.0)

    assert (verdict.candidate_id, verdict.verdict, verdict.confidence) == (
        "0000000000000001",
        "secret",
        0.9,
    )
    assert (verdict.error, verdict.replied) == (None, True)
    assert (verdict.tokens_in, verdict.tokens_out, verdict.cost_usd) == (400, 40, 0.001)
    assert verdict.latency >= 0


def test_a_failed_call_is_retried():
    calls = []

    def ask(system, user):
        calls.append(user)
        if len(calls) < 3:
            raise triage.ProviderError("connection refused")
        return triage.Reply(answer())

    verdict = triage.judge(provider(ask), prompts.V1, candidate(1), 0.0)
    assert len(calls) == 3
    assert verdict.verdict == "secret"


def test_a_call_failing_every_time_is_recorded_as_such():
    def ask(system, user):
        raise triage.ProviderError("connection refused")

    verdict = triage.judge(provider(ask), prompts.V1, candidate(1), 0.0)
    assert (verdict.verdict, verdict.replied, verdict.error) == (None, False, "connection refused")


def test_an_answer_that_does_not_parse_is_kept_as_it_came_and_not_retried():
    calls = []

    def ask(system, user):
        calls.append(user)
        return triage.Reply("It's probably a password.", tokens_out=7)

    verdict = triage.judge(provider(ask), prompts.V1, candidate(1), 0.0)
    assert len(calls) == 1
    assert (verdict.verdict, verdict.replied) == (None, True)
    assert verdict.reason == "It's probably a password."
    assert "no JSON" in verdict.error


def test_a_hosted_provider_never_sees_the_raw_value():
    seen = []

    def ask(system, user):
        seen.append(user)
        return triage.Reply(answer())

    triage.judge(provider(ask, masked=True), prompts.V1, candidate(1), 0.0)
    assert "Welcome1!" not in seen[0]


# run: the whole batch


def test_every_candidate_gets_a_verdict_whatever_the_concurrency():
    seen = []
    verdicts = triage.run(
        [candidate(n) for n in range(20)],
        provider(lambda s, u: triage.Reply(answer())),
        prompts.V1,
        concurrency=4,
        on_verdict=seen.append,
    )
    assert sorted(v.candidate_id for v in verdicts) == [f"{n:016d}" for n in range(20)]
    assert seen == verdicts


def test_a_provider_that_keeps_failing_stops_the_run():
    def ask(system, user):
        raise triage.ProviderError("usage limit reached")

    seen = []
    with pytest.raises(triage.RunAborted, match="usage limit"):
        candidates = [candidate(n) for n in range(50)]
        triage.run(candidates, provider(ask), prompts.V1, on_verdict=seen.append)
    assert len(seen) == triage.MAX_FAILURES_IN_A_ROW


# local: an OpenAI-compatible server, here a fake one on a free port


def test_local_asks_for_json_of_the_schema_without_thinking(openai_server):
    base_url, received, _ = openai_server
    reply = triage.local("gemma", base_url).ask("system text", "user text")

    assert (reply.tokens_in, reply.tokens_out) == (420, 38)
    assert triage.parse(reply.text)[0] == "secret"
    path, body = received[0]
    assert path == "/v1/chat/completions"
    assert body["model"] == "gemma"
    assert body["messages"] == [
        {"role": "system", "content": "system text"},
        {"role": "user", "content": "user text"},
    ]
    assert body["temperature"] == 0
    assert body["reasoning_effort"] == "none"
    assert body["response_format"]["json_schema"]["schema"] == prompts.SCHEMA


def test_local_sees_raw_values():
    assert triage.local("gemma", "http://localhost:1234/v1").masked is False


def test_local_turns_an_http_error_into_a_provider_error(openai_server):
    base_url, _, replies = openai_server
    replies.append((503, {"error": "model loading"}))
    with pytest.raises(triage.ProviderError, match="HTTP 503"):
        triage.local("gemma", base_url).ask("s", "u")


def test_local_with_nothing_listening_is_a_provider_error():
    with pytest.raises(triage.ProviderError, match="no answer"):
        triage.local("gemma", "http://127.0.0.1:9/v1").ask("s", "u")


# the CLIs: subprocess.run replaced by what they print


def fake_cli(monkeypatch, stdout, returncode=0, write_answer=None):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        if write_answer is not None:
            Path(command[command.index("--output-last-message") + 1]).write_text(write_answer)
        return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(triage.subprocess, "run", run)
    return calls


def test_claude_code_runs_without_tools_in_an_empty_folder(monkeypatch):
    printed = {
        "type": "result",
        "subtype": "success",
        "is_error": False,
        "result": "done",
        "structured_output": {"verdict": "not_secret", "confidence": 0.8, "reason": "a hash"},
        "usage": {"input_tokens": 2, "cache_creation_input_tokens": 1200, "output_tokens": 50},
        "total_cost_usd": 0.0004,
    }
    calls = fake_cli(monkeypatch, json.dumps(printed))

    reply = triage.claude_code("haiku").ask("the system prompt", "the finding")

    assert triage.parse(reply.text) == ("not_secret", 0.8, "a hash")
    assert (reply.tokens_in, reply.tokens_out, reply.cost_usd) == (1202, 50, 0.0004)
    command, options = calls[0]
    assert command[:2] == ["claude", "-p"]
    assert command[command.index("--tools") + 1] == ""
    assert command[command.index("--system-prompt") + 1] == "the system prompt"
    assert json.loads(command[command.index("--json-schema") + 1]) == prompts.SCHEMA
    assert command[-1] == "the finding"
    assert "secret-triage-" in options["cwd"]  # not the repository, no CLAUDE.md read
    assert triage.claude_code("haiku").masked is True


def test_claude_code_reporting_an_error_is_a_provider_error(monkeypatch):
    fake_cli(monkeypatch, json.dumps({"subtype": "error_during_execution", "is_error": True}))
    with pytest.raises(triage.ProviderError, match="claude"):
        triage.claude_code("haiku").ask("s", "u")


def test_codex_reads_the_answer_it_left_in_its_file(monkeypatch):
    events = [
        {"type": "thread.started"},
        {"type": "turn.completed", "usage": {"input_tokens": 900, "output_tokens": 60}},
    ]
    calls = fake_cli(
        monkeypatch,
        "\n".join(json.dumps(event) for event in events),
        write_answer=answer("secret", 0.7),
    )

    reply = triage.codex(None).ask("the system prompt", "the finding")

    assert triage.parse(reply.text)[:2] == ("secret", 0.7)
    assert (reply.tokens_in, reply.tokens_out) == (900, 60)
    command, options = calls[0]
    assert command[:2] == ["codex", "exec"]
    assert "--model" not in command  # the account's own default
    assert command[-1] == "the system prompt\n\nthe finding"
    assert options["stdin"] == subprocess.DEVNULL


def test_codex_out_of_quota_is_a_provider_error(monkeypatch):
    message = "You've hit your usage limit."
    fake_cli(monkeypatch, json.dumps({"type": "error", "message": message}), returncode=1)
    with pytest.raises(triage.ProviderError, match="usage limit"):
        triage.codex("gpt-5").ask("s", "u")


def test_a_missing_cli_is_a_provider_error(monkeypatch):
    def run(command, **kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(triage.subprocess, "run", run)
    with pytest.raises(triage.ProviderError, match="not found"):
        triage.claude_code("haiku").ask("s", "u")
