"""Ask a model, finding by finding, whether it is a real secret. One code path for every provider.

A provider only turns (system prompt, user prompt) into a reply. Everything else,
concurrency, retries, parsing and accounting, is the same whoever answers.

Three providers, none needing an API key:
- local: any server speaking the OpenAI chat API on this machine (LM Studio,
  Ollama, llama.cpp). It sees the raw values: they don't leave the machine.
- claude-code: the `claude` CLI, on its own login.
- codex: the `codex` CLI, on its own login.
The two CLIs send what they're given to a hosted model, so they get masked values.
"""

import json
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from . import prompts
from .models import LABEL_NOT_SECRET, LABEL_SECRET, Candidate, Verdict

# a call that failed this many times is a failure on that candidate
ATTEMPTS = 3
# this many failures in a row and the provider is down or out of quota: the run stops
MAX_FAILURES_IN_A_ROW = 5
_TIMEOUT = 300  # seconds. a local model can be slow, a stuck one must not hang the run


@dataclass(frozen=True)
class Reply:
    text: str
    tokens_in: int | None = None
    tokens_out: int | None = None
    cost_usd: float | None = None


@dataclass(frozen=True)
class Provider:
    name: str
    model: str
    masked: bool  # hosted: the model sees masked values, raw ones stay on the machine
    ask: Callable[[str, str], Reply]


class ProviderError(RuntimeError):
    """A call that got no reply: network, server, CLI."""


class RunAborted(RuntimeError):
    """The provider kept failing: the run stopped rather than fail every candidate."""


def local(model: str, base_url: str) -> Provider:
    def ask(system: str, user: str) -> Reply:
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "max_tokens": 400,
            # no thinking before the verdict: a classification gains nothing from it, and
            # Gemma 4 spends some 300 tokens on it by default, 30 s a call on this machine
            "reasoning_effort": "none",
            # constrained decoding: the server can only produce JSON of this shape
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "verdict", "strict": True, "schema": prompts.SCHEMA},
            },
        }
        request = urllib.request.Request(
            base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
                data = json.load(response)
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:300]
            raise ProviderError(f"HTTP {error.code} from {base_url}: {detail}") from error
        except (urllib.error.URLError, OSError) as error:
            raise ProviderError(f"no answer from {base_url}: {error}") from error
        usage = data.get("usage") or {}
        return Reply(
            text=data["choices"][0]["message"]["content"] or "",
            tokens_in=usage.get("prompt_tokens"),
            tokens_out=usage.get("completion_tokens"),
        )

    return Provider("local", model, masked=False, ask=ask)


_CLAUDE_INPUT_TOKENS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


def claude_code(model: str) -> Provider:
    def ask(system: str, user: str) -> Reply:
        # an empty folder to run in: no CLAUDE.md or project settings slip into the prompt
        with tempfile.TemporaryDirectory(prefix="secret-triage-") as folder:
            output = _run_cli(
                [
                    "claude", "-p",
                    "--model", model,
                    "--output-format", "json",
                    "--json-schema", json.dumps(prompts.SCHEMA),
                    "--system-prompt", system,
                    "--tools", "",  # a verdict, not an agent: nothing to read, run or fetch
                    "--strict-mcp-config",
                    "--setting-sources", "",
                    "--no-session-persistence",
                    user,
                ],
                folder,
            )
        try:
            data = json.loads(output)
        except json.JSONDecodeError as error:
            raise ProviderError(f"claude printed no JSON: {output[:300]}") from error
        if data.get("is_error") or data.get("subtype") != "success":
            raise ProviderError(f"claude: {data.get('result') or data.get('subtype')}")
        usage = data.get("usage") or {}
        structured = data.get("structured_output")
        return Reply(
            text=json.dumps(structured) if structured is not None else data.get("result") or "",
            # cached or not, every input token was read by the model
            tokens_in=sum(usage.get(key) or 0 for key in _CLAUDE_INPUT_TOKENS),
            tokens_out=usage.get("output_tokens"),
            # what the same tokens would cost on the API. the subscription bills nothing per call
            cost_usd=data.get("total_cost_usd"),
        )

    return Provider("claude-code", model, masked=True, ask=ask)


def codex(model: str | None) -> Provider:
    def ask(system: str, user: str) -> Reply:
        with tempfile.TemporaryDirectory(prefix="secret-triage-") as folder:
            schema = Path(folder) / "schema.json"
            schema.write_text(json.dumps(prompts.SCHEMA), encoding="utf-8")
            answer = Path(folder) / "answer.json"
            command = [
                "codex", "exec",
                "--skip-git-repo-check",
                "--ephemeral",
                "--sandbox", "read-only",
                "--cd", folder,
                "--output-schema", str(schema),
                "--output-last-message", str(answer),
                "--json",
            ]
            if model:
                command += ["--model", model]
            # codex takes one prompt, no separate system message
            output = _run_cli([*command, f"{system}\n\n{user}"], folder)
            events = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
            failure = next(
                (event.get("message") for event in events if event.get("type") == "error"), None
            )
            if failure or not answer.is_file():
                raise ProviderError(f"codex: {failure or 'no answer'}")
            text = answer.read_text(encoding="utf-8")
        usage = next((e.get("usage") for e in events if e.get("type") == "turn.completed"), None)
        usage = usage or {}
        return Reply(
            text=text,
            tokens_in=usage.get("input_tokens"),
            tokens_out=usage.get("output_tokens"),
        )

    return Provider("codex", model or "default", masked=True, ask=ask)


def _run_cli(command: list[str], folder: str) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=folder,
            capture_output=True,
            encoding="utf-8",
            stdin=subprocess.DEVNULL,  # codex waits on stdin otherwise
            timeout=_TIMEOUT,
        )
    except FileNotFoundError as error:
        raise ProviderError(f"{command[0]} not found on PATH") from error
    except subprocess.TimeoutExpired as error:
        raise ProviderError(f"{command[0]} took over {_TIMEOUT}s") from error
    if result.returncode != 0 and not result.stdout.strip():
        raise ProviderError(f"{command[0]}: {result.stderr.strip()[:300]}")
    return result.stdout


def parse(text: str) -> tuple[str, float, str]:
    """(verdict, confidence, reason) from a reply, or ValueError saying what's wrong with it.

    JSON wrapped in prose, or after a reasoning block, is taken out of it. Anything
    else that isn't exactly the expected object is an error, never a guess.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        found = re.findall(r"\{[^{}]*\}", text)
        if not found:
            raise ValueError("no JSON object in the reply") from None
        data = json.loads(found[-1])  # the answer comes last, after any thinking aloud
    if not isinstance(data, dict):
        raise ValueError("the reply is not a JSON object")
    verdict, confidence, reason = data.get("verdict"), data.get("confidence"), data.get("reason")
    if verdict not in (LABEL_SECRET, LABEL_NOT_SECRET):
        raise ValueError(f"verdict is {verdict!r}")
    if isinstance(confidence, bool) or not isinstance(confidence, int | float):
        raise ValueError(f"confidence is {confidence!r}")
    if not 0 <= confidence <= 1:
        raise ValueError(f"confidence {confidence} is outside 0..1")
    return verdict, float(confidence), reason if isinstance(reason, str) else ""


def judge(
    provider: Provider, prompt: prompts.Prompt, candidate: Candidate, started: float
) -> Verdict:
    """One candidate, retried on a failed call. A reply that doesn't parse is not retried."""
    user = prompts.render(prompt, candidate, masked=provider.masked)
    error = ""
    for attempt in range(ATTEMPTS):
        if attempt:
            time.sleep(2**attempt)  # 2 s, then 4 s
        sent = time.monotonic()
        try:
            reply = provider.ask(prompt.system, user)
        except ProviderError as failure:
            error = str(failure)
            continue
        latency = time.monotonic() - sent
        try:
            verdict, confidence, reason = parse(reply.text)
        except (ValueError, json.JSONDecodeError) as failure:
            verdict, confidence, reason, error = None, None, reply.text[:500], str(failure)
        else:
            error = None
        return Verdict(
            candidate_id=candidate.id,
            verdict=verdict,
            confidence=confidence,
            reason=reason,
            error=error,
            replied=True,
            tokens_in=reply.tokens_in,
            tokens_out=reply.tokens_out,
            cost_usd=reply.cost_usd,
            latency=latency,
            at=time.monotonic() - started,
        )
    return Verdict(
        candidate_id=candidate.id,
        verdict=None,
        confidence=None,
        reason="",
        error=error,
        replied=False,
        tokens_in=None,
        tokens_out=None,
        cost_usd=None,
        latency=0.0,
        at=time.monotonic() - started,
    )


def run(
    candidates: Sequence[Candidate],
    provider: Provider,
    prompt: prompts.Prompt,
    *,
    concurrency: int = 1,
    on_verdict: Callable[[Verdict], None] = lambda verdict: None,
) -> list[Verdict]:
    """Every candidate through the provider, `concurrency` at a time, in no fixed order."""
    started = time.monotonic()
    verdicts: list[Verdict] = []
    failures_in_a_row = 0
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(judge, provider, prompt, c, started) for c in candidates]
        try:
            for future in as_completed(futures):
                verdict = future.result()
                verdicts.append(verdict)
                on_verdict(verdict)
                failures_in_a_row = 0 if verdict.replied else failures_in_a_row + 1
                if failures_in_a_row >= MAX_FAILURES_IN_A_ROW:
                    raise RunAborted(
                        f"{failures_in_a_row} calls in a row got no reply, last: {verdict.error}"
                    )
        except BaseException:  # Ctrl-C too: what's still queued is dropped, not awaited
            pool.shutdown(wait=False, cancel_futures=True)
            raise
    return verdicts
