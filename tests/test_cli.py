import io
import json
import shutil
from pathlib import Path

import pytest

from secret_triage.cli import main
from secret_triage.models import Candidate, read_run, write_jsonl


def test_prefilter_sweep_prints_the_table_and_the_breakdown(capsys):
    assert main(["prefilter-sweep", "--seeds", "2", "--count", "50"]) == 0
    out = capsys.readouterr().out

    assert "100 candidates over 2 seeds" in out
    assert "<- default" in out
    assert "only rule" in out
    assert "false positives dropped" in out


def test_prefilter_sweep_refuses_zero_seeds():
    with pytest.raises(SystemExit):
        main(["prefilter-sweep", "--seeds", "0"])


def test_scan_without_gitleaks_fails_with_a_message(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert main(["scan", str(tmp_path)]) == 1
    assert "gitleaks not found" in capsys.readouterr().err


def test_review_refuses_a_missing_scan_file(tmp_path):
    with pytest.raises(SystemExit):
        main(["review", str(tmp_path / "nope.jsonl")])


# scan a made-up share, say yes to everything, get the list of what to fix
@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks not installed")
def test_scan_then_review_lists_what_to_fix(tmp_path, monkeypatch, capsys):
    share = tmp_path / "share"
    share.mkdir()
    (share / "acces.txt").write_text("login : admin\nmot de passe : Marseille13!\n")
    monkeypatch.setattr("secret_triage.cli.SCANS_DIR", tmp_path / "scans")

    assert main(["scan", str(share)]) == 0
    captured = capsys.readouterr()
    scan_file = captured.out.strip()
    assert scan_file.startswith(str(tmp_path / "scans" / "share-"))
    assert "to review      1" in captured.err

    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))  # the keyboard says yes
    assert main(["review", scan_file]) == 0
    out = capsys.readouterr().out
    assert "1 real, 0 not real, 0 still to review" in out
    assert f"{share / 'acces.txt'}:2  (password-assignment)" in out


# what could not be read is counted on screen and listed in a file next to the scan
def test_scan_lists_the_files_it_could_not_read(tmp_path, monkeypatch, capsys, make_ole):
    monkeypatch.setattr("secret_triage.scanners.gitleaks.find_binary", lambda: "gitleaks")
    monkeypatch.setattr("secret_triage.scanners.gitleaks.scan", lambda documents: [])
    monkeypatch.setattr("secret_triage.cli.SCANS_DIR", tmp_path / "scans")
    share = tmp_path / "share"
    share.mkdir()
    (share / "notes.txt").write_text("rien ici")
    (share / "paie.xlsx").write_bytes(make_ole({"EncryptedPackage": b"\0" * 64}))

    assert main(["scan", str(share)]) == 0
    err = capsys.readouterr().err

    assert "1 files read, 1 not read" in err
    assert "1  encrypted" in err
    (unread_list,) = (tmp_path / "scans").glob("share-*-unread.txt")
    assert unread_list.read_text() == f"encrypted\t{share / 'paie.xlsx'}\n"


def labelled(tmp_path):
    """A tiny labelled corpus: two passwords, a commit id, and a placeholder the prefilter drops."""
    rows = [
        ("Welcome1!", "secret"),
        ("4f9c2a1e7b3d5f8a0c6e9b2d4f7a1c3e5b8d0f2a", "not_secret"),
        ("CHANGEME", "not_secret"),
        ("Soleil2024", "secret"),
    ]
    path = tmp_path / "corpus.jsonl"
    write_jsonl(
        path,
        [
            Candidate(f"{n:016d}", "test", "test", "app.env", n, "rule", value, f"X={value}", label)
            for n, (value, label) in enumerate(rows)
        ],
    )
    return path


def reply(verdict: str) -> tuple[int, dict]:
    content = json.dumps({"verdict": verdict, "confidence": 0.9, "reason": "test"})
    return 200, {"choices": [{"message": {"content": content}}], "usage": {}}


def test_triage_writes_a_run_and_scores_it_against_the_scanner_alone(
    tmp_path, monkeypatch, capsys, openai_server
):
    base_url, received, replies = openai_server
    replies += [reply("secret"), reply("not_secret"), reply("secret")]  # in file order
    monkeypatch.setattr("secret_triage.cli.RUNS_DIR", tmp_path / "runs")

    assert main(["triage", str(labelled(tmp_path)), "--base-url", base_url]) == 0
    captured = capsys.readouterr()

    assert len(received) == 3  # CHANGEME never left the prefilter
    run, verdicts = read_run(Path(captured.out.strip()))
    assert (run.provider, run.model, run.prompt_version, run.masked) == (
        "local",
        "google/gemma-4-12b-qat",
        "v1",
        False,
    )
    assert len(verdicts) == 3
    assert "4 candidates, 3 sent to google/gemma-4-12b-qat" in captured.err
    assert "scanner alone               0.500   1.000  0.667" in captured.err
    assert "+ prefilter + model         1.000   1.000  1.000" in captured.err


def test_include_dropped_sends_everything_and_limit_estimates_the_rest(
    tmp_path, monkeypatch, capsys, openai_server
):
    base_url, received, _ = openai_server
    monkeypatch.setattr("secret_triage.cli.RUNS_DIR", tmp_path / "runs")
    corpus = str(labelled(tmp_path))

    command = ["triage", corpus, "--base-url", base_url, "--include-dropped", "--limit", "3"]
    assert main(command) == 0
    assert len(received) == 3
    assert "the whole file: 4 to send" in capsys.readouterr().err


def test_triage_stops_when_the_provider_is_down(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("secret_triage.cli.RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr("secret_triage.triage.time.sleep", lambda seconds: None)
    monkeypatch.setattr("secret_triage.triage.MAX_FAILURES_IN_A_ROW", 2)

    status = main(["triage", str(labelled(tmp_path)), "--base-url", "http://127.0.0.1:9/v1"])

    assert status == 1
    assert "stopped: 2 calls in a row got no reply" in capsys.readouterr().err


def test_triage_refuses_a_zero_limit(tmp_path):
    with pytest.raises(SystemExit):
        main(["triage", str(labelled(tmp_path)), "--limit", "0"])
