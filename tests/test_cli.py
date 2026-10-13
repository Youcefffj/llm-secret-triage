import io
import shutil

import pytest

from secret_triage.cli import main


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
