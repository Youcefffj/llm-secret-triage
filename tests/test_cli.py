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
