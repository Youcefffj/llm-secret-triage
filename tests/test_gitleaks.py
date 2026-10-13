import json
import shutil

import pytest

from secret_triage.scanners import gitleaks

# the real binary is optional: everything but the last tests runs on a hand-made report
needs_gitleaks = pytest.mark.skipif(
    shutil.which("gitleaks") is None, reason="gitleaks not installed"
)


# one finding as gitleaks reports it, reduced to the fields we read
def finding(path, line, secret, rule="password-assignment", end=None) -> dict:
    return {
        "File": str(path),
        "StartLine": line,
        "EndLine": end or line,
        "RuleID": rule,
        "Secret": secret,
        "Match": f"password={secret}",
    }


def report(*findings) -> str:
    return json.dumps(list(findings))


def test_a_finding_becomes_a_candidate_with_the_lines_around_it(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("\n".join(f"line {n}" for n in range(1, 21)), encoding="utf-8")

    (candidate,) = gitleaks.parse_report(report(finding(notes, 10, "line 10")))

    assert (candidate.path, candidate.line, candidate.match) == (str(notes), 10, "line 10")
    assert candidate.rule == "password-assignment"
    assert (candidate.detector, candidate.source) == ("gitleaks", "filesystem")
    assert candidate.label is None
    # 5 lines on each side of line 10
    assert candidate.context.splitlines() == [f"line {n}" for n in range(5, 16)]


def test_the_window_stops_at_the_edges_of_the_file(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("password=Welcome1!\nsecond line", encoding="utf-8")

    (candidate,) = gitleaks.parse_report(report(finding(notes, 1, "Welcome1!")))
    assert candidate.context == "password=Welcome1!\nsecond line"


def test_a_value_over_several_lines_keeps_all_of_them(tmp_path):
    key = tmp_path / "id_rsa"
    lines = ["-----BEGIN KEY-----"] + [f"body{n}" for n in range(20)] + ["-----END KEY-----"]
    key.write_text("\n".join(lines), encoding="utf-8")

    (candidate,) = gitleaks.parse_report(report(finding(key, 1, "\n".join(lines), end=22)))
    assert candidate.context == "\n".join(lines)


def test_two_rules_on_the_same_value_give_one_candidate(tmp_path):
    env = tmp_path / ".env"
    env.write_text("DB_PASSWORD=Xk9vT2qLm8Rp4Zw7", encoding="utf-8")

    candidates = gitleaks.parse_report(
        report(
            finding(env, 1, "Xk9vT2qLm8Rp4Zw7"),
            finding(env, 1, "Xk9vT2qLm8Rp4Zw7", rule="generic-api-key"),
        )
    )
    assert len(candidates) == 1


def test_candidates_come_in_file_order(tmp_path):
    for name in ("b.txt", "a.txt"):
        (tmp_path / name).write_text("x\n" * 10, encoding="utf-8")
    candidates = gitleaks.parse_report(
        report(
            finding(tmp_path / "b.txt", 2, "Soleil2024"),
            finding(tmp_path / "a.txt", 9, "Hiver-2023"),
            finding(tmp_path / "a.txt", 3, "Bonjour2025"),
        )
    )
    assert [(c.path[-5:], c.line) for c in candidates] == [("a.txt", 3), ("a.txt", 9), ("b.txt", 2)]


# minified files are one huge line: keep a readable slice, centred on the value
def test_a_long_line_is_cut_around_the_value(tmp_path):
    bundle = tmp_path / "app.min.js"
    bundle.write_text("a" * 5000 + 'pwd:"Welcome1!"' + "b" * 5000, encoding="utf-8")

    (candidate,) = gitleaks.parse_report(report(finding(bundle, 1, "Welcome1!")))
    assert len(candidate.context) == 300
    assert "Welcome1!" in candidate.context


# cutting through the value would leave a raw piece the mask can't find
def test_a_value_longer_than_the_cut_stays_whole(tmp_path):
    blob = "Q" * 400
    data = tmp_path / "data.txt"
    data.write_text("a" * 1000 + blob + "b" * 1000, encoding="utf-8")

    (candidate,) = gitleaks.parse_report(report(finding(data, 1, blob)))
    assert blob in candidate.context
    assert candidate.match_masked in candidate.context_masked


def test_a_file_gone_since_the_scan_falls_back_to_the_match(tmp_path):
    (candidate,) = gitleaks.parse_report(report(finding(tmp_path / "gone.txt", 4, "Welcome1!")))
    assert candidate.context == "password=Welcome1!"


def test_an_empty_report_gives_nothing():
    assert gitleaks.parse_report("[]") == []


def test_a_missing_gitleaks_says_where_to_get_it(tmp_path, monkeypatch):
    monkeypatch.setattr(gitleaks.shutil, "which", lambda name: None)
    with pytest.raises(gitleaks.GitleaksError, match="releases"):
        gitleaks.scan(tmp_path)


def test_a_missing_folder_is_refused(tmp_path):
    with pytest.raises(ValueError, match="not a folder"):
        gitleaks.scan(tmp_path / "nowhere")


# made-up passwords, written the way people leave them on a share
@needs_gitleaks
def test_gitleaks_finds_the_passwords_people_write_down(tmp_path):
    (tmp_path / "it").mkdir()
    (tmp_path / "it" / "deploy.ps1").write_text(
        '$user = "svc_backup"\n$password = "Welcome1!"\n', encoding="utf-8"
    )
    (tmp_path / "it" / ".env").write_text("DB_PASSWORD=Soleil2024\nSMTP_PASS=Hiver-2023\n")
    (tmp_path / "acces.txt").write_text(
        "login : admin\nmot de passe : Marseille13!\nMDP wifi: Bonjour2025\n", encoding="utf-8"
    )
    (tmp_path / "app.json").write_text('{"user": "svc", "password": "Lyon-69007"}\n')
    (tmp_path / "web.config").write_text('connectionString="Server=db;Password=Pa55w0rd;"\n')

    found = {candidate.match for candidate in gitleaks.scan(tmp_path)}
    assert found == {
        "Welcome1!",
        "Soleil2024",
        "Hiver-2023",
        "Marseille13!",
        "Bonjour2025",
        "Lyon-69007",
        "Pa55w0rd",
    }


# pwd, mdp and pass only count as a label of their own, not inside another word
@needs_gitleaks
def test_the_password_rule_leaves_lookalike_words_alone(tmp_path):
    (tmp_path / "settings.ini").write_text(
        "bypass = enabled\ncmdpath=/usr/local/bin\ncompass: north-east\n"
        "password: <your-password>\n",
        encoding="utf-8",
    )
    assert gitleaks.scan(tmp_path) == []
