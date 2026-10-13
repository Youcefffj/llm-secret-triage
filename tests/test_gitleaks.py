import json
import shutil

import pytest

from secret_triage.scanners import gitleaks

# the real binary is optional: everything but the last tests runs on a hand-made report
needs_gitleaks = pytest.mark.skipif(
    shutil.which("gitleaks") is None, reason="gitleaks not installed"
)


# one finding as gitleaks reports it on the n-th text, reduced to the fields we read
def finding(index, line, secret, rule="password-assignment") -> dict:
    return {
        "File": f"/tmp/secret-triage-x/{index}.txt",
        "StartLine": line,
        "RuleID": rule,
        "Secret": secret,
        "Match": f"password={secret}",
    }


def report(*findings) -> str:
    return json.dumps(list(findings))


def test_a_finding_becomes_a_candidate_with_100_chars_on_each_side():
    text = "a" * 300 + "password=Welcome1!" + "b" * 300
    documents = [("share/notes.txt", text)]

    (candidate,) = gitleaks.parse_report(report(finding(0, 1, "Welcome1!")), documents)

    assert (candidate.path, candidate.line, candidate.match) == ("share/notes.txt", 1, "Welcome1!")
    assert candidate.rule == "password-assignment"
    assert (candidate.detector, candidate.source) == ("gitleaks", "filesystem")
    assert candidate.label is None
    assert candidate.context == "a" * 91 + "password=Welcome1!" + "b" * 100


def test_the_context_stops_at_the_edges_of_the_text():
    documents = [("acces.txt", "password=Welcome1!\nsecond line")]
    (candidate,) = gitleaks.parse_report(report(finding(0, 1, "Welcome1!")), documents)
    assert candidate.context == "password=Welcome1!\nsecond line"


def test_the_value_is_taken_on_its_own_line_when_it_appears_twice():
    text = "old: Welcome1!\n" + "x" * 200 + "\npassword: Welcome1!\nport: 22"
    (candidate,) = gitleaks.parse_report(report(finding(0, 3, "Welcome1!")), [("a.txt", text)])
    assert candidate.context.endswith("password: Welcome1!\nport: 22")


def test_findings_go_back_to_the_file_they_came_from():
    documents = [("share/a.txt", "pwd: Soleil2024"), ("share/b.txt", "pwd: Hiver-2023")]
    candidates = gitleaks.parse_report(
        report(finding(1, 1, "Hiver-2023"), finding(0, 1, "Soleil2024")), documents
    )
    assert [(c.path, c.match) for c in candidates] == [
        ("share/a.txt", "Soleil2024"),
        ("share/b.txt", "Hiver-2023"),
    ]


def test_two_rules_on_the_same_value_give_one_candidate():
    documents = [(".env", "DB_PASSWORD=Xk9vT2qLm8Rp4Zw7")]
    candidates = gitleaks.parse_report(
        report(
            finding(0, 1, "Xk9vT2qLm8Rp4Zw7"),
            finding(0, 1, "Xk9vT2qLm8Rp4Zw7", rule="generic-api-key"),
        ),
        documents,
    )
    assert len(candidates) == 1


def test_a_value_the_text_does_not_hold_falls_back_to_the_match():
    (candidate,) = gitleaks.parse_report(report(finding(0, 4, "Welcome1!")), [("a.txt", "")])
    assert candidate.context == "password=Welcome1!"


def test_an_empty_report_gives_nothing():
    assert gitleaks.parse_report("[]", []) == []


def test_a_missing_gitleaks_says_where_to_get_it(monkeypatch):
    monkeypatch.setattr(gitleaks.shutil, "which", lambda name: None)
    with pytest.raises(gitleaks.GitleaksError, match="releases"):
        gitleaks.scan([("a.txt", "password=Welcome1!")])


def found(*texts: str) -> set[str]:
    documents = [(f"doc{index}", text) for index, text in enumerate(texts)]
    return {candidate.match for candidate in gitleaks.scan(documents)}


# made-up passwords, written the way people leave them on a share
@needs_gitleaks
def test_gitleaks_finds_the_passwords_people_write_down():
    assert found(
        '$user = "svc_backup"\n$password = "Welcome1!"\n',
        "DB_PASSWORD=Soleil2024\nSMTP_PASS=Hiver-2023\n",
        "login : admin\nmot de passe : Marseille13!\nMDP wifi: Bonjour2025\n",
        '{"user": "svc", "password": "Lyon-69007"}\n',
        'connectionString="Server=db;Password=Pa55w0rd;"\n',
    ) == {"Welcome1!", "Soleil2024", "Hiver-2023", "Marseille13!", "Bonjour2025", "Lyon-69007",
          "Pa55w0rd"}


# what a table looks like once extracted: the label and the value in two cells
@needs_gitleaks
def test_a_password_in_the_next_cell_is_found():
    assert found("Password | Welcome1! | prod\n", "Mot de passe\tSoleil2024\n") == {
        "Welcome1!",
        "Soleil2024",
    }


@needs_gitleaks
def test_a_password_inside_a_url_is_found():
    assert found(
        "postgres://admin:Soleil2024@db:5432/app\n",
        "git clone https://svc_build:Hiver-2023@git.intranet.local/app.git\n",
    ) == {"Soleil2024", "Hiver-2023"}


# pwd, mdp and pass only count as a label of their own, not inside another word
@needs_gitleaks
def test_the_rules_leave_lookalikes_alone():
    assert found(
        "bypass = enabled\ncmdpath=/usr/local/bin\ncompass: north-east\n"
        "password: <your-password>\n",
        "see https://example.com/12:30@x and git@github.com:org/repo.git, ssh://git@host/repo\n",
    ) == set()


@needs_gitleaks
def test_nothing_is_left_in_the_temporary_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr(gitleaks.tempfile, "tempdir", None)  # re-read TMPDIR
    gitleaks.scan([("a.txt", "password=Welcome1!")])
    assert list(tmp_path.iterdir()) == []
