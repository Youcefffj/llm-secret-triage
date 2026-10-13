from secret_triage import labeler
from secret_triage.models import LABEL_NOT_SECRET, LABEL_SECRET, Candidate, read_jsonl, write_jsonl


def candidate(match: str, line: int = 1, label: str | None = None) -> Candidate:
    return Candidate(
        id=f"{line:016d}",
        detector="gitleaks",
        source="filesystem",
        path="share/it/notes.txt",
        line=line,
        rule="password-assignment",
        match=match,
        context=f"login: admin\npassword: {match}\nport: 22",
        label=label,
    )


# scripted answers in place of the keyboard. running out of them is ctrl-d
def answers(*replies):
    replies = iter(replies)

    def ask(prompt):
        try:
            return next(replies)
        except StopIteration:
            raise EOFError from None

    return ask


def scan_file(tmp_path, *candidates):
    path = tmp_path / "scan.jsonl"
    write_jsonl(path, candidates)
    return path


def labels(path):
    return [c.label for c in read_jsonl(path)]


def test_the_queue_skips_what_the_prefilter_drops_and_what_is_labelled():
    candidates = [
        candidate("Welcome1!", 1),
        candidate("${DB_PASS}", 2),  # template: dropped
        candidate("Soleil2024", 3, label=LABEL_SECRET),  # already done
        candidate("Hiver-2023", 4),
    ]
    assert labeler.queue(candidates) == [0, 3]


def test_an_audit_mixes_in_dropped_candidates_the_same_ones_every_time():
    candidates = [candidate("Welcome1!", 0)] + [candidate(f"${{VAR_{n}}}", n) for n in range(1, 11)]

    first = labeler.queue(candidates, audit_dropped=3)
    assert len(first) == 4
    assert 0 in first
    assert first == labeler.queue(candidates, audit_dropped=3)
    assert first == sorted(first)


def test_an_audit_larger_than_what_was_dropped_takes_it_all():
    candidates = [candidate("Welcome1!", 0), candidate("${DB_PASS}", 1)]
    assert labeler.queue(candidates, audit_dropped=150) == [0, 1]


def test_answers_are_saved_as_human_labels(tmp_path):
    path = scan_file(tmp_path, candidate("Welcome1!", 1), candidate("Soleil2024", 2))

    labeler.review(path, ask=answers("y", "n"), show=lambda text: None)

    saved = list(read_jsonl(path))
    assert [c.label for c in saved] == [LABEL_SECRET, LABEL_NOT_SECRET]
    assert {c.label_source for c in saved} == {"human"}
    assert not path.with_name("scan.jsonl.tmp").exists()


def test_not_sure_leaves_it_and_quit_stops_with_the_answers_kept(tmp_path):
    path = scan_file(
        tmp_path, candidate("Welcome1!", 1), candidate("Soleil2024", 2), candidate("Hiver-2023", 3)
    )
    labeler.review(path, ask=answers("y", "?", "q"), show=lambda text: None)
    assert labels(path) == [LABEL_SECRET, None, None]


def test_a_review_resumes_where_it_stopped(tmp_path):
    path = scan_file(tmp_path, candidate("Welcome1!", 1), candidate("Soleil2024", 2))
    labeler.review(path, ask=answers("y"), show=lambda text: None)  # then ctrl-d

    shown = []
    labeler.review(path, ask=answers("n"), show=shown.append)

    assert labels(path) == [LABEL_SECRET, LABEL_NOT_SECRET]
    assert "Soleil2024" in shown[0]
    assert "Welcome1!" not in shown[0]


def test_anything_else_is_asked_again(tmp_path):
    path = scan_file(tmp_path, candidate("Welcome1!"))
    shown = []
    labeler.review(path, ask=answers("maybe", "", "Y"), show=shown.append)

    assert labels(path) == [LABEL_SECRET]
    assert shown.count("y, n, ? or q") == 2


def test_the_card_shows_where_and_marks_the_value():
    text = labeler.card(candidate("Welcome1!", line=12), 3, 40)

    assert "[3/40] share/it/notes.txt:12  (password-assignment)" in text
    assert "  >>  password: Welcome1!" in text
    assert "      login: admin" in text
