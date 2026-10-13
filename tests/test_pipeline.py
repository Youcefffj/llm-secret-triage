import io
import shutil
import zipfile
from functools import partial

import pytest

from secret_triage import extract, pipeline
from secret_triage.models import Candidate
from secret_triage.scanners import gitleaks
from secret_triage.sources import SourceFile, folder

needs_gitleaks = pytest.mark.skipif(
    shutil.which("gitleaks") is None, reason="gitleaks not installed"
)


@pytest.fixture
def fake_gitleaks(monkeypatch):
    """gitleaks without the binary: every text holding Welcome1! is one finding."""
    batches = []

    def scan(documents):
        batches.append([path for path, _ in documents])
        return [
            Candidate(path, "fake", "filesystem", path, 1, "fake", "Welcome1!", content)
            for path, content in documents
            if "Welcome1!" in content
        ]

    monkeypatch.setattr(gitleaks, "find_binary", lambda: "gitleaks")
    monkeypatch.setattr(gitleaks, "scan", scan)
    return batches


def zipped(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def in_memory(path: str, data: bytes) -> SourceFile:
    return SourceFile(path, len(data), partial(io.BytesIO, data))


def test_files_that_read_are_scanned_the_others_listed(tmp_path, fake_gitleaks, make_ole):
    (tmp_path / "acces.txt").write_text("password: Welcome1!")
    (tmp_path / "vide.txt").write_text("")
    (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF")
    (tmp_path / "paie.xlsx").write_bytes(make_ole({"EncryptedPackage": b"\0" * 64}))
    (tmp_path / "abime.docx").write_bytes(b"not a zip")

    scan = pipeline.run(folder.walk(tmp_path))

    assert [candidate.path for candidate in scan.candidates] == [str(tmp_path / "acces.txt")]
    assert scan.read == 2
    assert {(u.path[len(str(tmp_path)) + 1 :], u.reason) for u in scan.unread} == {
        ("photo.jpg", extract.BINARY),
        ("paie.xlsx", extract.ENCRYPTED),
        ("abime.docx", pipeline.DAMAGED),
    }
    (damaged,) = [u for u in scan.unread if u.reason == pipeline.DAMAGED]
    assert damaged.detail.startswith("BadZipFile")


def test_a_file_too_large_is_never_opened(fake_gitleaks):
    def explode():
        raise AssertionError("opened")

    big = SourceFile("share/backup.vhdx", pipeline.MAX_FILE_BYTES + 1, explode)
    scan = pipeline.run([big])
    assert [(u.path, u.reason) for u in scan.unread] == [("share/backup.vhdx", pipeline.TOO_LARGE)]


def test_a_file_that_cannot_be_opened_says_why(fake_gitleaks):
    def denied():
        raise PermissionError(13, "Permission denied")

    scan = pipeline.run([SourceFile("share/rh/salaires.txt", 10, denied)])
    (unread,) = scan.unread
    assert (unread.reason, unread.detail) == (pipeline.CANNOT_OPEN, "Permission denied")


def test_a_zip_is_read_like_a_folder_nested_ones_too(fake_gitleaks):
    inner = zipped({"deploy.ps1": b'$password = "Welcome1!"'})
    outer = zipped({"it/": b"", "it/old.zip": inner, "it/notes.txt": b"rien"})

    scan = pipeline.run([in_memory("share/archive.zip", outer)])

    assert [c.path for c in scan.candidates] == ["share/archive.zip/it/old.zip/deploy.ps1"]
    assert scan.read == 2
    assert scan.unread == []


def test_an_encrypted_member_is_listed_not_read(fake_gitleaks):
    data = bytearray(zipped({"secret.txt": b"password: Welcome1!"}))
    central = data.index(b"PK\x01\x02")
    data[central + 8] |= 0x1  # the "encrypted" bit, as a zip made with a password has it

    scan = pipeline.run([in_memory("share/pack.zip", bytes(data))])

    assert [(u.path, u.reason) for u in scan.unread] == [
        ("share/pack.zip/secret.txt", extract.ENCRYPTED)
    ]


def test_a_broken_zip_is_listed_and_the_scan_goes_on(fake_gitleaks):
    scan = pipeline.run(
        [in_memory("share/broken.zip", b"PK nope"), in_memory("share/a.txt", b"Welcome1!")]
    )
    assert [(u.path, u.reason) for u in scan.unread] == [("share/broken.zip", pipeline.DAMAGED)]
    assert [c.path for c in scan.candidates] == ["share/a.txt"]


def test_texts_go_to_gitleaks_in_batches(monkeypatch, fake_gitleaks):
    monkeypatch.setattr(pipeline, "_BATCH_FILES", 2)
    files = [in_memory(f"share/{name}.txt", b"Welcome1!") for name in "edcba"]

    scan = pipeline.run(files)

    assert [len(batch) for batch in fake_gitleaks] == [2, 2, 1]
    # found batch by batch, handed back in path order
    assert [c.path for c in scan.candidates] == [f"share/{name}.txt" for name in "abcde"]


def test_progress_counts_every_file_zip_members_included(fake_gitleaks):
    seen = []
    archive = zipped({"a.txt": b"x", "b.txt": b"y"})
    pipeline.run([in_memory("pack.zip", archive), in_memory("c.txt", b"z")], progress=seen.append)
    assert seen == [1, 2, 3]


def test_no_gitleaks_stops_the_scan_before_it_reads_anything(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)

    def explode():
        raise AssertionError("opened")

    with pytest.raises(gitleaks.GitleaksError, match="releases"):
        pipeline.run([SourceFile("share/a.txt", 1, explode)])


# the real thing: Office files and a zip, through the real gitleaks
@needs_gitleaks
def test_passwords_inside_documents_are_found(tmp_path):
    cell = "<w:tc><w:p><w:r><w:t>{}</w:t></w:r></w:p></w:tc>"
    cells = "".join(
        "<w:tr>" + "".join(cell.format(text) for text in row) + "</w:tr>"
        for row in (["Login", "Mot de passe"], ["admin", "Marseille13!"])
    )
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    document = f'<w:document xmlns:w="{ns}"><w:body><w:tbl>{cells}</w:tbl></w:body></w:document>'
    word = zipped({"word/document.xml": document.encode()})
    (tmp_path / "comptes.docx").write_bytes(word)
    (tmp_path / "export.csv").write_bytes(b"url,username,password\nhttps://intra,svc,Soleil2024\n")
    (tmp_path / "old.zip").write_bytes(zipped({"db.txt": b"postgres://app:Hiver-2023@db:5432/app"}))

    scan = pipeline.run(folder.walk(tmp_path))

    found = {(c.path[len(str(tmp_path)) + 1 :], c.match) for c in scan.candidates}
    assert found == {
        ("comptes.docx", "Marseille13!"),
        ("export.csv", "Soleil2024"),
        ("old.zip/db.txt", "Hiver-2023"),
    }
