import os

import pytest

from secret_triage.sources import folder


def test_every_file_in_name_order_subfolders_included(tmp_path):
    (tmp_path / "it").mkdir()
    (tmp_path / "it" / "deploy.ps1").write_text("x" * 7)
    (tmp_path / "b.txt").write_text("")
    (tmp_path / "a.txt").write_text("abc")

    files = list(folder.walk(tmp_path))

    assert [file.path for file in files] == [
        str(tmp_path / "a.txt"),
        str(tmp_path / "b.txt"),
        str(tmp_path / "it" / "deploy.ps1"),
    ]
    assert [file.size for file in files] == [3, 0, 7]
    with files[0].open() as handle:
        assert handle.read() == b"abc"


def test_a_linked_folder_is_not_followed(tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "notes.txt").write_text("x")
    (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)

    assert [file.path for file in folder.walk(tmp_path)] == [str(tmp_path / "real" / "notes.txt")]


# a folder the account may not list still shows up, so it lands in the unread list
@pytest.mark.skipif(os.geteuid() == 0, reason="root lists every folder")
def test_a_folder_that_cannot_be_listed_comes_out_as_a_file_that_cannot_be_opened(tmp_path):
    locked = tmp_path / "rh"
    locked.mkdir()
    locked.chmod(0)
    try:
        (file,) = folder.walk(tmp_path)
        assert file.path == str(locked)
        with pytest.raises(PermissionError):
            file.open()
    finally:
        locked.chmod(0o700)


def test_something_else_than_a_folder_is_refused(tmp_path):
    with pytest.raises(ValueError, match="not a folder"):
        folder.walk(tmp_path / "nowhere")
