import struct

import pytest

from secret_triage.ole import OleFile


def test_small_and_large_streams_come_back_whole(make_ole):
    streams = {
        "small": b"hello",  # under 4 KB: in the mini stream
        "large": bytes(range(256)) * 40,  # 10 KB: in regular sectors
        "empty": b"",
    }
    ole = OleFile(make_ole(streams))
    assert set(ole.names()) == set(streams)
    for name, content in streams.items():
        assert ole.read(name) == content


def test_not_a_compound_file_is_refused():
    with pytest.raises(ValueError, match="not an OLE"):
        OleFile(b"PK\x03\x04 a zip")


# a damaged file whose sector chain points back at itself must not hang the scan
def test_a_chain_that_loops_is_refused(make_ole):
    data = bytearray(make_ole({"large": b"x" * 5000}))
    fat_at = 512  # the FAT is the first sector, right after the header
    first = 2  # sector 0 is the FAT, 1 the directory, then the stream
    struct.pack_into("<I", data, fat_at + 4 * (first + 1), first)  # its 2nd sector leads back
    with pytest.raises(ValueError, match="loops"):
        OleFile(bytes(data)).read("large")
