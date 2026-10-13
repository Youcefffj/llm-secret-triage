import struct

import pytest

from secret_triage.ole import MAGIC

_SECTOR, _MINI, _CUTOFF = 512, 64, 4096
_END, _FREE, _FAT_SECTOR = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD


def _sectors(data: bytes) -> int:
    return -(-len(data) // _SECTOR)


def build_ole(streams: dict[str, bytes]) -> bytes:
    """A compound file holding `streams` at its root, the way Office 97-2003 lays one out:
    streams under 4 KB in the mini stream, the others in regular sectors."""
    mini = bytearray()
    minifat: list[int] = []
    mini_starts = {}
    for name, data in streams.items():
        if len(data) < _CUTOFF:
            count = -(-len(data) // _MINI)
            mini_starts[name] = len(minifat) if count else _END
            minifat += list(range(len(minifat) + 1, len(minifat) + count)) + [_END] * bool(count)
            mini += data.ljust(count * _MINI, b"\0")
    minifat_bytes = struct.pack(f"<{len(minifat)}I", *minifat)

    big = {name: data for name, data in streams.items() if len(data) >= _CUTOFF}
    directory_size = (1 + len(streams)) * 128
    chains = [directory_size, len(minifat_bytes), len(mini)] + [len(d) for d in big.values()]
    total = sum(-(-size // _SECTOR) for size in chains)
    fat_count = 1
    while fat_count * 128 < total + fat_count:
        fat_count += 1

    # sectors: the FAT first, then each chain end to end
    fat = [_FAT_SECTOR] * fat_count
    starts = []
    for size in chains:
        count = -(-size // _SECTOR)
        starts.append(len(fat) if count else _END)
        fat += list(range(len(fat) + 1, len(fat) + count)) + [_END] * bool(count)
    fat += [_FREE] * (fat_count * 128 - len(fat))
    directory_start, minifat_start, mini_start, *big_starts = starts

    def entry(name, kind, start, size, child=_FREE, right=_FREE):
        raw = name.encode("utf-16-le") + b"\0\0"
        return (
            raw.ljust(64, b"\0")
            + struct.pack("<HBB3I", len(raw), kind, 1, _FREE, right, child)
            + b"\0" * 36
            + struct.pack("<IQ", start, size)
        )

    names = list(streams)
    directory = entry("Root Entry", 5, mini_start, len(mini), child=1 if names else _FREE)
    big_start = dict(zip(big, big_starts, strict=True))
    for number, name in enumerate(names, start=1):
        start = big_start[name] if name in big_start else mini_starts[name]
        right = number + 1 if number < len(names) else _FREE
        directory += entry(name, 2, start, len(streams[name]), right=right)

    header = (
        MAGIC
        + b"\0" * 16
        + struct.pack("<5H", 0x3E, 3, 0xFFFE, 9, 6)
        + b"\0" * 6
        + struct.pack("<9I", 0, fat_count, directory_start, 0, _CUTOFF, minifat_start,
                      len(minifat_bytes) // _SECTOR + bool(len(minifat_bytes) % _SECTOR), _END, 0)
        + struct.pack("<109I", *(list(range(fat_count)) + [_FREE] * (109 - fat_count)))
    )
    body = struct.pack(f"<{len(fat)}I", *fat)
    for data in (directory, minifat_bytes, bytes(mini), *big.values()):
        body += data.ljust(_sectors(data) * _SECTOR, b"\0")
    return header + body


@pytest.fixture
def make_ole():
    return build_ole
