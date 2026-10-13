"""Read the streams of an OLE compound file: the container of .doc, .xls, .ppt and .msg.

The format is a small file system inside the file: fixed-size sectors, a table
chaining them (the FAT), a directory naming the streams, and a second, finer
level (the mini stream) for streams under 4 KB. Spec: [MS-CFB].
"""

import struct

MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# sector numbers at or above this are markers (end of chain, free, FAT...), not sectors
_LAST_SECTOR = 0xFFFFFFFA
_NO_ENTRY = 0xFFFFFFFF
_STORAGE, _STREAM, _ROOT = 1, 2, 5


class OleFile:
    """The streams of one compound file, by path: "WordDocument", "__attach_.../__substg...".

    Raises ValueError on anything that doesn't hold together: a damaged file.
    """

    def __init__(self, data: bytes):
        if not data.startswith(MAGIC) or len(data) < 512:
            raise ValueError("not an OLE compound file")
        self._data = data
        sector_shift, mini_shift = struct.unpack_from("<HH", data, 0x1E)
        if not (7 <= sector_shift <= 16 and 2 <= mini_shift <= sector_shift):
            raise ValueError("odd sector sizes")
        self._sector = 1 << sector_shift
        self._mini_sector = 1 << mini_shift
        (_, directory_start, _, self._cutoff, minifat_start, _, difat_start, difat_count) = (
            struct.unpack_from("<8I", data, 0x2C)
        )
        self._fat = self._read_fat(difat_start, difat_count)
        directory = self._chain(directory_start)
        self._streams: dict[str, tuple[int, int]] = {}
        root = self._walk_directory(directory)
        self._mini_stream = self._chain(root[0])[: root[1]]
        self._minifat = _uint32s(self._chain(minifat_start))

    def names(self) -> list[str]:
        return list(self._streams)

    def read(self, name: str) -> bytes:
        start, size = self._streams[name]
        if size < self._cutoff:
            return self._chain(start, self._minifat, self._mini_stream, self._mini_sector)[:size]
        return self._chain(start)[:size]

    def _sector_at(self, number: int) -> bytes:
        # sector 0 starts right after the header, which takes one sector
        offset = (number + 1) * self._sector
        if offset >= len(self._data):
            raise ValueError("sector past the end of the file")
        return self._data[offset : offset + self._sector]

    def _read_fat(self, difat_start: int, difat_count: int) -> list[int]:
        # where the FAT sectors are: 109 in the header, the rest in a chain of DIFAT sectors
        locations = list(struct.unpack_from("<109I", self._data, 0x4C))
        sector = difat_start
        for _ in range(difat_count):
            if sector >= _LAST_SECTOR:
                break
            entries = _uint32s(self._sector_at(sector))
            locations += entries[:-1]
            sector = entries[-1]
        fat = []
        for location in locations:
            if location < _LAST_SECTOR:
                fat += _uint32s(self._sector_at(location))
        return fat

    def _chain(
        self,
        start: int,
        table: list[int] | None = None,
        source: bytes | None = None,
        size: int | None = None,
    ) -> bytes:
        """The sectors chained from `start`, end to end. Mini sectors when given a source."""
        table = self._fat if table is None else table
        size = self._sector if size is None else size
        parts = []
        sector = start
        # a loop in the chain would never end: no chain is longer than the table
        for _ in range(len(table) + 1):
            if sector >= _LAST_SECTOR:
                return b"".join(parts)
            if sector >= len(table):
                raise ValueError("chain points past the table")
            if source is None:
                parts.append(self._sector_at(sector))
            else:
                parts.append(source[sector * size : (sector + 1) * size])
            sector = table[sector]
        raise ValueError("chain loops")

    def _walk_directory(self, directory: bytes) -> tuple[int, int]:
        """Fill `_streams` with every stream's path, return the root's (start, size)."""
        entries = [directory[at : at + 128] for at in range(0, len(directory) - 127, 128)]
        if not entries or entries[0][66] != _ROOT:
            raise ValueError("no root entry")
        # (entry, the storage path it sits in). siblings form a tree: left and right
        pending = [(_child(entries[0]), "")]
        seen = set()
        while pending:
            index, folder = pending.pop()
            if index == _NO_ENTRY or index in seen or index >= len(entries):
                continue
            seen.add(index)
            entry = entries[index]
            left, right, child = struct.unpack_from("<3I", entry, 68)
            pending += [(left, folder), (right, folder)]
            path = folder + _name(entry)
            if entry[66] == _STORAGE:
                pending.append((child, path + "/"))
            elif entry[66] == _STREAM:
                self._streams[path] = struct.unpack_from("<II", entry, 116)
        return struct.unpack_from("<II", entries[0], 116)


def _child(entry: bytes) -> int:
    return struct.unpack_from("<I", entry, 76)[0]


def _name(entry: bytes) -> str:
    length = struct.unpack_from("<H", entry, 64)[0]
    return entry[: max(length - 2, 0)].decode("utf-16-le", "replace")


def _uint32s(data: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(data) // 4}I", data[: len(data) // 4 * 4]))
