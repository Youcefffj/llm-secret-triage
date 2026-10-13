"""A file's bytes in, its text out, whatever the format, or the reason it can't be read.

Tables come out one row per line, cells joined by " | ", and each row after the
header again, one cell per line under its column name ("Mot de passe: ..."). A
password then sits right after its label whichever way the table was laid out,
which is what the password rule looks for.
"""

import codecs
import csv
import io
import logging
import re
import struct
import warnings
import zipfile
from collections.abc import Callable, Iterator
from pathlib import PurePath
from xml.etree import ElementTree

import pypdf

from . import ole

# why a file was not read, as the scan summary prints it
BINARY = "binary"
ENCRYPTED = "encrypted"
NO_TEXT = "PDF without text (a scan?)"
TOO_LARGE_UNPACKED = "too large once unpacked"

# an Office file is a zip of XML. a part bigger than this is a bomb or a data dump
_MAX_PART = 200 * 1024 * 1024

# an empty spreadsheet row can claim thousands of repeated cells: they carry nothing
_MAX_REPEAT = 1000

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
_TEXT = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
_TABLE = "{urn:oasis:names:tc:opendocument:xmlns:table:1.0}"

# pypdf talks about every odd object it meets. a damaged PDF ends up an exception anyway
logging.getLogger("pypdf").setLevel(logging.ERROR)


class Unreadable(Exception):
    """The file holds no text we can get at. `reason` says why."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def text(path: str, data: bytes) -> str:
    """The text of the file at `path`, picked by its extension, plain text by default."""
    if data.startswith(ole.MAGIC):
        content = _ole(data)
    else:
        content = _READERS.get(PurePath(path).suffix.lower(), _plain)(data)
    # one shape for every format: \n line ends, no NUL (gitleaks would call it binary)
    content = content.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    # a lone surrogate from a broken PDF would make the text unwritable as UTF-8
    return content.encode("utf-8", "replace").decode("utf-8")


def _plain(data: bytes) -> str:
    if data.startswith(codecs.BOM_UTF8):
        return data[len(codecs.BOM_UTF8) :].decode("utf-8", "replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", "replace")
    # images, archives, executables: a NUL byte early on, text never has one
    if b"\x00" in data[:8192]:
        raise Unreadable(BINARY)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # not UTF-8: on a company share, most likely a file saved by Windows
        return data.decode("cp1252", "replace")


def _csv(data: bytes) -> str:
    content = _plain(data)
    try:
        # French Excel writes ; where the rest of the world writes ,
        dialect = csv.Sniffer().sniff(content[:8192], delimiters=",;\t|")
        rows = list(csv.reader(io.StringIO(content), dialect))
    except csv.Error:  # one column, or something that isn't really CSV
        return content
    return "\n".join(_table(rows))


def _table(rows: list[list[str]]) -> list[str]:
    """Every row as one line, then every row after the header again, cell by cell."""
    cleaned = []
    for row in rows:
        cells = [cell.strip() for cell in row]
        while cells and not cells[-1]:  # the empty cells a spreadsheet pads rows with
            cells.pop()
        if cells:
            cleaned.append(cells)
    # the header is the first row with two names in it: a title row above has one
    header = next((row for row in cleaned if sum(map(bool, row)) >= 2), [])
    lines = []
    after_header = False
    for row in cleaned:
        lines.append(" | ".join(row))
        if after_header:
            # a cell past the last header has no name to go with: left to the row line
            pairs = zip(header, row, strict=False)
            lines.extend(f"{name}: {cell}" for name, cell in pairs if name and cell)
        after_header = after_header or row is header
    return lines


def _open_zip(data: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(data))


def _xml(archive: zipfile.ZipFile, name: str) -> ElementTree.Element:
    if archive.getinfo(name).file_size > _MAX_PART:
        raise Unreadable(TOO_LARGE_UNPACKED)
    return ElementTree.fromstring(archive.read(name))


def _parts(archive: zipfile.ZipFile, pattern: str) -> list[str]:
    """The archive's files matching `pattern`, slide2 before slide10."""
    names = [name for name in archive.namelist() if re.fullmatch(pattern, name)]
    return sorted(names, key=_natural)


def _natural(name: str) -> list[int | str]:
    return [int(piece) if piece.isdigit() else piece for piece in re.split(r"(\d+)", name)]


# Word and PowerPoint share the layout: p for a paragraph, tbl/tr/tc for a table
def _ooxml_blocks(
    element: ElementTree.Element, ns: str, paragraph: Callable[[ElementTree.Element], str]
) -> Iterator[str]:
    for child in element:
        if child.tag == ns + "p":
            yield paragraph(child)
        elif child.tag == ns + "tbl":
            rows = [row.findall(ns + "tc") for row in child.findall(ns + "tr")]
            yield from _table(
                [[" ".join(_ooxml_blocks(cell, ns, paragraph)) for cell in row] for row in rows]
            )
        else:
            yield from _ooxml_blocks(child, ns, paragraph)


def _word_paragraph(paragraph: ElementTree.Element) -> str:
    parts = []
    for run in paragraph.iter(_W + "r"):
        for node in run:
            # delText: a deletion with track changes on. still in the file, so still a leak
            if node.tag in (_W + "t", _W + "delText"):
                parts.append(node.text or "")
            elif node.tag == _W + "tab":
                parts.append("\t")
            elif node.tag in (_W + "br", _W + "cr"):
                parts.append("\n")
    return "".join(parts)


def _docx(data: bytes) -> str:
    with _open_zip(data) as archive:
        parts = ["word/document.xml"] + _parts(
            archive, r"word/(header\d*|footer\d*|footnotes|endnotes|comments)\.xml"
        )
        return "\n".join(
            line
            for name in parts
            for line in _ooxml_blocks(_xml(archive, name), _W, _word_paragraph)
        )


def _drawing_paragraph(paragraph: ElementTree.Element) -> str:
    return "".join(
        "\n" if node.tag == _A + "br" else node.text or ""
        for node in paragraph.iter()
        if node.tag in (_A + "t", _A + "br")
    )


def _pptx(data: bytes) -> str:
    with _open_zip(data) as archive:
        parts = _parts(archive, r"ppt/slides/slide\d+\.xml") + _parts(
            archive, r"ppt/notesSlides/notesSlide\d+\.xml"
        )
        return "\n".join(
            line
            for name in parts
            for line in _ooxml_blocks(_xml(archive, name), _A, _drawing_paragraph)
        )


def _xlsx(data: bytes) -> str:
    with _open_zip(data) as archive:
        shared = []
        if "xl/sharedStrings.xml" in archive.namelist():
            strings = _xml(archive, "xl/sharedStrings.xml")
            shared = ["".join(t.text or "" for t in item.iter(_S + "t")) for item in strings]
        lines = []
        for name in _parts(archive, r"xl/worksheets/sheet\d+\.xml"):
            rows = []
            for row in _xml(archive, name).iter(_S + "row"):
                cells: dict[int, str] = {}
                for cell in row.findall(_S + "c"):
                    cells[_column(cell.get("r"), len(cells))] = _cell(cell, shared)
                rows.append([cells.get(index, "") for index in range(max(cells, default=-1) + 1)])
            lines += _table(rows)
        for name in _parts(archive, r"xl/comments\d*\.xml"):
            for comment in _xml(archive, name).iter(_S + "comment"):
                lines.append("".join(t.text or "" for t in comment.iter(_S + "t")))
        return "\n".join(lines)


def _column(reference: str | None, fallback: int) -> int:
    """0 for A1, 27 for AB7: the column of a cell reference."""
    letters = re.match(r"[A-Z]+", reference or "")
    if letters is None:
        return fallback
    index = 0
    for letter in letters.group():
        index = index * 26 + ord(letter) - ord("A") + 1
    return index - 1


def _cell(cell: ElementTree.Element, shared: list[str]) -> str:
    kind = cell.get("t")
    if kind == "inlineStr":
        return "".join(t.text or "" for t in cell.iter(_S + "t"))
    value = cell.findtext(_S + "v") or ""
    return shared[int(value)] if kind == "s" else value


def _odf(data: bytes) -> str:
    with _open_zip(data) as archive:
        return "\n".join(_odf_blocks(_xml(archive, "content.xml")))


def _odf_blocks(element: ElementTree.Element) -> Iterator[str]:
    for child in element:
        if child.tag in (_TEXT + "p", _TEXT + "h"):
            yield _odf_text(child)
        elif child.tag == _TABLE + "table":
            yield from _table(_odf_rows(child))
        else:
            yield from _odf_blocks(child)


def _odf_rows(table: ElementTree.Element) -> list[list[str]]:
    rows = []
    for row in table.iter(_TABLE + "table-row"):
        cells: list[str] = []
        for cell in row:
            if cell.tag in (_TABLE + "table-cell", _TABLE + "covered-table-cell"):
                repeat = int(cell.get(_TABLE + "number-columns-repeated", "1"))
                cells += [" ".join(_odf_blocks(cell))] * min(repeat, _MAX_REPEAT)
        rows.append(cells)
    return rows


def _odf_text(element: ElementTree.Element) -> str:
    # ODF mixes text and tags: "Mot de passe :<text:s/>Soleil" holds the space as a tag
    parts = [element.text or ""]
    for child in element:
        if child.tag == _TEXT + "s":
            parts.append(" ")
        elif child.tag == _TEXT + "tab":
            parts.append("\t")
        elif child.tag == _TEXT + "line-break":
            parts.append("\n")
        else:
            parts.append(_odf_text(child))
        parts.append(child.tail or "")
    return "".join(parts)


def _pdf(data: bytes) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            reader = pypdf.PdfReader(io.BytesIO(data))
            # many PDFs are locked with an empty password, just to stop printing or copying
            if reader.is_encrypted and not reader.decrypt(""):
                raise Unreadable(ENCRYPTED)
            content = "\n".join(page.extract_text() or "" for page in reader.pages)
        # DependencyError: AES, which pypdf can only undo with an extra package
        except (pypdf.errors.FileNotDecryptedError, pypdf.errors.DependencyError) as error:
            raise Unreadable(ENCRYPTED) from error
    if not content.strip():
        raise Unreadable(NO_TEXT)
    return content


def _ole(data: bytes) -> str:
    """Office 97-2003 and Outlook files, told apart by the streams inside, not the name."""
    container = ole.OleFile(data)
    names = set(container.names())
    # a .docx or .ppt saved with a password: what's inside is encrypted
    if "EncryptedPackage" in names or "EncryptedSummary" in names:
        raise Unreadable(ENCRYPTED)
    if "WordDocument" in names:
        return _doc(container)
    if "Workbook" in names or "Book" in names:
        return _xls(container.read("Workbook" if "Workbook" in names else "Book"))
    if "PowerPoint Document" in names:
        return _ppt(container.read("PowerPoint Document"))
    if any(name.rsplit("/", 1)[-1].startswith("__substg1.0_") for name in names):
        return _msg(container)
    raise Unreadable(BINARY)  # Thumbs.db and the like


# Word 97 marks in the text: field brackets become spaces (a field code can hold a
# URL), object anchors go, line and page breaks become line ends
_WORD_MARKS = str.maketrans(
    {
        "\x13": " ", "\x14": " ", "\x15": " ",
        "\x01": None, "\x02": None, "\x05": None, "\x08": None, "\x1f": None,
        "\x0b": "\n", "\x0c": "\n", "\x1e": "-",
    }
)


def _doc(container: ole.OleFile) -> str:
    word = container.read("WordDocument")
    ident, version = struct.unpack_from("<HH", word, 0)
    flags = struct.unpack_from("<H", word, 0x0A)[0]
    if ident != 0xA5EC:
        raise ValueError("not a Word document")
    if flags & 0x0100:  # saved with a password
        raise Unreadable(ENCRYPTED)
    if version < 0x00C0:  # Word 6 and 95: one run of 8-bit text, from fcMin to fcMac
        start, end = struct.unpack_from("<II", word, 0x18)
        content = word[start:end].decode("cp1252", "replace")
    else:
        content = _word97_text(word, container.read("1Table" if flags & 0x0200 else "0Table"))
    return "\n".join(_word_lines(content.translate(_WORD_MARKS)))


def _word97_text(word: bytes, table: bytes) -> str:
    """The text, piece by piece: the piece table says where each run sits and how it's coded."""
    clx_at, clx_size = struct.unpack_from("<II", word, 0x01A2)
    clx = table[clx_at : clx_at + clx_size]
    at = 0
    while at < len(clx) and clx[at] == 0x01:  # formatting entries before the table: skipped
        at += 3 + struct.unpack_from("<H", clx, at + 1)[0]
    if at >= len(clx) or clx[at] != 0x02:
        raise ValueError("no piece table")
    size = struct.unpack_from("<I", clx, at + 1)[0]
    pieces = clx[at + 5 : at + 5 + size]
    count = (len(pieces) - 4) // 12
    positions = struct.unpack_from(f"<{count + 1}I", pieces)
    parts = []
    for index in range(count):
        offset = struct.unpack_from("<I", pieces, 4 * (count + 1) + 8 * index + 2)[0]
        length = positions[index + 1] - positions[index]
        if offset & 0x40000000:  # one byte a char, stored at half the offset
            start = (offset & 0x3FFFFFFF) // 2
            parts.append(word[start : start + length].decode("cp1252", "replace"))
        else:
            parts.append(word[offset : offset + 2 * length].decode("utf-16-le", "replace"))
    return "".join(parts)


def _word_lines(content: str) -> list[str]:
    """A paragraph ends in \\r. In a table, a cell ends in \\x07, a row in a second one."""
    lines = []
    for paragraph in content.split("\r"):
        *rows, rest = paragraph.split("\x07\x07")
        if rows:
            lines += _table([row.split("\x07") for row in rows])
        if rest.strip():
            lines.append(rest.replace("\x07", " | "))
    return lines


def _xls(stream: bytes) -> str:
    """Excel 97-2003 (BIFF8, and the BIFF5 of Excel 95): a stream of typed records."""
    records = []
    at = 0
    while at + 4 <= len(stream):
        kind, length = struct.unpack_from("<HH", stream, at)
        records.append((kind, stream[at + 4 : at + 4 + length]))
        at += 4 + length
    biff8 = bool(records) and records[0][1][:2] == b"\x00\x06"
    shared: list[str] = []
    lines: list[str] = []
    cells: dict[tuple[int, int], str] = {}
    formula_cell = None  # a formula whose text result comes in the next STRING record
    comment = False  # a comment's text comes in the CONTINUE record after its TXO
    for index, (kind, body) in enumerate(records):
        if kind == 0x002F:  # FILEPASS: the rest is encrypted
            raise Unreadable(ENCRYPTED)
        if kind == 0x00FC:  # SST, the shared strings, going on in the CONTINUE records after it
            chunks = [body[8:]]
            for following, more in records[index + 1 :]:
                if following != 0x003C:
                    break
                chunks.append(more)
            shared = _shared_strings(chunks, struct.unpack_from("<I", body, 4)[0])
        elif kind == 0x00FD:  # LABELSST: a cell holding a shared string
            row, column, _, number = struct.unpack_from("<HHHI", body)
            cells[row, column] = shared[number] if number < len(shared) else ""
        elif kind in (0x0204, 0x00D6):  # LABEL, RSTRING: a cell holding its own string
            row, column = struct.unpack_from("<HH", body)
            cells[row, column] = _biff_string(body[6:], biff8)
        elif kind == 0x0203:  # NUMBER
            row, column, _, value = struct.unpack_from("<HHHd", body)
            cells[row, column] = _number(value)
        elif kind == 0x027E:  # RK: a number, packed in 4 bytes
            row, column, _, value = struct.unpack_from("<HHHI", body)
            cells[row, column] = _number(_rk(value))
        elif kind == 0x00BD:  # MULRK: several RK side by side
            row, first = struct.unpack_from("<HH", body)
            for offset in range((len(body) - 6) // 6):
                value = struct.unpack_from("<I", body, 4 + 6 * offset + 2)[0]
                cells[row, first + offset] = _number(_rk(value))
        elif kind == 0x0006:  # FORMULA: its last result is stored with it
            row, column = struct.unpack_from("<HH", body)
            if body[12:14] != b"\xff\xff":
                cells[row, column] = _number(struct.unpack_from("<d", body, 6)[0])
            elif body[6] == 0:
                formula_cell = (row, column)
        elif kind == 0x0207 and formula_cell is not None:  # STRING
            cells[formula_cell] = _biff_string(body, biff8)
            formula_cell = None
        elif kind == 0x003C and comment and body:
            wide = body[0] & 0x01
            lines.append(body[1:].decode("utf-16-le" if wide else "latin-1", "replace"))
        elif kind == 0x000A and cells:  # EOF: the end of a sheet
            rows = sorted({row for row, _ in cells})
            width = max(column for _, column in cells) + 1
            lines += _table([[cells.get((row, col), "") for col in range(width)] for row in rows])
            cells = {}
        comment = kind == 0x01B6  # TXO
    return "\n".join(lines)


def _biff_string(body: bytes, biff8: bool) -> str:
    length = struct.unpack_from("<H", body)[0]
    if not biff8:  # Excel 95: bytes in the Windows code page
        return body[2 : 2 + length].decode("cp1252", "replace")
    if body[2] & 0x01:
        return body[3 : 3 + 2 * length].decode("utf-16-le", "replace")
    return body[3 : 3 + length].decode("latin-1")


def _shared_strings(chunks: list[bytes], count: int) -> list[str]:
    reader = _Continued(chunks)
    strings = []
    for _ in range(count):
        if reader.done():
            break
        length, flags = struct.unpack("<HB", reader.take(3))
        runs = struct.unpack("<H", reader.take(2))[0] if flags & 0x08 else 0
        extra = struct.unpack("<I", reader.take(4))[0] if flags & 0x04 else 0
        strings.append(reader.chars(length, flags & 0x01))
        reader.take(4 * runs + extra)  # formatting runs and phonetic data: skipped
    return strings


class _Continued:
    """Bytes spread over a record and its CONTINUE records.

    Text cut by a record boundary goes on after a fresh flags byte, saying whether
    the rest is one or two bytes a char. Anything else just goes on.
    """

    def __init__(self, chunks: list[bytes]):
        self._chunks = chunks
        self._index = 0
        self._at = 0

    def done(self) -> bool:
        return self._index >= len(self._chunks) or (
            self._index == len(self._chunks) - 1 and self._at >= len(self._chunks[-1])
        )

    def take(self, count: int) -> bytes:
        out = bytearray()
        while len(out) < count:
            while self._at >= len(self._chunk()):
                self._index += 1
                self._at = 0
            piece = self._chunk()[self._at : self._at + count - len(out)]
            out += piece
            self._at += len(piece)
        return bytes(out)

    def chars(self, count: int, wide: int) -> str:
        parts = []
        while True:
            width = 2 if wide else 1
            available = min(count, (len(self._chunk()) - self._at) // width)
            raw = self._chunk()[self._at : self._at + available * width]
            parts.append(raw.decode("utf-16-le" if wide else "latin-1", "replace"))
            self._at += available * width
            count -= available
            if not count:
                return "".join(parts)
            self._index += 1
            self._at = 0
            wide = self.take(1)[0] & 0x01

    def _chunk(self) -> bytes:
        if self._index >= len(self._chunks):
            raise ValueError("shared strings cut short")
        return self._chunks[self._index]


def _number(value: float) -> str:
    # 123456 typed in a cell is stored as 123456.0: written back the way it was typed
    return str(int(value)) if value.is_integer() and abs(value) < 1e15 else repr(value)


def _rk(value: int) -> float:
    if value & 0x02:  # a 30-bit integer
        number = float(struct.unpack("<i", struct.pack("<I", value))[0] >> 2)
    else:  # the top 30 bits of a double
        number = struct.unpack("<d", struct.pack("<Q", (value & 0xFFFFFFFC) << 32))[0]
    return number / 100 if value & 0x01 else number


def _ppt(stream: bytes) -> str:
    """PowerPoint 97-2003: records nested in containers, text in two kinds of atom."""
    texts = []
    at = 0
    while at + 8 <= len(stream):
        version, kind, length = struct.unpack_from("<HHI", stream, at)
        at += 8
        if kind == 0x2F14:  # CryptSession10Container: saved with a password
            raise Unreadable(ENCRYPTED)
        if version & 0x0F == 0x0F:  # a container: its records come next, walk in
            continue
        body = stream[at : at + length]
        at += length
        if kind == 0x0FA0:  # TextCharsAtom
            texts.append(body.decode("utf-16-le", "replace"))
        elif kind == 0x0FA8:  # TextBytesAtom
            texts.append(body.decode("cp1252", "replace"))
    # a slide's text is stored twice, in the outline and on the slide itself
    return "\n".join(dict.fromkeys(texts)).replace("\r", "\n").replace("\x0b", "\n")


def _msg(container: ole.OleFile) -> str:
    """Outlook .msg: every text property, subject, body, recipients, attachment names."""
    texts = []
    for name in sorted(container.names()):
        leaf = name.rsplit("/", 1)[-1]
        if leaf.startswith("__substg1.0_") and leaf[-4:] in ("001F", "001E"):
            encoding = "utf-16-le" if leaf.endswith("001F") else "cp1252"
            texts.append(container.read(name).decode(encoding, "replace"))
    return "\n".join(texts)


_READERS: dict[str, Callable[[bytes], str]] = {
    **dict.fromkeys((".docx", ".docm", ".dotx", ".dotm"), _docx),
    **dict.fromkeys((".xlsx", ".xlsm", ".xltx", ".xltm"), _xlsx),
    **dict.fromkeys((".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"), _pptx),
    **dict.fromkeys((".odt", ".ods", ".odp", ".ott", ".ots", ".otp"), _odf),
    ".pdf": _pdf,
    ".csv": _csv,
    ".tsv": _csv,
}
