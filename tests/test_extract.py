import io
import struct
import zipfile

import pypdf
import pytest

from secret_triage import extract

# every file here is built by the test, and every password is made up

W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
S = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
A = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
ODF = (
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
    'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0"'
)


def zipped(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def lines(path: str, data: bytes) -> list[str]:
    return extract.text(path, data).splitlines()


# Word: a paragraph is runs of text, a table is rows of cells of paragraphs
def w_p(text: str) -> str:
    return f'<w:p><w:r><w:t xml:space="preserve">{text}</w:t></w:r></w:p>'


def w_table(*rows: list[str]) -> str:
    cells = ("".join(f"<w:tc>{w_p(cell)}</w:tc>" for cell in row) for row in rows)
    return "<w:tbl>" + "".join(f"<w:tr>{row}</w:tr>" for row in cells) + "</w:tbl>"


def docx(body: str, **parts: str) -> bytes:
    document = f"<w:document {W}><w:body>{body}</w:body></w:document>"
    return zipped({"word/document.xml": document, **parts})


def test_plain_text_comes_back_with_unix_line_ends():
    assert extract.text("notes.txt", b"login: admin\r\npassword: Welcome1!\r\n") == (
        "login: admin\npassword: Welcome1!\n"
    )


def test_a_file_saved_by_windows_reads_too():
    data = "mot de passe d'été : Soleil2024".encode("cp1252")
    assert extract.text("acces.txt", data) == "mot de passe d'été : Soleil2024"


def test_utf16_with_its_bom_reads_too():
    data = "password=Hiver-2023".encode("utf-16")  # what PowerShell's Out-File writes
    assert extract.text("export.txt", data) == "password=Hiver-2023"


def test_a_binary_file_is_not_read():
    with pytest.raises(extract.Unreadable) as raised:
        extract.text("photo.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF")
    assert raised.value.reason == extract.BINARY


def test_word_paragraphs_headers_and_tracked_deletions():
    body = (
        "<w:p><w:r><w:t>MDP wifi</w:t><w:tab/><w:t>: Bonjour2025</w:t></w:r></w:p>"
        # deleted with track changes on: invisible in Word, still in the file
        "<w:p><w:del><w:r><w:delText>password: Soleil2024</w:delText></w:r></w:del></w:p>"
    )
    header = f"<w:hdr {W}>{w_p('Confidentiel')}</w:hdr>"
    assert lines("note.docx", docx(body, **{"word/header1.xml": header})) == [
        "MDP wifi\t: Bonjour2025",
        "password: Soleil2024",
        "Confidentiel",
    ]


def test_a_word_table_with_the_label_beside_the_value():
    table = w_table(["Login", "admin"], ["Password", "Welcome1!"])
    assert "Password | Welcome1!" in lines("serveur.docx", docx(table))


def test_a_word_table_with_the_label_above_the_value():
    table = w_table(["Login", "Mot de passe"], ["admin", "Marseille13!"])
    assert lines("comptes.docx", docx(table)) == [
        "Login | Mot de passe",
        "admin | Marseille13!",
        "Login: admin",
        "Mot de passe: Marseille13!",
    ]


def test_excel_cells_land_under_their_column_even_with_gaps_and_a_title_row():
    strings = (
        f"<sst {S}><si><t>Comptes 2024</t></si><si><t>Application</t></si>"
        "<si><t>Mot de passe</t></si><si><t>intranet</t></si></sst>"
    )
    sheet = (
        f"<worksheet {S}><sheetData>"
        '<row r="1"><c r="A1" t="s"><v>0</v></c></row>'
        '<row r="3"><c r="A3" t="s"><v>1</v></c><c r="C3" t="s"><v>2</v></c></row>'
        '<row r="4"><c r="A4" t="s"><v>3</v></c>'
        '<c r="C4" t="inlineStr"><is><t>Lyon-69007</t></is></c></row>'
        "</sheetData></worksheet>"
    )
    data = zipped({"xl/sharedStrings.xml": strings, "xl/worksheets/sheet1.xml": sheet})
    assert lines("comptes.xlsx", data) == [
        "Comptes 2024",
        "Application |  | Mot de passe",
        "intranet |  | Lyon-69007",
        "Application: intranet",
        "Mot de passe: Lyon-69007",
    ]


def test_powerpoint_slides_in_order_then_the_notes():
    def slide(text):
        return f"<p:sld xmlns:p='urn:p' {A}><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:sld>"

    data = zipped(
        {
            "ppt/slides/slide10.xml": slide("ten"),
            "ppt/slides/slide2.xml": slide("two"),
            "ppt/notesSlides/notesSlide1.xml": slide("pwd: Pa55w0rd"),
        }
    )
    assert lines("demo.pptx", data) == ["two", "ten", "pwd: Pa55w0rd"]


def test_an_opendocument_text_keeps_its_spaces_and_spans():
    content = (
        f"<office:document-content {ODF}><office:body><office:text>"
        "<text:p>Mot de passe :<text:s/><text:span>Soleil2024</text:span></text:p>"
        "</office:text></office:body></office:document-content>"
    )
    assert lines("note.odt", zipped({"content.xml": content})) == ["Mot de passe : Soleil2024"]


def test_an_opendocument_sheet_repeats_cells_where_it_says_so():
    def cell(text, repeat=1):
        return (
            f'<table:table-cell table:number-columns-repeated="{repeat}">'
            f"<text:p>{text}</text:p></table:table-cell>"
        )

    empty = '<table:table-cell table:number-columns-repeated="16000"/>'
    content = (
        f"<office:document-content {ODF}><office:body><office:spreadsheet><table:table>"
        f"<table:table-row>{cell('Login')}{cell('', 2)}{cell('Password')}{empty}"
        "</table:table-row>"
        f"<table:table-row>{cell('admin')}{cell('', 2)}{cell('Hiver-2023')}{empty}"
        "</table:table-row>"
        "</table:table></office:spreadsheet></office:body></office:document-content>"
    )
    assert lines("comptes.ods", zipped({"content.xml": content})) == [
        "Login |  |  | Password",
        "admin |  |  | Hiver-2023",
        "Login: admin",
        "Password: Hiver-2023",
    ]


def test_a_french_csv_is_read_as_a_table():
    data = "Nom;Identifiant;Mot de passe\nintranet;admin;Bonjour2025\n".encode("cp1252")
    assert "Mot de passe: Bonjour2025" in lines("export.csv", data)


def test_a_single_column_csv_is_read_as_it_is():
    assert lines("liste.csv", b"serveur\nsrv-app01\n") == ["serveur", "srv-app01"]


def pdf(text: str) -> bytes:
    """A one-page PDF showing `text`, written by hand: pypdf reads PDFs, it doesn't typeset."""
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET".encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"
        b" /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream), stream),
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return out


def test_a_pdf_gives_its_text():
    assert "Password: Welcome1!" in extract.text("procedure.pdf", pdf("Password: Welcome1!"))


def test_a_pdf_without_text_is_reported_as_such():
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=612, height=792)
    buffer = io.BytesIO()
    writer.write(buffer)
    with pytest.raises(extract.Unreadable) as raised:
        extract.text("scan.pdf", buffer.getvalue())
    assert raised.value.reason == extract.NO_TEXT


def test_a_pdf_locked_with_a_password_is_not_read():
    writer = pypdf.PdfWriter(clone_from=io.BytesIO(pdf("Password: Welcome1!")))
    writer.encrypt("open-sesame", algorithm="RC4-128")
    buffer = io.BytesIO()
    writer.write(buffer)
    with pytest.raises(extract.Unreadable) as raised:
        extract.text("locked.pdf", buffer.getvalue())
    assert raised.value.reason == extract.ENCRYPTED


# Office 97-2003: built field by field, as Word, Excel and PowerPoint write them


def word97(text: str, *, wide: bool = False, flags: int = 0x0200) -> dict[str, bytes]:
    """The streams of a .doc holding `text` in one piece, 1Table as its table stream."""
    fib = bytearray(0x800)
    struct.pack_into("<HH", fib, 0, 0xA5EC, 0x00C1)  # Word's signature, Word 97 format
    struct.pack_into("<H", fib, 0x0A, flags)
    if wide:
        body, offset = text.encode("utf-16-le"), len(fib)
    else:  # one byte a char: the offset is doubled and flagged
        body, offset = text.encode("cp1252"), (len(fib) * 2) | 0x40000000
    pieces = struct.pack("<II", 0, len(text)) + struct.pack("<HIH", 0, offset, 0)
    formatting = b"\x01" + struct.pack("<H", 3) + b"abc"  # skipped on the way to the pieces
    clx = formatting + b"\x02" + struct.pack("<I", len(pieces)) + pieces
    struct.pack_into("<II", fib, 0x01A2, 0, len(clx))
    return {"WordDocument": bytes(fib) + body, "1Table": clx}


def test_an_old_word_file_with_a_table(make_ole):
    text = (
        "Accès serveur\r"
        "Login\x07Mot de passe\x07\x07admin\x07Marseille13!\x07\x07"
        "Voir aussi \x13 HYPERLINK \"https://svc:Hiver-2023@intra\" \x14le wiki\x15\r"
    )
    assert lines("serveurs.doc", make_ole(word97(text))) == [
        "Accès serveur",
        "Login | Mot de passe",
        "admin | Marseille13!",
        "Login: admin",
        "Mot de passe: Marseille13!",
        'Voir aussi   HYPERLINK "https://svc:Hiver-2023@intra"  le wiki ',
    ]


def test_an_old_word_file_stored_two_bytes_a_char(make_ole):
    data = make_ole(word97("Mot de passe d'été : Soleil2024\r", wide=True))
    assert lines("note.doc", data) == ["Mot de passe d'été : Soleil2024"]


def test_an_old_word_file_saved_with_a_password(make_ole):
    with pytest.raises(extract.Unreadable) as raised:
        extract.text("rh.doc", make_ole(word97("x", flags=0x0200 | 0x0100)))
    assert raised.value.reason == extract.ENCRYPTED


def record(kind: int, body: bytes) -> bytes:
    return struct.pack("<HH", kind, len(body)) + body


def label(text: str, flags: int = 0) -> bytes:
    """A string header, as the shared string table starts each one."""
    return struct.pack("<HB", len(text), flags)


def workbook(*sheet: bytes, globals_: bytes = b"") -> bytes:
    bof = struct.pack("<HH", 0x0600, 0x0005) + b"\0" * 12  # BIFF8, workbook globals
    sheet_bof = struct.pack("<HH", 0x0600, 0x0010) + b"\0" * 12  # BIFF8, worksheet
    return (
        record(0x0809, bof) + globals_ + record(0x000A, b"")
        + record(0x0809, sheet_bof) + b"".join(sheet) + record(0x000A, b"")
    )


def cell(kind: int, row: int, column: int, value: bytes) -> bytes:
    return record(kind, struct.pack("<HHH", row, column, 0) + value)


def test_an_old_excel_file_every_kind_of_cell(make_ole):
    # "Mot de passe" is cut by the record boundary, and goes on two bytes a char
    sst = (
        struct.pack("<II", 4, 4)
        + label("Application") + b"Application"
        + label("Mot de passe") + b"Mot de"
    )
    more = (
        b"\x01" + " passe".encode("utf-16-le")
        + label("intranet") + b"intranet"
        + label("Lyon-69007", 0x08) + struct.pack("<H", 1) + b"Lyon-69007" + b"\0" * 4
    )
    labelsst = 0x00FD
    sheet = [
        cell(labelsst, 0, 0, struct.pack("<I", 0)),
        cell(labelsst, 0, 2, struct.pack("<I", 1)),
        cell(labelsst, 1, 0, struct.pack("<I", 2)),
        cell(labelsst, 1, 2, struct.pack("<I", 3)),
        cell(0x0203, 2, 0, struct.pack("<d", 123456.0)),  # NUMBER
        cell(0x027E, 2, 1, struct.pack("<I", (42 << 2) | 0x02)),  # RK, an integer
        # MULRK: 7, then 1.5 from the top half of its double
        record(0x00BD, struct.pack("<HHHIHIH", 3, 0, 0, (7 << 2) | 0x02, 0, 0x3FF80000, 1)),
        cell(0x0006, 3, 2, b"\0" * 6 + b"\xff\xff" + b"\0" * 8),  # FORMULA, text result...
        record(0x0207, label("Soleil2024") + b"Soleil2024"),  # ...given in STRING
        record(0x01B6, b"\0" * 18),  # TXO: a comment, its text next
        record(0x003C, b"\x00mdp: Pa55w0rd"),
    ]
    data = workbook(*sheet, globals_=record(0x00FC, sst) + record(0x003C, more))
    assert lines("comptes.xls", make_ole({"Workbook": data})) == [
        "mdp: Pa55w0rd",
        "Application |  | Mot de passe",
        "intranet |  | Lyon-69007",
        "Application: intranet",
        "Mot de passe: Lyon-69007",
        "123456 | 42",
        "Application: 123456",
        "7 | 1.5 | Soleil2024",
        "Application: 7",
        "Mot de passe: Soleil2024",
    ]


def test_an_old_excel_file_saved_with_a_password(make_ole):
    data = workbook(globals_=record(0x002F, b"\0" * 6))  # FILEPASS
    with pytest.raises(extract.Unreadable) as raised:
        extract.text("paie.xls", make_ole({"Workbook": data}))
    assert raised.value.reason == extract.ENCRYPTED


def atom(kind: int, body: bytes, version: int = 0) -> bytes:
    return struct.pack("<HHI", version, kind, len(body)) + body


def test_an_old_powerpoint_file(make_ole):
    slide = "Mot de passe : Soleil2024".encode("utf-16-le")
    inner = (
        atom(0x0FA0, slide)  # TextCharsAtom
        + atom(0x0FA8, b"pwd: Pa55w0rd\rsecond line")  # TextBytesAtom
        + atom(0x0FA0, slide)  # the same text again, from the outline
        + atom(0x0FF5, b"\0" * 4)  # anything else: skipped
    )
    document = atom(0x03E8, inner, version=0x000F)  # a container holding them
    assert lines("formation.ppt", make_ole({"PowerPoint Document": document})) == [
        "Mot de passe : Soleil2024",
        "pwd: Pa55w0rd",
        "second line",
    ]


def test_an_outlook_message_gives_its_subject_and_body(make_ole):
    data = make_ole(
        {
            "__substg1.0_0037001F": "Accès VPN".encode("utf-16-le"),
            "__substg1.0_1000001F": "identifiant : jdupont\nmot de passe : Bonjour2025".encode(
                "utf-16-le"
            ),
            "__substg1.0_37010102": b"\x00\x01 an attachment's bytes",
        }
    )
    assert lines("RE acces.msg", data) == [
        "Accès VPN",
        "identifiant : jdupont",
        "mot de passe : Bonjour2025",
    ]


def test_a_new_office_file_saved_with_a_password(make_ole):
    data = make_ole({"EncryptionInfo": b"\0" * 8, "EncryptedPackage": b"\0" * 64})
    with pytest.raises(extract.Unreadable) as raised:
        extract.text("salaires.xlsx", data)
    assert raised.value.reason == extract.ENCRYPTED


def test_a_compound_file_that_is_no_document_counts_as_binary(make_ole):
    with pytest.raises(extract.Unreadable) as raised:
        extract.text("Thumbs.db", make_ole({"Catalog": b"\0" * 16}))
    assert raised.value.reason == extract.BINARY
