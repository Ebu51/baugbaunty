"""A tiny, dependency-free PDF writer for text reports.

Rich PDF libraries are heavy dependencies; this renders a paginated, monospaced
text PDF using only the standard library, which is enough to hand someone a
printable .pdf of a report or submission. It embeds no fonts (uses the standard
Helvetica) and keeps the structure minimal but valid.
"""

from __future__ import annotations

from pathlib import Path

_PAGE_W, _PAGE_H = 612, 792      # US Letter, points
_MARGIN = 50
_FONT_SIZE = 9
_LEADING = 11.4
_WRAP = 95                        # characters per line before wrapping


def _escape(text: str) -> str:
    out = text.encode("latin-1", "replace").decode("latin-1")
    return out.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _wrap(lines: list[str]) -> list[str]:
    wrapped: list[str] = []
    for line in lines:
        line = line.rstrip("\n").replace("\t", "    ")
        if not line:
            wrapped.append("")
            continue
        while len(line) > _WRAP:
            wrapped.append(line[:_WRAP])
            line = line[_WRAP:]
        wrapped.append(line)
    return wrapped


def _paginate(lines: list[str]) -> list[list[str]]:
    per_page = int((_PAGE_H - 2 * _MARGIN) / _LEADING)
    return [lines[i:i + per_page] for i in range(0, len(lines), per_page)] or [[]]


def _content_stream(page_lines: list[str]) -> bytes:
    start_y = _PAGE_H - _MARGIN
    parts = ["BT", f"/F1 {_FONT_SIZE} Tf", f"{_LEADING} TL", f"{_MARGIN} {start_y} Td"]
    for line in page_lines:
        parts.append(f"({_escape(line)}) Tj")
        parts.append("T*")
    parts.append("ET")
    return ("\n".join(parts)).encode("latin-1", "replace")


def render_pdf(title: str, lines: list[str], path: str | Path) -> Path:
    pages = _paginate(_wrap(lines))
    n_pages = len(pages)

    # Object IDs: 1 Catalog, 2 Pages, 3 Font, then content + page objects.
    font_id = 3
    content_ids = list(range(4, 4 + n_pages))
    page_ids = list(range(4 + n_pages, 4 + 2 * n_pages))

    objects: dict[int, bytes] = {}
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode()
    objects[font_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    for cid, plines in zip(content_ids, pages):
        stream = _content_stream(plines)
        objects[cid] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode()
            + stream + b"\nendstream"
        )
    for pid, cid in zip(page_ids, content_ids):
        objects[pid] = (
            f"<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
            f"/Contents {cid} 0 R >>"
        ).encode()

    # Serialise with an xref table.
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for oid in sorted(objects):
        offsets[oid] = len(out)
        out += f"{oid} 0 obj\n".encode() + objects[oid] + b"\nendobj\n"

    xref_pos = len(out)
    max_id = max(objects)
    out += f"xref\n0 {max_id + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for oid in range(1, max_id + 1):
        out += f"{offsets.get(oid, 0):010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {max_id + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()

    p = Path(path)
    p.write_bytes(bytes(out))
    return p
