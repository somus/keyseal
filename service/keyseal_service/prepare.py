"""Preparing a PDF for signing: one empty signature field per signer."""

from __future__ import annotations

import io
from dataclasses import dataclass

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import SigFieldSpec, append_signature_field

MAX_FIELDS = 20


@dataclass(frozen=True)
class FieldRequest:
    name: str
    #: 0-based; negative counts from the last page (-1 is the last).
    page: int
    box: tuple[int, int, int, int]


class PrepareError(ValueError):
    pass


def prepare_fields(pdf: bytes, fields: list[FieldRequest]) -> bytes:
    """Adds the empty signature fields as one incremental update."""
    if not fields:
        raise PrepareError("No fields")
    if len(fields) > MAX_FIELDS:
        raise PrepareError("Too many fields")
    names = [f.name for f in fields]
    if len(set(names)) != len(names):
        raise PrepareError("Field names repeat")
    try:
        page_count = int(PdfFileReader(io.BytesIO(pdf)).root["/Pages"]["/Count"])
    except Exception as error:  # noqa: BLE001
        raise PrepareError("Not a readable PDF") from error
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    for field in fields:
        page = field.page if field.page >= 0 else page_count + field.page
        if not 0 <= page < page_count:
            raise PrepareError(f"No page {field.page} for {field.name}")
        append_signature_field(
            writer,
            SigFieldSpec(
                sig_field_name=field.name,
                on_page=page,
                box=field.box,
            ),
        )
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()
