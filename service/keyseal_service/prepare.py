"""Preparing a PDF for signing: one empty signature field per signer."""

from __future__ import annotations

import io
from dataclasses import dataclass

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import MDPPerm, SigFieldSpec, append_signature_field
from pyhanko.sign.validation import read_certification_data

MAX_FIELDS = 20

#: Why a PDF can't take a signature, passed on to the integrator's caller.
ENCRYPTED = "The PDF is encrypted; send a copy without a password or other protection"
CERTIFIED_NO_CHANGES = "The PDF is certified with no changes allowed, so no signature can be added"


@dataclass(frozen=True)
class FieldRequest:
    name: str
    #: 0-based; negative counts from the last page (-1 is the last).
    page: int
    box: tuple[int, int, int, int]


class PrepareError(ValueError):
    pass


def unsignable(reader: PdfFileReader) -> str | None:
    """Why no signature can be added to the PDF, or None when one can."""
    if reader.encrypted:
        return ENCRYPTED
    certification = read_certification_data(reader)
    if certification is not None and certification.permission == MDPPerm.NO_CHANGES:
        return CERTIFIED_NO_CHANGES
    return None


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
        reader = PdfFileReader(io.BytesIO(pdf))
        page_count = int(reader.root["/Pages"]["/Count"])
        reason = unsignable(reader)
    except Exception as error:  # noqa: BLE001
        raise PrepareError("Not a readable PDF") from error
    if reason is not None:
        raise PrepareError(reason)
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
