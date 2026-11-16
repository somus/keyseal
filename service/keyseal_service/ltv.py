"""Long-term validation of a signed PDF (PAdES B-LTA).

`finalize` makes a fully signed PDF long-term verifiable: revocation data
for every signature and a document timestamp. `retimestamp` adds another
document timestamp before the last one's certificate expires.
"""

from __future__ import annotations

import io

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, timestamps
from pyhanko.sign.validation import async_add_validation_info
from pyhanko_certvalidator import ValidationContext

from . import validate
from .prepare import ENCRYPTED
from .remote_sign import MD, RemoteSignError


async def finalize(
    pdf: bytes,
    timestamper: timestamps.TimeStamper,
    validation_context: ValidationContext,
) -> bytes:
    """Adds revocation data for every signature and a document timestamp (B-LTA).

    Each signature's data is its own incremental update, written over a fresh
    parse of the PDF, so the work grows with the square of the signatures:
    a PDF with more than `validate.MAX_SIGNATURES`, or a run past the
    validation budget, raises `ValidationLimitError`."""
    buf = io.BytesIO(pdf)
    reader = PdfFileReader(io.BytesIO(pdf))
    if reader.encrypted:
        raise RemoteSignError(ENCRYPTED)
    count = len(reader.embedded_signatures)
    if count > validate.MAX_SIGNATURES:
        raise validate.ValidationLimitError(f"More than {validate.MAX_SIGNATURES} signatures")
    async with validate.within_budget("Finalising"):
        for index in range(count):
            reader = PdfFileReader(buf)
            sig = reader.embedded_signatures[index]
            out = io.BytesIO()
            await async_add_validation_info(sig, validation_context, output=out)
            buf = io.BytesIO(out.getvalue())
        writer = IncrementalPdfFileWriter(buf)
        out = io.BytesIO()
        await signers.PdfTimeStamper(timestamper).async_timestamp_pdf(
            writer,
            md_algorithm=MD,
            validation_context=validation_context,
            output=out,
        )
    return out.getvalue()


async def retimestamp(
    pdf: bytes,
    timestamper: timestamps.TimeStamper,
    validation_context: ValidationContext,
) -> bytes:
    """Adds revocation data for the last timestamp and a new document
    timestamp; a run past the validation budget raises `ValidationLimitError`."""
    reader = PdfFileReader(io.BytesIO(pdf))
    if reader.encrypted:
        raise RemoteSignError(ENCRYPTED)
    out = io.BytesIO()
    async with validate.within_budget("Timestamping"):
        await signers.PdfTimeStamper(timestamper).async_update_archival_timestamp_chain(
            reader, validation_context, output=out
        )
    return out.getvalue()
