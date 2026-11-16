"""What changed since the copy a signer was given (`base_review`)."""

from __future__ import annotations

import io
from collections.abc import Callable

import pytest
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader

from keyseal_service import base_review

from .conftest import Pki, blank_pdf, prepared, settings_with, sign, validate_pdf


def _with_looping_widget(pdf: bytes) -> bytes:
    """`pdf` with a widget whose /Parent is itself appended as a revision."""
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    page = writer.find_page_for_modification(0)[0].get_object()
    widget = generic.DictionaryObject(
        {
            generic.NameObject("/Type"): generic.NameObject("/Annot"),
            generic.NameObject("/Subtype"): generic.NameObject("/Widget"),
            generic.NameObject("/Rect"): generic.ArrayObject(
                [generic.NumberObject(n) for n in (0, 0, 10, 10)]
            ),
            generic.NameObject("/T"): generic.TextStringObject("loop"),
        }
    )
    ref = writer.add_object(widget)
    widget[generic.NameObject("/Parent")] = ref
    annots = list(page["/Annots"]) if "/Annots" in page else []
    page[generic.NameObject("/Annots")] = generic.ArrayObject([*annots, ref])
    writer.update_container(page)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def test_a_looping_field_tree_counts_as_changed_instead_of_hanging(pki: Pki) -> None:
    looping = generic.DictionaryObject({generic.NameObject("/T"): generic.TextStringObject("a")})
    looping[generic.NameObject("/Parent")] = looping
    with pytest.raises(PdfReadError):
        base_review._field_name(looping)
    deep = generic.DictionaryObject()
    for _ in range(base_review.MAX_FIELD_DEPTH + 1):
        deep = generic.DictionaryObject({generic.NameObject("/Parent"): deep})
    with pytest.raises(PdfReadError):
        base_review._field_name(deep)

    base = sign(blank_pdf(), pki)
    report = validate_pdf(_with_looping_widget(base), settings_with(pki), len(base))
    assert report["changesSinceBase"] == "OTHER"


def test_a_widget_sharing_objects_is_digested_once_per_object(pki: Pki) -> None:
    base = sign(blank_pdf(), pki)
    writer = IncrementalPdfFileWriter(io.BytesIO(base))
    # Each array refers twice to the next: 2**60 paths, 60 objects.
    node = writer.add_object(generic.ArrayObject())
    for _ in range(60):
        node = writer.add_object(generic.ArrayObject([node, node]))
    widget = generic.DictionaryObject(
        {
            generic.NameObject("/Type"): generic.NameObject("/Annot"),
            generic.NameObject("/Subtype"): generic.NameObject("/Widget"),
            generic.NameObject("/Rect"): generic.ArrayObject(
                [generic.NumberObject(n) for n in (0, 0, 10, 10)]
            ),
            generic.NameObject("/T"): generic.TextStringObject("shared"),
            generic.NameObject("/MK"): node,
        }
    )
    page = writer.find_page_for_modification(0)[0].get_object()
    annots = list(page["/Annots"]) if "/Annots" in page else []
    page[generic.NameObject("/Annots")] = generic.ArrayObject([*annots, writer.add_object(widget)])
    writer.update_container(page)
    out = io.BytesIO()
    writer.write(out)

    report = validate_pdf(out.getvalue(), settings_with(pki), len(base))
    assert report["changesSinceBase"] == "OTHER"


def _updated(pdf: bytes, change: Callable[[IncrementalPdfFileWriter], None]) -> bytes:
    """`pdf` with one incremental update that `change` makes."""
    writer = IncrementalPdfFileWriter(io.BytesIO(pdf))
    change(writer)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def _field(writer: IncrementalPdfFileWriter, name: str) -> generic.DictionaryObject:
    for ref in writer.root["/AcroForm"]["/Fields"]:
        field = ref.get_object()
        if str(field["/T"]) == name:
            return field
    raise KeyError(name)


def _add_text_field(writer: IncrementalPdfFileWriter) -> None:
    """Adds an empty text field `Note`, its own widget, to the first page."""
    page_ref = writer.find_page_for_modification(0)[0]
    page = page_ref.get_object()
    field = writer.add_object(
        generic.DictionaryObject(
            {
                generic.NameObject("/Type"): generic.NameObject("/Annot"),
                generic.NameObject("/Subtype"): generic.NameObject("/Widget"),
                generic.NameObject("/FT"): generic.NameObject("/Tx"),
                generic.NameObject("/T"): generic.TextStringObject("Note"),
                generic.NameObject("/F"): generic.NumberObject(4),
                generic.NameObject("/P"): page_ref,
                generic.NameObject("/Rect"): generic.ArrayObject(
                    [generic.NumberObject(n) for n in (50, 50, 250, 80)]
                ),
            }
        )
    )
    annots = list(page["/Annots"]) if "/Annots" in page else []
    page[generic.NameObject("/Annots")] = generic.ArrayObject([*annots, field])
    writer.update_container(page)
    fields = writer.root["/AcroForm"]["/Fields"]
    fields.append(field)
    writer.update_container(fields)


def test_the_copy_a_signer_was_given_changes_nothing(pki: Pki) -> None:
    base = sign(prepared(), pki, "Signer_a")
    report = validate_pdf(base, settings_with(pki), len(base))
    assert report["changesSinceBase"] == "NONE"
    assert report["baseSignatureFields"] == ["Signer_a", "Signer_b"]


def test_the_first_signer_signing_their_prepared_field_fills_the_form(pki: Pki) -> None:
    base = prepared()
    report = validate_pdf(sign(base, pki, "Signer_a"), settings_with(pki), len(base))
    assert report["changesSinceBase"] == "FORM_FILLING"


def test_the_next_signer_signing_their_prepared_field_fills_the_form(pki: Pki) -> None:
    base = sign(prepared(), pki, "Signer_a")
    report = validate_pdf(sign(base, pki, "Signer_b"), settings_with(pki), len(base))
    assert report["changesSinceBase"] == "FORM_FILLING"
    assert [(s["fieldName"], s["certifies"], s["locks"]) for s in report["signatures"]] == [
        ("Signer_a", False, []),
        ("Signer_b", False, []),
    ]


def test_filling_a_text_field_counts_as_changed(pki: Pki) -> None:
    """pyHanko rates this as form filling. The review is stricter on purpose:
    only a field signed since the base may change its value and appearance."""
    base = sign(_updated(prepared(), _add_text_field), pki, "Signer_a")

    def fill(writer: IncrementalPdfFileWriter) -> None:
        field = _field(writer, "Note")
        appearance = generic.StreamObject(
            {
                generic.NameObject("/Type"): generic.NameObject("/XObject"),
                generic.NameObject("/Subtype"): generic.NameObject("/Form"),
                generic.NameObject("/BBox"): generic.ArrayObject(
                    [generic.NumberObject(n) for n in (0, 0, 200, 30)]
                ),
            },
            stream_data=b"",
        )
        field[generic.NameObject("/V")] = generic.TextStringObject("filled")
        field[generic.NameObject("/AP")] = generic.DictionaryObject(
            {generic.NameObject("/N"): writer.add_object(appearance)}
        )
        writer.update_container(field)

    report = validate_pdf(_updated(base, fill), settings_with(pki), len(base))
    assert report["textFields"] == {"Note": "filled"}
    assert report["changesSinceBase"] == "OTHER"


def test_an_update_that_replaces_the_base_instead_of_following_it_counts_as_changed(
    pki: Pki,
) -> None:
    base = sign(prepared(), pki, "Signer_a")
    signed = sign(base, pki, "Signer_b")
    xrefs = PdfFileReader(io.BytesIO(base)).xrefs
    # The next signer's update points back past the base's last revision,
    # dropping the first signature from the document.
    old = f"/Prev {xrefs.get_startxref_for_revision(2)}".encode()
    new = f"/Prev {xrefs.get_startxref_for_revision(1)}".encode().ljust(len(old))
    update = signed[len(base) :]
    assert update.count(old) == 1
    report = validate_pdf(base + update.replace(old, new), settings_with(pki), len(base))
    assert [s["fieldName"] for s in report["signatures"]] == ["Signer_b"]
    assert report["changesSinceBase"] == "OTHER"


#: pyHanko refuses most of these itself, but counts new flags on a text
#: field's widget as form filling, which only the render digest catches.
@pytest.mark.parametrize("name", ["Signer_b", "Note"])
@pytest.mark.parametrize(
    ("key", "value"),
    [
        (
            "/MK",
            generic.DictionaryObject(
                {
                    generic.NameObject("/BC"): generic.ArrayObject(
                        [generic.NumberObject(n) for n in (1, 0, 0)]
                    )
                }
            ),
        ),
        # Hidden as well as printed.
        ("/F", generic.NumberObject(6)),
    ],
)
def test_a_new_look_for_an_unsigned_field_counts_as_changed(
    pki: Pki, name: str, key: str, value: generic.PdfObject
) -> None:
    base = sign(_updated(prepared(), _add_text_field), pki, "Signer_a")

    def restyle(writer: IncrementalPdfFileWriter) -> None:
        field = _field(writer, name)
        field[generic.NameObject(key)] = value
        writer.update_container(field)

    report = validate_pdf(_updated(base, restyle), settings_with(pki), len(base))
    assert report["changesSinceBase"] == "OTHER"


def test_asking_viewers_to_redraw_the_fields_counts_as_changed(pki: Pki) -> None:
    base = sign(prepared(), pki, "Signer_a")

    def redraw(writer: IncrementalPdfFileWriter) -> None:
        acroform = writer.root["/AcroForm"]
        acroform[generic.NameObject("/NeedAppearances")] = generic.BooleanObject(True)
        writer.update_container(acroform)

    report = validate_pdf(_updated(base, redraw), settings_with(pki), len(base))
    assert report["changesSinceBase"] == "OTHER"


def test_a_new_signature_field_counts_as_changed(pki: Pki) -> None:
    base = sign(prepared(), pki, "Signer_a")
    report = validate_pdf(sign(base, pki, "Signer_c"), settings_with(pki), len(base))
    assert report["changesSinceBase"] == "OTHER"
