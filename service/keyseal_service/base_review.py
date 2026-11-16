"""What changed in a PDF since the copy a signer was given (the base)."""

from __future__ import annotations

import hashlib
import io
from collections.abc import Collection
from typing import Any

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.form_tools import enumerate_fields_in
from pyhanko.pdf_utils.misc import PdfReadError
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import (
    DEFAULT_DIFF_POLICY,
    FormUpdatingRule,
    GenericFieldModificationRule,
    SigFieldCreationRule,
    SigFieldModificationRule,
    StandardDiffPolicy,
    SuspiciousModification,
)
from pyhanko.sign.diff_analysis.constants import ACROFORM_EXEMPT_STRICT_COMPARISON

#: pyHanko's default policy, except that a non-signature field's existing
#: appearance stream can't be rewritten in place. pyHanko (0.37, 0.38) counts
#: every such stream written before the signed revision as rewritten, so a
#: signature that locks a filled text field would fail once anyone else
#: fills or signs later. A changed appearance must be a new stream instead.
#: The first signature also turns /SigFlags from 1 to 3 (append only), which
#: the review from the copy a signer was given has to allow.
DIFF_POLICY = StandardDiffPolicy(
    global_rules=DEFAULT_DIFF_POLICY.global_rules,
    form_rule=FormUpdatingRule(
        field_rules=[
            SigFieldCreationRule(),
            SigFieldModificationRule(),
            GenericFieldModificationRule(allow_in_place_appearance_stream_changes=False),
        ],
        ignored_acroform_keys=ACROFORM_EXEMPT_STRICT_COMPARISON | {"/SigFlags"},
    ),
)

#: Deeper field trees than this count as malformed.
MAX_FIELD_DEPTH = 64


def _field_chain(widget: generic.DictionaryObject) -> list[generic.DictionaryObject]:
    """The widget and its ancestors up the field tree. A /Parent that loops,
    or a tree deeper than MAX_FIELD_DEPTH, is malformed and stops the walk,
    so a crafted PDF can't keep the service busy forever."""
    chain: list[generic.DictionaryObject] = []
    seen: set[int] = set()
    node: generic.DictionaryObject | None = widget
    while node is not None and id(node) not in seen:
        if len(chain) == MAX_FIELD_DEPTH:
            raise PdfReadError("Field tree too deep")
        seen.add(id(node))
        chain.append(node)
        node = node["/Parent"] if "/Parent" in node else None
    if node is not None:
        raise PdfReadError("Field tree loops")
    return chain


def _field_name(widget: generic.DictionaryObject) -> str:
    """The fully qualified name of the field a widget belongs to."""
    parts = [str(node["/T"]) for node in _field_chain(widget) if "/T" in node]
    return ".".join(reversed(parts))


#: A field's links to the page and form tree, which the walk doesn't follow.
TREE_KEYS = {"/P", "/Parent", "/Kids"}
#: What signing a prepared signature field changes on it.
SIGNING_KEYS = {"/V", "/AP"}


def _digest_object(
    obj: generic.PdfObject,
    digest: Any,
    path: frozenset[tuple[int, int]],
    digests: dict[tuple[int, int], bytes],
) -> None:
    """Feeds an object's resolved content to the digest, whatever objects hold
    it. Each indirect object is resolved once, its digest kept in `digests`:
    expanded again wherever it is shared, objects that each refer twice to the
    next would take exponential time."""
    if isinstance(obj, generic.IndirectObject):
        ref = (obj.idnum, obj.generation)
        if ref in path:
            digest.update(b"<cycle>")
            return
        if ref not in digests:
            inner = hashlib.sha256()
            _digest_object(obj.get_object(), inner, path | {ref}, digests)
            digests[ref] = inner.digest()
        digest.update(digests[ref])
    elif isinstance(obj, generic.DictionaryObject):
        digest.update(b"<<")
        for key in sorted(obj):
            digest.update(repr(key).encode())
            _digest_object(obj.raw_get(key), digest, path, digests)
        digest.update(b">>")
        if isinstance(obj, generic.StreamObject):
            digest.update(b"stream")
            digest.update(obj.encoded_data)
    elif isinstance(obj, generic.ArrayObject):
        digest.update(b"[")
        for index in range(len(obj)):
            _digest_object(obj.raw_get(index), digest, path, digests)
        digest.update(b"]")
    else:
        digest.update(f"{type(obj).__name__}:{obj!r};".encode())


def _rendering(
    widget: generic.DictionaryObject,
    signed: bool,
    digests: dict[tuple[int, int], bytes],
) -> str:
    """A digest of everything about a widget and its field that decides how it
    shows: flags, rect, appearance streams and their resources, /MK, /DA, /Ff
    and the rest. A field signed since may change only its value and appearance."""
    digest = hashlib.sha256()
    skipped = TREE_KEYS | (SIGNING_KEYS if signed else set())
    for node in _field_chain(widget):
        for key in sorted(k for k in node if k not in skipped):
            digest.update(repr(key).encode())
            _digest_object(node.raw_get(key), digest, frozenset(), digests)
        digest.update(b"|")
    return digest.hexdigest()


def _widgets(
    reader: PdfFileReader, signed: Collection[str] = ()
) -> list[tuple[str, int, tuple[float, ...], str]]:
    """Every form field widget on a page: field name, 0-based page, /Rect
    (normalised) and a digest of how it renders (`signed` fields aside)."""
    found: list[tuple[str, int, tuple[float, ...], str]] = []
    digests: dict[tuple[int, int], bytes] = {}
    for index in range(int(reader.root["/Pages"]["/Count"])):
        page = reader.find_page_for_modification(index)[0].get_object()
        for ref in page["/Annots"] if "/Annots" in page else ():
            annot = ref.get_object()
            if "/Subtype" not in annot or annot["/Subtype"] != "/Widget":
                continue
            x1, y1, x2, y2 = (float(v) for v in annot["/Rect"])
            rect = (min(x1, x2), min(y1, y2), max(x1, x2), max(y1, y2))
            name = _field_name(annot)
            found.append((name, index, rect, _rendering(annot, name in signed, digests)))
    return found


def signature_fields(reader: PdfFileReader, signed_only: bool = False) -> set[str]:
    try:
        fields = reader.root["/AcroForm"]["/Fields"]
    except KeyError:
        return set()
    return {
        name
        for name, value, _ in enumerate_fields_in(
            fields, refs_seen=set(), target_field_type="/Sig"
        )
        if value is not None or not signed_only
    }


def changes_since(reader: PdfFileReader, data: bytes, base_length: int) -> str:
    """The most the revisions appended to the first `base_length` bytes change.

    pyHanko only judges changes made after a signature, so a first signer could
    otherwise rewrite the text in the revision their signature covers. It also
    counts a new signature field's widget, and a new appearance, flags or
    look for an unsigned field's widget, as form filling, so the widgets must
    be the ones the base had, each rendering as it did (a field signed since
    may change only its value and appearance).
    """
    try:
        base = PdfFileReader(io.BytesIO(data[:base_length]), strict=False)
        last = base.xrefs.total_revisions - 1
        # The appended update must build on the base's last revision.
        if reader.xrefs.get_startxref_for_revision(
            last
        ) != base.xrefs.get_startxref_for_revision(last):
            return "OTHER"
        result = DIFF_POLICY.review_file(reader, last)
        signed_since = signature_fields(reader, signed_only=True) - signature_fields(
            base, signed_only=True
        )
        before = sorted(_widgets(base, signed_since))
        after = sorted(_widgets(reader, signed_since))
        # Asked to, a viewer redraws every field from its value and /DR.
        redraw_before, redraw_after = (
            str(r.root["/AcroForm"].get("/NeedAppearances", False))
            for r in (base, reader)
        )
    except Exception:  # noqa: BLE001 - unreadable counts as changed
        return "OTHER"
    if (
        isinstance(result, SuspiciousModification)
        or before != after
        or redraw_before != redraw_after
    ):
        return "OTHER"
    return result.modification_level.name
