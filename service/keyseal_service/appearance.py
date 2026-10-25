"""The built-in stamp: the signer's name large on the left, and "Digitally
signed by", the name, the reason if one was given and the date on the right,
in Geist. The date is in the service's local time, so set `TZ` to show
another zone.
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pyhanko.pdf_utils import layout
from pyhanko.pdf_utils.font.opentype import GlyphAccumulatorFactory
from pyhanko.pdf_utils.text import TextBox, TextBoxStyle
from pyhanko.pdf_utils.writer import BasePdfFileWriter
from pyhanko.stamp.base import BaseStamp, BaseStampStyle

FONT = str(Path(__file__).parent / "fonts" / "Geist-Regular.ttf")
#: The name column's share of the box; the details take the rest.
NAME_SHARE = 0.48
#: The date line's length, so a wrapped reason doesn't shrink the details.
DETAILS_LINE_CHARS = 33


def signed_on(at: datetime) -> str:
    """Acrobat's form: 2026.10.20 10:05:25 +05'30'."""
    offset = at.strftime("%z")
    return at.strftime("%Y.%m.%d %H:%M:%S ") + f"{offset[:3]}'{offset[3:5]}'"


def two_lines(name: str) -> str:
    """Splits a name where its two lines come out most even, as Acrobat does."""
    words = name.split()
    if len(words) < 2:
        return name
    split = min(
        range(1, len(words)),
        key=lambda i: max(len(" ".join(words[:i])), len(" ".join(words[i:]))),
    )
    return f"{' '.join(words[:split])}\n{' '.join(words[split:])}"


def reason_lines(reason: str) -> list[str]:
    """The reason in at most two lines as long as the date's; the signature
    dictionary keeps it whole."""
    return textwrap.wrap(
        f"Reason: {reason}", width=DETAILS_LINE_CHARS, max_lines=2, placeholder=" ..."
    )


def _style(size: int) -> TextBoxStyle:
    return TextBoxStyle(
        font=GlyphAccumulatorFactory(FONT, font_size=size),
        font_size=size,
        leading=round(size * 1.2),
    )


# Rendered large and shrunk into its column, so a long name still fits.
NAME_STYLE = _style(28)
DETAILS_STYLE = _style(10)


@dataclass(frozen=True)
class SignedByStampStyle(BaseStampStyle):
    border_width: int = 0

    def create_stamp(
        self,
        writer: BasePdfFileWriter,
        box: layout.BoxConstraints,
        text_params: dict,
    ) -> SignedByStamp:
        return SignedByStamp(
            writer=writer,
            style=self,
            box=box,
            signer=text_params.get("signer") or "",
            reason=text_params.get("reason") or "",
            at=datetime.now().astimezone(),
        )


class SignedByStamp(BaseStamp):
    def __init__(self, writer, style, box, signer: str, reason: str, at: datetime):
        super().__init__(writer=writer, style=style, box=box)
        self.signer = signer
        self.reason = reason
        self.at = at

    def _column(self, text: str, style: TextBoxStyle, x: float, width: float):
        box = TextBox(style, writer=self.writer, resources=self.resources, box=None)
        box.content = text
        commands = box.render()
        rule = layout.SimpleBoxLayoutRule(
            x_align=layout.AxisAlignment.ALIGN_MIN,
            y_align=layout.AxisAlignment.ALIGN_MID,
            margins=layout.Margins.uniform(4),
            inner_content_scaling=layout.InnerScaling.SHRINK_TO_FIT,
        )
        column = layout.BoxConstraints(width=width, height=self.box.height)
        at = rule.fit(column, box.box.width, box.box.height)
        shifted = layout.Positioning(
            x_pos=at.x_pos + x, y_pos=at.y_pos, x_scale=at.x_scale, y_scale=at.y_scale
        )
        return [b"q", shifted.as_cm(), commands, b"Q"]

    def _render_inner_content(self):
        width = self.box.width
        name_width = width * NAME_SHARE
        reason = reason_lines(self.reason) if self.reason else []
        details = "\n".join(
            ["Digitally signed by", self.signer, *reason, f"Date: {signed_on(self.at)}"]
        )
        return [
            *self._column(two_lines(self.signer), NAME_STYLE, 0, name_width),
            *self._column(details, DETAILS_STYLE, name_width, width - name_width),
        ]
