"""Adapter for PDF files — character-level hidden-content detection.

PDF is the format requiring the most careful, character-level inspection
for hidden content.  Two of the three signals used here are *inferred*
(invisibility is deduced from other properties), while one is *explicit*
(a formal rendering instruction).

Three independent signals are checked per character:

1. **Colour matching** *(inferred, confidence 0.75)*: A character whose
   fill colour matches (or is very close to) the inferred page
   background colour is likely camouflaged text — invisible to a human
   reader but fully extractable by any text-extraction tool.

2. **Invisible rendering mode** *(explicit, confidence 0.9)*: PDF text
   rendering mode 3 is defined by the PDF spec as "invisible" — text is
   present in the content stream but *explicitly* not rendered.  This is
   a formal rendering instruction, structurally equivalent to Word's
   ``font.hidden`` attribute — the format is directly telling us the
   text is invisible, not something we infer.  ``pdfplumber`` exposes
   this via character properties when available; when the property is
   absent (some PDF producers don't emit it), this *specific check* is
   skipped — but colour-matching and off-page checks still run
   independently.

3. **Off-page positioning** *(inferred, confidence 0.75)*: Characters
   positioned outside the page's visible boundary are not visible in any
   normal viewer.

Adjacent hidden characters on the same line are merged into spans before
being added to ``hidden_spans``, rather than flagged character-by-
character.

**Requires:** ``pdfplumber`` — install via ``pip install okf-guard[pdf]``.
"""

from __future__ import annotations

import io
import os

from okfguard.adapters.base import SourceAdapter, _utc_now_iso
from okfguard.core.models import ExtractedContent

# Colour-matching tolerance per channel (out of 255) to accommodate
# PDF anti-aliasing and compression artifacts.
_COLOUR_TOLERANCE = 10


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

def _normalise_pdf_colour(raw: object) -> tuple[int, int, int] | None:
    """Convert a pdfplumber colour value to an ``(R, G, B)`` tuple.

    pdfplumber represents colours differently depending on the PDF's
    colour space:

    - DeviceGray: a single float (0 = black, 1 = white)
    - DeviceRGB: a 3-tuple of floats in [0, 1]
    - DeviceCMYK: a 4-tuple of floats in [0, 1]

    Returns ``None`` if the value cannot be interpreted.
    """
    if raw is None:
        return None

    if isinstance(raw, (int, float)):
        v = int(round(float(raw) * 255))
        return (v, v, v)

    if isinstance(raw, (tuple, list)):
        if len(raw) == 1:
            v = int(round(float(raw[0]) * 255))
            return (v, v, v)
        if len(raw) == 3:
            return (
                int(round(float(raw[0]) * 255)),
                int(round(float(raw[1]) * 255)),
                int(round(float(raw[2]) * 255)),
            )
        if len(raw) == 4:
            c, m, y, k = (float(x) for x in raw)
            return (
                int(round(255 * (1 - c) * (1 - k))),
                int(round(255 * (1 - m) * (1 - k))),
                int(round(255 * (1 - y) * (1 - k))),
            )

    return None


def _colours_close(
    c1: tuple[int, int, int],
    c2: tuple[int, int, int],
) -> bool:
    """Return ``True`` if two RGB colours are within tolerance."""
    return all(abs(a - b) <= _COLOUR_TOLERANCE for a, b in zip(c1, c2))


# ---------------------------------------------------------------------------
# Page-level helpers
# ---------------------------------------------------------------------------

def _infer_page_bg(page: object) -> tuple[int, int, int]:
    """Infer page background colour from large background-fill rectangles.

    Defaults to white ``(255, 255, 255)`` if no explicit background is
    detected — matching the rendering default for the vast majority of
    PDF documents.
    """
    try:
        rects = getattr(page, "rects", None) or []
        page_w = float(getattr(page, "width", 0))
        page_h = float(getattr(page, "height", 0))
        page_area = page_w * page_h
        if page_area <= 0:
            return (255, 255, 255)

        for rect in rects:
            rx0 = float(rect.get("x0", 0))
            ry0 = float(rect.get("top", 0))
            rx1 = float(rect.get("x1", 0))
            ry1 = float(rect.get("bottom", 0))
            rect_area = (rx1 - rx0) * (ry1 - ry0)
            if rect_area >= page_area * 0.9:
                fill = rect.get("non_stroking_color") or rect.get("fill")
                colour = _normalise_pdf_colour(fill)
                if colour is not None:
                    return colour
    except Exception:
        # If rect inspection fails for any reason, fall back to white.
        pass

    return (255, 255, 255)


# ---------------------------------------------------------------------------
# Character-level hidden detection
# ---------------------------------------------------------------------------

def _check_char_hidden(
    char: dict[str, object],
    page_width: float,
    page_height: float,
    bg_colour: tuple[int, int, int],
) -> str | None:
    """Determine whether a single PDF character is hidden.

    Returns a human-readable reason string if hidden, ``None`` if
    visible.  All three checks (colour, rendermode, position) are
    independent — any one of them is sufficient to classify the
    character as hidden.
    """
    # 1. Colour matching — INFERRED signal (confidence 0.75).
    #    We deduce invisibility from the colour being close to
    #    the background.  Always runs regardless of rendermode.
    fill = char.get("non_stroking_color") or char.get("color")
    char_colour = _normalise_pdf_colour(fill)
    if char_colour is not None and _colours_close(char_colour, bg_colour):
        return "colour matches background"

    # 2. Invisible rendering mode — EXPLICIT signal (confidence 0.9).
    #    PDF rendering mode 3 is a formal instruction defined by the
    #    PDF spec that explicitly marks text as invisible.  This is
    #    structurally equivalent to Word's font.hidden: the format
    #    itself is directly saying "this text is not rendered," not
    #    something we infer from other properties.
    #    Only checked when the property is present.  Absence is
    #    genuinely ambiguous — many PDF producers don't emit it —
    #    and skipping this single signal when absent is correct.
    #    Colour and position checks still run independently.
    # 
    #    COVERAGE GAP: This specific check is currently untested in the v0.1.0 test suite.
    #    The pdfminer.six/pdfplumber stack does not reliably expose the PDF text-rendering
    #    mode at the character level across all PDF producers, and our reportlab-based 
    #    fixture generation tooling could not be made to reliably produce a testable 
    #    rendermode-3 character that pdfplumber could see. We retain this check because 
    #    some PDF producers may expose it, but PDF hidden-text detection in practice 
    #    currently relies primarily on the color-matching and off-page checks (which are fully tested).
    rendermode = char.get("rendermode")
    if rendermode is not None:
        try:
            if int(rendermode) == 3:  # type: ignore[arg-type,call-overload]
                return "invisible rendering mode (mode 3)"
        except (ValueError, TypeError):
            pass

    # 3. Off-page positioning — INFERRED signal (confidence 0.75).
    #    We deduce invisibility from position relative to the page
    #    boundary.  Always runs.
    # pdfplumber chars are untyped dictionaries returning object.
    x0 = float(char.get("x0", 0))  # type: ignore[arg-type]
    x1 = float(char.get("x1", 0))  # type: ignore[arg-type]
    top = float(char.get("top", 0))  # type: ignore[arg-type]
    bottom = float(char.get("bottom", 0))  # type: ignore[arg-type]
    if x1 < 0 or x0 > page_width or bottom < 0 or top > page_height:
        return "positioned outside page boundary"

    return None


# ---------------------------------------------------------------------------
# Span grouping
# ---------------------------------------------------------------------------

def _group_hidden_chars(
    hidden_chars: list[tuple[dict[str, object], str]],
    page_number: int,
) -> list[str]:
    """Merge adjacent hidden characters on the same line into spans.

    Returns formatted hidden-span strings with location info, e.g.
    ``"[page 2, approx. x=72.0, y=340.5 — colour matches background]
    the hidden text"``.
    """
    if not hidden_chars:
        return []

    spans: list[str] = []
    current_text: list[str] = []
    current_reason = ""
    current_top: float | None = None
    current_x0: float | None = None
    line_tolerance = 2.0  # points — chars within this vertical distance
    # are considered "same line"

    for char_dict, reason in hidden_chars:
        char_text = str(char_dict.get("text", ""))
        # pdfplumber chars are untyped dictionaries returning object.
        char_top = float(char_dict.get("top", 0))  # type: ignore[arg-type]
        char_x0 = float(char_dict.get("x0", 0))  # type: ignore[arg-type]

        if (
            current_top is not None
            and abs(char_top - current_top) <= line_tolerance
            and reason == current_reason
        ):
            current_text.append(char_text)
        else:
            # Flush previous span
            if current_text:
                spans.append(_format_span(
                    page_number, current_x0 or 0, current_top or 0,
                    current_reason, "".join(current_text),
                ))
            current_text = [char_text]
            current_reason = reason
            current_top = char_top
            current_x0 = char_x0

    # Flush final span
    if current_text:
        spans.append(_format_span(
            page_number, current_x0 or 0, current_top or 0,
            current_reason, "".join(current_text),
        ))

    return spans


def _format_span(
    page: int, x: float, y: float, reason: str, text: str,
) -> str:
    """Format a hidden span with location and mechanism info."""
    return (
        f"[page {page}, approx. x={round(x, 1)}, y={round(y, 1)}"
        f" — {reason}] {text}"
    )


# ---------------------------------------------------------------------------
# PDFAdapter
# ---------------------------------------------------------------------------

class PDFAdapter(SourceAdapter):
    """Extract visible text and detect hidden content in PDF files.

    Uses ``pdfplumber``'s character-level inspection to identify text
    that is present in the PDF content stream but invisible to a human
    reader, then uses ``pdfplumber``'s built-in text extraction for
    visible text (preserving normal reading order without hand-rolling
    layout analysis).

    **Requires:** ``pdfplumber``.
    Install via ``pip install okf-guard[pdf]``.
    """

    @property
    def format_name(self) -> str:
        """Return ``'pdf'``."""
        return "pdf"

    def extract(self, source: str | bytes) -> ExtractedContent:
        """Extract content from a PDF file.

        Args:
            source: A file path (``str``) or raw PDF bytes.

        Returns:
            ``ExtractedContent`` with visible text separated from
            hidden spans, plus metadata including page count.

        Raises:
            FileNotFoundError: If *source* is a path that doesn't exist.
            ValueError: If the content cannot be parsed as a valid PDF.
        """
        try:
            import pdfplumber
        except ImportError as exc:
            raise ImportError(
                "PDFAdapter requires 'pdfplumber'.  "
                "Install it with:  pip install okf-guard[pdf]"
            ) from exc

        path: str | None = None

        try:
            if isinstance(source, bytes):
                pdf = pdfplumber.open(io.BytesIO(source))
            elif isinstance(source, str):
                if not os.path.isfile(source):
                    raise FileNotFoundError(
                        f"PDF file not found: {source!r}"
                    )
                path = source
                pdf = pdfplumber.open(source)
            else:
                raise TypeError(
                    f"PDFAdapter.extract() expects str or bytes, "
                    f"got {type(source).__name__}"
                )
        except (FileNotFoundError, TypeError, ImportError):
            raise
        except Exception as exc:
            raise ValueError(f"Failed to parse PDF: {exc}") from exc

        try:
            page_count = len(pdf.pages)
            visible_parts: list[str] = []
            all_hidden: list[str] = []

            for page_idx, page in enumerate(pdf.pages, start=1):
                bg_colour = _infer_page_bg(page)
                page_w = float(page.width)
                page_h = float(page.height)
                chars = page.chars or []

                # --- identify hidden characters ---
                hidden_chars: list[tuple[dict[str, object], str]] = []
                hidden_keys: set[tuple[float, float, str]] = set()

                for char in chars:
                    reason = _check_char_hidden(
                        char, page_w, page_h, bg_colour,
                    )
                    if reason:
                        hidden_chars.append((char, reason))
                        hidden_keys.add((
                            round(float(char.get("x0", 0)), 2),
                            round(float(char.get("top", 0)), 2),
                            str(char.get("text", "")),
                        ))

                all_hidden.extend(
                    _group_hidden_chars(hidden_chars, page_idx)
                )

                # --- extract visible text via pdfplumber's built-in ---
                # Filter the page to exclude hidden chars first, so
                # that `extract_text()` returns only visible content.
                if hidden_keys:
                    excluded = frozenset(hidden_keys)

                    def _keep(
                        obj: dict[str, object],
                        _ex: frozenset[tuple[float, float, str]] = excluded,
                    ) -> bool:
                        if obj.get("object_type") != "char":
                            return True
                        key = (
                            # pdfplumber objects are untyped dictionaries.
                            round(float(obj.get("x0", 0)), 2),  # type: ignore[arg-type]
                            round(float(obj.get("top", 0)), 2),  # type: ignore[arg-type]
                            str(obj.get("text", "")),
                        )
                        return key not in _ex

                    page_text = page.filter(_keep).extract_text() or ""
                else:
                    page_text = page.extract_text() or ""

                if page_text.strip():
                    visible_parts.append(page_text)
        finally:
            pdf.close()

        metadata: dict[str, str] = {
            "format": self.format_name,
            "extracted_at": _utc_now_iso(),
            "page_count": str(page_count),
        }
        if path is not None:
            metadata["path"] = path

        return ExtractedContent(
            text="\n\n".join(visible_parts),
            hidden_spans=all_hidden,
            source_metadata=metadata,
        )
