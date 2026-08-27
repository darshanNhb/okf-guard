"""Adapter for HTML files — extracts visible text and detects CSS-hidden content.

HTML documents can hide text from a human reader through several CSS
mechanisms while keeping that text fully present in the DOM (and
therefore fully readable by any text-extraction tool or AI agent).
This adapter walks the parsed DOM and separates truly visible text from
text hidden via:

- ``display: none``
- ``visibility: hidden``
- ``opacity: 0`` (or any value below 0.05)
- ``font-size: 0`` (or below 1 px / 0.1 em equivalent)
- Off-screen positioning (``position: absolute`` with large negative
  ``left`` / ``top``, threshold: beyond −9999 px)
- Text colour matching background colour exactly (supports hex, named
  CSS colours for common values, and ``rgb()`` / ``rgba()`` syntax)

Only inline ``style`` attributes and simple selectors from ``<style>``
blocks are resolved.  A full CSS cascade / specificity resolution is
explicitly out of scope for v0.1.0 (see spec §8.2).

**Requires:** ``beautifulsoup4`` and ``lxml`` — install via
``pip install okf-guard[html]``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from okfguard.adapters.base import SourceAdapter, _utc_now_iso
from okfguard.core.models import ExtractedContent

if TYPE_CHECKING:
    # These are only needed for type-checking; runtime imports are
    # deferred to avoid a hard dependency.
    import bs4


# ---------------------------------------------------------------------------
# Named CSS colour subset — we only need reliable matching for
# white/black and close variants, since those are the colours most
# commonly abused for text-on-matching-background hiding.  We include
# the full 17 CSS2.1 named colours plus a handful of common extras so
# that legitimate colour use doesn't produce false positives.
# ---------------------------------------------------------------------------

_NAMED_COLOURS: dict[str, tuple[int, int, int]] = {
    "black": (0, 0, 0),
    "silver": (192, 192, 192),
    "gray": (128, 128, 128),
    "grey": (128, 128, 128),
    "white": (255, 255, 255),
    "maroon": (128, 0, 0),
    "red": (255, 0, 0),
    "purple": (128, 0, 128),
    "fuchsia": (255, 0, 255),
    "green": (0, 128, 0),
    "lime": (0, 255, 0),
    "olive": (128, 128, 0),
    "yellow": (255, 255, 0),
    "navy": (0, 0, 128),
    "blue": (0, 0, 255),
    "teal": (0, 128, 128),
    "aqua": (0, 255, 255),
    "transparent": (0, 0, 0),  # treated as black with alpha=0
}

# Regex helpers for CSS value parsing.
_RE_HEX3 = re.compile(r"^#([0-9a-fA-F]{3})$")
_RE_HEX6 = re.compile(r"^#([0-9a-fA-F]{6})$")
_RE_RGB = re.compile(
    r"^rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})"
)
_RE_FONT_SIZE_PX = re.compile(r"([\d.]+)\s*px", re.IGNORECASE)
_RE_FONT_SIZE_EM = re.compile(r"([\d.]+)\s*e[mx]", re.IGNORECASE)
_RE_FONT_SIZE_PT = re.compile(r"([\d.]+)\s*pt", re.IGNORECASE)
_RE_POSITION_PX = re.compile(r"(-?[\d.]+)\s*px", re.IGNORECASE)

# Off-screen threshold: any position component more negative than this
# is treated as intentionally off-screen.  -9999 px is the de-facto
# convention used by CSS "image replacement" techniques and screen-reader
# hacks, so anything at or beyond that magnitude is suspect.
_OFF_SCREEN_THRESHOLD = -9999.0


# ---------------------------------------------------------------------------
# Colour parsing helpers
# ---------------------------------------------------------------------------

def _parse_colour(value: str | None) -> tuple[int, int, int] | None:
    """Parse a CSS colour string into an (R, G, B) tuple, or ``None``.

    Supports hex (3- and 6-digit), ``rgb()`` / ``rgba()`` with integer
    components, and a subset of named CSS colours (see
    ``_NAMED_COLOURS``).  Returns ``None`` for any value that cannot be
    confidently parsed — a false negative (not flagging) is safer than
    a false positive on an ambiguous colour value, since the
    pattern-matching layer provides a second line of defence.
    """
    if value is None:
        return None
    value = value.strip().lower()
    if not value or value in ("inherit", "initial", "unset", "currentcolor"):
        return None

    # Named colour.
    if value in _NAMED_COLOURS:
        return _NAMED_COLOURS[value]

    # Hex — 6 digits.
    m = _RE_HEX6.match(value)
    if m:
        h = m.group(1)
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)

    # Hex — 3 digits (shorthand).
    m = _RE_HEX3.match(value)
    if m:
        h = m.group(1)
        return int(h[0] * 2, 16), int(h[1] * 2, 16), int(h[2] * 2, 16)

    # rgb() / rgba().
    m = _RE_RGB.match(value)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))

    return None


def _colours_match(
    c1: tuple[int, int, int],
    c2: tuple[int, int, int],
    tolerance: int = 5,
) -> bool:
    """Return ``True`` if two RGB colours are within *tolerance* per channel."""
    return all(abs(a - b) <= tolerance for a, b in zip(c1, c2))


# ---------------------------------------------------------------------------
# Style-sheet rule cache (simple selectors only)
# ---------------------------------------------------------------------------

def _build_style_rules(
    soup: bs4.BeautifulSoup,
) -> list[tuple[str, dict[str, str]]]:
    """Extract simple CSS rules from ``<style>`` blocks.

    Returns a list of ``(selector, {property: value})`` pairs.  Only
    tag, ``.class``, and ``#id`` selectors are handled — complex
    combinators and pseudo-selectors are ignored.  This is intentionally
    limited per spec §8.2.
    """
    rules: list[tuple[str, dict[str, str]]] = []
    for style_tag in soup.find_all("style"):
        css_text = style_tag.string or ""
        # Very simple regex-based rule parser — not a full CSS parser.
        for m in re.finditer(
            r"([^{]+)\{([^}]*)\}", css_text, re.DOTALL
        ):
            selector = m.group(1).strip()
            body = m.group(2).strip()
            props: dict[str, str] = {}
            for decl in body.split(";"):
                decl = decl.strip()
                if ":" in decl:
                    prop, val = decl.split(":", 1)
                    prop = prop.strip().lower()
                    val = val.lower().strip()
                    if prop in ("display", "visibility", "opacity", "font-size", "color", "position", "left", "top", "background", "background-color"):
                        # Note: !important previously caused a silent false-pass on display:none.
                        # It is stripped here for evaluated properties only. See test_malformed.py.
                        val = val.replace("!important", "").strip()
                    props[prop] = val
            if props:
                # Handle comma-separated selectors.
                for sel in selector.split(","):
                    rules.append((sel.strip(), props))
    return rules


def _selector_matches(selector: str, tag: bs4.Tag) -> bool:
    """Check whether a simple CSS selector matches *tag*.

    Supports: bare tag name (``div``), class selector (``.foo``),
    ID selector (``#bar``), and tag+class/tag+id combinations
    (``div.foo``, ``div#bar``).  Anything more complex is silently
    ignored (returns ``False``).
    """
    selector = selector.strip()
    if not selector:
        return False

    # ID selector: "#foo" or "tag#foo"
    if "#" in selector:
        parts = selector.split("#", 1)
        tag_part = parts[0]
        id_part = parts[1]
        tag_id = tag.get("id", "")
        if tag_id != id_part:
            return False
        if tag_part and tag.name != tag_part:
            return False
        return True

    # Class selector: ".foo" or "tag.foo"
    if "." in selector:
        parts = selector.split(".", 1)
        tag_part = parts[0]
        class_part = parts[1]
        tag_classes = tag.get("class", [])
        if class_part not in tag_classes:
            return False
        if tag_part and tag.name != tag_part:
            return False
        return True

    # Bare tag name.
    return tag.name == selector


def _get_effective_styles(
    tag: bs4.Tag,
    style_rules: list[tuple[str, dict[str, str]]],
) -> dict[str, str]:
    """Merge inline styles and matching ``<style>`` rules for *tag*.

    Inline styles take precedence over ``<style>`` rules (no specificity
    calculation beyond "inline wins").
    """
    merged: dict[str, str] = {}

    # Apply matching <style> rules first (later rules override earlier).
    for selector, props in style_rules:
        if _selector_matches(selector, tag):
            merged.update(props)

    # Inline style attribute overrides.
    inline = tag.get("style", "")
    if inline:
        # tag.get returns str | list[str], but 'style' is always a string.
        for decl in inline.split(";"):  # type: ignore[union-attr]
            decl = decl.strip()
            if ":" in decl:
                prop, val = decl.split(":", 1)
                prop = prop.strip().lower()
                val = val.lower().strip()
                if prop in ("display", "visibility", "opacity", "font-size", "color", "position", "left", "top", "background", "background-color"):
                    # Note: !important previously caused a silent false-pass on display:none.
                    # It is stripped here for evaluated properties only. See test_malformed.py.
                    val = val.replace("!important", "").strip()
                merged[prop] = val

    return merged


# ---------------------------------------------------------------------------
# Hidden-content detection helpers
# ---------------------------------------------------------------------------

def _is_hidden(
    styles: dict[str, str],
    bg_colour: tuple[int, int, int] | None,
) -> str | None:
    """Determine if an element is hidden based on its effective CSS.

    Returns a short human-readable reason string (e.g.
    ``"display:none"``) if hidden, or ``None`` if the element is
    considered visible.
    """
    # display: none
    if styles.get("display", "").strip() == "none":
        return "display:none"

    # visibility: hidden
    if styles.get("visibility", "").strip() == "hidden":
        return "visibility:hidden"

    # opacity: 0 or very low (< 0.05)
    opacity_str = styles.get("opacity", "").strip()
    if opacity_str:
        try:
            if float(opacity_str) < 0.05:
                return f"opacity:{opacity_str}"
        except ValueError:
            pass

    # font-size: 0 or effectively zero
    font_size_str = styles.get("font-size", "").strip()
    if font_size_str:
        reason = _check_font_size(font_size_str)
        if reason:
            return reason

    # Off-screen positioning
    position = styles.get("position", "").strip()
    if position in ("absolute", "fixed"):
        for prop in ("left", "top"):
            val = styles.get(prop, "").strip()
            if val:
                m = _RE_POSITION_PX.search(val)
                if m:
                    px = float(m.group(1))
                    if px <= _OFF_SCREEN_THRESHOLD:
                        return f"position:{position}; {prop}:{val} (off-screen)"

    # Text colour matching background colour
    if bg_colour is not None:
        fg_raw = styles.get("color", "").strip()
        fg = _parse_colour(fg_raw)
        if fg is not None and _colours_match(fg, bg_colour):
            return f"color matches background ({fg_raw})"

    return None


def _check_font_size(value: str) -> str | None:
    """Return a reason string if *value* represents a near-zero font size."""
    if value == "0" or value == "0px" or value == "0em":
        return f"font-size:{value}"

    m = _RE_FONT_SIZE_PX.search(value)
    if m and float(m.group(1)) < 1.0:
        return f"font-size:{value} (< 1px)"

    m = _RE_FONT_SIZE_EM.search(value)
    if m and float(m.group(1)) < 0.1:
        return f"font-size:{value} (< 0.1em)"

    m = _RE_FONT_SIZE_PT.search(value)
    if m and float(m.group(1)) < 1.0:
        return f"font-size:{value} (< 1pt)"

    return None


def _infer_bg_colour(
    soup: bs4.BeautifulSoup,
    style_rules: list[tuple[str, dict[str, str]]],
) -> tuple[int, int, int]:
    """Infer the page background colour from the ``<body>`` element.

    Falls back to white ``(255, 255, 255)`` if no explicit background
    is found — this matches the browser default and is reasonable for
    the overwhelming majority of HTML documents processed by OKF
    generators.
    """
    body = soup.find("body")
    if body:
        # soup.find can return NavigableString, but <body> is always a Tag.
        styles = _get_effective_styles(body, style_rules)  # type: ignore[arg-type]
        bg_raw = styles.get("background-color") or styles.get("background")
        if bg_raw:
            parsed = _parse_colour(bg_raw)
            if parsed is not None:
                return parsed
    return (255, 255, 255)


def _tag_description(tag: bs4.Tag) -> str:
    """Build a human-readable element description for flag locations."""
    parts = [f"<{tag.name}"]
    tag_id = tag.get("id")
    if tag_id:
        parts.append(f" id='{tag_id}'")
    classes = tag.get("class", [])
    if classes:
        parts.append(f" class='{' '.join(classes)}'")
    parts.append(">")
    return "".join(parts)


# ---------------------------------------------------------------------------
# HTMLAdapter
# ---------------------------------------------------------------------------

class HTMLAdapter(SourceAdapter):
    """Extract visible text and detect CSS-hidden content in HTML.

    Parses the HTML DOM using BeautifulSoup with the ``lxml`` parser and
    walks every text-bearing element, classifying it as visible or hidden
    based on computed CSS properties (inline styles and simple selectors
    from ``<style>`` blocks).

    **Requires:** ``beautifulsoup4`` and ``lxml``.
    Install via ``pip install okf-guard[html]``.
    """

    @property
    def format_name(self) -> str:
        """Return ``'html'``."""
        return "html"

    def extract(self, source: str | bytes) -> ExtractedContent:
        """Extract content from an HTML source.

        Args:
            source: A file path (``str`` ending in ``.html`` /
                ``.htm``), an HTML string, or raw ``bytes``.

        Returns:
            ``ExtractedContent`` with visible text separated from
            CSS-hidden text.

        Raises:
            FileNotFoundError: If *source* is a file path that does
                not exist.
        """
        try:
            from bs4 import BeautifulSoup, Tag
        except ImportError as exc:
            raise ImportError(
                "HTMLAdapter requires 'beautifulsoup4' and 'lxml'.  "
                "Install them with:  pip install okf-guard[html]"
            ) from exc

        path: str | None = None
        html_content: str

        if isinstance(source, bytes):
            html_content = source.decode("utf-8", errors="replace")
        elif isinstance(source, str):
            if self._is_file_path(source):
                if not os.path.isfile(source):
                    raise FileNotFoundError(
                        f"HTML file not found: {source!r}"
                    )
                path = source
                html_content = Path(source).read_text(
                    encoding="utf-8", errors="replace"
                )
            else:
                html_content = source
        else:
            raise TypeError(
                f"HTMLAdapter.extract() expects str or bytes, "
                f"got {type(source).__name__}"
            )

        soup = BeautifulSoup(html_content, "lxml")
        style_rules = _build_style_rules(soup)
        bg_colour = _infer_bg_colour(soup, style_rules)

        visible_parts: list[str] = []
        hidden_spans: list[str] = []

        # Walk every element that can contain direct text.  We process
        # leaf-level text nodes via their parent elements to avoid
        # double-counting nested structures.
        for tag in soup.find_all(True):  # every tag in the DOM
            if not isinstance(tag, Tag):
                continue

            # Skip non-content elements.
            if tag.name in (
                "script", "style", "head", "meta", "link", "title",
                "noscript",
            ):
                continue

            # Get only this element's *direct* text (not children's).
            direct_text = tag.string
            if direct_text is None:
                # tag.string is None when tag has mixed content or
                # multiple children.  Use .find_all(string=True,
                # recursive=False) for direct text nodes only.
                direct_texts = tag.find_all(string=True, recursive=False)
                direct_text = " ".join(
                    t.strip() for t in direct_texts if t.strip()
                )
            else:
                direct_text = direct_text.strip()

            if not direct_text:
                continue

            # Check if this element or any ancestor is hidden.
            hidden_reason = self._check_element_hidden(
                tag, style_rules, bg_colour, Tag
            )

            if hidden_reason:
                desc = _tag_description(tag)
                hidden_spans.append(
                    f"[{desc} — {hidden_reason}] {direct_text}"
                )
            else:
                visible_parts.append(direct_text)

        metadata: dict[str, str] = {
            "format": self.format_name,
            "extracted_at": _utc_now_iso(),
        }
        if path is not None:
            metadata["path"] = path

        return ExtractedContent(
            text="\n".join(visible_parts),
            hidden_spans=hidden_spans,
            source_metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_file_path(value: str) -> bool:
        """Heuristic: is *value* a file path rather than HTML content?"""
        stripped = value.strip()
        if stripped.startswith("<"):
            return False
        lower = stripped.lower()
        if lower.endswith((".html", ".htm")):
            return True
        if os.sep in stripped or "/" in stripped:
            return True
        return False

    @staticmethod
    def _check_element_hidden(
        tag: bs4.Tag,
        style_rules: list[tuple[str, dict[str, str]]],
        bg_colour: tuple[int, int, int],
        tag_class: type,
    ) -> str | None:
        """Walk *tag* and its ancestors, returning a reason if hidden."""
        current: bs4.Tag | None = tag
        while current is not None and isinstance(current, tag_class):
            styles = _get_effective_styles(current, style_rules)
            reason = _is_hidden(styles, bg_colour)
            if reason is not None:
                return reason
            current = current.parent  # type: ignore[assignment]
        return None
