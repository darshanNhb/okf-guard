"""Detection engine — produces ``Flag`` instances from ``ExtractedContent``.

The detector takes an ``ExtractedContent`` (the output of an adapter)
and produces a ``list[Flag]``.  It does **not** decide pass/quarantine/
block — that is the decision layer's job (``core.decision``).

Three independent checks always run on every scan:

1. **Hidden-content flagging** — one flag per hidden span, with
   confidence assigned by mechanism category (explicit vs. inferred
   vs. notes/comments).

2. **Pattern-bank matching** — regex-based detection of injection-style
   language.  Runs against both visible text *and* hidden spans, since
   hidden spans containing injection phrasing should raise both a
   ``hidden_text`` flag and an ``injection_pattern`` flag (independent,
   compounding signals).

3. **Encoding-trick detection** — zero-width characters embedded in
   words and homoglyph substitution (mixed-script words).
"""

from __future__ import annotations

import re
import unicodedata

from okfguard.core.models import ExtractedContent, Flag
from okfguard.rules.injection_patterns import PATTERNS

# ═══════════════════════════════════════════════════════════════════════
# Confidence constants for hidden-content flagging (§9.1)
#
# Named constants — not magic numbers inline — so they are easy to find
# and tune later.
# ═══════════════════════════════════════════════════════════════════════

CONFIDENCE_EXPLICIT = 0.9
"""Explicit hidden-text properties: Word's ``font.hidden``, a
spreadsheet's hidden-row/sheet flag, or PDF rendering mode 3.  The
format itself is directly stating that this content is hidden."""

CONFIDENCE_INFERRED = 0.75
"""Inferred hiding: colour-matching, off-canvas positioning, zero-
opacity CSS, ``display:none``.  We deduce invisibility from rendering
properties rather than an explicit "hidden" attribute."""

CONFIDENCE_NOTES_COMMENTS = 0.6
"""Speaker notes and cell comments.  These are a real risk vector but
have a much higher legitimate-use rate than the other categories —
presenters write real notes to themselves, spreadsheet authors write
real comments — so a slightly lower default confidence is appropriate.
Still always flagged, never silently skipped."""

# Keywords in the hidden-span bracket prefix that determine the
# confidence tier.  The detector parses the ``[LOCATION — MECHANISM]``
# prefix from each hidden-span string and matches on these keywords.
_EXPLICIT_KEYWORDS = (
    "font.hidden",
    "invisible rendering mode",
    "(hidden)",       # spreadsheet hidden sheet/row/col
    "hidden row",
    "hidden column",
    "hidden sheet",
)
_NOTES_COMMENTS_KEYWORDS = (
    "speaker notes",
    "comment",
)


# ═══════════════════════════════════════════════════════════════════════
# Encoding-trick detection (§9.3)
# ═══════════════════════════════════════════════════════════════════════

# Zero-width and invisible Unicode characters to check for.
_ZERO_WIDTH_CHARS: dict[int, str] = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x2060: "WORD JOINER",
    0x2061: "FUNCTION APPLICATION",
    0x2062: "INVISIBLE TIMES",
    0x2063: "INVISIBLE SEPARATOR",
    0x2064: "INVISIBLE PLUS",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
}

# Unicode "tag" characters sometimes used for steganographic hiding.
_TAG_RANGE_START = 0xE0000
_TAG_RANGE_END = 0xE007F

# Homoglyph mapping: Cyrillic look-alikes of Latin characters.
# Each key is a Cyrillic character, value is the Latin character it
# visually resembles.
_CYRILLIC_HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а → Latin a
    "\u0435": "e",  # Cyrillic е → Latin e
    "\u043E": "o",  # Cyrillic о → Latin o
    "\u0440": "p",  # Cyrillic р → Latin p
    "\u0441": "c",  # Cyrillic с → Latin c
    "\u0445": "x",  # Cyrillic х → Latin x
    "\u0443": "y",  # Cyrillic у → Latin y
    "\u0456": "i",  # Cyrillic і → Latin i
    "\u0458": "j",  # Cyrillic ј → Latin j
    "\u04BB": "h",  # Cyrillic һ → Latin h
    "\u0455": "s",  # Cyrillic ѕ → Latin s
    "\u0471": "ψ",  # Cyrillic ѱ (less common)
    "\u0410": "A",  # Cyrillic А → Latin A
    "\u0412": "B",  # Cyrillic В → Latin B
    "\u0415": "E",  # Cyrillic Е → Latin E
    "\u041A": "K",  # Cyrillic К → Latin K
    "\u041C": "M",  # Cyrillic М → Latin M
    "\u041D": "H",  # Cyrillic Н → Latin H
    "\u041E": "O",  # Cyrillic О → Latin O
    "\u0420": "P",  # Cyrillic Р → Latin P
    "\u0421": "C",  # Cyrillic С → Latin C
    "\u0422": "T",  # Cyrillic Т → Latin T
    "\u0425": "X",  # Cyrillic Х → Latin X
}

_CYRILLIC_CODEPOINTS = set(_CYRILLIC_HOMOGLYPHS.keys())

# Context window: how many characters before/after a pattern match to
# include in the snippet for human review.
_CONTEXT_CHARS = 40

# Maximum snippet length before truncation (spec §6.1).
_MAX_SNIPPET_LEN = 200


# ═══════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════

def detect(extracted: ExtractedContent) -> list[Flag]:
    """Run all detection checks on extracted content.

    Args:
        extracted: The output of a source adapter.

    Returns:
        A list of ``Flag`` instances, one per finding.  May be empty
        if no issues are detected.
    """
    flags: list[Flag] = []

    # --- 1. Hidden-content flagging (§9.1) ---
    flags.extend(_flag_hidden_spans(extracted))

    # --- 2. Pattern-bank matching (§9.2) ---
    # Run against visible text.
    flags.extend(_scan_patterns(extracted.text, "visible text"))

    # Also run against hidden spans — a hidden span containing
    # injection phrasing should raise both a hidden_text flag
    # (already done above) AND an injection_pattern flag, since
    # these are two independent, compounding risk signals.
    for span in extracted.hidden_spans:
        _, hidden_text = _parse_hidden_span(span)
        flags.extend(_scan_patterns(hidden_text, "hidden span"))

    # --- 3. Encoding-trick detection (§9.3) ---
    flags.extend(_detect_encoding_tricks(extracted.text))
    for span in extracted.hidden_spans:
        _, hidden_text = _parse_hidden_span(span)
        flags.extend(_detect_encoding_tricks(hidden_text))

    return flags


# ═══════════════════════════════════════════════════════════════════════
# Hidden-span parsing
# ═══════════════════════════════════════════════════════════════════════

def _parse_hidden_span(span: str) -> tuple[str, str]:
    """Parse a hidden span string into ``(location, hidden_text)``.

    Adapters encode hidden spans as::

        [LOCATION — MECHANISM] HIDDEN_TEXT

    This function splits on the first ``] `` to separate the bracket
    prefix (used as the Flag's location and for mechanism-tier
    identification) from the raw hidden text (used as the Flag's
    snippet and for pattern matching).

    If the string doesn't match the expected format, the entire string
    is returned as both location and text — degrading gracefully rather
    than failing.
    """
    idx = span.find("] ")
    if idx >= 0 and span.startswith("["):
        location = span[1:idx]  # strip leading '['
        text = span[idx + 2:]   # text after '] '
        return location, text
    # Fallback: the whole string is the hidden text, location unknown.
    return "unknown", span


def _classify_mechanism(location: str) -> float:
    """Assign confidence based on the hiding mechanism encoded in *location*.

    The location string (from the adapter's bracket prefix) contains
    keywords that indicate whether the hiding mechanism was explicit,
    inferred, or notes/comments.
    """
    location_lower = location.lower()

    # Explicit mechanisms — highest confidence
    for kw in _EXPLICIT_KEYWORDS:
        if kw in location_lower:
            return CONFIDENCE_EXPLICIT

    # Notes and comments — moderate confidence
    for kw in _NOTES_COMMENTS_KEYWORDS:
        if kw in location_lower:
            return CONFIDENCE_NOTES_COMMENTS

    # Default: inferred hiding mechanism
    return CONFIDENCE_INFERRED


# ═══════════════════════════════════════════════════════════════════════
# 9.1  Hidden-content flagging
# ═══════════════════════════════════════════════════════════════════════

def _flag_hidden_spans(extracted: ExtractedContent) -> list[Flag]:
    """Produce one ``hidden_text`` flag per hidden span.

    Confidence is assigned by the hiding mechanism category, determined
    by parsing keywords from the adapter's bracket-prefix convention.
    """
    flags: list[Flag] = []

    for span in extracted.hidden_spans:
        location, hidden_text = _parse_hidden_span(span)
        confidence = _classify_mechanism(location)
        snippet = _truncate(hidden_text)

        flags.append(Flag(
            type="hidden_text",
            location=location,
            snippet=snippet,
            confidence=confidence,
        ))

    return flags


# ═══════════════════════════════════════════════════════════════════════
# 9.2  Pattern-bank matching
# ═══════════════════════════════════════════════════════════════════════

def _scan_patterns(text: str, source_label: str) -> list[Flag]:
    """Scan *text* against the injection pattern bank.

    Args:
        text: The text to scan.
        source_label: Used in the Flag's location field to distinguish
            matches in visible text from matches in hidden spans.

    Returns:
        A list of ``injection_pattern`` flags.
    """
    flags: list[Flag] = []

    for ip in PATTERNS:
        for match in ip.pattern.finditer(text):
            start = match.start()
            end = match.end()

            # Build snippet with surrounding context (40 chars on each
            # side) so a human reviewer has enough context to judge.
            ctx_start = max(0, start - _CONTEXT_CHARS)
            ctx_end = min(len(text), end + _CONTEXT_CHARS)
            snippet_text = text[ctx_start:ctx_end]
            snippet = _truncate(snippet_text)

            location = (
                f"{source_label}, offset {start}-{end} "
                f"[{ip.label}]"
            )

            flags.append(Flag(
                type="injection_pattern",
                location=location,
                snippet=snippet,
                confidence=ip.confidence,
            ))

    return flags


# ═══════════════════════════════════════════════════════════════════════
# 9.3  Encoding-trick detection
# ═══════════════════════════════════════════════════════════════════════

def _detect_encoding_tricks(text: str) -> list[Flag]:
    """Detect zero-width characters and homoglyph substitution in *text*.

    Returns:
        A list of ``encoding_trick`` flags.
    """
    flags: list[Flag] = []

    # --- Zero-width and invisible Unicode characters ---
    flags.extend(_detect_zero_width(text))

    # --- Homoglyph substitution (mixed-script words) ---
    flags.extend(_detect_homoglyphs(text))

    return flags


def _detect_zero_width(text: str) -> list[Flag]:
    """Flag zero-width and invisible characters embedded in words.

    Only flags characters that appear *within* otherwise-ordinary words
    (not isolated whitespace-like usage), since zero-width characters
    used as word separators in some scripts are legitimate.
    """
    flags: list[Flag] = []

    # Find runs of "normal" characters with zero-width chars inside
    # Pattern: word char, then one or more zero-width chars, then more
    # word chars — indicating the invisible char is embedded mid-word.
    zw_pattern = re.compile(
        r"(\w)(["
        + "".join(chr(cp) for cp in _ZERO_WIDTH_CHARS)
        + "\U000E0000-\U000E007F"
        + r"]+)(\w)"
    )

    for match in zw_pattern.finditer(text):
        invisible_chars = match.group(2)
        char_names: list[str] = []
        for ch in invisible_chars:
            cp = ord(ch)
            name = _ZERO_WIDTH_CHARS.get(cp)
            if name is None and _TAG_RANGE_START <= cp <= _TAG_RANGE_END:
                name = f"TAG CHARACTER U+{cp:04X}"
            elif name is None:
                name = f"U+{cp:04X}"
            char_names.append(name)

        # Show surrounding context
        ctx_start = max(0, match.start() - 20)
        ctx_end = min(len(text), match.end() + 20)
        context = text[ctx_start:ctx_end]

        snippet = _truncate(
            f"Zero-width character(s) [{', '.join(char_names)}] "
            f"embedded in: ...{context!r}..."
        )

        flags.append(Flag(
            type="encoding_trick",
            location=f"character offset {match.start()}-{match.end()}",
            snippet=snippet,
            confidence=0.65,
        ))

    # Also check for tag characters (U+E0000–U+E007F) used for
    # steganographic text hiding, even if not embedded mid-word.
    tag_pattern = re.compile(r"[\U000E0000-\U000E007F]{2,}")
    for match in tag_pattern.finditer(text):
        decoded = "".join(
            chr(ord(ch) - 0xE0000) if 0xE0000 <= ord(ch) <= 0xE007F else ch
            for ch in match.group()
        )
        snippet = _truncate(
            f"Steganographic tag characters at offset "
            f"{match.start()}-{match.end()}, decoded: {decoded!r}"
        )
        flags.append(Flag(
            type="encoding_trick",
            location=f"character offset {match.start()}-{match.end()}",
            snippet=snippet,
            confidence=0.65,
        ))

    return flags


def _detect_homoglyphs(text: str) -> list[Flag]:
    """Flag words that mix Latin and visually-similar Cyrillic characters.

    This is inherently a heuristic with some false-positive risk —
    genuinely multilingual text may contain mixed-script words.
    Confidence is kept moderate (0.5) for this reason, and the
    trade-off is documented here.
    """
    flags: list[Flag] = []

    # Split text into word-like tokens.
    words = re.findall(r"\S+", text)

    for word in words:
        has_latin = False
        has_cyrillic_homoglyph = False
        homoglyph_details: list[str] = []

        for ch in word:
            cat = unicodedata.category(ch)
            if not cat.startswith("L"):
                continue  # Skip non-letter characters

            if ch in _CYRILLIC_CODEPOINTS:
                has_cyrillic_homoglyph = True
                latin_equiv = _CYRILLIC_HOMOGLYPHS[ch]
                homoglyph_details.append(
                    f"U+{ord(ch):04X} ({ch!r} looks like "
                    f"Latin {latin_equiv!r})"
                )
            elif "\u0041" <= ch <= "\u007A":  # Basic Latin A-z
                has_latin = True

        if has_latin and has_cyrillic_homoglyph:
            snippet = _truncate(
                f"Mixed-script word {word!r}: "
                + "; ".join(homoglyph_details)
            )
            flags.append(Flag(
                type="encoding_trick",
                location=f"word {word!r}",
                snippet=snippet,
                confidence=0.5,
            ))

    return flags


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════

def _truncate(text: str, max_len: int = _MAX_SNIPPET_LEN) -> str:
    """Truncate *text* to *max_len* characters, appending ``'...'``."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."
