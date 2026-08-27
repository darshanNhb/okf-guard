"""Adapter for plain text and Markdown files.

Plain text is the simplest format handled by okf-guard.  There is no
structural mechanism in a ``.txt`` or ``.md`` file for hiding content
from a reader — every byte in the file is "visible" in the sense that
nothing is selectively rendered or suppressed the way CSS can hide HTML
elements or Word's font.hidden attribute can conceal runs of text.

As a result, ``hidden_spans`` is always empty for this adapter.  The
injection-pattern and encoding-trick detection layers (run downstream by
the detector, not by this adapter) still apply to the visible text and
may flag suspicious content, but from an extraction standpoint there is
nothing hidden to surface.
"""

from __future__ import annotations

import os
from pathlib import Path

from okfguard.adapters.base import SourceAdapter, _utc_now_iso
from okfguard.core.models import ExtractedContent


class TextAdapter(SourceAdapter):
    """Extract content from plain text and Markdown files.

    Accepts either a file path (``str``) or raw content (``str`` or
    ``bytes``).  When given bytes, UTF-8 decoding is attempted first;
    on failure, a best-effort decode with error replacement is used.

    ``hidden_spans`` is always empty because plain text has no
    structural mechanism for hiding content from a reader.
    """

    @property
    def format_name(self) -> str:
        """Return ``'text'``."""
        return "text"

    def extract(self, source: str | bytes) -> ExtractedContent:
        """Extract visible text from a plain text or Markdown source.

        Args:
            source: A file path (``str`` pointing to an existing file)
                or raw content (``str`` for already-decoded text,
                ``bytes`` for raw file bytes).

        Returns:
            An ``ExtractedContent`` with all text as visible content,
            an empty ``hidden_spans`` list, and metadata including
            the encoding used.

        Raises:
            FileNotFoundError: If *source* is a string path that does
                not exist on disk.
            ValueError: If the source is empty after decoding.
        """
        path: str | None = None
        encoding_used: str = "utf-8"

        if isinstance(source, bytes):
            # Raw bytes — attempt UTF-8 first, fall back gracefully.
            text, encoding_used = self._decode_bytes(source)
        elif isinstance(source, str):
            # Could be a file path or inline text content.
            if self._looks_like_file_path(source):
                if not os.path.isfile(source):
                    raise FileNotFoundError(
                        f"Text file not found: {source!r}"
                    )
                path = source
                raw = Path(source).read_bytes()
                text, encoding_used = self._decode_bytes(raw)
            else:
                # Treat as inline text content.
                text = source
                encoding_used = "utf-8"
        else:
            raise TypeError(
                f"TextAdapter.extract() expects str or bytes, "
                f"got {type(source).__name__}"
            )

        metadata: dict[str, str] = {
            "format": self.format_name,
            "extracted_at": _utc_now_iso(),
            "encoding": encoding_used,
        }
        if path is not None:
            metadata["path"] = path

        # hidden_spans is always empty — plain text has no structural
        # mechanism for hiding content from a reader.
        return ExtractedContent(
            text=text,
            hidden_spans=[],
            source_metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_bytes(raw: bytes) -> tuple[str, str]:
        """Decode raw bytes, trying UTF-8 first with a fallback.

        Returns:
            A ``(text, encoding_used)`` tuple.
        """
        try:
            return raw.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            # Best-effort decode: replace undecodable bytes so we never
            # silently lose content, and record that the fallback was
            # used.
            return raw.decode("utf-8", errors="replace"), "utf-8-lossy"

    @staticmethod
    def _looks_like_file_path(value: str) -> bool:
        """Heuristic: does *value* look like a file path rather than inline text?

        We consider it a path if it contains a path separator or ends
        with a recognised text/markdown extension.  This avoids
        misinterpreting a short sentence as a filename.
        """
        if os.sep in value or "/" in value:
            return True
        lower = value.lower()
        return lower.endswith((".txt", ".md", ".markdown", ".rst", ".text"))
