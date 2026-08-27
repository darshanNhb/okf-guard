"""Abstract base class for all source-format adapters.

An adapter's sole responsibility is extracting content from a raw input
and identifying which parts of that content, if any, were hidden from a
human reader in the original source.  Adapters must NOT perform any
injection-pattern detection themselves — that is the detector's job.

Keep this separation strict: an adapter answers "what does this source
contain and what was hidden," not "is this dangerous."
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone

from okfguard.core.models import ExtractedContent


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with explicit offset.

    All adapters must use this helper — not ``datetime.now()`` or any
    other ad-hoc timestamp construction — so that
    ``source_metadata["extracted_at"]`` is always a timezone-aware UTC
    string (e.g. ``"2026-08-24T10:30:00+00:00"``).  This value feeds
    directly into OKF v0.2's ``generated.at`` field, which requires
    ISO 8601 with an explicit UTC offset.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SourceAdapter(ABC):
    """Base class for all source-format adapters.

    An adapter's sole responsibility is extracting content from a raw
    input and identifying which parts of that content, if any, were
    hidden from a human reader in the original source.  Adapters must
    NOT perform any injection-pattern detection themselves — that is
    the detector's job.  Keep this separation strict: an adapter answers
    "what does this source contain and what was hidden," not "is this
    dangerous."
    """

    @abstractmethod
    def extract(self, source: str | bytes) -> ExtractedContent:
        """Extract content from a raw source.

        Args:
            source: Either a file path (str) or raw bytes of the file
                content.  Implementations should accept both where the
                underlying parsing library supports it; if a given
                adapter can only sensibly accept one, document that
                clearly in its own docstring and raise a clear
                ``TypeError`` for the unsupported input type, rather
                than failing with a confusing library-internal error.

        Returns:
            An ``ExtractedContent`` instance.

        Raises:
            FileNotFoundError: If *source* is a path that doesn't exist.
            ValueError: If the content cannot be parsed as this
                adapter's expected format.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Short lowercase identifier for this format, e.g. ``'pdf'``.

        Used to populate ``ExtractedContent.source_metadata['format']``
        and in CLI output.
        """
        raise NotImplementedError
