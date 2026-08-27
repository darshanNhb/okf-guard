"""High-level orchestration API.

This module provides the primary entry points for scanning files or
raw bytes, coordinating the adapters, detector, decision layer, and
provenance stamper.
"""

from __future__ import annotations

import os

from okfguard.adapters.base import SourceAdapter
from okfguard.adapters.docx import DocxAdapter
from okfguard.adapters.html import HTMLAdapter
from okfguard.adapters.pdf import PDFAdapter
from okfguard.adapters.pptx import PPTXAdapter
from okfguard.adapters.spreadsheet import SpreadsheetAdapter
from okfguard.adapters.text import TextAdapter
from okfguard.core.decision import calculate_action
from okfguard.core.detector import detect
from okfguard.core.models import Config, SanitizeResult
from okfguard.core.provenance import generate_provenance


def get_adapter_for_extension(ext: str) -> SourceAdapter | None:
    """Return the appropriate adapter for a given file extension."""
    ext = ext.lower().strip(".")
    if ext in ("txt", "md", "csv"):
        return TextAdapter()
    if ext in ("html", "htm"):
        return HTMLAdapter()
    if ext == "pdf":
        return PDFAdapter()
    if ext == "docx":
        return DocxAdapter()
    if ext == "pptx":
        return PPTXAdapter()
    if ext in ("xlsx", "xls"):
        # We only support xlsx (openpyxl), but let the adapter throw the
        # specific ValueError if someone passes an old .xls binary file.
        return SpreadsheetAdapter()
    return None


def sanitize(
    source: str | bytes,
    config: Config | None = None,
    adapter: SourceAdapter | None = None,
) -> SanitizeResult:
    """Scan a source file or bytes and produce a final decision.

    Args:
        source: A file path (str) or raw bytes.
        config: Optional configuration.  If omitted, defaults are used.
        adapter: Optional explicit adapter to use.  If omitted, and
            ``source`` is a path, the adapter is inferred from the
            file extension.

    Returns:
        The full sanitization result including extracted text, flags,
        risk score, action, and provenance fields.

    Raises:
        ValueError: If the adapter cannot be inferred, or parsing fails.
    """
    if config is None:
        config = Config()

    if adapter is None:
        if isinstance(source, str):
            _, ext = os.path.splitext(source)
            adapter = get_adapter_for_extension(ext)
            if adapter is None:
                raise ValueError(
                    f"No adapter found for extension: {ext!r}. "
                    "Provide an explicit adapter."
                )
        else:
            raise ValueError(
                "Must provide an explicit adapter when scanning raw bytes."
            )

    # 1. Extraction (Adapters)
    extracted = adapter.extract(source)

    # 2. Detection (Detector)
    flags = detect(extracted)

    # 3. Decision (Decision layer)
    risk_score, action = calculate_action(flags, config)

    # 4. Provenance (Provenance stamper)
    provenance_fields = generate_provenance(
        extracted=extracted,
        flags=flags,
        risk_score=risk_score,
        action=action,
        config=config,
    )

    return SanitizeResult(
        clean_text=extracted.text,
        flags=flags,
        risk_score=risk_score,
        action=action,
        provenance_fields=provenance_fields,
    )
