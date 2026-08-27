"""Provenance stamping — prepares OKF v0.2 frontmatter fields.

This module is responsible for producing the metadata fields that an
OKF consumer will merge into the frontmatter of a generated concept
file.  It strictly adheres to the OKF v0.2 specification.

CRITICAL RULE: This module must NEVER write a ``verified`` field.
Per the OKF spec, ``verified`` represents an independent human or
process confirmation that content is accurate.  A tool cannot verify
its own output.
"""

from __future__ import annotations

from typing import Literal

from okfguard import __version__
from okfguard.core.models import Config, ExtractedContent, Flag


def generate_provenance(
    extracted: ExtractedContent,
    flags: list[Flag],
    risk_score: float,
    action: Literal["pass", "quarantine", "block"],
    config: Config,  # Included for future-proofing, unused in v0.1.0
) -> dict[str, object]:
    """Generate OKF v0.2 frontmatter fields for the scan results.

    Args:
        extracted: The extracted content output from the adapter.
        flags: The list of flags produced by the detection engine.
        risk_score: The final risk score from the decision layer.
        action: The recommended action from the decision layer.
        config: The configuration used for the scan.

    Returns:
        A dictionary containing the ``generated``, ``sources``,
        ``status``, and ``okfguard`` fields to be merged into the
        resulting OKF concept file.
    """
    format_name = extracted.source_metadata["format"]
    
    # Use the path if we have it, otherwise fallback to the format name.
    # We do not invent a fake path.
    resource = extracted.source_metadata.get("path", format_name)

    # 1. generated: who generated this and when
    generated = {
        "by": f"okf-guard/{__version__}",
        "at": extracted.source_metadata["extracted_at"],
    }

    # 2. sources: what this content derives from
    sources = [
        {
            "id": "raw-input",
            "resource": resource,
            "title": f"Raw {format_name} input scanned by okf-guard",
        }
    ]

    # 3. status: "draft" if not completely clean
    status = "draft" if action != "pass" else "stable"

    # 4. okfguard: our custom extension namespace
    okfguard_ext = {
        "risk_score": round(risk_score, 3),
        "action": action,
        "flags_found": len(flags),
    }

    return {
        "generated": generated,
        "sources": sources,
        "status": status,
        "okfguard": okfguard_ext,
    }
