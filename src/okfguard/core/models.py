"""Core data models for okf-guard.

This module defines the immutable data structures used throughout the
okf-guard pipeline: findings from the detection engine (``Flag``),
normalized extracted content from source adapters (``ExtractedContent``),
user-controllable configuration (``Config``), and the final output
returned to callers after a complete scan-and-decide cycle
(``SanitizeResult``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------------------
# 6.1  Flag — a single finding from the detection engine
# ---------------------------------------------------------------------------

# The three flag types recognised in v0.1.0.  Defined as a type alias here
# so that both the dataclass and call-sites can reference a single source of
# truth.  Adding new types later means extending this Literal union only.
FlagType = Literal["hidden_text", "injection_pattern", "encoding_trick"]


@dataclass(frozen=True)
class Flag:
    """A single finding raised by the detection engine.

    Instances are frozen (immutable) because a flag represents an
    observed fact about a source document — once created it must not be
    mutated.

    Attributes:
        type: Category of the finding.  One of ``"hidden_text"``,
            ``"injection_pattern"``, or ``"encoding_trick"``.
        location: Human-readable description of where in the source the
            finding was observed (e.g. ``"page 3, character range
            120-340"``).
        snippet: The actual text that triggered the flag, truncated to
            200 characters with ``"..."`` appended when longer.
        confidence: A value in [0.0, 1.0] expressing how confident the
            detector is that this represents a genuine risk.
    """

    type: FlagType
    location: str
    snippet: str
    confidence: float

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"Flag confidence must be between 0.0 and 1.0 inclusive, "
                f"got {self.confidence!r}"
            )


# ---------------------------------------------------------------------------
# 6.2  ExtractedContent — adapter output before detection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExtractedContent:
    """Normalized output of a source adapter.

    Contains the visible text a human reader would see, any text that
    was structurally hidden in the original source, and metadata about
    the extraction.

    Attributes:
        text: The visible text extracted from the source — what a human
            reading the original document would actually see.
        hidden_spans: Text segments that were present in the source but
            hidden from a human reader (invisible text, hidden rows,
            speaker notes, off-canvas content, etc.).  Empty for formats
            where hidden content is structurally impossible (e.g. plain
            text).
        source_metadata: Arbitrary metadata about the source.  Always
            contains at least ``"format"`` (e.g. ``"pdf"``) and
            ``"extracted_at"`` (ISO 8601 timestamp string).  Adapters
            may add additional keys relevant to their format.
    """

    text: str
    hidden_spans: list[str] = field(default_factory=list)
    source_metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# 6.3  Config — user-controllable detection thresholds
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """Configuration controlling detection thresholds and behaviour.

    Not frozen — callers are expected to construct and modify this
    freely.

    Attributes:
        threshold_quarantine: Risk score at or above which content is
            quarantined rather than passed.
        threshold_block: Risk score at or above which content is blocked
            outright rather than quarantined.
        strict_mode: When ``True``, the decision layer lowers effective
            thresholds by 30 %, making the tool more cautious.  Intended
            for future presets targeting adversarial-by-default sources
            (e.g. support tickets).

    The default thresholds (0.4 quarantine, 0.8 block) are deliberately
    conservative toward quarantining rather than passing.  v0.1.0 has no
    LLM layer to reduce false positives through contextual judgement, so
    it is better to over-flag content for human review than to under-flag
    and let something genuinely dangerous pass silently.  A future
    contributor should not casually "tune" these defaults without
    understanding this trade-off.
    """

    threshold_quarantine: float = 0.4
    threshold_block: float = 0.92
    strict_mode: bool = False

    def __post_init__(self) -> None:
        if not (0.0 <= self.threshold_quarantine <= self.threshold_block <= 1.0):
            raise ValueError(
                f"Config thresholds must satisfy "
                f"0.0 <= threshold_quarantine <= threshold_block <= 1.0.  "
                f"Got threshold_quarantine={self.threshold_quarantine!r}, "
                f"threshold_block={self.threshold_block!r}"
            )


# ---------------------------------------------------------------------------
# 6.4  SanitizeResult — final output of a complete scan cycle
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SanitizeResult:
    """Final output returned after a full scan-and-decide cycle.

    Attributes:
        clean_text: The extracted visible text (same as
            ``ExtractedContent.text``).  Included for caller convenience
            so that downstream code does not need to hold onto the
            intermediate ``ExtractedContent`` object.
        flags: Every flag raised during detection, regardless of the
            final action taken.
        risk_score: Combined risk score in [0.0, 1.0] computed by the
            decision layer.
        action: The recommended action — one of ``"pass"``,
            ``"quarantine"``, or ``"block"``.
        provenance_fields: OKF v0.2 frontmatter fields that should be
            merged into the resulting concept file's YAML frontmatter.
            Typed as ``dict[str, object]`` because several values
            (``generated``, ``sources``, the ``okfguard`` extension
            block) are nested structures, not flat strings.
    """

    clean_text: str
    flags: list[Flag]
    risk_score: float
    action: Literal["pass", "quarantine", "block"]
    provenance_fields: dict[str, object]
