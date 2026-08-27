"""Decision layer — determines the final action based on detector flags.

This module is responsible for calculating the combined risk score from
a list of flags and applying threshold logic to determine whether the
content should be passed, quarantined, or blocked.

It relies on a probabilistic independence model to combine confidence
scores, preventing a single low-confidence flag from triggering a block
while ensuring that many low-confidence flags add up to a significant
risk score.
"""

from __future__ import annotations

from typing import Literal

from okfguard.core.models import Config, Flag


def calculate_action(
    flags: list[Flag],
    config: Config,
) -> tuple[float, Literal["pass", "quarantine", "block"]]:
    """Calculate the final risk score and action for a set of flags.

    Args:
        flags: The list of flags produced by the detection engine.
        config: The configuration containing thresholds.

    Returns:
        A tuple of ``(risk_score, action)``.  Action is one of ``"pass"``,
        ``"quarantine"``, or ``"block"``.
    """
    if not flags:
        return 0.0, "pass"

    # Sort flags by confidence descending to get the highest confidence first
    sorted_flags = sorted(flags, key=lambda f: f.confidence, reverse=True)
    
    # Apply spec formula: highest confidence + 0.15 * each additional flag
    risk_score = sorted_flags[0].confidence
    for f in sorted_flags[1:]:
        risk_score += f.confidence * 0.15
        
    risk_score = min(risk_score, 1.0)

    # Apply strict mode multiplier if enabled (spec §10.2).
    quarantine_threshold = config.threshold_quarantine
    block_threshold = config.threshold_block

    if config.strict_mode:
        quarantine_threshold *= 0.5
        block_threshold *= 0.7

    # Determine action.
    action: Literal["pass", "quarantine", "block"]
    if risk_score >= block_threshold:
        action = "block"
    elif risk_score >= quarantine_threshold:
        action = "quarantine"
    else:
        action = "pass"

    return risk_score, action
