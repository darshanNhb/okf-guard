from okfguard.core.decision import calculate_action
from okfguard.core.models import Config, Flag


def test_decision_pass():
    flags = [Flag(type="hidden_text", location="unknown", snippet="foo", confidence=0.3)]
    config = Config(threshold_quarantine=0.4, threshold_block=0.92)
    risk_score, action = calculate_action(flags, config)
    assert action == "pass"
    assert risk_score == 0.3


def test_decision_quarantine():
    flags = [Flag(type="hidden_text", location="unknown", snippet="foo", confidence=0.5)]
    config = Config(threshold_quarantine=0.4, threshold_block=0.92)
    risk_score, action = calculate_action(flags, config)
    assert action == "quarantine"
    assert risk_score == 0.5


def test_decision_block():
    flags = [
        Flag(type="hidden_text", location="x", snippet="y", confidence=0.7),
        Flag(type="injection_pattern", location="x", snippet="y", confidence=0.8)
    ]
    config = Config(threshold_quarantine=0.4, threshold_block=0.8)
    risk_score, action = calculate_action(flags, config)
    # Highest is 0.8. Next is 0.7 * 0.15 = 0.105. Total = 0.905
    assert action == "block"
    assert round(risk_score, 3) == 0.905


def test_decision_strict_mode():
    flags = [Flag(type="hidden_text", location="x", snippet="y", confidence=0.3)]
    config = Config(threshold_quarantine=0.4, threshold_block=0.92, strict_mode=True)
    # Quarantine threshold is lowered to 0.2
    risk_score, action = calculate_action(flags, config)
    assert action == "quarantine"


def test_score_capping():
    # Provide enough flags to push risk score > 1.0
    flags = [Flag(type="hidden_text", location="x", snippet="y", confidence=0.9)] * 10
    config = Config()
    risk_score, action = calculate_action(flags, config)
    assert risk_score == 1.0
