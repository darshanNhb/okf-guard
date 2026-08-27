import os
from pathlib import Path

import pytest

from okfguard.api import sanitize


FIXTURES_DIR = Path(__file__).parent.parent / "tests" / "fixtures"

FORMATS = ["text", "html", "docx", "pptx", "xlsx", "pdf"]
EXTENSIONS = {
    "text": ".txt",
    "html": ".html",
    "docx": ".docx",
    "pptx": ".pptx",
    "xlsx": ".xlsx",
    "pdf": ".pdf",
}

def test_fixtures_exist():
    for fmt in FORMATS:
        ext = EXTENSIONS[fmt]
        assert (FIXTURES_DIR / fmt / f"clean{ext}").exists(), f"Missing clean fixture for {fmt}"
        assert (FIXTURES_DIR / fmt / f"poisoned{ext}").exists(), f"Missing poisoned fixture for {fmt}"


@pytest.mark.parametrize("fmt", FORMATS)
def test_clean_fixtures_pass(fmt):
    """Clean fixtures should have risk score near 0.0 and action 'pass'."""
    ext = EXTENSIONS[fmt]
    path = FIXTURES_DIR / fmt / f"clean{ext}"
    
    result = sanitize(str(path))
    
    # Clean fixtures should never contain injection patterns.
    injection_flags = [f for f in result.flags if f.type == "injection_pattern"]
    assert not injection_flags, f"Found injection flags in clean {fmt} document"

    # DOCX, PPTX, and XLSX contain legitimately-hidden content (draft notes, 
    # speaker notes, helper rows) which yield hidden_text flags. With 
    # threshold_block = 0.92, these land in quarantine for human review 
    # (not pass, not block).
    if fmt in ("xlsx", "docx", "pptx"):
        assert result.action == "quarantine"
    else:
        assert result.action == "pass"
        assert result.risk_score < 0.4


@pytest.mark.parametrize("fmt", FORMATS)
def test_poisoned_fixtures_caught(fmt):
    """Poisoned fixtures contain 'Ignore all previous instructions' which is an injection."""
    ext = EXTENSIONS[fmt]
    path = FIXTURES_DIR / fmt / f"poisoned{ext}"
    
    result = sanitize(str(path))
    
    assert result.action in ("quarantine", "block")
    
    injection_flags = [f for f in result.flags if f.type == "injection_pattern"]
    assert len(injection_flags) > 0, f"No injection flags found in poisoned {fmt} document"
    
    # Formats other than text should also have flagged the hidden text itself,
    # since we put the injection inside a hidden mechanism.
    if fmt != "text":
        hidden_flags = [f for f in result.flags if f.type == "hidden_text"]
        assert len(hidden_flags) > 0, f"No hidden_text flags found in poisoned {fmt} document"
