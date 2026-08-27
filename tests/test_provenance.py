from okfguard.core.models import Config, ExtractedContent
from okfguard.core.provenance import generate_provenance


def test_provenance_never_writes_verified():
    extracted = ExtractedContent(text="x", hidden_spans=[], source_metadata={"format": "txt", "extracted_at": "now"})
    prov = generate_provenance(extracted, [], 0.0, "pass", Config())
    assert "verified" not in prov


def test_provenance_uses_path_fallback():
    extracted = ExtractedContent(text="x", hidden_spans=[], source_metadata={"format": "txt", "extracted_at": "now"})
    prov = generate_provenance(extracted, [], 0.0, "pass", Config())
    assert prov["sources"][0]["resource"] == "txt"

    extracted2 = ExtractedContent(text="x", hidden_spans=[], source_metadata={"format": "txt", "extracted_at": "now", "path": "file.txt"})
    prov2 = generate_provenance(extracted2, [], 0.0, "pass", Config())
    assert prov2["sources"][0]["resource"] == "file.txt"


def test_provenance_status():
    extracted = ExtractedContent(text="x", hidden_spans=[], source_metadata={"format": "txt", "extracted_at": "now"})
    prov_pass = generate_provenance(extracted, [], 0.0, "pass", Config())
    assert prov_pass["status"] == "stable"
    
    prov_quarantine = generate_provenance(extracted, [], 0.5, "quarantine", Config())
    assert prov_quarantine["status"] == "draft"
    
    prov_block = generate_provenance(extracted, [], 0.9, "block", Config())
    assert prov_block["status"] == "draft"
