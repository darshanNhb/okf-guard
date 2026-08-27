import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from okfguard.cli import main


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_cli_scan_pass():
    test_args = ["okfguard", "scan", str(FIXTURES_DIR / "text" / "clean.txt")]
    with patch("sys.argv", test_args):
        # clean text should pass (exit code 0)
        assert main() == 0


def test_cli_scan_block():
    test_args = ["okfguard", "scan", str(FIXTURES_DIR / "text" / "poisoned.txt")]
    with patch("sys.argv", test_args):
        # poisoned text should quarantine (exit code 1) because risk score is 0.797
        assert main() == 1


def test_cli_scan_json():
    test_args = ["okfguard", "scan", str(FIXTURES_DIR / "text" / "clean.txt"), "--json"]
    with patch("sys.argv", test_args), patch("sys.stdout") as mock_stdout:
        main()
        # Capturing stdout isn't strictly necessary but we want to test no crash
        assert mock_stdout.write.called


def test_cli_review():
    # Make a dummy JSON log file
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(json.dumps({"path": "x.txt", "action": "quarantine", "risk_score": 0.5, "flags": []}) + "\n")
        log_path = f.name
    
    test_args = ["okfguard", "review", "--json-log", log_path]
    with patch("sys.argv", test_args), patch("builtins.input", return_value="a"):
        assert main() == 0
