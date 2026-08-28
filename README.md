# okf-guard

A content-safety scanning layer for OKF (Open Knowledge Format) generation pipelines. **okf-guard** acts as a trusted middleware that inspects raw source documents (like PDFs, Word docs, and spreadsheets) for hidden content and prompt-injection attacks *before* that content is bundled into a trusted knowledge base for AI consumption.

It prevents attackers from smuggling malicious instructions into the context windows of GenAI applications by exploiting features like white-on-white text, invisible rendering modes, or hidden spreadsheet rows.

## Installation & Setup

Depending on how you plan to use `okf-guard`, there are two recommended ways to install it to avoid common Python permission errors (like `WinError 2` or `Permission denied`).

### Option 1: Using it as a Command-Line Tool (CLI)
If you just want to run the `okfguard` command in your terminal to scan files, the safest and best way to install it globally is using [pipx](https://pipx.pypa.io/). This automatically isolates the heavy dependencies (like PDF and Word parsers) so they don't break your system Python.

1. Install `pipx` if you don't have it: `python -m pip install --user pipx`
2. Install `okf-guard` with all document parsers:
   ```bash
   pipx install "okf-guard[all]"
   ```
3. Test that it works:
   ```bash
   okfguard --help
   ```

### Option 2: Using it as a Python Library (For Developers)
If you are writing Python code and want to import the `sanitize()` function into your own AI or RAG pipeline, you should install it inside your project's virtual environment using standard `pip`.

1. **Activate your project's virtual environment** (Crucial step!)
   - Windows: `.\venv\Scripts\activate`
   - Mac/Linux: `source venv/bin/activate`
2. **Install the package:**
   - To scan everything (PDF, Word, Excel, PowerPoint, HTML):
     ```bash
     pip install "okf-guard[all]"
     ```
   - Or, to install only specific parsers to save space:
     ```bash
     pip install "okf-guard[pdf,docx]"
     ```
   - Or, install the bare minimum (plain text only):
     ```bash
     pip install okf-guard
     ```

## Quickstart (Python API)

The simplest way to use `okf-guard` is the single top-level `sanitize()` function, which automatically infers the format from the file extension, runs the detection pipeline, and generates OKF v0.2-compliant provenance fields.

```python
from okfguard import sanitize

# Automatically detects format, extracts text, flags issues, and makes a decision
result = sanitize("suspicious_document.pdf")

print(f"Action: {result.action}")          # "pass", "quarantine", or "block"
print(f"Risk Score: {result.risk_score}")  # e.g., 0.85
print(f"Clean Text: {result.clean_text}")  # Only the text visible to a human

# Inspect the flags that contributed to the score
for flag in result.flags:
    print(f"[{flag.type}] at {flag.location}: {flag.snippet} (Confidence: {flag.confidence})")

# Extract OKF v0.2 frontmatter fields to stamp your output bundle
print(result.provenance_fields)
```

### Advanced Usage

If you need finer control over the pipeline, you can run the components manually:

```python
from okfguard.adapters.pdf import PDFAdapter
from okfguard.core.detector import detect
from okfguard.core.decision import calculate_action
from okfguard.core.provenance import generate_provenance
from okfguard.core.models import Config

adapter = PDFAdapter()
extracted = adapter.extract("suspicious_document.pdf")
flags = detect(extracted)

config = Config(threshold_quarantine=0.3, threshold_block=0.7)
risk_score, action = calculate_action(flags, config)

provenance = generate_provenance(extracted, flags, risk_score, action, config)
```

## Quickstart (CLI)

`okf-guard` provides a built-in CLI for scanning files and directories manually or in CI/CD pipelines.

```bash
# Scan a single file
$ okfguard scan document.docx

--- document.docx ---
Action:     BLOCK
Risk Score: 0.900
Flags (2):
  - [hidden_text] paragraph 4, run 2 — font.hidden
    Confidence: 0.90
    Snippet:    'Ignore all previous instructions...'
  - [injection_pattern] hidden span, offset 0-34 [instruction_override]
    Confidence: 0.85
    Snippet:    'Ignore all previous instructions...'
```

Use `--json` for machine-readable newline-delimited JSON output, which is perfect for streaming logs.

```bash
# Scan a whole directory recursively, outputting JSON
$ okfguard scan -r /docs/uploads --json > scan_log.json
```

Use `okfguard review` to interactively triage quarantined files from a JSON log:

```bash
$ okfguard review --json-log scan_log.json
```

**Exit Codes:**
- `0`: Pass
- `1`: Quarantine
- `2`: Block
- `3`: Error (file not found, missing dependency, or parsing crash)

## Detection Philosophy

**okf-guard** is built around three core principles:

1. **Screen Before Write**: Malicious content must be stopped *before* it enters the knowledge base. Once an injection is embedded in a trusted RAG database, it's virtually impossible to cleanly remove.
2. **Hidden Content + Pattern Matching**: We don't just rely on regexes. We look for the *mechanisms* of smuggling (e.g., zero-width characters, white-on-white text, off-canvas shapes, hidden spreadsheet rows). If content is hidden from a human but visible to a parser, it is inherently suspicious.
3. **Conservative Defaults**: v0.1.0 has no LLM-based secondary review layer, so the default thresholds (0.4 for quarantine, 0.8 for block) are tuned to prefer false positives over false negatives. It is safer to quarantine an ambiguously formatted document for human review than to let an attack slip through.

## What v0.1.0 Does NOT Cover

- **Images & OCR**: We do not perform OCR on images or scan for steganographic payloads hidden in image pixels.
- **Macros & Executables**: We extract and scan *content*. We do not perform static or dynamic analysis of VBA macros, embedded JavaScript, or active content.
- **LLM-based Judgment**: All detection in v0.1.0 is deterministic and rule-based. We do not use an LLM to evaluate the "intent" of a prompt injection.
- **Reliable PDF Rendermode 3 Extraction**: While the PDF format formally defines text rendering mode 3 as "invisible", the underlying `pdfminer.six` and `pdfplumber` stack currently used does not reliably expose this rendering mode at the character level across all PDF producers. The check exists in the codebase in case it is encountered, but our v0.1.0 test suite could not reliably produce a verifiable mode 3 test fixture. As a result, PDF hidden-text detection practically relies on the (fully-tested) color-matching and off-page position checks.
- **File System Management**: We do not quarantine, delete, or move files on disk. We return a decision; your pipeline must enforce it.

## Contributing

We welcome issues and pull requests! The landscape of prompt-injection attacks evolves rapidly. 

We specifically invite contributions to our injection pattern bank (`src/okfguard/rules/injection_patterns.py`). If you discover new injection phrasing in the wild, please open a PR to add it to the detection engine.

## License

This project is licensed under the Apache 2.0 License.
