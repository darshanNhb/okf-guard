# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-24

### Added
- **Core Models**: Implemented `Flag`, `ExtractedContent`, `Config`, and `SanitizeResult` objects for representing safety states.
- **Decision Layer**: Deterministic probability-based risk score calculator that categorizes inputs into pass, quarantine, or block actions with configurable thresholds.
- **Detection Engine**:
  - **Injection-Pattern Matching**: Regular expression bank targeting prompt-injection language across 8 common attack categories.
  - **Encoding-Trick Detection**: Scans for zero-width characters and cross-script homoglyphs used to bypass basic keyword filters.
- **Adapters**: Six format-specific adapters that separate visible text from explicitly hidden content:
  - `TextAdapter` for plain text and markdown.
  - `HTMLAdapter` detecting invisible elements (CSS `display:none`, `visibility:hidden`, zero opacity, and white-on-white text).
  - `PDFAdapter` detecting characters outside page boundaries, explicitly invisible render modes, and background-color matching.
  - `DocxAdapter` for Word documents checking `font.hidden` attributes and XML shading elements.
  - `PPTXAdapter` extracting speaker notes and identifying off-canvas shapes.
  - `SpreadsheetAdapter` detecting completely hidden sheets, hidden rows/columns, and cell comments.
- **Provenance Stamping**: Output generation matching the Open Knowledge Format (OKF) v0.2 spec, attaching scan metadata as an extension without auto-verifying content.
- **CLI**: A command-line interface (`okfguard scan` and `okfguard review`) for running manual security audits and reviewing quarantined logs.
