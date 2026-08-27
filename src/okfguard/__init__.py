"""okf-guard: Content-safety scanning for OKF generation pipelines.

Detects hidden content and prompt-injection patterns in source documents
before they are written into trusted OKF (Open Knowledge Format) bundles.
"""

__version__ = "0.1.0"

from okfguard.api import sanitize

__all__ = ["sanitize"]
