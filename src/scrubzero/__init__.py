"""ScrubZero — zero-dependency PII and secret redaction.

Strip emails, cards, SSNs, phones, IBANs, IPs, API keys and JWTs from
logs, prompts and datasets — deterministically, with checksum validation
before anything is masked, and a report that never re-exposes a raw value.
"""

from .core import Redaction, ScrubReport, scrub
from .recognizers import ENTITIES

__version__ = "0.1.0"
__all__ = ["scrub", "ScrubReport", "Redaction", "ENTITIES", "__version__"]
