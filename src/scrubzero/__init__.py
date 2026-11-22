"""ScrubZero — zero-dependency PII and secret redaction.

Strip emails, cards, SSNs, phones, IBANs, IPs, API keys, JWTs, password
and secret assignments, connection-string passwords and private keys
from logs, prompts and datasets — deterministically, with checksum
validation before anything is masked, and a report that never
re-exposes a raw value.
"""

from .core import Redaction, ScrubReport, scrub
from .recognizers import ENTITIES

__version__ = "0.2.0"
__all__ = ["scrub", "ScrubReport", "Redaction", "ENTITIES", "__version__"]
