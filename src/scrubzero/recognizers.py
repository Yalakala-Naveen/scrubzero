"""Deterministic recognizers for ScrubZero.

Every recognizer is a regex candidate finder plus a validator. A candidate
is only redacted when its validator passes — checksum validation (Luhn for
cards, mod-97 for IBANs, structural rules for SSNs) runs *before* masking,
so look-alike numbers (order ids, timestamps, random digit strings) are
left alone. No model, no network, no dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterator


@dataclass(frozen=True)
class Candidate:
    entity: str
    start: int
    end: int
    text: str


# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------

def _luhn_ok(digits: str) -> bool:
    total = 0
    alt = False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0 and len(digits) >= 13


def _iban_ok(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if not (15 <= len(compact) <= 34):
        return False
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        else:
            numeric += str(ord(ch) - 55)  # A=10 ... Z=35
    # mod-97 in chunks to keep ints small
    remainder = 0
    for i in range(0, len(numeric), 7):
        remainder = int(str(remainder) + numeric[i : i + 7]) % 97
    return remainder == 1


def _ssn_ok(value: str) -> bool:
    area, group, serial = value.split("-")
    a, g, s = int(area), int(group), int(serial)
    if a == 0 or a == 666 or 900 <= a <= 999:
        return False
    if g == 0 or s == 0:
        return False
    return True


def _ipv4_ok(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
        if len(p) > 1 and p.startswith("0"):
            return False
    return True


def _always(_: str) -> bool:
    return True


# --------------------------------------------------------------------------
# Patterns — ordered by priority in find_candidates (secrets first).
# --------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str], Callable[[str], bool]]] = [
    # JWT: three base64url segments, header starts with eyJ
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), _always),
    # Cloud / provider token shapes
    ("API_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), _always),  # AWS access key id
    ("API_KEY", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), _always),  # GitHub token
    ("API_KEY", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), _always),  # Slack token
    ("API_KEY", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), _always),  # Stripe
    ("API_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), _always),  # OpenAI-style
    ("API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), _always),  # Google API key
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), _always),
    (
        "IBAN",
        re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?\d{1,3})?\b"),
        _iban_ok,
    ),
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        lambda v: _luhn_ok(re.sub(r"[ -]", "", v)),
    ),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), _ssn_ok),
    ("IP_ADDRESS", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), _ipv4_ok),
    (
        "IP_ADDRESS",
        re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b"),
        _always,
    ),
    # US phone shapes with explicit separators or +1 prefix — bare
    # 10-digit runs are deliberately NOT matched (too many order ids).
    (
        "PHONE",
        re.compile(
            r"(?:\+?1[-.\s]?)?(?:\(\d{3}\)\s?|\d{3}[-.\s])\d{3}[-.\s]\d{4}\b"
        ),
        _always,
    ),
]

#: Entity names ScrubZero can redact in v1.
ENTITIES: tuple[str, ...] = (
    "EMAIL",
    "CREDIT_CARD",
    "SSN",
    "PHONE",
    "IBAN",
    "IP_ADDRESS",
    "API_KEY",
    "JWT",
)


def find_candidates(text: str, entities: tuple[str, ...] | None = None) -> Iterator[Candidate]:
    """Yield validated, non-overlapping candidates in priority order."""
    wanted = set(entities) if entities is not None else set(ENTITIES)
    found: list[Candidate] = []
    for entity, pattern, validator in _PATTERNS:
        if entity not in wanted:
            continue
        for m in pattern.finditer(text):
            value = m.group(0)
            try:
                if not validator(value):
                    continue
            except Exception:
                continue
            found.append(Candidate(entity, m.start(), m.end(), value))
    # Resolve overlaps: earliest start wins; on a tie, the longest wins.
    found.sort(key=lambda c: (c.start, -(c.end - c.start)))
    chosen: list[Candidate] = []
    occupied_until = -1
    for cand in found:
        if cand.start >= occupied_until:
            chosen.append(cand)
            occupied_until = cand.end
    return iter(chosen)
