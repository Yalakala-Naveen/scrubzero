"""Deterministic recognizers for ScrubZero.

Every recognizer is a regex candidate finder plus a validator. A candidate
is only redacted when its validator passes — checksum validation (Luhn for
cards, mod-97 for IBANs, structural rules for SSNs) runs *before* masking,
so look-alike numbers (order ids, timestamps, random digit strings) are
left alone. No model, no network, no dependencies.

v2 (Nov 22, 2026) adds the secret shapes people actually paste into AI
tools — the v1 misses the owner's probing exposed:

- ``PASSWORD``: keyword assignments (``password=...``, ``"password": "..."``)
  and the password segment of connection-string URLs
  (``postgres://user:pass@host`` — only the password is masked, the rest of
  the URL survives so the line stays debuggable).
- ``SECRET``: token/secret assignments (``api_key=...``, ``client_secret:
  ...``) and ``Authorization: Bearer ...`` values.
- ``PRIVATE_KEY``: PEM private-key blocks, whole or truncated.
- More ``API_KEY`` shapes: Anthropic, GitHub fine-grained PATs, npm, PyPI,
  Slack webhook URLs.

Assignment finders are context-anchored and prose-guarded: a bare value is
only masked when it does not read as an English instruction word (see
``_PROSE_WORDS``), and references/placeholders (``${ENV}``, ``$ENV``,
``<...>``, ``[...]``, ``***``) are never masked — they are not secrets.
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
    # Higher priority wins an overlap at the same start (a URL password
    # segment beats an EMAIL candidate that starts at the same character).
    priority: int = 0


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
# v2 assignment-value guard: is this literal a secret, or prose/a reference?
# --------------------------------------------------------------------------

#: Bare values that read as instructions or UI words, not secrets. A pasted
#: config line ``password: required`` is documentation, not a leak.
_PROSE_WORDS = frozenset({
    "required", "optional", "reset", "change", "changed", "forgot",
    "forgotten", "policy", "field", "fields", "input", "label", "text",
    "hidden", "visible", "incorrect", "correct", "valid", "invalid",
    "expired", "expiry", "update", "updated", "confirm", "confirmation",
    "entry", "prompt", "hint", "rules", "length", "strength", "recovery",
    "protect", "protected", "secure", "security", "manager", "management",
    "authentication", "login", "logon", "signin", "username", "user",
    "admin", "default", "example", "sample", "test", "testing", "demo",
    "placeholder", "changeme", "redacted", "masked", "password", "passwd",
    "secret", "token", "string", "number", "enabled", "disabled", "true",
    "false", "null", "none", "undefined",
})


def _is_reference_or_placeholder(value: str) -> bool:
    """Env references and placeholders name a secret; they are not one."""
    if value.startswith(("${", "$", "<", "[", "{", "env:", "ENV:")):
        return True
    if value and all(ch in "*xX•·." for ch in value):
        return True
    return False


def _assignment_value_is_secret(value: str, *, quoted: bool, password_key: bool) -> bool:
    if not value or _is_reference_or_placeholder(value):
        return False
    if value.lower() in _PROSE_WORDS:
        return False
    if quoted:
        # An explicitly quoted literal after a secret key is a secret,
        # however short or plain it reads.
        return True
    if password_key:
        # The key itself is the context: any non-prose literal of a
        # plausible password length counts, plain lowercase included.
        return len(value) >= 4
    # Token/secret keys are more ambiguous in prose and configs, so a bare
    # value must look token-like: long enough and not a plain lowercase word.
    return len(value) >= 8 and not (value.isalpha() and value.islower())


# --------------------------------------------------------------------------
# Patterns — ordered by priority in find_candidates (secrets first).
# --------------------------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern[str], Callable[[str], bool]]] = [
    # JWT: three base64url segments, header starts with eyJ
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), _always),
    # Cloud / provider token shapes
    ("API_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), _always),  # AWS access key id
    ("API_KEY", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), _always),  # GitHub token (classic)
    ("API_KEY", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), _always),  # GitHub fine-grained PAT
    ("API_KEY", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), _always),  # Slack token
    ("API_KEY", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), _always),  # Stripe
    ("API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"), _always),  # Anthropic
    ("API_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), _always),  # OpenAI-style
    ("API_KEY", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), _always),  # Google API key
    ("API_KEY", re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), _always),  # npm token
    ("API_KEY", re.compile(r"\bpypi-[A-Za-z0-9_-]{16,}\b"), _always),  # PyPI token
    ("API_KEY", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"), _always),  # Slack webhook
    # An email-shaped segment inside a URL authority (postgres://app@host)
    # is a username, not an email — the (?<!/) guard keeps it untouched.
    ("EMAIL", re.compile(r"(?<!/)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), _always),
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

# --------------------------------------------------------------------------
# v2 context finders — candidates are value *segments*, not whole matches,
# so the key, the quotes and the rest of the line survive the redaction.
# --------------------------------------------------------------------------

_PASSWORD_KEYS = {"password", "passwd", "pwd", "passphrase"}

_ASSIGNMENT_RE = re.compile(
    r"""["']?\b(?P<key>password|passwd|pwd|passphrase"""
    r"""|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token"""
    r"""|client[_-]?secret|secret|token)\b["']?"""
    r"""\s*[:=]\s*"""
    r"""(?P<val>"[^"\n]+"|'[^'\n]+'|[^\s,;]+)""",
    re.IGNORECASE,
)

_URL_PASSWORD_RE = re.compile(
    r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@]+:(?P<pw>[^\s/@]+)@"
)

_BEARER_RE = re.compile(r"(?i)\bBearer\s+(?P<tok>[A-Za-z0-9._\-+/=~]{12,})")

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
    re.DOTALL,
)
# A truncated paste: header + base64 body lines, no END line.
_PRIVATE_KEY_TRUNCATED_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[ \t]*(?:\n[ \t]*[A-Za-z0-9+/=]{8,}[ \t]*)+"
)


def _find_assignments(text: str) -> Iterator[Candidate]:
    for m in _ASSIGNMENT_RE.finditer(text):
        key = re.sub(r"[_-]", "", m.group("key").lower())
        password_key = key in _PASSWORD_KEYS
        raw = m.group("val")
        quoted = raw[:1] in ("'", '"')
        value = raw[1:-1] if quoted else raw
        if not _assignment_value_is_secret(value, quoted=quoted, password_key=password_key):
            continue
        start, end = m.span("val")
        if quoted:
            start, end = start + 1, end - 1
        yield Candidate("PASSWORD" if password_key else "SECRET", start, end, value)


def _find_url_passwords(text: str) -> Iterator[Candidate]:
    for m in _URL_PASSWORD_RE.finditer(text):
        value = m.group("pw")
        if _is_reference_or_placeholder(value):
            continue
        start, end = m.span("pw")
        yield Candidate("PASSWORD", start, end, value, priority=1)


def _find_bearer_tokens(text: str) -> Iterator[Candidate]:
    for m in _BEARER_RE.finditer(text):
        start, end = m.span("tok")
        yield Candidate("SECRET", start, end, m.group("tok"))


def _find_private_keys(text: str) -> Iterator[Candidate]:
    spans = []
    for m in _PRIVATE_KEY_RE.finditer(text):
        spans.append((m.start(), m.end()))
        yield Candidate("PRIVATE_KEY", m.start(), m.end(), m.group(0))
    for m in _PRIVATE_KEY_TRUNCATED_RE.finditer(text):
        if any(m.start() < e and m.end() > s for s, e in spans):
            continue  # already covered by a complete block
        yield Candidate("PRIVATE_KEY", m.start(), m.end(), m.group(0))


_FINDERS = (_find_assignments, _find_url_passwords, _find_bearer_tokens, _find_private_keys)

#: Entity names ScrubZero can redact.
ENTITIES: tuple[str, ...] = (
    "EMAIL",
    "CREDIT_CARD",
    "SSN",
    "PHONE",
    "IBAN",
    "IP_ADDRESS",
    "API_KEY",
    "JWT",
    "PASSWORD",
    "SECRET",
    "PRIVATE_KEY",
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
    for finder in _FINDERS:
        for cand in finder(text):
            if cand.entity in wanted:
                found.append(cand)
    # Resolve overlaps: earliest start wins; on a tie, higher priority,
    # then the longest candidate wins.
    found.sort(key=lambda c: (c.start, -c.priority, -(c.end - c.start)))
    chosen: list[Candidate] = []
    occupied_until = -1
    for cand in found:
        if cand.start >= occupied_until:
            chosen.append(cand)
            occupied_until = cand.end
    return iter(chosen)
