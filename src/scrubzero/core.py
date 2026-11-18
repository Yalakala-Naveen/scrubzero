"""ScrubZero core: scrub() — deterministic PII/secret redaction.

The report never contains a raw value: each redaction is listed with its
entity type and its span in the *original* text, in the FailLoud verdict
style — a verdict you can audit without re-exposing what was removed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Callable, Literal, Union

from .recognizers import ENTITIES, find_candidates

Replacement = Union[Literal["label", "hash"], Callable[[str, str], str]]


@dataclass(frozen=True)
class Redaction:
    entity: str
    start: int
    end: int
    replacement: str

    def to_dict(self) -> dict:
        return {
            "entity": self.entity,
            "start": self.start,
            "end": self.end,
            "replacement": self.replacement,
        }


@dataclass
class ScrubReport:
    redactions: list[Redaction] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.redactions:
            out[r.entity] = out.get(r.entity, 0) + 1
        return out

    @property
    def total(self) -> int:
        return len(self.redactions)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "counts": self.counts,
            "redactions": [r.to_dict() for r in self.redactions],
        }


def _replacement_for(mode: Replacement, entity: str, raw: str) -> str:
    if callable(mode):
        return str(mode(entity, raw))
    if mode == "hash":
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]
        return f"[{entity}:sha256:{digest}]"
    return f"[{entity}]"


def scrub(
    text: str,
    entities: tuple[str, ...] | list[str] | None = None,
    replacement: Replacement = "label",
) -> tuple[str, ScrubReport]:
    """Redact PII and secrets from *text*.

    Returns ``(clean_text, report)``. The report lists every redaction by
    type and original span — never the raw value.
    """
    if not isinstance(text, str):
        raise TypeError("scrub() expects a str")
    wanted = tuple(entities) if entities is not None else None
    if wanted is not None:
        unknown = set(wanted) - set(ENTITIES)
        if unknown:
            raise ValueError(f"unknown entities: {sorted(unknown)}; known: {list(ENTITIES)}")

    candidates = list(find_candidates(text, wanted))
    report = ScrubReport()
    parts: list[str] = []
    cursor = 0
    for cand in candidates:
        repl = _replacement_for(replacement, cand.entity, cand.text)
        parts.append(text[cursor : cand.start])
        parts.append(repl)
        cursor = cand.end
        report.redactions.append(
            Redaction(cand.entity, cand.start, cand.end, repl)
        )
    parts.append(text[cursor:])
    return "".join(parts), report
