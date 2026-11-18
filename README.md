# ScrubZero

**Zero-dependency PII and secret redaction for logs, prompts, and datasets.**

Your logs, prompt traces, and support tickets are full of things that should
never have been stored in plain text: customer emails, card numbers, SSNs,
API keys, session tokens. The thorough redaction tools are frameworks —
Presidio pulls in spaCy and an NLP pipeline. The lightweight one,
scrubadub, has had no code push since September 2023. ScrubZero is the
lightweight seat, rebuilt properly: **pure standard library, deterministic,
and checksum-validated**, so it only masks what is actually a card, an
IBAN, an SSN — not every long number that walks by.

```bash
pip install scrubzero   # from Mon Nov 23, 2026 — until then, install from GitHub (below)
```

```python
from scrubzero import scrub

clean, report = scrub("mail jane@example.com, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE")
clean
# 'mail [EMAIL], card [CREDIT_CARD], key [API_KEY]'
report.counts   # {'EMAIL': 1, 'CREDIT_CARD': 1, 'API_KEY': 1}
report.to_dict()  # every redaction: type + span — never the raw value
```

## What it catches (v1)

| Entity | How it is verified |
|---|---|
| `EMAIL` | Address shape |
| `CREDIT_CARD` | **Luhn checksum** — a 16-digit order id that fails Luhn is left alone |
| `IBAN` | **mod-97 checksum** (ISO 13616) |
| `SSN` | Structural rules (area 001–665/667–899, group/serial non-zero) |
| `PHONE` | US shapes with separators or `+1` — bare 10-digit runs are *not* touched |
| `IP_ADDRESS` | IPv4 octet range-checked; IPv6 shapes |
| `API_KEY` | AWS access key ids, GitHub, Slack, Stripe, OpenAI-style, Google API key shapes |
| `JWT` | Three-segment `eyJ…` token shape |

Replacement modes: `"label"` (`[EMAIL]`), `"hash"`
(`[EMAIL:sha256:1a2b3c4d]` — stable per value, still irreversible), or any
callable `(entity, raw) -> str`.

CLI:

```bash
scrubzero app.log --replacement hash --report redactions.json
cat app.log | scrubzero - --entities EMAIL,CREDIT_CARD
```

## Honest scope

- **No NER.** Person names, addresses, and free-text secrets are *not*
  detected — that is Presidio's slice, and pretending a regex does it
  would be a false claim. ScrubZero covers structured identifiers and
  token shapes, deterministically.
- US phone shapes in v1; non-Latin scripts and image OCR are out of scope.
- A checksum-valid number that happens to be a real card *shape* will be
  masked — for redaction, a rare over-mask beats a leak.

## Why

Demand, counted Nov 16–18, 2026 (pypistats): presidio-analyzer
≈6.26M downloads/month, scrubadub ≈2.35M/month — ≈8.6M/month of people
reaching for redaction, with the lightweight option unmaintained since
2023-09-01 (22 open issues). ScrubZero is the maintained, zero-dependency
answer for the structured-identifier slice.

## Development

```bash
pip install -e ".[dev]"
pytest   # 32 tests
```

MIT License.
