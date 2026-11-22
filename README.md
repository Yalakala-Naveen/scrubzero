# ScrubZero

**Zero-dependency PII and secret redaction for logs, prompts, and datasets.**

Your logs, prompt traces, and support tickets are full of things that should
never have been stored in plain text: customer emails, card numbers, SSNs,
API keys, session tokens — and the things people paste straight into AI
tools: passwords, `postgres://user:pass@host` connection strings, private
keys. The thorough redaction tools are frameworks — Presidio pulls in
spaCy and an NLP pipeline. The lightweight one, scrubadub, has had no
code push since September 2023. ScrubZero is the lightweight seat,
rebuilt properly: **pure standard library, deterministic, and
checksum-validated**, so it only masks what is actually a card, an
IBAN, an SSN — not every long number that walks by.

```bash
pip install git+https://github.com/Yalakala-Naveen/scrubzero.git
# PyPI launch is held — this project does not launch into the void
# without a named buyer. The GitHub install above is the live route.
```

```python
from scrubzero import scrub

clean, report = scrub("mail jane@example.com, card 4111 1111 1111 1111, key AKIAIOSFODNN7EXAMPLE, password=hunter2, db=postgres://app:Sup3rSecret@db.internal:5432/shop")
clean
# 'mail [EMAIL], card [CREDIT_CARD], key [API_KEY], password=[PASSWORD], db=postgres://app:[PASSWORD]@db.internal:5432/shop'
report.counts   # {'EMAIL': 1, 'CREDIT_CARD': 1, 'API_KEY': 1, 'PASSWORD': 2}
report.to_dict()  # every redaction: type + span — never the raw value
```

## What it catches

| Entity | How it is verified |
|---|---|
| `EMAIL` | Address shape (an email-shaped URL username is *not* touched) |
| `CREDIT_CARD` | **Luhn checksum** — a 16-digit order id that fails Luhn is left alone |
| `IBAN` | **mod-97 checksum** (ISO 13616) |
| `SSN` | Structural rules (area 001–665/667–899, group/serial non-zero) |
| `PHONE` | US shapes with separators or `+1` — bare 10-digit runs are *not* touched |
| `IP_ADDRESS` | IPv4 octet range-checked; IPv6 shapes |
| `API_KEY` | AWS access key ids, GitHub (classic + fine-grained PATs), Slack tokens + webhook URLs, Stripe, Anthropic, OpenAI-style, Google, npm and PyPI token shapes |
| `JWT` | Three-segment `eyJ…` token shape |
| `PASSWORD` *(v2)* | Keyword assignments (`password=…`, `"password": "…"`) and the password segment of connection-string URLs — only the password is masked, the rest of the URL survives |
| `SECRET` *(v2)* | Token/secret assignments (`api_key=…`, `client_secret: …`) and `Authorization: Bearer …` values |
| `PRIVATE_KEY` *(v2)* | PEM private-key blocks, whole or truncated |

The v2 finders are context-anchored and prose-guarded: `password: required`
is documentation, not a leak, and references/placeholders (`${ENV}`, `$ENV`,
`<your-password>`, `********`) are never masked — they name a secret, they
are not one.

Replacement modes: `"label"` (`[EMAIL]`), `"hash"`
(`[EMAIL:sha256:1a2b3c4d]` — stable per value, still irreversible), or any
callable `(entity, raw) -> str`.

CLI:

```bash
scrubzero app.log --replacement hash --report redactions.json
cat app.log | scrubzero - --entities EMAIL,CREDIT_CARD,PASSWORD
```

## Honest scope

- **No NER.** Person names, addresses, and free-text secrets are *not*
  detected — that is Presidio's slice, and pretending a regex does it
  would be a false claim. ScrubZero covers structured identifiers and
  token shapes, deterministically.
- Assignment detection needs the key (`password=`, `api_key:`, …) or a
  URL/Bearer context. A bare secret standing alone with no known shape
  and no context is not detected — including AWS *secret* access keys
  (40-character base64 is indistinguishable from other base64).
- A bare all-lowercase word after a *token/secret* key is left alone
  (too often prose); quote it or use a password key and it is masked.
- US phone shapes; non-Latin scripts and image OCR are out of scope.
- A checksum-valid number that happens to be a real card *shape* will be
  masked — for redaction, a rare over-mask beats a leak.

## Why

Demand, counted Nov 16–22, 2026 (pypistats): presidio-analyzer
≈6.33M downloads/month, scrubadub ≈2.25M/month — ≈8.6M/month of people
reaching for redaction, with the lightweight option unmaintained since
2023-09-01 (22 open issues). ScrubZero is the maintained, zero-dependency
answer for the structured-identifier slice.

## Development

```bash
pip install -e ".[dev]"
pytest   # 48 tests
```

MIT License.
