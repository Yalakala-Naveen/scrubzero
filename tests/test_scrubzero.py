"""ScrubZero tests — every recognizer, every validator, the false-positive
discipline, and the shortest-identifier edge cases (rule from FailLoud,
Nov 15: any filter ships with a test on the shortest realistic id)."""

import hashlib

import pytest

from scrubzero import ENTITIES, scrub

# Well-known published test values (payment-network / IBAN test numbers,
# fictional 555 phone, RFC documentation ranges where noted).
VISA = "4111111111111111"
VISA_SPACED = "4111 1111 1111 1111"
AMEX = "378282246310005"  # 15 digits — shortest mainstream card shape
IBAN_GB = "GB29 NWBK 6016 1331 9268 19"
JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_email_redacted():
    clean, rep = scrub("reach me at jane.doe@example.com please")
    assert clean == "reach me at [EMAIL] please"
    assert rep.counts == {"EMAIL": 1}


def test_credit_card_luhn_valid_redacted():
    clean, rep = scrub(f"card {VISA} charged")
    assert VISA not in clean and rep.counts == {"CREDIT_CARD": 1}


def test_credit_card_spaced_redacted():
    clean, rep = scrub(f"card {VISA_SPACED}")
    assert "4111" not in clean and rep.counts == {"CREDIT_CARD": 1}


def test_credit_card_amex_15_digits_redacted():
    clean, rep = scrub(f"amex {AMEX}")
    assert AMEX not in clean and rep.counts == {"CREDIT_CARD": 1}


def test_credit_card_luhn_invalid_left_alone():
    # One digit off the valid test card — fails Luhn, must NOT be masked.
    clean, rep = scrub("order 4111111111111112 confirmed")
    assert clean == "order 4111111111111112 confirmed"
    assert rep.total == 0


def test_random_16_digit_order_id_left_alone():
    clean, rep = scrub("order id 1234567890123456 shipped")
    assert "1234567890123456" in clean and rep.total == 0


def test_iban_mod97_valid_redacted():
    clean, rep = scrub(f"pay to {IBAN_GB} today")
    assert "NWBK" not in clean and rep.counts == {"IBAN": 1}


def test_iban_mod97_invalid_left_alone():
    bad = "GB29 NWBK 6016 1331 9268 18"  # check digits broken
    clean, rep = scrub(f"pay to {bad} today")
    assert bad in clean and rep.total == 0


def test_ssn_valid_redacted():
    clean, rep = scrub("ssn 123-45-6789 on file")
    assert "123-45-6789" not in clean and rep.counts == {"SSN": 1}


@pytest.mark.parametrize("bad", ["000-45-6789", "666-45-6789", "900-45-6789", "123-00-6789", "123-45-0000"])
def test_ssn_structurally_invalid_left_alone(bad):
    clean, rep = scrub(f"ssn {bad} on file")
    assert bad in clean and rep.total == 0


def test_phone_shapes_redacted():
    for phone in ["415-555-2671", "(415) 555-2671", "+1 415-555-2671", "415.555.2671"]:
        clean, rep = scrub(f"call {phone} now")
        assert rep.counts.get("PHONE") == 1, phone
        assert "2671" not in clean


def test_bare_10_digit_run_not_a_phone():
    clean, rep = scrub("reference 4155552671 attached")
    assert "4155552671" in clean


def test_ipv4_redacted_and_invalid_left_alone():
    clean, rep = scrub("from 192.168.0.1 and 999.10.1.1")
    assert "192.168.0.1" not in clean
    assert "999.10.1.1" in clean
    assert rep.counts == {"IP_ADDRESS": 1}


def test_ipv6_redacted():
    clean, rep = scrub("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 up")
    assert rep.counts.get("IP_ADDRESS") == 1


def test_aws_key_redacted():
    clean, rep = scrub("key AKIAIOSFODNN7EXAMPLE leaked")
    assert "AKIA" not in clean and rep.counts == {"API_KEY": 1}


def test_github_and_stripe_and_openai_shapes():
    samples = [
        "ghp_" + "A" * 36,
        "sk_live_" + "B" * 24,
        "sk-proj-" + "C" * 24,
        "AIza" + "D" * 35,
        "xoxb-123456789012-abcdefghijkl",
    ]
    for s in samples:
        clean, rep = scrub(f"token {s} end")
        assert rep.counts.get("API_KEY") == 1, s
        assert s not in clean


def test_jwt_redacted_as_jwt_not_api_key():
    clean, rep = scrub(f"auth {JWT_SAMPLE}")
    assert rep.counts == {"JWT": 1}
    assert JWT_SAMPLE not in clean


def test_hash_replacement_is_deterministic_and_hides_value():
    text = "mail jane@example.com"
    clean1, _ = scrub(text, replacement="hash")
    clean2, _ = scrub(text, replacement="hash")
    digest = hashlib.sha256(b"jane@example.com").hexdigest()[:8]
    assert clean1 == clean2 == f"mail [EMAIL:sha256:{digest}]"


def test_callable_replacement():
    clean, _ = scrub("mail jane@example.com", replacement=lambda e, raw: f"<{e.lower()}>")
    assert clean == "mail <email>"


def test_entity_subset_filter():
    clean, rep = scrub("mail jane@example.com card " + VISA, entities=["EMAIL"])
    assert rep.counts == {"EMAIL": 1}
    assert VISA in clean


def test_unknown_entity_raises():
    with pytest.raises(ValueError):
        scrub("x", entities=["NOPE"])


def test_report_never_contains_raw_values():
    text = f"mail jane@example.com card {VISA} ssn 123-45-6789"
    _, rep = scrub(text)
    blob = str(rep.to_dict())
    for raw in ["jane@example.com", VISA, "123-45-6789"]:
        assert raw not in blob
    assert rep.total == 3


def test_report_spans_point_at_original():
    text = "mail jane@example.com end"
    _, rep = scrub(text)
    r = rep.redactions[0]
    assert text[r.start : r.end] == "jane@example.com"


def test_clean_text_untouched():
    text = "The quarterly report is ready. See page 42 for the summary of 2026 results."
    clean, rep = scrub(text)
    assert clean == text and rep.total == 0


def test_date_not_redacted():
    clean, rep = scrub("due 2026-11-23, call after")
    assert clean == "due 2026-11-23, call after" and rep.total == 0


def test_multiple_entities_one_pass():
    text = f"user jane@example.com from 10.0.0.5 paid {VISA_SPACED}"
    clean, rep = scrub(text)
    assert rep.total == 3
    assert rep.counts == {"EMAIL": 1, "IP_ADDRESS": 1, "CREDIT_CARD": 1}


def test_entities_constant_matches_scope():
    assert set(ENTITIES) == {
        "EMAIL", "CREDIT_CARD", "SSN", "PHONE", "IBAN", "IP_ADDRESS", "API_KEY", "JWT",
    }


def test_non_string_raises():
    with pytest.raises(TypeError):
        scrub(None)  # type: ignore[arg-type]
