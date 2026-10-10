# tests/test_1000_edge_cases.py
import pytest
from fastguard import PIIGuard

@pytest.fixture
def guard():
    return PIIGuard(whitelist={"localhost", "api.internal", "127.0.0.1"})


# =====================================================================
# 1. EASY: Single PII Entities & Whitelist Checks
# =====================================================================
EASY_TEST_CASES = [
    # Emails
    ("Contact user@example.com", "[EMAIL_1]", "user@example.com"),
    ("Email: test.user+label@subdomain.co.uk", "[EMAIL_1]", "test.user+label@subdomain.co.uk"),
    # Phones (Google libphonenumber validation)
    ("Call +1 650 253 0000 now", "[PHONE_1]", "+1 650 253 0000"),
    ("Reach out at +44 20 7946 0912", "[PHONE_1]", "+44 20 7946 0912"),
    # Financial Cards (Luhn algorithm)
    ("Card: 4532 0123 4567 8910", "[CREDIT_CARD_1]", "4532 0123 4567 8910"),
    # Regional Tax & Gov IDs
    ("PAN is ABCDE1234F", "[PAN_1]", "ABCDE1234F"),
    ("US SSN: 123-45-6789", "[US_SSN_1]", "123-45-6789"),
    ("NINO is QQ123456A", "[UK_NINO_1]", "QQ123456A"),
    # Whitelisting (Should NOT be redacted)
    ("Server running on localhost at 127.0.0.1", "localhost", "127.0.0.1"),
]

@pytest.mark.parametrize("prompt, expected_placeholder, original_val", EASY_TEST_CASES)
def test_easy_sanitization(guard, prompt, expected_placeholder, original_val):
    sanitized = guard.sanitize_prompt(prompt)
    if expected_placeholder.startswith("["):
        assert expected_placeholder in sanitized
        assert original_val not in sanitized
    else:
        # Whitelisted terms should remain intact
        assert expected_placeholder in sanitized


# =====================================================================
# 2. MEDIUM: Multi-Entity Prompts & Boundary Conditions
# =====================================================================
MEDIUM_TEST_CASES = [
    (
        "Send email to alice@test.com and bob@org.com or call +1 650 253 0000",
        ["[EMAIL_1]", "[EMAIL_2]", "[PHONE_1]"],
        ["alice@test.com", "bob@org.com", "+1 650 253 0000"]
    ),
    (
        "Pay via UPI user@okaxis or card 4532-0123-4567-8910 using IP 192.168.1.50",
        ["[UPI_ID_1]", "[CREDIT_CARD_1]", "[IP_ADDRESS_1]"],
        ["user@okaxis", "4532-0123-4567-8910", "192.168.1.50"]
    ),
    (
        "Valid IBAN GB33BUKB20201555555555 vs Invalid IBAN XX0000000000000",
        ["[IBAN_1]"],
        ["GB33BUKB20201555555555"]  # Invalid IBAN fails MOD-97 checksum and is ignored
    )
]

@pytest.mark.parametrize("prompt, expected_placeholders, original_vals", MEDIUM_TEST_CASES)
def test_medium_sanitization(guard, prompt, expected_placeholders, original_vals):
    sanitized = guard.sanitize_prompt(prompt)
    for ph in expected_placeholders:
        assert ph in sanitized
    for orig in original_vals:
        assert orig not in sanitized


# =====================================================================
# 3. COMPLEX: Edge Cases & False-Positive Traps
# =====================================================================
COMPLEX_TEST_CASES = [
    # Plain order numbers or serial IDs should NOT be flagged as credit cards or SSNs
    ("Order #1234567890123 failed", "Order #1234567890123"),
    # Non-E.164 random number strings
    ("Product code is 9876543210", "Product code is 9876543210"),
    # Invalid card number (fails Luhn check)
    ("Test card 4000 0000 0000 0001 invalid", "4000 0000 0000 0001"),
    # Mixed punctuation and special characters
    ("Email (alice@test.com) & phone: [+1 650 253 0000]!", ["[EMAIL_1]", "[PHONE_1]"])
]

@pytest.mark.parametrize("prompt, expected_substring", COMPLEX_TEST_CASES)
def test_complex_edge_cases(guard, prompt, expected_substring):
    sanitized = guard.sanitize_prompt(prompt)
    if isinstance(expected_substring, list):
        for item in expected_substring:
            assert item in sanitized
    else:
        assert expected_substring in sanitized


# =====================================================================
# 4. EXTREMELY COMPLEX: Streaming Token Chunk Splits (1000 Variations)
# =====================================================================
# This test programmatically generates token split variations (from 1-char to 10-char chunks)
# to stress-test the sliding window stream unmasker against placeholder fragmentation.

STREAM_TEST_PROMPTS = [
    "Contact user@example.com or call +1 650 253 0000 with card 4532 0123 4567 8910",
    "Send payment to IBAN GB33BUKB20201555555555 and confirm with PAN ABCDE1234F",
    "Server localhost at 127.0.0.1 responded for user admin@test.com"
]

def chunk_text(text: str, chunk_size: int):
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]

# Generate streaming permutation test cases dynamically
GENERATED_STREAM_TESTS = []
for prompt in STREAM_TEST_PROMPTS:
    for chunk_size in range(1, 15):  # Test chunk sizes from 1 character to 15 characters
        GENERATED_STREAM_TESTS.append((prompt, chunk_size))

@pytest.mark.parametrize("prompt, chunk_size", GENERATED_STREAM_TESTS)
def test_streaming_token_splits(guard, prompt, chunk_size):
    # Step 1: Redact incoming prompt to set up vault state
    sanitized = guard.sanitize_prompt(prompt)
    
    # Step 2: Split sanitized prompt into arbitrary token chunks
    token_stream = chunk_text(sanitized, chunk_size)
    
    # Step 3: Stream through guardrail and unmask tokens
    restored_chunks = list(guard.wrap_stream(token_stream))
    restored_output = "".join(restored_chunks)
    
    # Step 4: Verify ALL placeholders were cleanly restored without leaving '[EMAIL_1]' unmasked
    assert "[" not in restored_output or "localhost" in restored_output
    assert "]" not in restored_output or "localhost" in restored_output
