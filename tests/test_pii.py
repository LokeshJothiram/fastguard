from fastguard import PIIGuard

def test_sanitization():
    guard = PIIGuard()
    prompt = "Contact me at alice@test.com and PAN is ABCDE1234F"
    clean = guard.sanitize_prompt(prompt)
    assert "alice@test.com" not in clean
    assert "[EMAIL_1]" in clean
    assert "[PAN_1]" in clean

def test_whitelisting():
    guard = PIIGuard(whitelist={"alice@test.com"})
    prompt = "Contact alice@test.com or +1 650 253 0000"
    clean = guard.sanitize_prompt(prompt)
    assert "alice@test.com" in clean  # Kept intact
    assert "[PHONE_1]" in clean      # Phone masked

def test_default_ip_whitelist():
    guard = PIIGuard()
    # 127.0.0.1 and localhost should not be masked
    prompt = "Connect to http://127.0.0.1:8080 and server 192.168.1.50"
    clean = guard.sanitize_prompt(prompt)
    assert "127.0.0.1" in clean
    assert "[IP_ADDRESS_1]" in clean
    assert "192.168.1.50" not in clean

def test_iban_validation():
    guard = PIIGuard()
    # Valid IBAN (GB82 WEST 1234 5698 7654 32)
    valid_iban = "GB82WEST12345698765432"
    clean_valid = guard.sanitize_prompt(f"My account is {valid_iban}")
    assert "[IBAN_1]" in clean_valid

    # Invalid check digits
    invalid_iban = "GB83WEST12345698765432"
    clean_invalid = guard.sanitize_prompt(f"My code is {invalid_iban}")
    assert "[IBAN" not in clean_invalid

def test_dynamic_whitelist():
    guard = PIIGuard()
    guard.add_whitelist_terms({"custom-service.internal", "support@fastguard.ai"})
    prompt = "Reach support@fastguard.ai or john@other.com"
    clean = guard.sanitize_prompt(prompt)
    assert "support@fastguard.ai" in clean
    assert "[EMAIL_1]" in clean

def test_stream_restoration():
    guard = PIIGuard()
    _ = guard.sanitize_prompt("My email is alice@test.com")
    
    stream_input = ["Sent ", "to ", "[EMAIL_1]", "!"]
    stream_output = list(guard.wrap_stream(stream_input))
    
    assert "alice@test.com" in "".join(stream_output)

def test_multi_entity_streaming_restoration():
    guard = PIIGuard()
    prompt = "Contact me at user@example.com or +1 650 253 0000 with card 4532 0123 4567 8910"
    sanitized = guard.sanitize_prompt(prompt)
    
    tokens = [token + " " for token in sanitized.split()]
    restored_stream = list(guard.wrap_stream(tokens))
    result = "".join(restored_stream).strip()
    
    assert "user@example.com" in result
    assert "+1 650 253 0000" in result
    assert "4532 0123 4567 8910" in result

