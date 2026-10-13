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
    assert "user@example.com" in result
    assert "+1 650 253 0000" in result
    assert "4532 0123 4567 8910" in result

def test_redact_input_disabled():
    guard = PIIGuard(redact_input=False)
    prompt = "My secret email is secret@corp.com"
    clean = guard.sanitize_prompt(prompt)
    assert clean == prompt  # Untouched raw text

def test_unmask_output_disabled():
    guard = PIIGuard(unmask_output=False)
    _ = guard.sanitize_prompt("My email is secret@corp.com")
    
    stream_input = ["Sent ", "to ", "[EMAIL_1]", "!"]
    stream_output = "".join(list(guard.wrap_stream(stream_input)))
    assert "[EMAIL_1]" in stream_output  # Retains placeholder
    assert "secret@corp.com" not in stream_output

def test_selective_enabled_entities():
    # Only mask CREDIT_CARD, leave EMAIL untouched
    guard = PIIGuard(enabled_entities={"CREDIT_CARD"})
    prompt = "Email alice@test.com card 4532 0123 4567 8910"
    clean = guard.sanitize_prompt(prompt)
    assert "alice@test.com" in clean
    assert "[CREDIT_CARD_1]" in clean

def test_selective_disabled_entities():
    # Disable PHONE, keep EMAIL
    guard = PIIGuard(disabled_entities={"PHONE"})
    prompt = "Call +1 650 253 0000 or email alice@test.com"
    clean = guard.sanitize_prompt(prompt)
    assert "+1 650 253 0000" in clean
    assert "[EMAIL_1]" in clean

def test_personal_vs_work_email():
    # Only mask personal consumer email, leave corporate email intact
    guard = PIIGuard(personal_email_only=True, work_domains={"fastguard.ai", "acme.corp"})
    prompt = "Reach colleague at john@fastguard.ai or personal at john.doe@gmail.com"
    clean = guard.sanitize_prompt(prompt)
    assert "john@fastguard.ai" in clean      # Work email preserved
    assert "john.doe@gmail.com" not in clean  # Personal email masked
    assert "[EMAIL_1]" in clean

def test_partial_masking_mode():
    guard = PIIGuard()
    prompt = "My card is 4532 0123 4567 8910 and email alice.smith@gmail.com"
    partial_clean = guard.sanitize_prompt(prompt, mask_mode="partial")
    assert "4532-xxxx-xxxx-8910" in partial_clean
    assert "alixxxxxxx@xxxxxxx.com" in partial_clean
    assert "[EMAIL_1]" not in partial_clean

def test_label_glued_boundary():
    guard = PIIGuard()
    # Unspaced label attached directly to digits
    prompt = "Here is my ssn123-45-6789 and card4532012345678910"
    clean = guard.sanitize_prompt(prompt)
    assert "[US_SSN_1]" in clean
    assert "[CREDIT_CARD_1]" in clean
    assert "123-45-6789" not in clean

def test_audit_telemetry_events():
    guard = PIIGuard()
    prompt = "Alert user at dev@test.com with IP 192.168.1.100"
    clean = guard.sanitize_prompt(prompt)
    events = guard.get_last_audit_events()
    assert len(events) == 2
    entities = [e["entity"] for e in events]
    assert "EMAIL" in entities
    assert "IP_ADDRESS" in entities
    assert all("latency_us" in e and "original_length" in e for e in events)

def test_street_address_detection():
    guard = PIIGuard()
    prompt = "The package was shipped to 742 Evergreen Terrace, Apt 4B yesterday."
    clean = guard.sanitize_prompt(prompt)
    assert "[STREET_ADDRESS_1]" in clean
    assert "742 Evergreen Terrace, Apt 4B" not in clean

def test_ipv6_detection_and_whitelist():
    guard = PIIGuard()
    # ::1 should be whitelisted by default, 2001:db8::1 and fe80::1 should be masked
    prompt = "Connect loopback ::1 or remote 2001:0db8:85a3:0000:0000:8a2e:0370:7334 or fe80::1 at 12:30:45"
    clean = guard.sanitize_prompt(prompt)
    assert "::1" in clean
    assert "12:30:45" in clean  # Timestamps are not masked as IP
    assert "[IP_ADDRESS_1]" in clean
    assert "[IP_ADDRESS_2]" in clean
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in clean
    assert "fe80::1" not in clean

def test_developer_secrets_detection():
    guard = PIIGuard()
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    gh_pat = "ghp_123456789012345678901234567890123456"
    openai_key = "sk-proj-" + "a" * 50
    bearer_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
    private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    
    prompt = (
        f"Config secrets: aws={aws_key}, token={gh_pat}, ai={openai_key}, "
        f"auth={bearer_token}, key=\n{private_key}"
    )
    clean = guard.sanitize_prompt(prompt)
    
    assert "[AWS_KEY_1]" in clean
    assert "[GITHUB_TOKEN_1]" in clean
    assert "[OPENAI_KEY_1]" in clean
    assert "[BEARER_TOKEN_1]" in clean
    assert "[PRIVATE_KEY_1]" in clean
    
    assert aws_key not in clean
    assert gh_pat not in clean
    assert openai_key not in clean
    assert bearer_token not in clean
    assert private_key not in clean

def test_span_offset_duplicate_pii_collision_free():
    guard = PIIGuard()
    prompt = "Reach alice@test.com today, and please CC alice@test.com again."
    clean = guard.sanitize_prompt(prompt)
    assert clean == "Reach [EMAIL_1] today, and please CC [EMAIL_1] again."
    assert "alice@test.com" not in clean

def test_dynamic_sliding_window_safety_tail():
    guard = PIIGuard()
    prompt = "Our headquarters is at 742 Evergreen Terrace, Apt 4B"
    clean = guard.sanitize_prompt(prompt)
    assert "[STREET_ADDRESS_1]" in clean
    
    # Stream in fragmented small chunks through the dynamic tail buffer
    stream_input = ["Headquarters ", "is ", "at ", "[STRE", "ET_AD", "DRESS_1]", "."]
    restored = "".join(list(guard.wrap_stream(stream_input)))
    assert "Headquarters is at 742 Evergreen Terrace." in restored


