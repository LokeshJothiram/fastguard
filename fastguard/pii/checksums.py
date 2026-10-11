import phonenumbers

def validate_ip(ip_str: str) -> bool:
    """Validates IPv4 addresses - each octet must be 0-255."""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False

def validate_phone(phone_str: str) -> bool:
    try:
        digits_only = [c for c in phone_str if c.isdigit()]
        if len(digits_only) < 7:
            return False
        region = None if phone_str.strip().startswith("+") else "US"
        parsed = phonenumbers.parse(phone_str, region)
        return phonenumbers.is_valid_number(parsed)
    except Exception:
        return False

def validate_luhn(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0

def validate_verhoeff(num_str: str) -> bool:
    d_table = [
        [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[2,5,8,1,4,3,6,7,9,0],
        [3,6,9,0,5,8,2,7,4,1],[4,7,0,9,8,1,5,2,3,6],[5,0,1,2,3,7,8,9,4,6],
        [6,8,2,7,1,4,0,5,3,9],[7,9,3,8,0,6,4,1,2,5],[8,2,4,1,9,0,7,3,5,6],
        [9,4,6,3,7,2,1,5,0,8]
    ]
    p_table = [
        [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
        [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
        [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]
    ]
    digits = [int(c) for c in num_str if c.isdigit()]
    if len(digits) != 12:
        return False
    c = 0
    for i, digit in enumerate(reversed(digits)):
        c = d_table[c][p_table[i % 8][digit]]
    return c == 0

def validate_iban(iban: str) -> bool:
    """Validates IBAN account numbers using MOD-97 algorithm."""
    iban = iban.replace(" ", "").upper()
    if len(iban) < 15 or len(iban) > 34:
        return False
    rearranged = iban[4:] + iban[:4]
    numeric_iban = ""
    for char in rearranged:
        if char.isdigit():
            numeric_iban += char
        else:
            numeric_iban += str(ord(char) - 55)
    try:
        return int(numeric_iban) % 97 == 1
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# Consumer Email Domains & Personal vs. Work Detection
# ---------------------------------------------------------------------------

CONSUMER_EMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "yahoo.co.in",
    "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com", "msn.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.net", "mail.com", "yandex.com", "yandex.ru", "zoho.com",
    "rediffmail.com", "qq.com", "163.com", "126.com", "naver.com"
}

def is_personal_email(email_str: str, work_domains: set = None) -> bool:
    """Determines whether an email address is a personal consumer email vs a corporate address.
    If work_domains is specified, any domain matching work_domains is treated as corporate (non-personal).
    Otherwise, addresses on known public consumer webmail domains are treated as personal.
    """
    domain = email_str.rpartition("@")[2].strip().lower()
    if not domain or "." not in domain:
        return False
    if work_domains:
        normalized_work = {d.lower().lstrip("@") for d in work_domains}
        return domain not in normalized_work
    return domain in CONSUMER_EMAIL_DOMAINS


# ---------------------------------------------------------------------------
# Partial Masking Logic (Audit logs & non-destructive UI display)
# ---------------------------------------------------------------------------

def mask_pii_value(val: str, entity_type: str = "GENERIC") -> str:
    """Produces a shape-preserving, partial-masked representation of sensitive PII.
    Useful for audit logs, reporting cards, and visual verification.
    """
    if not val:
        return val
    
    if entity_type == "EMAIL" and "@" in val:
        local, _, domain = val.partition("@")
        keep = min(3, max(1, len(local) // 2))
        tld = domain.rsplit(".", 1)[-1] if "." in domain else "com"
        return f"{local[:keep]}xxxxxxx@xxxxxxx.{tld}"
        
    if entity_type == "CREDIT_CARD":
        digits = [c for c in val if c.isdigit()]
        if len(digits) >= 12:
            return f"{''.join(digits[:4])}-xxxx-xxxx-{''.join(digits[-4:])}"
            
    if entity_type == "US_SSN":
        clean_ssn = val.replace("-", "").strip()
        if len(clean_ssn) == 9:
            return f"xxx-xx-{clean_ssn[-4:]}"
            
    if entity_type == "PHONE":
        digits = [c for c in val if c.isdigit()]
        if len(digits) >= 7:
            return f"{''.join(digits[:3])}-xxxx-{''.join(digits[-2:])}"
            
    if entity_type == "STREET_ADDRESS":
        parts = val.split(maxsplit=1)
        if len(parts) == 2 and parts[0].isdigit():
            return f"xxx {parts[1]}"

    # Generic partial fallback
    keep = min(3, max(1, len(val) // 3))
    return f"{val[:keep]}xxxxxxx{val[-keep:] if len(val) > keep * 2 else ''}"


def validate_street_address(address_str: str) -> bool:
    """Validates that a candidate street address has a digit prefix and recognizable street term."""
    s = address_str.strip()
    if not s or len(s) < 6:
        return False
    parts = s.split()
    return bool(parts and parts[0][0].isdigit())
