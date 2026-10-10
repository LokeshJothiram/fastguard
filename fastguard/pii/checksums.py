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
        parsed = phonenumbers.parse(phone_str, "US")
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
