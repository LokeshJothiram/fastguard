import re
from typing import Set, Optional
from fastguard.pii.checksums import (
    validate_luhn, 
    validate_verhoeff, 
    validate_phone, 
    validate_iban
)

class PIIVault:
    PATTERNS = {
        # Network & Contact
        "EMAIL": (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), None),
        "PHONE": (re.compile(r'(?:\+\d{1,3}[-.\s]?|\b\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,9}\b'), validate_phone),
        "IP_ADDRESS": (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), None),
        
        # Financial & Banking
        "CREDIT_CARD": (re.compile(r'\b(?:\d[ -]*?){13,19}\b'), validate_luhn),
        "IBAN": (re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'), validate_iban),
        "SWIFT_BIC": (re.compile(r'\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b'), None),
        "IFSC": (re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'), None),
        "UK_SORT_CODE": (re.compile(r'\b\d{2}-\d{2}-\d{2}\b'), None),
        
        # Identity Documents
        "US_SSN": (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), None),
        "AADHAAR": (re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b'), validate_verhoeff),
        "PAN": (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'), None),
        "UPI_ID": (re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}(?!\.[a-zA-Z])\b'), None),
        "UK_NINO": (re.compile(r'\b[A-Z]{2}\d{6}[A-D]\b'), None),
    }

    def __init__(self, whitelist: Optional[Set[str]] = None):
        self.forward_map = {}
        self.reverse_map = {}
        self.counters = {}
        # Default safe terms that should never be masked
        self.whitelist = set(whitelist) if whitelist else {"localhost", "127.0.0.1", "0.0.0.0"}

    def _get_placeholder(self, entity_type: str) -> str:
        self.counters[entity_type] = self.counters.get(entity_type, 0) + 1
        return f"[{entity_type}_{self.counters[entity_type]}]"

    def redact(self, text: str) -> str:
        redacted = text
        for entity_type, (pattern, validator) in self.PATTERNS.items():
            for match in pattern.finditer(text):
                val = match.group(0)
                
                # Skip whitelisted values
                if val.lower() in self.whitelist:
                    continue
                
                # Run validator if present
                if validator and not validator(val):
                    continue

                if val not in self.forward_map:
                    placeholder = self._get_placeholder(entity_type)
                    self.forward_map[val] = placeholder
                    self.reverse_map[placeholder] = val
                
                redacted = redacted.replace(val, self.forward_map[val])
        return redacted

    def unmask(self, text: str) -> str:
        unmasked = text
        for placeholder, val in self.reverse_map.items():
            unmasked = unmasked.replace(placeholder, val)
        return unmasked
