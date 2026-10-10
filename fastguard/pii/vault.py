import re
import threading
from typing import Set, Optional
from fastguard.pii.checksums import (
    validate_luhn, 
    validate_verhoeff, 
    validate_phone, 
    validate_iban,
    validate_ip
)

class PIIVault:
    PATTERNS = {
        # High-specificity Identity & Banking
        "EMAIL": (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), None),
        "UPI_ID": (re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}(?!\.[a-zA-Z])\b'), None),
        "IBAN": (re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b'), validate_iban),
        "IFSC": (re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'), None),
        "SWIFT_BIC": (re.compile(r'\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b'), None),
        "UK_SORT_CODE": (re.compile(r'\b\d{2}-\d{2}-\d{2}\b'), None),
        "US_SSN": (re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'), None),
        "AADHAAR": (re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b'), validate_verhoeff),
        "PAN": (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'), None),
        "UK_NINO": (re.compile(r'\b[A-Z]{2}\d{6}[A-D]\b'), None),
        "IP_ADDRESS": (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), validate_ip),
        
        # Financial & Contact numbers
        "CREDIT_CARD": (re.compile(r'\b(?:\d[ -]*?){13,19}\b'), validate_luhn),
        "PHONE": (re.compile(r'(?:\+\d{1,3}[-.\s]*)?(?:\(\d{2,4}\)[-.\s]*|\b\d{1,4}[-.\s]*)(?:\d{2,4}[-.\s]*){2,5}\b'), validate_phone),
    }

    def __init__(
        self, 
        whitelist: Optional[Set[str]] = None,
        enabled_entities: Optional[Set[str]] = None,
        disabled_entities: Optional[Set[str]] = None
    ):
        self.forward_map: dict = {}
        self.reverse_map: dict = {}
        self.counters: dict = {}
        # Default safe terms that should never be masked
        self.whitelist: Set[str] = set(whitelist) if whitelist else {"localhost", "127.0.0.1", "0.0.0.0"}
        # Thread-safety lock for concurrent request environments (FastAPI, Django, etc.)
        self._lock = threading.RLock()
        
        # Filter active pattern detectors
        active = dict(self.PATTERNS)
        if enabled_entities is not None:
            enabled_set = {e.upper() for e in enabled_entities}
            active = {k: v for k, v in active.items() if k in enabled_set}
        if disabled_entities is not None:
            disabled_set = {d.upper() for d in disabled_entities}
            active = {k: v for k, v in active.items() if k not in disabled_set}
        self.active_patterns = active

    def _get_placeholder(self, entity_type: str) -> str:
        self.counters[entity_type] = self.counters.get(entity_type, 0) + 1
        return f"[{entity_type}_{self.counters[entity_type]}]"

    def redact(self, text: str) -> str:
        redacted = text
        with self._lock:
            for entity_type, (pattern, validator) in self.active_patterns.items():
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
        with self._lock:
            unmasked = text
            for placeholder, val in self.reverse_map.items():
                unmasked = unmasked.replace(placeholder, val)
        return unmasked
