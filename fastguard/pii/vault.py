import re
import time
import threading
from typing import Set, Optional, List, Dict, Any
from fastguard.pii.checksums import (
    validate_luhn, 
    validate_verhoeff, 
    validate_phone, 
    validate_iban,
    validate_ip,
    validate_street_address,
    is_personal_email,
    mask_pii_value
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
        # Label-glued lookaround boundary for SSN (e.g., ssn987-65-4321)
        "US_SSN": (re.compile(r'(?<!\d)(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}(?!\d)'), None),
        "AADHAAR": (re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b'), validate_verhoeff),
        "PAN": (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b'), None),
        "UK_NINO": (re.compile(r'\b[A-Z]{2}\d{6}[A-D]\b'), None),
        "IP_ADDRESS": (
            re.compile(
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|'
                r'(?<![:\w])(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?![:\w])|'
                r'(?<![:\w])(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}(?![:\w])|'
                r'(?<![:\w])(?:[0-9a-fA-F]{1,4}:){1,7}:(?![:\w])|'
                r'(?<![:\w])::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(?![:\w])|'
                r'(?<![:\w])::(?![:\w])'
            ),
            validate_ip
        ),
        
        # Developer Secrets & Cloud Credentials (Roadmap v1.1.0)
        "AWS_KEY": (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), None),
        "GITHUB_TOKEN": (re.compile(r'\b(?:ghp_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})\b'), None),
        "OPENAI_KEY": (re.compile(r'\bsk-proj-[A-Za-z0-9_-]{48,}\b'), None),
        "BEARER_TOKEN": (re.compile(r'\bBearer\s+[A-Za-z0-9\-\._~\+\/]+=*\b'), None),
        "PRIVATE_KEY": (re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----|-----BEGIN (?:RSA )?PRIVATE KEY-----'), None),
        
        # Physical Street Address (Regex-only, sub-millisecond, zero NLP dependency)
        "STREET_ADDRESS": (
            re.compile(
                r'\b\d{1,5}\s+[A-Za-z0-9\.\s]{2,30}?\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Way|Court|Ct|Circle|Cir|Terrace|Ter|Place|Pl|Highway|Hwy|Suite|Ste|Apt|Unit|Floor|Fl)\b(?:\s+(?:Apt|Suite|Ste|Unit|#)\s*[A-Za-z0-9\-]+)?',
                re.IGNORECASE
            ),
            validate_street_address
        ),
        
        # Financial & Contact numbers (Lookaround boundary catches card4532015012345678)
        "CREDIT_CARD": (re.compile(r'(?<!\d)(?:\d[ -]*?){13,19}(?!\d)'), validate_luhn),
        "PHONE": (re.compile(r'(?:\+\d{1,3}[-.\s]*)?(?:\(\d{2,4}\)[-.\s]*|\b\d{1,4}[-.\s]*)(?:\d{2,4}[-.\s]*){2,5}\b'), validate_phone),
    }

    def __init__(
        self, 
        whitelist: Optional[Set[str]] = None,
        enabled_entities: Optional[Set[str]] = None,
        disabled_entities: Optional[Set[str]] = None,
        personal_email_only: bool = False,
        work_domains: Optional[Set[str]] = None,
        mask_mode: str = "placeholder"
    ):
        self.forward_map: dict = {}
        self.reverse_map: dict = {}
        self.counters: dict = {}
        # Default safe terms that should never be masked
        self.whitelist: Set[str] = set(whitelist) if whitelist else {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
        # Thread-safety lock for concurrent request environments (FastAPI, Django, etc.)
        self._lock = threading.RLock()
        
        # Enterprise policy options
        self.personal_email_only = personal_email_only
        self.work_domains = work_domains
        self.mask_mode = mask_mode.lower()
        self.last_audit_events: List[Dict[str, Any]] = []
        
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

    def redact(self, text: str, mask_mode: Optional[str] = None) -> str:
        start_time = time.perf_counter()
        effective_mode = (mask_mode or self.mask_mode).lower()
        redacted = text
        events: List[Dict[str, Any]] = []
        
        with self._lock:
            # 1. Collect all valid candidate matches across active patterns
            candidates = []
            for entity_type, (pattern, validator) in self.active_patterns.items():
                for match in pattern.finditer(text):
                    val = match.group(0)
                    
                    # Skip whitelisted values
                    if val.lower() in self.whitelist:
                        continue
                    
                    # Personal email only policy
                    if entity_type == "EMAIL" and self.personal_email_only:
                        if not is_personal_email(val, self.work_domains):
                            continue
                    
                    # Run validator if present
                    if validator and not validator(val):
                        continue

                    candidates.append((match.start(), match.end(), entity_type, val))

            # 2. Filter overlapping spans: prioritize earliest start offset, then longest match
            candidates.sort(key=lambda m: (m[0], -(m[1] - m[0])))
            non_overlapping = []
            current_end = -1
            for m in candidates:
                start, end, entity_type, val = m
                if start >= current_end:
                    non_overlapping.append(m)
                    current_end = end

            # 3. Assign replacements and record audit telemetry in text order
            replacements = []
            for start, end, entity_type, val in non_overlapping:
                if effective_mode == "partial":
                    replacement = mask_pii_value(val, entity_type)
                    self.forward_map[val] = replacement
                    self.reverse_map[replacement] = val
                else:
                    if val not in self.forward_map:
                        placeholder = self._get_placeholder(entity_type)
                        self.forward_map[val] = placeholder
                        self.reverse_map[placeholder] = val
                    replacement = self.forward_map[val]

                events.append({
                    "entity": entity_type,
                    "original_value": val,
                    "masked_value": replacement,
                    "original_length": len(val),
                    "start": start,
                    "end": end,
                    "latency_us": round((time.perf_counter() - start_time) * 1_000_000, 2)
                })

                replacements.append((start, end, replacement))

            # 4. Perform character offset span replacement slicing from right-to-left
            for start, end, replacement in sorted(replacements, key=lambda x: x[0], reverse=True):
                redacted = redacted[:start] + replacement + redacted[end:]

            self.last_audit_events = events
        return redacted

    def unmask(self, text: str) -> str:
        with self._lock:
            unmasked = text
            for placeholder, val in self.reverse_map.items():
                unmasked = unmasked.replace(placeholder, val)
        return unmasked

    def get_last_audit_events(self) -> List[Dict[str, Any]]:
        """Returns structured audit telemetry events from the most recent redaction run."""
        with self._lock:
            return list(self.last_audit_events)
