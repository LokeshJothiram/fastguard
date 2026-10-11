from typing import Iterable, Generator, Optional, Set, List, Dict, Any
from fastguard.pii.vault import PIIVault
from fastguard.pii.stream import StreamingGuardrail

class PIIGuard:
    def __init__(
        self, 
        window_size: int = 25, 
        whitelist: Optional[Set[str]] = None,
        redact_input: bool = True,
        unmask_output: bool = True,
        enabled_entities: Optional[Set[str]] = None,
        disabled_entities: Optional[Set[str]] = None,
        personal_email_only: bool = False,
        work_domains: Optional[Set[str]] = None,
        mask_mode: str = "placeholder"
    ):
        self.redact_input = redact_input
        self.unmask_output = unmask_output
        self.vault = PIIVault(
            whitelist=whitelist,
            enabled_entities=enabled_entities,
            disabled_entities=disabled_entities,
            personal_email_only=personal_email_only,
            work_domains=work_domains,
            mask_mode=mask_mode
        )
        self.streamer = StreamingGuardrail(
            self.vault, 
            window_size=window_size,
            enabled=unmask_output
        )

    def sanitize_prompt(self, prompt: str, mask_mode: Optional[str] = None) -> str:
        """Redacts sensitive PII from incoming prompt before sending to LLM.
        If redact_input=False, returns raw prompt untouched.
        mask_mode can optionally be overridden per-call ('placeholder' or 'partial').
        """
        if not self.redact_input:
            return prompt
        return self.vault.redact(prompt, mask_mode=mask_mode)

    def wrap_stream(self, token_stream: Iterable[str]) -> Generator[str, None, None]:
        """Unmasks tokens in real-time as they stream from LLM back to client.
        If unmask_output=False, yields stream directly with placeholders intact.
        """
        return self.streamer.process_stream(token_stream)

    def add_whitelist_terms(self, terms: Set[str]):
        """Adds terms dynamically to the vault whitelist."""
        self.vault.whitelist.update({t.lower() for t in terms})

    def get_last_audit_events(self) -> List[Dict[str, Any]]:
        """Returns structured audit telemetry events from the most recent redaction run."""
        return self.vault.get_last_audit_events()
