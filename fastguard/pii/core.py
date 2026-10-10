from typing import Iterable, Generator, Optional, Set
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
        disabled_entities: Optional[Set[str]] = None
    ):
        self.redact_input = redact_input
        self.unmask_output = unmask_output
        self.vault = PIIVault(
            whitelist=whitelist,
            enabled_entities=enabled_entities,
            disabled_entities=disabled_entities
        )
        self.streamer = StreamingGuardrail(
            self.vault, 
            window_size=window_size,
            enabled=unmask_output
        )

    def sanitize_prompt(self, prompt: str) -> str:
        """Redacts sensitive PII from incoming prompt before sending to LLM.
        If redact_input=False, returns raw prompt untouched.
        """
        if not self.redact_input:
            return prompt
        return self.vault.redact(prompt)

    def wrap_stream(self, token_stream: Iterable[str]) -> Generator[str, None, None]:
        """Unmasks tokens in real-time as they stream from LLM back to client.
        If unmask_output=False, yields stream directly with placeholders intact.
        """
        return self.streamer.process_stream(token_stream)

    def add_whitelist_terms(self, terms: Set[str]):
        """Adds terms dynamically to the vault whitelist."""
        self.vault.whitelist.update({t.lower() for t in terms})
