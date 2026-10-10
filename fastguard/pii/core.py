from typing import Iterable, Generator, Optional, Set
from fastguard.pii.vault import PIIVault
from fastguard.pii.stream import StreamingGuardrail

class PIIGuard:
    def __init__(self, window_size: int = 35, whitelist: Optional[Set[str]] = None):
        self.vault = PIIVault(whitelist=whitelist)
        self.streamer = StreamingGuardrail(self.vault, window_size=window_size)

    def sanitize_prompt(self, prompt: str) -> str:
        return self.vault.redact(prompt)

    def wrap_stream(self, token_stream: Iterable[str]) -> Generator[str, None, None]:
        return self.streamer.process_stream(token_stream)

    def add_whitelist_terms(self, terms: Set[str]):
        """Adds terms dynamically to the vault whitelist."""
        self.vault.whitelist.update({t.lower() for t in terms})
