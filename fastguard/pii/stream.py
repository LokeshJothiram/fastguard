# fastguard/pii/stream.py
from typing import Generator, Iterable
from fastguard.pii.vault import PIIVault

class StreamingGuardrail:
    """Sliding-window buffer engine for real-time LLM token stream unmasking."""
    
    def __init__(self, vault: PIIVault, window_size: int = 25, enabled: bool = True):
        self.vault = vault
        self.window_size = window_size
        self.enabled = enabled

    def process_stream(self, token_stream: Iterable[str]) -> Generator[str, None, None]:
        if not self.enabled:
            for token in token_stream:
                yield token
            return

        buffer = ""
        for token in token_stream:
            buffer += token

            # 1. Direct unmask pass for all active vault placeholders
            for placeholder, original in list(self.vault.reverse_map.items()):
                if placeholder in buffer:
                    buffer = buffer.replace(placeholder, original)

            # 2. Yield processed content when buffer exceeds dynamic window size
            safety_tail = max(20, *(len(p) for p in self.vault.reverse_map)) if self.vault.reverse_map else 20
            effective_window = max(self.window_size, safety_tail + 5)
            if len(buffer) >= effective_window:
                yield_len = max(1, len(buffer) - safety_tail)
                yield buffer[:yield_len]
                buffer = buffer[yield_len:]

        # 3. Final flush at stream end
        if buffer:
            for placeholder, original in list(self.vault.reverse_map.items()):
                if placeholder in buffer:
                    buffer = buffer.replace(placeholder, original)
            yield buffer
