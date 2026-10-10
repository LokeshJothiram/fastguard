# fastguard/pii/stream.py
from typing import Generator, Iterable
from fastguard.pii.vault import PIIVault

class StreamingGuardrail:
    """Sliding-window buffer engine for real-time LLM token stream unmasking."""
    
    def __init__(self, vault: PIIVault, window_size: int = 25):
        self.vault = vault
        self.window_size = window_size

    def process_stream(self, token_stream: Iterable[str]) -> Generator[str, None, None]:
        buffer = ""
        for token in token_stream:
            buffer += token

            # 1. Direct unmask pass for all active vault placeholders
            for placeholder, original in list(self.vault.reverse_map.items()):
                if placeholder in buffer:
                    buffer = buffer.replace(placeholder, original)

            # 2. Yield processed content when buffer exceeds window_size
            if len(buffer) >= self.window_size:
                # Keep a 20-char safety tail to cover longest possible placeholder [CREDIT_CARD_1] = 14 chars
                yield_len = max(1, len(buffer) - 20)
                yield buffer[:yield_len]
                buffer = buffer[yield_len:]

        # 3. Final flush at stream end
        if buffer:
            for placeholder, original in list(self.vault.reverse_map.items()):
                if placeholder in buffer:
                    buffer = buffer.replace(placeholder, original)
            yield buffer
