import gradio as gr
from fastguard import PIIGuard

DEFAULT_WHITELIST = {"localhost", "127.0.0.1"}

def process_prompt(user_text):
    if not user_text:
        return "", ""
    # Fresh guard per request to prevent state leakage across sessions
    guard = PIIGuard(whitelist=DEFAULT_WHITELIST)
    # 1. Sanitize input
    sanitized = guard.sanitize_prompt(user_text)
    
    # 2. Simulate stream unmasking
    tokens = [t + " " for t in sanitized.split()]
    restored = "".join(list(guard.wrap_stream(tokens))).strip()
    
    return sanitized, restored

# Build single-page UI
demo = gr.Interface(
    fn=process_prompt,
    inputs=gr.Textbox(lines=3, placeholder="Enter text with emails, phone numbers, or cards..."),
    outputs=[
        gr.Textbox(label="Sanitized Prompt (Redacted)"),
        gr.Textbox(label="Stream Output (Unmasked)")
    ],
    title="🛡️ fastguard Live Sandbox",
    description="Type any text to test real-time PII masking and vault restoration.",
    examples=[
        ["Contact Alice at alice@test.com or call +1 650 253 0000 with PAN ABCDE1234F."],
        ["Pay via UPI user@okaxis or card 4532 0123 4567 8910 using IP 192.168.1.50."],
        ["Server running on localhost at 127.0.0.1 responded for user admin@test.com."]
    ]
)

if __name__ == "__main__":
    demo.launch()
