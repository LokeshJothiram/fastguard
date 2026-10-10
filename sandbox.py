from fastguard import PIIGuard

def interactive_sandbox():
    guard = PIIGuard(whitelist={"localhost", "api.internal"})
    
    print("=" * 60)
    print("🛡️  FASTGUARD INTERACTIVE PII TEST HARNESS 🛡️")
    print("Type any prompt containing emails, phone numbers, cards, or IDs.")
    print("Type 'exit' or 'q' to quit.")
    print("=" * 60)

    while True:
        try:
            user_input = input("\n[Input Prompt] > ").strip()
            if not user_input or user_input.lower() in ["exit", "q"]:
                print("Exiting test harness.")
                break

            # 1. Sanitize input prompt
            sanitized_prompt = guard.sanitize_prompt(user_input)
            print(f"[Sanitized Prompt] > {sanitized_prompt}")

            # 2. Simulate streaming tokens back
            print("\n[Simulated LLM Stream Output]:")
            tokens = [token + " " for token in sanitized_prompt.split()]
            restored_stream = guard.wrap_stream(tokens)
            print("".join(restored_stream))

        except KeyboardInterrupt:
            print("\nExiting test harness.")
            break

if __name__ == "__main__":
    interactive_sandbox()
