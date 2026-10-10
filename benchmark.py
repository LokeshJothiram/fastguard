import time
from fastguard import PIIGuard

def run_benchmark():
    guard = PIIGuard()
    sample_prompt = (
        "Hello, my email is alice@test.com, my phone is +1 650 253 0000, "
        "my PAN is ABCDE1234F, and my card is 4532 0123 4567 8910."
    )

    # Warmup
    _ = guard.sanitize_prompt(sample_prompt)

    # Measure 1,000 iterations
    iterations = 1000
    start_time = time.perf_counter_ns()
    for _ in range(iterations):
        _ = guard.sanitize_prompt(sample_prompt)
    total_time_ns = time.perf_counter_ns() - start_time

    avg_latency_us = (total_time_ns / iterations) / 1000
    print("=" * 50)
    print("FASTGUARD PERFORMANCE BENCHMARK")
    print("=" * 50)
    print(f"Sample Input: {sample_prompt}")
    print(f"Redacted Output: {guard.sanitize_prompt(sample_prompt)}")
    print("-" * 50)
    print(f"Average Execution Latency: {avg_latency_us:.2f} microseconds (µs)")
    print(f"Throughput: {1_000_000 / avg_latency_us:.0f} ops/second")
    print("=" * 50)

if __name__ == "__main__":
    run_benchmark()
