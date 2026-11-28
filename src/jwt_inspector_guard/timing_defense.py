"""Signature Timing Attack Defense Validator & Side-Channel Benchmark Engine.

Empirically evaluates token signature comparison functions to detect timing side-channel
vulnerabilities (early-exit byte-by-byte comparisons) and validates constant-time
defenses implemented with hmac.compare_digest.
100% Python Standard Library.
"""

from __future__ import annotations

import hmac
import statistics
import time
from typing import Callable, List, Optional

from .models import TimingDefenseReport


def vulnerable_early_exit_compare(a: str, b: str) -> bool:
    """Intentionally vulnerable string equality function demonstrating timing leakage."""
    if len(a) != len(b):
        return False
    for char_a, char_b in zip(a, b):
        if char_a != char_b:
            return False  # Early exit leaks position of mismatch
    return True


def safe_constant_time_compare(a: str, b: str) -> bool:
    """Safe constant-time digest comparison using hmac.compare_digest."""
    return hmac.compare_digest(a, b)


def benchmark_signature_comparison(
    compare_func: Optional[Callable[[str, str], bool]] = None,
    trials: int = 50,
    target_length: int = 64,
) -> TimingDefenseReport:
    """Empirically measure timing characteristics of signature verification under varying prefix matches.

    Computes `timing_leakage_detected` and `vulnerability_score` directly from observed
    timing distributions (no hardcoded verdicts by function identity).
    """
    func = compare_func or safe_constant_time_compare
    bounded_trials = max(5, min(int(trials), 5000))
    sig_len = max(32, int(target_length))
    secret_sig = "A" * sig_len

    # Candidate 1: Immediate mismatch at index 0
    mismatch_early = "Z" + ("A" * (sig_len - 1))

    # Candidate 2: Full match up to final index
    mismatch_late = ("A" * (sig_len - 1)) + "Z"

    # Warmup loop to stabilize interpreter/cache
    for _ in range(120):
        func(secret_sig, mismatch_early)
        func(secret_sig, mismatch_late)

    # Batch inner calls per trial so timer resolution accurately resolves ns deltas
    batch_size = 24
    times_early: List[float] = []
    times_late: List[float] = []

    for i in range(bounded_trials):
        # Alternate execution order each trial to cancel thermal/scheduler drift
        if i % 2 == 0:
            t0 = time.perf_counter_ns()
            for _ in range(batch_size):
                func(secret_sig, mismatch_early)
            t1 = time.perf_counter_ns()

            t2 = time.perf_counter_ns()
            for _ in range(batch_size):
                func(secret_sig, mismatch_late)
            t3 = time.perf_counter_ns()
            times_early.append((t1 - t0) / batch_size)
            times_late.append((t3 - t2) / batch_size)
        else:
            t2 = time.perf_counter_ns()
            for _ in range(batch_size):
                func(secret_sig, mismatch_late)
            t3 = time.perf_counter_ns()

            t0 = time.perf_counter_ns()
            for _ in range(batch_size):
                func(secret_sig, mismatch_early)
            t1 = time.perf_counter_ns()
            times_early.append((t1 - t0) / batch_size)
            times_late.append((t3 - t2) / batch_size)

    median_early = statistics.median(times_early)
    median_late = statistics.median(times_late)
    ratio = (median_late / median_early) if median_early > 0 else 1.0

    # Empirical statistical delta (Welch-like effect size using pooled IQR/stdev)
    diffs = [late - early for early, late in zip(times_early, times_late)]
    median_diff = statistics.median(diffs)
    stdev_early = statistics.stdev(times_early) if len(times_early) > 1 else 0.0
    stdev_late = statistics.stdev(times_late) if len(times_late) > 1 else 0.0
    pooled_sd = max(1.0, ((stdev_early ** 2 + stdev_late ** 2) / 2.0) ** 0.5)
    effect_size = median_diff / pooled_sd

    # Empirical verdict driven solely by measured timing ratio and positive separation
    leakage = (ratio > 1.35) and (median_diff > 40.0 or effect_size > 0.75)
    constant_time = not leakage

    if ratio <= 1.0:
        vuln_score = 0.0
    else:
        # Smooth empirical score mapping: 1.0x -> 0, 1.35x -> ~28, 2.0x+ -> 80..100
        raw_score = (ratio - 1.0) * 80.0
        vuln_score = round(min(100.0, max(0.0, raw_score)), 2)

    recommendations: List[str] = []
    if leakage:
        recommendations.append(
            f"CRITICAL: Measured late/early mismatch timing ratio {ratio:.2f}x (delta +{median_diff:.1f} ns) "
            "indicates early-exit comparison leakage. Use `hmac.compare_digest(sig_a, sig_b)` for constant-time verification."
        )
        recommendations.append(
            "Ensure signature validation does not return differing HTTP status codes or response times based on matching prefix length."
        )
    else:
        recommendations.append(
            f"PASS: Measured late/early mismatch timing ratio {ratio:.2f}x (delta {median_diff:+.1f} ns) "
            "is within constant-time tolerance across signature byte prefixes."
        )
        recommendations.append(
            "Maintain use of `hmac.compare_digest` in all authentication gates and MAC verification routines."
        )

    return TimingDefenseReport(
        constant_time_verified=constant_time,
        timing_leakage_detected=leakage,
        vulnerability_score=vuln_score,
        sample_count=bounded_trials * 2,
        average_early_ns=round(median_early, 2),
        average_full_ns=round(median_late, 2),
        timing_delta_ratio=round(ratio, 4),
        recommendations=recommendations,
    )
