#!/usr/bin/env python3
"""
COMPREHENSIVE ECDSA vs Probabilistic RSA-PSS Benchmark
=======================================================
Full cryptographic performance comparison across 3 matched security levels.
Generates CSV results + Seaborn graphs including batch-verification
throughput with milestone-based measurement and a ratio summary.

USAGE:
    python3 benchmark_complete.py

REQUIREMENTS:
    pip install cryptography matplotlib seaborn psutil

OUTPUT:
    results/benchmark_results_comprehensive.csv
    results/batch_verification_results.csv
    results/graphs/*.png
"""

import csv
import os
import platform
import statistics
import sys
import time
from datetime import datetime
from itertools import cycle
from pathlib import Path

import psutil
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

try:
    import matplotlib
    import matplotlib.pyplot as plt
    import pandas as pd
    import seaborn as sns

    matplotlib.use("Agg")
    sns.set_theme(
        style="whitegrid",
        palette="muted",
        rc={
            "figure.dpi": 150,
            "axes.titlesize": 16,
            "axes.labelsize": 13,
            "legend.fontsize": 11,
            "xtick.labelsize": 11,
            "ytick.labelsize": 11,
        },
    )
except ImportError:
    print("❌ plotting dependencies not found. Install with: pip install matplotlib seaborn pandas")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

SECURITY_LEVELS = [
    {
        "bits": 112,
        "rsa": 2048,
        "ecdsa": "secp224r1",
        "notes": "secp224r1 baseline (~112-bit)",
    },
    {
        "bits": 128,
        "rsa": 3072,
        "ecdsa": "P-256",
        "notes": "Modern standard baseline",
    },
    {
        "bits": 192,
        "rsa": 7680,
        "ecdsa": "P-384",
        "notes": "High security",
    },
]

CURVES: dict = {
    "secp224r1": ec.SECP224R1(),
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
}

# Warmup runs discarded before timed measurement
WARMUP_ITERATIONS: dict[int, int] = {2048: 20, 3072: 20, 7680: 10}

# Timed iterations; larger = more stable mean/stdev
TIMED_ITERATIONS: dict[int, int] = {2048: 200, 3072: 200, 7680: 100}

# Number of distinct pre-generated signatures cycled during batch verification.
# Using a pool prevents the CPU from trivially caching a single input.
SIG_POOL_SIZE = 50

TEST_MESSAGE = b"Blockchain transaction data for signing and verification benchmark"

OUTPUT_DIR = Path(__file__).parent / "results"
GRAPHS_DIR = OUTPUT_DIR / "graphs"
CSV_PATH = OUTPUT_DIR / "benchmark_results_comprehensive.csv"
BATCH_CSV_PATH = OUTPUT_DIR / "batch_verification_results.csv"

# Milestone tx counts for batch graphs.  A single continuous run is used and
# elapsed time is snapshotted at each milestone — avoiding N redundant passes.
TRANSACTION_COUNTS = [5_000, 10_000, 15_000, 20_000, 25_000, 30_000]


# ============================================================================
# HELPERS
# ============================================================================


def get_memory_mb() -> float:
    """Current process RSS in MB."""
    try:
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0


def get_cpu_time() -> float:
    """Cumulative user+system CPU seconds consumed by this process."""
    try:
        t = psutil.Process(os.getpid()).cpu_times()
        return t.user + t.system
    except Exception:
        return 0.0


def compute_stats(samples: list[float]) -> dict[str, float]:
    """Return mean, median, stdev, min, max, p95 for a list of float samples."""
    n = len(samples)
    sorted_s = sorted(samples)
    p95_idx = min(int(0.95 * n), n - 1)
    return {
        "mean": statistics.mean(samples),
        "median": statistics.median(samples),
        "stdev": statistics.stdev(samples) if n > 1 else 0.0,
        "min": sorted_s[0],
        "max": sorted_s[-1],
        "p95": sorted_s[p95_idx],
    }


def log_system_info() -> None:
    print("💻 System Info:")
    print(f"   Platform     : {platform.platform()}")
    print(f"   Processor    : {platform.processor() or 'unknown'}")
    print(
        f"   CPUs         : {psutil.cpu_count(logical=True)} logical / "
        f"{psutil.cpu_count(logical=False)} physical"
    )
    print(f"   RAM          : {psutil.virtual_memory().total / (1024 ** 3):.1f} GB")
    print(f"   Python       : {sys.version.split()[0]}")
    print()


def measure_batch_milestones(
    verify_fn, tx_counts: list[int]
) -> dict[int, float]:
    """
    Execute verify_fn exactly max(tx_counts) times in one continuous pass and
    record the cumulative elapsed time (ms) at each milestone in tx_counts.

    This avoids running N separate loops for N transaction counts — total work
    equals one pass through the largest count rather than the sum of all counts.
    """
    sorted_counts = sorted(tx_counts)
    max_count = sorted_counts[-1]
    milestones = set(sorted_counts)

    # Warmup: enough to warm branch predictors / instruction caches without
    # being so large it distorts the subsequent timed run.
    for _ in range(min(20, max_count)):
        verify_fn()

    results: dict[int, float] = {}
    t_start = time.perf_counter()
    for i in range(1, max_count + 1):
        verify_fn()
        if i in milestones:
            results[i] = (time.perf_counter() - t_start) * 1000.0

    return results


# ============================================================================
# BENCHMARK FUNCTIONS
# ============================================================================


def benchmark_rsa(key_size: int, security_bits: int) -> dict | None:
    """
    Benchmark RSA-PSS sign + verify.

    Padding and hash descriptors are created once outside the hot loop —
    they are stateless Python objects; OpenSSL builds its own per-call context.
    A pool of SIG_POOL_SIZE distinct PSS signatures (each with a fresh random
    salt) is retained for batch verification cycling.
    """
    print(f"   🔓 RSA-PSS ({key_size}-bit)...", end=" ", flush=True)
    try:
        warmup = WARMUP_ITERATIONS.get(key_size, 5)
        timed = TIMED_ITERATIONS.get(key_size, 20)

        mem_before = get_memory_mb()
        cpu_before = get_cpu_time()

        # --- Key generation -------------------------------------------------
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Stateless descriptors — safe to reuse across calls.
        sign_pad = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )
        verify_pad = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )
        hash_alg = hashes.SHA256()

        # --- Signing --------------------------------------------------------
        for _ in range(warmup):
            private_key.sign(TEST_MESSAGE, sign_pad, hash_alg)

        sign_times: list[float] = []
        signatures: list[bytes] = []
        for _ in range(timed):
            t0 = time.perf_counter()
            sig = private_key.sign(TEST_MESSAGE, sign_pad, hash_alg)
            sign_times.append((time.perf_counter() - t0) * 1000.0)
            signatures.append(sig)

        # --- Verification ---------------------------------------------------
        for sig in signatures[:warmup]:
            public_key.verify(sig, TEST_MESSAGE, verify_pad, hash_alg)

        verify_times: list[float] = []
        for sig in signatures:
            t0 = time.perf_counter()
            public_key.verify(sig, TEST_MESSAGE, verify_pad, hash_alg)
            verify_times.append((time.perf_counter() - t0) * 1000.0)

        # --- Stats ----------------------------------------------------------
        ss = compute_stats(sign_times)
        vs = compute_stats(verify_times)
        mem_delta = max(get_memory_mb() - mem_before, 0.0)
        cpu_elapsed = max(get_cpu_time() - cpu_before, 0.0)

        # Signature pool: cycle through SIG_POOL_SIZE distinct sigs.
        pool = signatures[:SIG_POOL_SIZE]
        pool_iter = cycle(pool)

        def verify_fn() -> None:
            public_key.verify(next(pool_iter), TEST_MESSAGE, verify_pad, hash_alg)

        print(
            f"✅  Sign {ss['mean']:.3f}ms ±{ss['stdev']:.3f}"
            f" | Verify {vs['mean']:.3f}ms ±{vs['stdev']:.3f}"
        )
        return {
            "rsa_sign_mean_ms": ss["mean"],
            "rsa_sign_median_ms": ss["median"],
            "rsa_sign_stdev_ms": ss["stdev"],
            "rsa_sign_p95_ms": ss["p95"],
            "rsa_verify_mean_ms": vs["mean"],
            "rsa_verify_median_ms": vs["median"],
            "rsa_verify_stdev_ms": vs["stdev"],
            "rsa_verify_p95_ms": vs["p95"],
            "rsa_cpu_time_s": cpu_elapsed,
            "rsa_memory_delta_mb": mem_delta,
            "rsa_public_key_size": len(pub_pem),
            "rsa_signature_size": len(signatures[0]),
            "rsa_verify_fn": verify_fn,
        }

    except Exception as exc:
        print(f"❌  {exc}")
        return None


def benchmark_ecdsa(
    curve_name: str, security_bits: int, rsa_key_size: int
) -> dict | None:
    """
    Benchmark ECDSA sign + verify.

    Each signing call produces a unique signature (fresh random nonce k), so
    the timed pool already contains SIG_POOL_SIZE cryptographically distinct
    signatures for cycling during batch measurement.
    """
    print(f"   🔑 ECDSA ({curve_name})...", end=" ", flush=True)
    try:
        warmup = WARMUP_ITERATIONS.get(rsa_key_size, 5)
        timed = TIMED_ITERATIONS.get(rsa_key_size, 20)

        mem_before = get_memory_mb()
        cpu_before = get_cpu_time()

        # --- Key generation -------------------------------------------------
        private_key = ec.generate_private_key(CURVES[curve_name], default_backend())
        public_key = private_key.public_key()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        ecdsa_alg = ec.ECDSA(hashes.SHA256())  # stateless descriptor

        # --- Signing --------------------------------------------------------
        for _ in range(warmup):
            private_key.sign(TEST_MESSAGE, ecdsa_alg)

        sign_times: list[float] = []
        signatures: list[bytes] = []
        for _ in range(timed):
            t0 = time.perf_counter()
            sig = private_key.sign(TEST_MESSAGE, ecdsa_alg)
            sign_times.append((time.perf_counter() - t0) * 1000.0)
            signatures.append(sig)

        # --- Verification ---------------------------------------------------
        for sig in signatures[:warmup]:
            public_key.verify(sig, TEST_MESSAGE, ecdsa_alg)

        verify_times: list[float] = []
        for sig in signatures:
            t0 = time.perf_counter()
            public_key.verify(sig, TEST_MESSAGE, ecdsa_alg)
            verify_times.append((time.perf_counter() - t0) * 1000.0)

        # --- Stats ----------------------------------------------------------
        ss = compute_stats(sign_times)
        vs = compute_stats(verify_times)
        mem_delta = max(get_memory_mb() - mem_before, 0.0)
        cpu_elapsed = max(get_cpu_time() - cpu_before, 0.0)

        pool = signatures[:SIG_POOL_SIZE]
        pool_iter = cycle(pool)

        def verify_fn() -> None:
            public_key.verify(next(pool_iter), TEST_MESSAGE, ecdsa_alg)

        print(
            f"✅  Sign {ss['mean']:.3f}ms ±{ss['stdev']:.3f}"
            f" | Verify {vs['mean']:.3f}ms ±{vs['stdev']:.3f}"
        )
        return {
            "ecdsa_sign_mean_ms": ss["mean"],
            "ecdsa_sign_median_ms": ss["median"],
            "ecdsa_sign_stdev_ms": ss["stdev"],
            "ecdsa_sign_p95_ms": ss["p95"],
            "ecdsa_verify_mean_ms": vs["mean"],
            "ecdsa_verify_median_ms": vs["median"],
            "ecdsa_verify_stdev_ms": vs["stdev"],
            "ecdsa_verify_p95_ms": vs["p95"],
            "ecdsa_cpu_time_s": cpu_elapsed,
            "ecdsa_memory_delta_mb": mem_delta,
            "ecdsa_public_key_size": len(pub_pem),
            "ecdsa_signature_size": len(signatures[0]),
            "ecdsa_verify_fn": verify_fn,
        }

    except Exception as exc:
        print(f"❌  {exc}")
        return None


# ============================================================================
# MAIN BENCHMARK ORCHESTRATION
# ============================================================================


def run_benchmark() -> tuple[list, list]:
    print("=" * 80)
    print("🔐  COMPREHENSIVE ECDSA vs RSA-PSS Benchmark")
    print("=" * 80)
    log_system_info()
    print(f"Started: {datetime.now()}\n")

    results: list[dict] = []
    batch_results: list[dict] = []

    for level in SECURITY_LEVELS:
        bits = level["bits"]
        rsa_size = level["rsa"]
        ecdsa_curve = level["ecdsa"]

        print(f"🔑  Security Level: {bits}-bit  "
              f"(RSA-{rsa_size} vs ECDSA-{ecdsa_curve})")
        print(f"    {level['notes']}")
        print(f"    {'─' * 74}")

        rsa_r = benchmark_rsa(rsa_size, bits)
        ecdsa_r = benchmark_ecdsa(ecdsa_curve, bits, rsa_size)

        if not (rsa_r and ecdsa_r):
            print(f"⚠️   Skipping {bits}-bit — benchmark error.\n")
            continue

        sign_ratio = rsa_r["rsa_sign_mean_ms"] / ecdsa_r["ecdsa_sign_mean_ms"]
        verify_ratio = rsa_r["rsa_verify_mean_ms"] / ecdsa_r["ecdsa_verify_mean_ms"]

        result_row: dict = {
            "security_bits": bits,
            "rsa_key_size": rsa_size,
            "ecdsa_curve": ecdsa_curve,
            "notes": level["notes"],
            # RSA timing
            "rsa_sign_mean_ms": round(rsa_r["rsa_sign_mean_ms"], 4),
            "rsa_sign_median_ms": round(rsa_r["rsa_sign_median_ms"], 4),
            "rsa_sign_stdev_ms": round(rsa_r["rsa_sign_stdev_ms"], 4),
            "rsa_sign_p95_ms": round(rsa_r["rsa_sign_p95_ms"], 4),
            "rsa_verify_mean_ms": round(rsa_r["rsa_verify_mean_ms"], 4),
            "rsa_verify_median_ms": round(rsa_r["rsa_verify_median_ms"], 4),
            "rsa_verify_stdev_ms": round(rsa_r["rsa_verify_stdev_ms"], 4),
            "rsa_verify_p95_ms": round(rsa_r["rsa_verify_p95_ms"], 4),
            "rsa_cpu_time_s": round(rsa_r["rsa_cpu_time_s"], 4),
            "rsa_memory_delta_mb": round(rsa_r["rsa_memory_delta_mb"], 4),
            "rsa_public_key_size": rsa_r["rsa_public_key_size"],
            "rsa_signature_size": rsa_r["rsa_signature_size"],
            # ECDSA timing
            "ecdsa_sign_mean_ms": round(ecdsa_r["ecdsa_sign_mean_ms"], 4),
            "ecdsa_sign_median_ms": round(ecdsa_r["ecdsa_sign_median_ms"], 4),
            "ecdsa_sign_stdev_ms": round(ecdsa_r["ecdsa_sign_stdev_ms"], 4),
            "ecdsa_sign_p95_ms": round(ecdsa_r["ecdsa_sign_p95_ms"], 4),
            "ecdsa_verify_mean_ms": round(ecdsa_r["ecdsa_verify_mean_ms"], 4),
            "ecdsa_verify_median_ms": round(ecdsa_r["ecdsa_verify_median_ms"], 4),
            "ecdsa_verify_stdev_ms": round(ecdsa_r["ecdsa_verify_stdev_ms"], 4),
            "ecdsa_verify_p95_ms": round(ecdsa_r["ecdsa_verify_p95_ms"], 4),
            "ecdsa_cpu_time_s": round(ecdsa_r["ecdsa_cpu_time_s"], 4),
            "ecdsa_memory_delta_mb": round(ecdsa_r["ecdsa_memory_delta_mb"], 4),
            "ecdsa_public_key_size": ecdsa_r["ecdsa_public_key_size"],
            "ecdsa_signature_size": ecdsa_r["ecdsa_signature_size"],
            # Ratios (mean-based)
            "sign_ratio_rsa_ecdsa": round(sign_ratio, 4),
            "verify_ratio_rsa_ecdsa": round(verify_ratio, 4),
        }
        results.append(result_row)

        # --- Batch verification (single continuous pass per algorithm) ------
        print(
            f"\n    ⏳  Batch verification "
            f"({', '.join(f'{t//1000}k' for t in TRANSACTION_COUNTS)} tx) …"
        )
        rsa_milestones = measure_batch_milestones(
            rsa_r["rsa_verify_fn"], TRANSACTION_COUNTS
        )
        ecdsa_milestones = measure_batch_milestones(
            ecdsa_r["ecdsa_verify_fn"], TRANSACTION_COUNTS
        )

        for tx in TRANSACTION_COUNTS:
            rsa_total = rsa_milestones.get(tx, 0.0)
            ecdsa_total = ecdsa_milestones.get(tx, 0.0)
            ratio = rsa_total / ecdsa_total if ecdsa_total else 0.0
            batch_results.append(
                {
                    "security_bits": bits,
                    "tx_count": tx,
                    "rsa_verify_total_ms": round(rsa_total, 2),
                    "ecdsa_verify_total_ms": round(ecdsa_total, 2),
                    "verify_ratio_rsa_ecdsa": round(ratio, 4),
                }
            )
            print(
                f"       {tx:>6,} tx  "
                f"RSA={rsa_total:>8.0f} ms  "
                f"ECDSA={ecdsa_total:>8.0f} ms  "
                f"ratio={ratio:.3f}"
            )

        print()

    return results, batch_results


# ============================================================================
# SAVE RESULTS
# ============================================================================


def save_results(results: list[dict], batch_results: list[dict]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(CSV_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"✅  Saved: {CSV_PATH}")

    if batch_results:
        with open(BATCH_CSV_PATH, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=batch_results[0].keys())
            writer.writeheader()
            writer.writerows(batch_results)
        print(f"✅  Saved: {BATCH_CSV_PATH}\n")


# ============================================================================
# GRAPH GENERATION
# ============================================================================


def _bar_pair(
    ax,
    x,
    rsa_vals: list,
    ecdsa_vals: list,
    ylabel: str,
    title: str,
    security_bits: list,
    width: float = 0.35,
    rsa_errs: list | None = None,
    ecdsa_errs: list | None = None,
) -> None:
    """Shared helper: side-by-side Seaborn bars with optional error caps."""
    _ = (x, width)
    hue_order = ["RSA-PSS", "ECDSA"]
    df = pd.DataFrame(
        {
            "security_bits": security_bits * 2,
            "algorithm": [hue_order[0]] * len(security_bits) + [hue_order[1]] * len(security_bits),
            "value": rsa_vals + ecdsa_vals,
        }
    )

    sns.barplot(
        data=df,
        x="security_bits",
        y="value",
        hue="algorithm",
        hue_order=hue_order,
        errorbar=None,
        ax=ax,
    )

    if rsa_errs or ecdsa_errs:
        err_sets = [rsa_errs or [0.0] * len(security_bits), ecdsa_errs or [0.0] * len(security_bits)]
        for container, errs in zip(ax.containers[:2], err_sets):
            centers = [bar.get_x() + (bar.get_width() / 2) for bar in container]
            heights = [bar.get_height() for bar in container]
            ax.errorbar(
                centers,
                heights,
                yerr=errs,
                fmt="none",
                ecolor="black",
                elinewidth=1,
                capsize=4,
                capthick=1,
                zorder=3,
            )

    ax.set_xlabel("Security Level (bits)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0), frameon=True, borderaxespad=0)
    sns.despine(ax=ax, top=True, right=True)


def generate_graphs(results: list[dict], batch_results: list[dict]) -> None:
    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)

    sec_bits = [r["security_bits"] for r in results]
    x = list(range(len(sec_bits)))

    # ── 1. Signing time (mean ± stdev error bars) ──────────────────────────
    fig, ax = plt.subplots(figsize=(12, 6.5))
    _bar_pair(
        ax, x,
        [r["rsa_sign_mean_ms"] for r in results],
        [r["ecdsa_sign_mean_ms"] for r in results],
        ylabel="Sign Time (ms)",
        title="Signing Time Comparison (mean ± stdev)",
        security_bits=sec_bits,
        rsa_errs=[r["rsa_sign_stdev_ms"] for r in results],
        ecdsa_errs=[r["ecdsa_sign_stdev_ms"] for r in results],
    )
    plt.tight_layout(rect=[0, 0, 0.84, 1])
    plt.savefig(GRAPHS_DIR / "signing_time.png")
    plt.close()
    print("✅  signing_time.png")

    # ── 2. Single-op verification time (mean ± stdev) ──────────────────────
    fig, ax = plt.subplots(figsize=(12, 6.5))
    _bar_pair(
        ax, x,
        [r["rsa_verify_mean_ms"] for r in results],
        [r["ecdsa_verify_mean_ms"] for r in results],
        ylabel="Verify Time (ms)",
        title="Verification Time — Single Operation (mean ± stdev)",
        security_bits=sec_bits,
        rsa_errs=[r["rsa_verify_stdev_ms"] for r in results],
        ecdsa_errs=[r["ecdsa_verify_stdev_ms"] for r in results],
    )
    plt.tight_layout(rect=[0, 0, 0.84, 1])
    plt.savefig(GRAPHS_DIR / "verification_time_single.png")
    plt.close()
    print("✅  verification_time_single.png")

    # ── 3. CPU time consumed ───────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(12, 6.5))
    _bar_pair(
        ax, x,
        [r["rsa_cpu_time_s"] for r in results],
        [r["ecdsa_cpu_time_s"] for r in results],
        ylabel="CPU Time (s)",
        title="CPU Time Consumed During Sign + Verify Phase",
        security_bits=sec_bits,
    )
    plt.tight_layout(rect=[0, 0, 0.84, 1])
    plt.savefig(GRAPHS_DIR / "cpu_time.png")
    plt.close()
    print("✅  cpu_time.png")

    # ── 4. Memory delta ────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(12, 6.5))
    _bar_pair(
        ax, x,
        [r["rsa_memory_delta_mb"] for r in results],
        [r["ecdsa_memory_delta_mb"] for r in results],
        ylabel="Memory Increase (MB)",
        title="Process RSS Increase During Benchmark Phase",
        security_bits=sec_bits,
    )
    plt.tight_layout(rect=[0, 0, 0.84, 1])
    plt.savefig(GRAPHS_DIR / "memory_usage.png")
    plt.close()
    print("✅  memory_usage.png")

    # ── 5. Public key size ─────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(12, 6.5))
    _bar_pair(
        ax, x,
        [r["rsa_public_key_size"] / 1024 for r in results],
        [r["ecdsa_public_key_size"] / 1024 for r in results],
        ylabel="Key Size (KB)",
        title="Public Key Size Comparison",
        security_bits=sec_bits,
    )
    plt.tight_layout(rect=[0, 0, 0.84, 1])
    plt.savefig(GRAPHS_DIR / "key_size.png")
    plt.close()
    print("✅  key_size.png")

    # ── 6. Signature size ──────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(12, 6.5))
    _bar_pair(
        ax, x,
        [r["rsa_signature_size"] for r in results],
        [r["ecdsa_signature_size"] for r in results],
        ylabel="Signature Size (bytes)",
        title="Signature Size Comparison",
        security_bits=sec_bits,
    )
    plt.tight_layout(rect=[0, 0, 0.84, 1])
    plt.savefig(GRAPHS_DIR / "signature_size.png")
    plt.close()
    print("✅  signature_size.png")

    # ── 7. Batch verification charts (one per tx_count) ────────────────────
    for tx_count in TRANSACTION_COUNTS:
        tx_rows = sorted(
            [row for row in batch_results if row["tx_count"] == tx_count],
            key=lambda r: r["security_bits"],
        )
        row_bits = [row["security_bits"] for row in tx_rows]
        df_tx = pd.DataFrame(
            {
                "security_bits": row_bits * 2,
                "algorithm": ["RSA-PSS"] * len(row_bits) + ["ECDSA"] * len(row_bits),
                "total_verify_ms": [row["rsa_verify_total_ms"] for row in tx_rows]
                + [row["ecdsa_verify_total_ms"] for row in tx_rows],
            }
        )
        df_ratio = pd.DataFrame(
            {
                "security_bits": row_bits,
                "verify_ratio": [row["verify_ratio_rsa_ecdsa"] for row in tx_rows],
            }
        )

        fig, ax1 = plt.subplots(figsize=(12, 6.5))
        sns.barplot(
            data=df_tx,
            x="security_bits",
            y="total_verify_ms",
            hue="algorithm",
            hue_order=["RSA-PSS", "ECDSA"],
            errorbar=None,
            ax=ax1,
        )
        ax1.set_xlabel("Security Level (bits)")
        ax1.set_ylabel("Total Verify Time (ms)")
        ax1.set_title(f"Batch Verification Time — {tx_count:,} Transactions")

        ax2 = ax1.twinx()
        sns.lineplot(
            data=df_ratio,
            x="security_bits",
            y="verify_ratio",
            marker="o",
            linewidth=2,
            color="#2ca02c",
            label="RSA/ECDSA Ratio",
            ax=ax2,
        )
        ax2.set_ylabel("Verify Time Ratio (RSA / ECDSA)")
        if not df_ratio.empty:
            ax2.set_ylim(0, df_ratio["verify_ratio"].max() * 1.4)

        h1, l1 = ax1.get_legend_handles_labels()
        h2, l2 = ax2.get_legend_handles_labels()
        ax1.legend(
            h1 + h2,
            l1 + l2,
            loc="upper left",
            bbox_to_anchor=(1.02, 1.0),
            frameon=True,
            borderaxespad=0,
        )
        if ax2.legend_ is not None:
            ax2.legend_.remove()

        sns.despine(ax=ax1, top=True, right=True)
        sns.despine(ax=ax2, top=True, left=True)

        plt.tight_layout(rect=[0, 0, 0.84, 1])
        fname = GRAPHS_DIR / f"verification_time_{tx_count // 1000}k.png"
        plt.savefig(fname)
        plt.close()
        print(f"✅  {fname.name}")

    # ── 8. Ratio summary — lines now differ because each uses measured batch
    #       timings rather than a per-operation constant repeated N times ───
    summary_rows = []
    for tx_count in TRANSACTION_COUNTS:
        for row in sorted(
            [r for r in batch_results if r["tx_count"] == tx_count],
            key=lambda r: r["security_bits"],
        ):
            summary_rows.append(
                {
                    "security_bits": row["security_bits"],
                    "verify_ratio": row["verify_ratio_rsa_ecdsa"],
                    "tx_label": f"{tx_count // 1000}k tx",
                }
            )
    df_summary = pd.DataFrame(summary_rows)

    fig, ax = plt.subplots(figsize=(12, 6.5))
    sns.lineplot(
        data=df_summary,
        x="security_bits",
        y="verify_ratio",
        hue="tx_label",
        marker="o",
        linewidth=2,
        ax=ax,
    )
    ax.set_xlabel("Security Level (bits)")
    ax.set_ylabel("Verify Time Ratio (RSA / ECDSA)")
    ax.set_title("Batch Verification Ratio Across Security Levels (All Tx Counts)")
    ax.set_xticks(sec_bits)
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1.0), ncol=1, frameon=True, borderaxespad=0)
    sns.despine(ax=ax, top=True, right=True)

    plt.tight_layout(rect=[0, 0, 0.84, 1])
    plt.savefig(GRAPHS_DIR / "verification_ratio_summary.png")
    plt.close()
    print("✅  verification_ratio_summary.png")

    print(f"\n✅  All graphs saved to: {GRAPHS_DIR}\n")


# ============================================================================
# CONSOLE SUMMARY
# ============================================================================


def print_summary(results: list[dict]) -> None:
    print("=" * 80)
    print("📊  RESULTS SUMMARY")
    print("=" * 80 + "\n")
    for r in results:
        print(
            f"🔐  {r['security_bits']}-bit  "
            f"RSA-{r['rsa_key_size']} vs ECDSA-{r['ecdsa_curve']}"
        )
        print(
            f"    Signing    RSA: {r['rsa_sign_mean_ms']:.3f} ms "
            f"(med {r['rsa_sign_median_ms']:.3f}, ±{r['rsa_sign_stdev_ms']:.3f}, "
            f"p95 {r['rsa_sign_p95_ms']:.3f})"
        )
        print(
            f"               ECDSA: {r['ecdsa_sign_mean_ms']:.3f} ms "
            f"(med {r['ecdsa_sign_median_ms']:.3f}, ±{r['ecdsa_sign_stdev_ms']:.3f}, "
            f"p95 {r['ecdsa_sign_p95_ms']:.3f})"
        )
        print(f"               ratio RSA/ECDSA: {r['sign_ratio_rsa_ecdsa']:.2f}x")
        print(
            f"    Verify     RSA: {r['rsa_verify_mean_ms']:.3f} ms "
            f"(med {r['rsa_verify_median_ms']:.3f}, ±{r['rsa_verify_stdev_ms']:.3f}, "
            f"p95 {r['rsa_verify_p95_ms']:.3f})"
        )
        print(
            f"               ECDSA: {r['ecdsa_verify_mean_ms']:.3f} ms "
            f"(med {r['ecdsa_verify_median_ms']:.3f}, ±{r['ecdsa_verify_stdev_ms']:.3f}, "
            f"p95 {r['ecdsa_verify_p95_ms']:.3f})"
        )
        print(f"               ratio RSA/ECDSA: {r['verify_ratio_rsa_ecdsa']:.2f}x")
        print(
            f"    Key size   RSA: {r['rsa_public_key_size']} B  "
            f"ECDSA: {r['ecdsa_public_key_size']} B"
        )
        print(
            f"    Sig size   RSA: {r['rsa_signature_size']} B  "
            f"ECDSA: {r['ecdsa_signature_size']} B"
        )
        print()


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print(f"\n⏱️   Starting benchmark at {datetime.now()}\n")
    results, batch_results = run_benchmark()

    if not results:
        print("❌  Benchmark failed — no results produced.")
        sys.exit(1)

    save_results(results, batch_results)
    print("📊  Generating graphs …")
    generate_graphs(results, batch_results)
    print_summary(results)

    print("=" * 80)
    print(f"✅  Complete at {datetime.now()}")
    print(f"    Main CSV  : {CSV_PATH}")
    print(f"    Batch CSV : {BATCH_CSV_PATH}")
    print(f"    Graphs    : {GRAPHS_DIR}")
    print("=" * 80)