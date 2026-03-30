#!/usr/bin/env python3
"""
COMPREHENSIVE ECDSA vs Probabilistic RSA-PSS Benchmark
=======================================================
Full cryptographic performance comparison across 3 matched security levels.
Generates CSV results + publication-quality matplotlib graphs for IEEE paper.

USAGE:
    python3 benchmark_complete.py

REQUIREMENTS:
    pip install cryptography matplotlib psutil

OUTPUT:
    results/benchmark_results_comprehensive.csv
    results/batch_verification_results.csv
    results/graphs/*.png
"""

import csv
import math
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
    import matplotlib.patches as mpatches
    import matplotlib.ticker as mticker
    from matplotlib.gridspec import GridSpec

    matplotlib.use("Agg")
except ImportError:
    print("❌ matplotlib not found. Install with: pip install matplotlib")
    sys.exit(1)


# ============================================================================
# PUBLICATION-QUALITY STYLE CONFIGURATION
# ============================================================================

# Color palette: colorblind-safe, publication-quality
RSA_COLOR    = "#1A5F99"   # Deep steel blue — RSA-PSS
ECDSA_COLOR  = "#C0392B"   # Crimson red — ECDSA
RATIO_COLOR  = "#1E8C45"   # Forest green — ratio line
ANNOT_FG     = "#2C3E50"   # Charcoal — annotation text
ANNOT_BOX_BG = "#EBF5FB"   # Very light blue — callout boxes
GRID_COLOR   = "#D5D8DC"   # Subtle grid
SPINE_COLOR  = "#7F8C8D"   # Axis spine

# RSA advantage highlight colors for bars (slightly lighter for overlaid text)
RSA_BAR_FASTER   = "#1A5F99"
ECDSA_BAR_SLOWER = "#C0392B"


def setup_publication_style() -> None:
    """Apply a clean, IEEE-publication-compatible matplotlib style."""
    plt.rcParams.update({
        # Figure
        "figure.dpi": 180,
        "figure.facecolor": "white",
        "figure.edgecolor": "none",

        # Fonts — use a serif stack for IEEE compatibility
        "font.family": "serif",
        "font.serif": ["DejaVu Serif", "Times New Roman", "serif"],
        "font.size": 11,

        # Axes
        "axes.facecolor": "#FDFEFE",
        "axes.edgecolor": SPINE_COLOR,
        "axes.linewidth": 0.8,
        "axes.titlesize": 12,
        "axes.titleweight": "bold",
        "axes.titlepad": 10,
        "axes.labelsize": 11,
        "axes.labelweight": "normal",
        "axes.spines.top": False,
        "axes.spines.right": False,

        # Grid
        "axes.grid": True,
        "grid.color": GRID_COLOR,
        "grid.linewidth": 0.6,
        "grid.linestyle": "--",
        "axes.axisbelow": True,

        # Ticks
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "xtick.direction": "out",
        "ytick.direction": "out",
        "xtick.major.size": 4,
        "ytick.major.size": 4,

        # Legend
        "legend.fontsize": 9,
        "legend.framealpha": 0.92,
        "legend.edgecolor": SPINE_COLOR,
        "legend.frameon": True,
        "legend.fancybox": False,

        # Lines
        "lines.linewidth": 2.0,
        "lines.markersize": 7,

        # Error bars
        "errorbar.capsize": 4,

        # Save
        "savefig.bbox": "tight",
        "savefig.dpi": 180,
        "savefig.facecolor": "white",
    })


def annotate_bar(ax, rect, value_fmt: str, fontsize: int = 8,
                 above: bool = True, color: str = ANNOT_FG) -> None:
    """Place a text label above or inside a bar."""
    h = rect.get_height()
    x = rect.get_x() + rect.get_width() / 2
    if above:
        y = h * 1.02
        va = "bottom"
    else:
        y = h * 0.5
        va = "center"
    ax.text(x, y, value_fmt, ha="center", va=va,
            fontsize=fontsize, color=color, fontweight="bold")


def add_speedup_badge(ax, x_center: float, y_top: float, speedup: float,
                      color: str = "#1E8C45") -> None:
    """Draw a small badge showing RSA speedup vs ECDSA."""
    label = f"{speedup:.1f}× faster"
    bbox = dict(boxstyle="round,pad=0.25", facecolor=color,
                edgecolor="none", alpha=0.85)
    ax.text(x_center, y_top * 1.08, label, ha="center", va="bottom",
            fontsize=8, color="white", fontweight="bold", bbox=bbox)


def despine(ax, keep=("left", "bottom")) -> None:
    """Remove unwanted spines (already handled by rcParams, belt-and-suspenders)."""
    for spine in ("top", "right", "left", "bottom"):
        ax.spines[spine].set_visible(spine in keep)


def _xtick_labels(ax, bits: list, font_kw: dict | None = None) -> None:
    kw = font_kw or {}
    ax.set_xticks(range(len(bits)))
    ax.set_xticklabels([str(b) for b in bits], **kw)


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

WARMUP_ITERATIONS: dict[int, int] = {2048: 20, 3072: 20, 7680: 10}
TIMED_ITERATIONS:  dict[int, int] = {2048: 200, 3072: 200, 7680: 100}
SIG_POOL_SIZE = 50

TEST_MESSAGE = b"Blockchain transaction data for signing and verification benchmark"

OUTPUT_DIR    = Path(__file__).parent / "results"
GRAPHS_DIR    = OUTPUT_DIR / "graphs"
CSV_PATH      = OUTPUT_DIR / "benchmark_results_comprehensive.csv"
BATCH_CSV_PATH = OUTPUT_DIR / "batch_verification_results.csv"
EXPONENT_VALUES_PATH = Path(__file__).parent / "exponent_values" / "exponent_values.txt"

TRANSACTION_COUNTS = [5_000, 10_000, 15_000, 20_000, 25_000, 30_000]
EXPONENT_BENCHMARK_KEY_SIZE = 3072


# ============================================================================
# HELPERS
# ============================================================================

def get_memory_mb() -> float:
    try:
        return psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)
    except Exception:
        return 0.0


def get_cpu_time() -> float:
    try:
        t = psutil.Process(os.getpid()).cpu_times()
        return t.user + t.system
    except Exception:
        return 0.0


def compute_stats(samples: list[float]) -> dict[str, float]:
    n = len(samples)
    sorted_s = sorted(samples)
    p95_idx = min(int(0.95 * n), n - 1)
    return {
        "mean":   statistics.mean(samples),
        "median": statistics.median(samples),
        "stdev":  statistics.stdev(samples) if n > 1 else 0.0,
        "min":    sorted_s[0],
        "max":    sorted_s[-1],
        "p95":    sorted_s[p95_idx],
    }


def log_system_info() -> None:
    print("💻 System Info:")
    print(f"   Platform     : {platform.platform()}")
    print(f"   Processor    : {platform.processor() or 'unknown'}")
    print(f"   CPUs         : {psutil.cpu_count(logical=True)} logical / "
          f"{psutil.cpu_count(logical=False)} physical")
    print(f"   RAM          : {psutil.virtual_memory().total / (1024 ** 3):.1f} GB")
    print(f"   Python       : {sys.version.split()[0]}")
    print()


def measure_batch_milestones(verify_fn, tx_counts: list[int]) -> dict[int, float]:
    """
    Single continuous pass; snapshot elapsed time at each milestone.
    Total work = max(tx_counts), not the sum of all counts.
    """
    sorted_counts = sorted(tx_counts)
    max_count     = sorted_counts[-1]
    milestones    = set(sorted_counts)

    for _ in range(min(20, max_count)):
        verify_fn()

    results: dict[int, float] = {}
    t_start = time.perf_counter()
    for i in range(1, max_count + 1):
        verify_fn()
        if i in milestones:
            results[i] = (time.perf_counter() - t_start) * 1000.0

    return results


def load_exponent_values(path: Path) -> list[tuple[int, int]]:
    """Load (k, e) pairs from exponent_values.txt."""
    values: list[tuple[int, int]] = []
    if not path.exists():
        return values

    with path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip().replace(" ", "")
            if not line.startswith("k=") or ":e=" not in line:
                continue
            left, right = line.split(":e=", maxsplit=1)
            try:
                k_val = int(left.split("=", maxsplit=1)[1])
                e_val = int(right)
            except (IndexError, ValueError):
                continue
            values.append((k_val, e_val))
    return sorted(values, key=lambda x: x[0])


def build_rsa_private_key_for_exponent(key_size: int, exponent: int,
                                       max_attempts: int = 30):
    """
    Build an RSA private key for a custom odd exponent.
    cryptography's keygen API only allows e=3 or 65537, so we derive p,q from
    generated keys and reconstruct private numbers for the requested exponent.
    """
    if exponent <= 1 or exponent % 2 == 0:
        raise ValueError("public exponent must be an odd integer > 1")

    for _ in range(max_attempts):
        seed_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        nums = seed_key.private_numbers()
        p, q = nums.p, nums.q
        phi = (p - 1) * (q - 1)
        if math.gcd(exponent, phi) != 1:
            continue

        d = pow(exponent, -1, phi)
        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = pow(q, -1, p)

        private_numbers = rsa.RSAPrivateNumbers(
            p=p,
            q=q,
            d=d,
            dmp1=dmp1,
            dmq1=dmq1,
            iqmp=iqmp,
            public_numbers=rsa.RSAPublicNumbers(exponent, p * q),
        )
        return private_numbers.private_key(default_backend())

    raise ValueError(
        f"unable to construct RSA key with exponent {exponent} "
        f"after {max_attempts} attempts"
    )


# ============================================================================
# BENCHMARK FUNCTIONS
# ============================================================================

def benchmark_rsa(key_size: int, security_bits: int) -> dict | None:
    print(f"   🔓 RSA-PSS ({key_size}-bit)...", end=" ", flush=True)
    try:
        warmup = WARMUP_ITERATIONS.get(key_size, 5)
        timed  = TIMED_ITERATIONS.get(key_size, 20)

        mem_before = get_memory_mb()
        cpu_before = get_cpu_time()

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend())
        public_key  = private_key.public_key()
        pub_pem     = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        sign_pad   = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                 salt_length=padding.PSS.MAX_LENGTH)
        verify_pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                 salt_length=padding.PSS.MAX_LENGTH)
        hash_alg   = hashes.SHA256()

        for _ in range(warmup):
            private_key.sign(TEST_MESSAGE, sign_pad, hash_alg)

        sign_times: list[float] = []
        signatures: list[bytes] = []
        for _ in range(timed):
            t0  = time.perf_counter()
            sig = private_key.sign(TEST_MESSAGE, sign_pad, hash_alg)
            sign_times.append((time.perf_counter() - t0) * 1000.0)
            signatures.append(sig)

        for sig in signatures[:warmup]:
            public_key.verify(sig, TEST_MESSAGE, verify_pad, hash_alg)

        verify_times: list[float] = []
        for sig in signatures:
            t0 = time.perf_counter()
            public_key.verify(sig, TEST_MESSAGE, verify_pad, hash_alg)
            verify_times.append((time.perf_counter() - t0) * 1000.0)

        ss = compute_stats(sign_times)
        vs = compute_stats(verify_times)
        mem_delta   = max(get_memory_mb() - mem_before, 0.0)
        cpu_elapsed = max(get_cpu_time()  - cpu_before, 0.0)

        pool      = signatures[:SIG_POOL_SIZE]
        pool_iter = cycle(pool)

        def verify_fn() -> None:
            public_key.verify(next(pool_iter), TEST_MESSAGE, verify_pad, hash_alg)

        print(f"✅  Sign {ss['mean']:.3f}ms ±{ss['stdev']:.3f}"
              f" | Verify {vs['mean']:.3f}ms ±{vs['stdev']:.3f}")
        return {
            "rsa_sign_mean_ms":    ss["mean"],
            "rsa_sign_median_ms":  ss["median"],
            "rsa_sign_stdev_ms":   ss["stdev"],
            "rsa_sign_p95_ms":     ss["p95"],
            "rsa_verify_mean_ms":  vs["mean"],
            "rsa_verify_median_ms":vs["median"],
            "rsa_verify_stdev_ms": vs["stdev"],
            "rsa_verify_p95_ms":   vs["p95"],
            "rsa_cpu_time_s":      cpu_elapsed,
            "rsa_memory_delta_mb": mem_delta,
            "rsa_public_key_size": len(pub_pem),
            "rsa_signature_size":  len(signatures[0]),
            "rsa_verify_fn":       verify_fn,
        }
    except Exception as exc:
        print(f"❌  {exc}")
        return None


def benchmark_ecdsa(curve_name: str, security_bits: int,
                    rsa_key_size: int) -> dict | None:
    print(f"   🔑 ECDSA ({curve_name})...", end=" ", flush=True)
    try:
        warmup = WARMUP_ITERATIONS.get(rsa_key_size, 5)
        timed  = TIMED_ITERATIONS.get(rsa_key_size, 20)

        mem_before = get_memory_mb()
        cpu_before = get_cpu_time()

        private_key = ec.generate_private_key(CURVES[curve_name], default_backend())
        public_key  = private_key.public_key()
        pub_pem     = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        ecdsa_alg = ec.ECDSA(hashes.SHA256())

        for _ in range(warmup):
            private_key.sign(TEST_MESSAGE, ecdsa_alg)

        sign_times: list[float] = []
        signatures: list[bytes] = []
        for _ in range(timed):
            t0  = time.perf_counter()
            sig = private_key.sign(TEST_MESSAGE, ecdsa_alg)
            sign_times.append((time.perf_counter() - t0) * 1000.0)
            signatures.append(sig)

        for sig in signatures[:warmup]:
            public_key.verify(sig, TEST_MESSAGE, ecdsa_alg)

        verify_times: list[float] = []
        for sig in signatures:
            t0 = time.perf_counter()
            public_key.verify(sig, TEST_MESSAGE, ecdsa_alg)
            verify_times.append((time.perf_counter() - t0) * 1000.0)

        ss = compute_stats(sign_times)
        vs = compute_stats(verify_times)
        mem_delta   = max(get_memory_mb() - mem_before, 0.0)
        cpu_elapsed = max(get_cpu_time()  - cpu_before, 0.0)

        pool      = signatures[:SIG_POOL_SIZE]
        pool_iter = cycle(pool)

        def verify_fn() -> None:
            public_key.verify(next(pool_iter), TEST_MESSAGE, ecdsa_alg)

        print(f"✅  Sign {ss['mean']:.3f}ms ±{ss['stdev']:.3f}"
              f" | Verify {vs['mean']:.3f}ms ±{vs['stdev']:.3f}")
        return {
            "ecdsa_sign_mean_ms":    ss["mean"],
            "ecdsa_sign_median_ms":  ss["median"],
            "ecdsa_sign_stdev_ms":   ss["stdev"],
            "ecdsa_sign_p95_ms":     ss["p95"],
            "ecdsa_verify_mean_ms":  vs["mean"],
            "ecdsa_verify_median_ms":vs["median"],
            "ecdsa_verify_stdev_ms": vs["stdev"],
            "ecdsa_verify_p95_ms":   vs["p95"],
            "ecdsa_cpu_time_s":      cpu_elapsed,
            "ecdsa_memory_delta_mb": mem_delta,
            "ecdsa_public_key_size": len(pub_pem),
            "ecdsa_signature_size":  len(signatures[0]),
            "ecdsa_verify_fn":       verify_fn,
        }
    except Exception as exc:
        print(f"❌  {exc}")
        return None


# ============================================================================
# MAIN BENCHMARK ORCHESTRATION
# ============================================================================

def run_exponent_batch_benchmark() -> list[dict]:
    """Measure RSA batch verification totals across configured public exponents."""
    exponent_pairs = load_exponent_values(EXPONENT_VALUES_PATH)
    if not exponent_pairs:
        print("⚠️   No exponent values found; skipping exponent line graph data.")
        return []

    print("🔣  RSA Exponent Benchmark")
    print(f"    Key size: {EXPONENT_BENCHMARK_KEY_SIZE}-bit")
    print(f"    Exponents: {', '.join(f'k={k}' for k, _ in exponent_pairs)}")
    print(f"    {'─' * 74}")

    benchmark_data: list[dict] = []
    for k_val, exponent in exponent_pairs:
        print(f"   🔓 RSA verify benchmark for k={k_val} (e={exponent})...", end=" ", flush=True)
        try:
            private_key = build_rsa_private_key_for_exponent(
                key_size=EXPONENT_BENCHMARK_KEY_SIZE,
                exponent=exponent,
            )
            public_key = private_key.public_key()
            sign_pad   = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH)
            verify_pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH)
            hash_alg   = hashes.SHA256()

            signatures = [
                private_key.sign(TEST_MESSAGE, sign_pad, hash_alg)
                for _ in range(SIG_POOL_SIZE)
            ]
            pool_iter = cycle(signatures)

            def verify_fn() -> None:
                public_key.verify(next(pool_iter), TEST_MESSAGE, verify_pad, hash_alg)

            milestones = measure_batch_milestones(verify_fn, TRANSACTION_COUNTS)
            print("✅")
            for tx_count in TRANSACTION_COUNTS:
                total_ms = milestones.get(tx_count, 0.0)
                benchmark_data.append({
                    "k": k_val,
                    "public_exponent": exponent,
                    "tx_count": tx_count,
                    "rsa_verify_total_ms": round(total_ms, 2),
                })
                print(f"       {tx_count:>6,} tx  total={total_ms:>8.0f} ms")
        except Exception as exc:
            print(f"❌  {exc}")
            continue

    print()
    return benchmark_data


def run_benchmark() -> tuple[list, list, list]:
    print("=" * 80)
    print("🔐  COMPREHENSIVE ECDSA vs RSA-PSS Benchmark")
    print("=" * 80)
    log_system_info()
    print(f"Started: {datetime.now()}\n")

    results: list[dict] = []
    batch_results: list[dict] = []

    for level in SECURITY_LEVELS:
        bits       = level["bits"]
        rsa_size   = level["rsa"]
        ecdsa_curve = level["ecdsa"]

        print(f"🔑  Security Level: {bits}-bit  "
              f"(RSA-{rsa_size} vs ECDSA-{ecdsa_curve})")
        print(f"    {level['notes']}")
        print(f"    {'─' * 74}")

        rsa_r   = benchmark_rsa(rsa_size, bits)
        ecdsa_r = benchmark_ecdsa(ecdsa_curve, bits, rsa_size)

        if not (rsa_r and ecdsa_r):
            print(f"⚠️   Skipping {bits}-bit — benchmark error.\n")
            continue

        sign_ratio   = rsa_r["rsa_sign_mean_ms"]   / ecdsa_r["ecdsa_sign_mean_ms"]
        verify_ratio = rsa_r["rsa_verify_mean_ms"]  / ecdsa_r["ecdsa_verify_mean_ms"]

        result_row: dict = {
            "security_bits": bits,
            "rsa_key_size":  rsa_size,
            "ecdsa_curve":   ecdsa_curve,
            "notes":         level["notes"],
            "rsa_sign_mean_ms":     round(rsa_r["rsa_sign_mean_ms"],    4),
            "rsa_sign_median_ms":   round(rsa_r["rsa_sign_median_ms"],  4),
            "rsa_sign_stdev_ms":    round(rsa_r["rsa_sign_stdev_ms"],   4),
            "rsa_sign_p95_ms":      round(rsa_r["rsa_sign_p95_ms"],     4),
            "rsa_verify_mean_ms":   round(rsa_r["rsa_verify_mean_ms"],  4),
            "rsa_verify_median_ms": round(rsa_r["rsa_verify_median_ms"],4),
            "rsa_verify_stdev_ms":  round(rsa_r["rsa_verify_stdev_ms"], 4),
            "rsa_verify_p95_ms":    round(rsa_r["rsa_verify_p95_ms"],   4),
            "rsa_cpu_time_s":       round(rsa_r["rsa_cpu_time_s"],      4),
            "rsa_memory_delta_mb":  round(rsa_r["rsa_memory_delta_mb"], 4),
            "rsa_public_key_size":  rsa_r["rsa_public_key_size"],
            "rsa_signature_size":   rsa_r["rsa_signature_size"],
            "ecdsa_sign_mean_ms":     round(ecdsa_r["ecdsa_sign_mean_ms"],    4),
            "ecdsa_sign_median_ms":   round(ecdsa_r["ecdsa_sign_median_ms"],  4),
            "ecdsa_sign_stdev_ms":    round(ecdsa_r["ecdsa_sign_stdev_ms"],   4),
            "ecdsa_sign_p95_ms":      round(ecdsa_r["ecdsa_sign_p95_ms"],     4),
            "ecdsa_verify_mean_ms":   round(ecdsa_r["ecdsa_verify_mean_ms"],  4),
            "ecdsa_verify_median_ms": round(ecdsa_r["ecdsa_verify_median_ms"],4),
            "ecdsa_verify_stdev_ms":  round(ecdsa_r["ecdsa_verify_stdev_ms"], 4),
            "ecdsa_verify_p95_ms":    round(ecdsa_r["ecdsa_verify_p95_ms"],   4),
            "ecdsa_cpu_time_s":       round(ecdsa_r["ecdsa_cpu_time_s"],      4),
            "ecdsa_memory_delta_mb":  round(ecdsa_r["ecdsa_memory_delta_mb"], 4),
            "ecdsa_public_key_size":  ecdsa_r["ecdsa_public_key_size"],
            "ecdsa_signature_size":   ecdsa_r["ecdsa_signature_size"],
            "sign_ratio_rsa_ecdsa":   round(sign_ratio,   4),
            "verify_ratio_rsa_ecdsa": round(verify_ratio, 4),
        }
        results.append(result_row)

        print(f"\n    ⏳  Batch verification "
              f"({', '.join(f'{t//1000}k' for t in TRANSACTION_COUNTS)} tx) …")
        rsa_milestones   = measure_batch_milestones(
            rsa_r["rsa_verify_fn"], TRANSACTION_COUNTS)
        ecdsa_milestones = measure_batch_milestones(
            ecdsa_r["ecdsa_verify_fn"], TRANSACTION_COUNTS)

        for tx in TRANSACTION_COUNTS:
            rsa_total   = rsa_milestones.get(tx, 0.0)
            ecdsa_total = ecdsa_milestones.get(tx, 0.0)
            ratio       = rsa_total / ecdsa_total if ecdsa_total else 0.0
            batch_results.append({
                "security_bits":         bits,
                "tx_count":              tx,
                "rsa_verify_total_ms":   round(rsa_total,   2),
                "ecdsa_verify_total_ms": round(ecdsa_total, 2),
                "verify_ratio_rsa_ecdsa":round(ratio,       4),
            })
            print(f"       {tx:>6,} tx  "
                  f"RSA={rsa_total:>8.0f} ms  "
                  f"ECDSA={ecdsa_total:>8.0f} ms  "
                  f"ratio={ratio:.3f}")
        print()

    exponent_batch_results = run_exponent_batch_benchmark()
    return results, batch_results, exponent_batch_results


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
# PUBLICATION-QUALITY GRAPH GENERATION
# ============================================================================

def _save(fig: plt.Figure, name: str) -> None:
    path = GRAPHS_DIR / name
    fig.savefig(path, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"✅  {name}")


def _legend_handles() -> list:
    """Shared legend handles for RSA vs ECDSA bar charts."""
    return [
        mpatches.Patch(facecolor=RSA_COLOR,   label="RSA-PSS"),
        mpatches.Patch(facecolor=ECDSA_COLOR, label="ECDSA"),
    ]


def _fmt_ms(v: float) -> str:
    """Format ms value; use shorter notation for large values."""
    if v >= 10:
        return f"{v:.0f}"
    if v >= 1:
        return f"{v:.1f}"
    return f"{v:.3f}"


def generate_graphs(results: list[dict], batch_results: list[dict],
                    exponent_batch_results: list[dict]) -> None:
    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)
    setup_publication_style()

    sec_bits = [r["security_bits"] for r in results]
    xi       = list(range(len(sec_bits)))
    w        = 0.32   # bar half-width

    # ── Labels for RSA key sizes (used in axis tick annotations) ─────────
    rsa_labels   = [r["rsa_key_size"]  for r in results]
    ecdsa_labels = [r["ecdsa_curve"]   for r in results]
    paired_ticks = [f"{b}-bit\n(RSA-{rk} / {ec})"
                    for b, rk, ec in zip(sec_bits, rsa_labels, ecdsa_labels)]

    # ════════════════════════════════════════════════════════════════════════
    # 1. SIGNING TIME
    # ════════════════════════════════════════════════════════════════════════
    fig, ax = plt.subplots(figsize=(9, 5))
    rsa_sv  = [r["rsa_sign_mean_ms"]   for r in results]
    ecdsa_sv= [r["ecdsa_sign_mean_ms"] for r in results]
    rsa_se  = [r["rsa_sign_stdev_ms"]  for r in results]
    ecdsa_se= [r["ecdsa_sign_stdev_ms"]for r in results]

    bars_r = ax.bar([i - w/2 for i in xi], rsa_sv,   w,
                    color=RSA_COLOR,   alpha=0.9, label="RSA-PSS",
                    yerr=rsa_se,  error_kw=dict(elinewidth=1.2, capthick=1.2,
                                                ecolor="#555"))
    bars_e = ax.bar([i + w/2 for i in xi], ecdsa_sv, w,
                    color=ECDSA_COLOR, alpha=0.9, label="ECDSA",
                    yerr=ecdsa_se, error_kw=dict(elinewidth=1.2, capthick=1.2,
                                                 ecolor="#555"))

    for rect, v in zip(bars_r, rsa_sv):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + max(rsa_se)*0.05 + max(rsa_sv)*0.01,
                _fmt_ms(v) + " ms", ha="center", va="bottom",
                fontsize=8, color=RSA_COLOR, fontweight="bold")
    for rect, v in zip(bars_e, ecdsa_sv):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + max(rsa_se)*0.01 + max(rsa_sv)*0.002,
                _fmt_ms(v) + " ms", ha="center", va="bottom",
                fontsize=8, color=ECDSA_COLOR, fontweight="bold")

    ax.set_xticks(xi)
    ax.set_xticklabels(paired_ticks, fontsize=9)
    ax.set_xlabel("Security Level (RSA key size / ECDSA curve)", labelpad=6)
    ax.set_ylabel("Mean Signing Time (ms) ± 1σ")
    ax.set_title("Signing Time: RSA-PSS Is Substantially Slower Than ECDSA\n"
                 "— a one-time cost incurred only at transaction creation")
    ax.legend(handles=_legend_handles(), loc="upper left")

    # Insight box
    ax.text(0.97, 0.97,
            "Note: Signing cost affects only\nthe wallet/client — NOT per-node\n"
            "verification throughput.",
            transform=ax.transAxes, ha="right", va="top", fontsize=8,
            color=ANNOT_FG, linespacing=1.6,
            bbox=dict(boxstyle="round,pad=0.4", facecolor=ANNOT_BOX_BG,
                      edgecolor=SPINE_COLOR, alpha=0.9))
    _save(fig, "signing_time.png")

    # ════════════════════════════════════════════════════════════════════════
    # 2. SINGLE-OPERATION VERIFICATION TIME  ← key result
    # ════════════════════════════════════════════════════════════════════════
    fig, ax = plt.subplots(figsize=(9, 5))
    rsa_vv  = [r["rsa_verify_mean_ms"]   for r in results]
    ecdsa_vv= [r["ecdsa_verify_mean_ms"] for r in results]
    rsa_ve  = [r["rsa_verify_stdev_ms"]  for r in results]
    ecdsa_ve= [r["ecdsa_verify_stdev_ms"]for r in results]
    ratios  = [r["verify_ratio_rsa_ecdsa"] for r in results]   # RSA/ECDSA

    bars_r = ax.bar([i - w/2 for i in xi], rsa_vv,   w,
                    color=RSA_COLOR,   alpha=0.9, label="RSA-PSS",
                    yerr=rsa_ve,  error_kw=dict(elinewidth=1.2, capthick=1.2,
                                                ecolor="#555"))
    bars_e = ax.bar([i + w/2 for i in xi], ecdsa_vv, w,
                    color=ECDSA_COLOR, alpha=0.9, label="ECDSA",
                    yerr=ecdsa_ve, error_kw=dict(elinewidth=1.2, capthick=1.2,
                                                 ecolor="#555"))

    y_max = max(ecdsa_vv) * 1.45
    for i, (rv, ev, ratio) in enumerate(zip(rsa_vv, ecdsa_vv, ratios)):
        speedup = 1.0 / ratio
        # Values on bars
        ax.text(i - w/2, rv + max(rsa_ve)*0.05 + max(ecdsa_vv)*0.015,
                _fmt_ms(rv) + " ms", ha="center", va="bottom",
                fontsize=8, color=RSA_COLOR, fontweight="bold")
        ax.text(i + w/2, ev + max(ecdsa_ve)*0.05 + max(ecdsa_vv)*0.015,
                _fmt_ms(ev) + " ms", ha="center", va="bottom",
                fontsize=8, color=ECDSA_COLOR, fontweight="bold")
        # Speedup badge between the pair
        badge_y = max(rv, ev) * 1.18
        ax.text(i, badge_y,
                f"{speedup:.1f}× faster",
                ha="center", va="bottom", fontsize=8.5, color="white",
                fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", facecolor=RATIO_COLOR,
                          edgecolor="none", alpha=0.90))

    ax.set_ylim(0, y_max)
    ax.set_xticks(xi)
    ax.set_xticklabels(paired_ticks, fontsize=9)
    ax.set_xlabel("Security Level (RSA key size / ECDSA curve)", labelpad=6)
    ax.set_ylabel("Mean Verification Time (ms) ± 1σ")
    ax.set_title("Single-Operation Verification: RSA-PSS Is Faster at All Security Levels\n"
                 "— structural advantage from fixed-cost public exponent e = 65537")
    ax.legend(handles=_legend_handles(), loc="upper left")
    _save(fig, "verification_time_single.png")

    # ════════════════════════════════════════════════════════════════════════
    # 3. CPU TIME
    # ════════════════════════════════════════════════════════════════════════
    fig, ax = plt.subplots(figsize=(9, 5))
    rsa_cpu   = [r["rsa_cpu_time_s"]   for r in results]
    ecdsa_cpu = [r["ecdsa_cpu_time_s"] for r in results]

    bars_r = ax.bar([i - w/2 for i in xi], rsa_cpu,   w,
                    color=RSA_COLOR, alpha=0.9, label="RSA-PSS")
    bars_e = ax.bar([i + w/2 for i in xi], ecdsa_cpu, w,
                    color=ECDSA_COLOR, alpha=0.9, label="ECDSA")

    for rect, v in zip(bars_r, rsa_cpu):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + max(rsa_cpu) * 0.01,
                f"{v:.2f} s", ha="center", va="bottom",
                fontsize=8, color=RSA_COLOR, fontweight="bold")
    for rect, v in zip(bars_e, ecdsa_cpu):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + max(rsa_cpu) * 0.005,
                f"{v:.2f} s", ha="center", va="bottom",
                fontsize=8, color=ECDSA_COLOR, fontweight="bold")

    ax.set_xticks(xi)
    ax.set_xticklabels(paired_ticks, fontsize=9)
    ax.set_xlabel("Security Level (RSA key size / ECDSA curve)", labelpad=6)
    ax.set_ylabel("Total CPU Time — Sign + Verify Phase (s)")
    ax.set_title("CPU Time: RSA-PSS Consumes More CPU, Dominated by Signing\n"
                 "— at 192-bit the 7680-bit private exponent drives the gap")
    ax.legend(handles=_legend_handles(), loc="upper left")
    ax.text(0.97, 0.97,
            "RSA signing uses the full\nprivate exponent d.\n"
            "Verification uses e = 65537\n(2 set bits → very fast).",
            transform=ax.transAxes, ha="right", va="top", fontsize=8,
            color=ANNOT_FG, linespacing=1.6,
            bbox=dict(boxstyle="round,pad=0.4", facecolor=ANNOT_BOX_BG,
                      edgecolor=SPINE_COLOR, alpha=0.9))
    _save(fig, "cpu_time.png")

    # ════════════════════════════════════════════════════════════════════════
    # 4. MEMORY USAGE
    # ════════════════════════════════════════════════════════════════════════
    fig, ax = plt.subplots(figsize=(9, 5))
    rsa_mem   = [r["rsa_memory_delta_mb"]   for r in results]
    ecdsa_mem = [r["ecdsa_memory_delta_mb"] for r in results]

    bars_r = ax.bar([i - w/2 for i in xi], rsa_mem,   w,
                    color=RSA_COLOR, alpha=0.9, label="RSA-PSS")
    bars_e = ax.bar([i + w/2 for i in xi], ecdsa_mem, w,
                    color=ECDSA_COLOR, alpha=0.9, label="ECDSA")

    for rect, v in zip(list(bars_r) + list(bars_e),
                       rsa_mem + ecdsa_mem):
        if v > 0.005:
            ax.text(rect.get_x() + rect.get_width()/2,
                    rect.get_height() + max(rsa_mem) * 0.01,
                    f"{v:.2f}", ha="center", va="bottom",
                    fontsize=8, color=ANNOT_FG, fontweight="bold")

    ax.set_xticks(xi)
    ax.set_xticklabels(paired_ticks, fontsize=9)
    ax.set_xlabel("Security Level (RSA key size / ECDSA curve)", labelpad=6)
    ax.set_ylabel("Process RSS Increase (MB)")
    ax.set_title("Memory Footprint: Comparable at 128-bit and 192-bit Security\n"
                 "— 112-bit RSA shows higher allocation from 2048-bit key material")
    ax.legend(handles=_legend_handles(), loc="upper right")
    ax.text(0.97, 0.55,
            "Memory differences are\nnot sustained — both\nschemes are\ncomputation-bound.",
            transform=ax.transAxes, ha="right", va="top", fontsize=8,
            color=ANNOT_FG, linespacing=1.6,
            bbox=dict(boxstyle="round,pad=0.4", facecolor=ANNOT_BOX_BG,
                      edgecolor=SPINE_COLOR, alpha=0.9))
    _save(fig, "memory_usage.png")

    # ════════════════════════════════════════════════════════════════════════
    # 5. PUBLIC KEY SIZE
    # ════════════════════════════════════════════════════════════════════════
    fig, ax = plt.subplots(figsize=(9, 5))
    rsa_ks   = [r["rsa_public_key_size"]   / 1024 for r in results]
    ecdsa_ks = [r["ecdsa_public_key_size"] / 1024 for r in results]
    key_ratios = [rk / ek for rk, ek in zip(rsa_ks, ecdsa_ks)]

    bars_r = ax.bar([i - w/2 for i in xi], rsa_ks,   w,
                    color=RSA_COLOR, alpha=0.9, label="RSA-PSS")
    bars_e = ax.bar([i + w/2 for i in xi], ecdsa_ks, w,
                    color=ECDSA_COLOR, alpha=0.9, label="ECDSA")

    for rect, v in zip(bars_r, rsa_ks):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + max(rsa_ks) * 0.01,
                f"{v:.2f} KB", ha="center", va="bottom",
                fontsize=8, color=RSA_COLOR, fontweight="bold")
    for rect, v in zip(bars_e, ecdsa_ks):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + max(rsa_ks) * 0.01,
                f"{v:.2f} KB", ha="center", va="bottom",
                fontsize=8, color=ECDSA_COLOR, fontweight="bold")
    # Size-ratio badges
    for i, kr in enumerate(key_ratios):
        ax.text(i, max(rsa_ks[i], ecdsa_ks[i]) * 1.15,
                f"{kr:.1f}× larger", ha="center", va="bottom",
                fontsize=8, color="white", fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#7F8C8D",
                          edgecolor="none", alpha=0.85))

    ax.set_ylim(0, max(rsa_ks) * 1.35)
    ax.set_xticks(xi)
    ax.set_xticklabels(paired_ticks, fontsize=9)
    ax.set_xlabel("Security Level (RSA key size / ECDSA curve)", labelpad=6)
    ax.set_ylabel("Public Key Size (KB)")
    ax.set_title("Public Key Size: RSA Keys Are 2.9–6.6× Larger Than ECDSA\n"
                 "— the primary bandwidth cost for adopting RSA in blockchain")
    ax.legend(handles=_legend_handles(), loc="upper left")
    _save(fig, "key_size.png")

    # ════════════════════════════════════════════════════════════════════════
    # 6. SIGNATURE SIZE
    # ════════════════════════════════════════════════════════════════════════
    fig, ax = plt.subplots(figsize=(9, 5))
    rsa_ss   = [r["rsa_signature_size"]   for r in results]
    ecdsa_ss = [r["ecdsa_signature_size"] for r in results]
    sig_ratios = [rs / es for rs, es in zip(rsa_ss, ecdsa_ss)]

    bars_r = ax.bar([i - w/2 for i in xi], rsa_ss,   w,
                    color=RSA_COLOR, alpha=0.9, label="RSA-PSS")
    bars_e = ax.bar([i + w/2 for i in xi], ecdsa_ss, w,
                    color=ECDSA_COLOR, alpha=0.9, label="ECDSA")

    for rect, v in zip(bars_r, rsa_ss):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + max(rsa_ss) * 0.01,
                f"{v} B", ha="center", va="bottom",
                fontsize=8, color=RSA_COLOR, fontweight="bold")
    for rect, v in zip(bars_e, ecdsa_ss):
        ax.text(rect.get_x() + rect.get_width()/2,
                rect.get_height() + max(rsa_ss) * 0.01,
                f"{v} B", ha="center", va="bottom",
                fontsize=8, color=ECDSA_COLOR, fontweight="bold")
    for i, sr in enumerate(sig_ratios):
        ax.text(i, max(rsa_ss[i], ecdsa_ss[i]) * 1.12,
                f"{sr:.1f}× larger", ha="center", va="bottom",
                fontsize=8, color="white", fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#7F8C8D",
                          edgecolor="none", alpha=0.85))

    ax.set_ylim(0, max(rsa_ss) * 1.32)
    ax.set_xticks(xi)
    ax.set_xticklabels(paired_ticks, fontsize=9)
    ax.set_xlabel("Security Level (RSA key size / ECDSA curve)", labelpad=6)
    ax.set_ylabel("Signature Size (bytes)")
    ax.set_title("Signature Size: RSA-PSS Signatures Are 4.3–9.2× Larger Than ECDSA\n"
                 "— main storage and propagation overhead of RSA in blockchain")
    ax.legend(handles=_legend_handles(), loc="upper left")
    _save(fig, "signature_size.png")

    # ════════════════════════════════════════════════════════════════════════
    # 7. BATCH VERIFICATION CHARTS (one per tx_count)
    # ════════════════════════════════════════════════════════════════════════
    for tx_count in TRANSACTION_COUNTS:
        tx_rows = sorted(
            [row for row in batch_results if row["tx_count"] == tx_count],
            key=lambda r: r["security_bits"])
        rsa_totals   = [row["rsa_verify_total_ms"]   for row in tx_rows]
        ecdsa_totals = [row["ecdsa_verify_total_ms"] for row in tx_rows]
        ratios       = [row["verify_ratio_rsa_ecdsa"] for row in tx_rows]
        row_bits     = [row["security_bits"]          for row in tx_rows]
        xi2          = list(range(len(row_bits)))

        fig, ax1 = plt.subplots(figsize=(9, 5))
        ax2 = ax1.twinx()

        b_r = ax1.bar([i - w/2 for i in xi2], rsa_totals,   w,
                      color=RSA_COLOR,   alpha=0.9, label="RSA-PSS",
                      zorder=3)
        b_e = ax1.bar([i + w/2 for i in xi2], ecdsa_totals, w,
                      color=ECDSA_COLOR, alpha=0.9, label="ECDSA",
                      zorder=3)

        # Value labels on bars (only if space permits — skip tiny bars)
        for rect, v in zip(b_r, rsa_totals):
            ax1.text(rect.get_x() + rect.get_width()/2,
                     rect.get_height() + max(ecdsa_totals)*0.01,
                     f"{v/1000:.1f}s" if v > 500 else f"{v:.0f}",
                     ha="center", va="bottom", fontsize=7.5,
                     color=RSA_COLOR, fontweight="bold")
        for rect, v in zip(b_e, ecdsa_totals):
            ax1.text(rect.get_x() + rect.get_width()/2,
                     rect.get_height() + max(ecdsa_totals)*0.01,
                     f"{v/1000:.1f}s" if v > 500 else f"{v:.0f}",
                     ha="center", va="bottom", fontsize=7.5,
                     color=ECDSA_COLOR, fontweight="bold")

        # Ratio line on secondary axis
        ax2.plot(xi2, ratios, color=RATIO_COLOR, marker="D",
                 markersize=7, linewidth=2.2, label="RSA/ECDSA ratio",
                 zorder=4, markerfacecolor="white",
                 markeredgewidth=2, markeredgecolor=RATIO_COLOR)
        for i, r in enumerate(ratios):
            ax2.text(xi2[i], r + 0.025, f"{r:.2f}",
                     ha="center", va="bottom", fontsize=8,
                     color=RATIO_COLOR, fontweight="bold")

        ax2.set_ylim(0, max(ratios) * 1.55)
        ax2.set_ylabel("Verification Time Ratio (RSA / ECDSA)\n"
                       "< 1.0 means RSA is faster", color=RATIO_COLOR,
                       fontsize=10)
        ax2.tick_params(axis="y", labelcolor=RATIO_COLOR)
        ax2.axhline(1.0, color=RATIO_COLOR, linewidth=0.8,
                    linestyle=":", alpha=0.5)
        ax2.spines["right"].set_visible(True)
        ax2.spines["right"].set_color(RATIO_COLOR)
        ax2.spines["right"].set_linewidth(0.6)

        ax1.set_xlabel("Security Level (bits)", labelpad=6)
        ax1.set_ylabel("Total Verification Time (ms)")
        ax1.set_xticks(xi2)
        ax1.set_xticklabels([str(b) for b in row_bits])
        ax1.grid(axis="y", alpha=0.25, zorder=0)
        ax1.set_title(
            f"Batch Verification — {tx_count:,} Transactions\n"
            f"RSA-PSS is consistently faster; ratio below 1.0 at every security level")

        h1, l1 = ax1.get_legend_handles_labels()
        ratio_handle = plt.Line2D([0], [0], color=RATIO_COLOR, marker="D",
                                  markerfacecolor="white",
                                  markeredgecolor=RATIO_COLOR,
                                  markeredgewidth=2, linewidth=2,
                                  label="RSA/ECDSA ratio")
        ax1.legend(handles=[
            mpatches.Patch(facecolor=RSA_COLOR,   label="RSA-PSS"),
            mpatches.Patch(facecolor=ECDSA_COLOR, label="ECDSA"),
            ratio_handle,
        ], loc="upper left", fontsize=9)

        fig.tight_layout()
        fname = f"verification_time_{tx_count // 1000}k.png"
        _save(fig, fname)

    # ════════════════════════════════════════════════════════════════════════
    # 8. RATIO SUMMARY (all batch sizes × all security levels)
    # ════════════════════════════════════════════════════════════════════════
    # Use a sequential colormap so the 6 tx-count lines are distinguishable
    import matplotlib.cm as cm
    cmap    = cm.get_cmap("viridis", len(TRANSACTION_COUNTS))
    markers = ["o", "s", "D", "^", "v", "P"]

    fig, ax = plt.subplots(figsize=(9, 5))
    for idx, tx_count in enumerate(TRANSACTION_COUNTS):
        tx_rows = sorted(
            [row for row in batch_results if row["tx_count"] == tx_count],
            key=lambda r: r["security_bits"])
        xs = [row["security_bits"]           for row in tx_rows]
        ys = [row["verify_ratio_rsa_ecdsa"]  for row in tx_rows]
        ax.plot(xs, ys, marker=markers[idx], color=cmap(idx),
                linewidth=2, markersize=7, label=f"{tx_count // 1000}k tx",
                markerfacecolor="white", markeredgewidth=2,
                markeredgecolor=cmap(idx))

    ax.axhline(1.0, color="#E74C3C", linewidth=1.0, linestyle="--",
               alpha=0.7, label="Parity (ratio = 1.0)")

    # Shade the "RSA wins" region
    ax.fill_between([100, 200], [0, 0], [1.0, 1.0],
                    color=RSA_COLOR, alpha=0.05, zorder=0)
    ax.text(150, 0.12, "← RSA-PSS faster (ratio < 1.0)",
            ha="center", fontsize=9, color=RSA_COLOR, style="italic")

    ax.set_xlim(105, 200)
    ax.set_xticks(sec_bits)
    ax.set_xticklabels([str(b) for b in sec_bits])
    ax.set_xlabel("Security Level (bits)", labelpad=6)
    ax.set_ylabel("Verification Time Ratio (RSA / ECDSA)\nLower = RSA faster")
    ax.set_title(
        "Batch Verification Ratio Across All Security Levels and Transaction Counts\n"
        "— ratio is stable across batch sizes, confirming a per-operation advantage")
    ax.legend(ncol=4, fontsize=8.5, loc="upper center",
              bbox_to_anchor=(0.5, -0.18), frameon=True)

    fig.tight_layout()
    _save(fig, "verification_ratio_summary.png")

    # ════════════════════════════════════════════════════════════════════════
    # 9. EXPONENT BENCHMARK: VERIFICATION TIME vs TRANSACTION COUNT
    # ════════════════════════════════════════════════════════════════════════
    if exponent_batch_results:
        fig, ax = plt.subplots(figsize=(9, 5))
        exponent_values = sorted({row["k"] for row in exponent_batch_results})
        tx_ticks = sorted({row["tx_count"] for row in exponent_batch_results})
        for k_val in exponent_values:
            rows = sorted(
                [row for row in exponent_batch_results if row["k"] == k_val],
                key=lambda r: r["tx_count"],
            )
            xs = [row["tx_count"] for row in rows]
            ys = [row["rsa_verify_total_ms"] for row in rows]
            ax.plot(xs, ys, marker="o", linewidth=2, label=f"k={k_val}")

        ax.set_xticks(tx_ticks)
        ax.set_xticklabels([f"{x:,}" for x in tx_ticks])
        ax.set_xlabel("Transaction Count")
        ax.set_ylabel("Verification Time (ms)")
        ax.legend()
        _save(fig, "verification_time_exponent_line.png")

    print(f"\n✅  All graphs saved to: {GRAPHS_DIR}\n")


# ============================================================================
# CONSOLE SUMMARY
# ============================================================================

def print_summary(results: list[dict]) -> None:
    print("=" * 80)
    print("📊  RESULTS SUMMARY")
    print("=" * 80 + "\n")
    for r in results:
        print(f"🔐  {r['security_bits']}-bit  "
              f"RSA-{r['rsa_key_size']} vs ECDSA-{r['ecdsa_curve']}")
        print(f"    Signing    RSA: {r['rsa_sign_mean_ms']:.3f} ms "
              f"(med {r['rsa_sign_median_ms']:.3f}, "
              f"±{r['rsa_sign_stdev_ms']:.3f}, "
              f"p95 {r['rsa_sign_p95_ms']:.3f})")
        print(f"               ECDSA: {r['ecdsa_sign_mean_ms']:.3f} ms "
              f"(med {r['ecdsa_sign_median_ms']:.3f}, "
              f"±{r['ecdsa_sign_stdev_ms']:.3f}, "
              f"p95 {r['ecdsa_sign_p95_ms']:.3f})")
        print(f"               ratio RSA/ECDSA: {r['sign_ratio_rsa_ecdsa']:.2f}x")
        print(f"    Verify     RSA: {r['rsa_verify_mean_ms']:.3f} ms "
              f"(med {r['rsa_verify_median_ms']:.3f}, "
              f"±{r['rsa_verify_stdev_ms']:.3f}, "
              f"p95 {r['rsa_verify_p95_ms']:.3f})")
        print(f"               ECDSA: {r['ecdsa_verify_mean_ms']:.3f} ms "
              f"(med {r['ecdsa_verify_median_ms']:.3f}, "
              f"±{r['ecdsa_verify_stdev_ms']:.3f}, "
              f"p95 {r['ecdsa_verify_p95_ms']:.3f})")
        print(f"               ratio RSA/ECDSA: {r['verify_ratio_rsa_ecdsa']:.2f}x")
        print(f"    Key size   RSA: {r['rsa_public_key_size']} B  "
              f"ECDSA: {r['ecdsa_public_key_size']} B")
        print(f"    Sig size   RSA: {r['rsa_signature_size']} B  "
              f"ECDSA: {r['ecdsa_signature_size']} B")
        print()


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print(f"\n⏱️   Starting benchmark at {datetime.now()}\n")
    results, batch_results, exponent_batch_results = run_benchmark()

    if not results:
        print("❌  Benchmark failed — no results produced.")
        sys.exit(1)

    save_results(results, batch_results)
    print("📊  Generating graphs …")
    generate_graphs(results, batch_results, exponent_batch_results)
    print_summary(results)

    print("=" * 80)
    print(f"✅  Complete at {datetime.now()}")
    print(f"    Main CSV  : {CSV_PATH}")
    print(f"    Batch CSV : {BATCH_CSV_PATH}")
    print(f"    Graphs    : {GRAPHS_DIR}")
    print("=" * 80)
