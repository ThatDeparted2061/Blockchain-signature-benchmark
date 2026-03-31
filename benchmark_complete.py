#!/usr/bin/env python3
"""
COMPREHENSIVE ECDSA vs Probabilistic RSA-PSS Benchmark
=======================================================
Full cryptographic performance comparison across matched security levels.
Generates CSV results + publication-quality matplotlib line graphs for IEEE paper.

Active security level  : 128-bit  (RSA-3072 vs ECDSA P-256)
Commented-out levels   : 112-bit  (RSA-2048 vs ECDSA secp224r1)
                         192-bit  (RSA-7680 vs ECDSA P-384)

USAGE:
    python3 benchmark_complete.py

REQUIREMENTS:
    pip install cryptography matplotlib psutil pyJoules

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
    import matplotlib.cm as cm
    matplotlib.use("Agg")
except ImportError:
    print("❌ matplotlib not found.  Install with: pip install matplotlib")
    sys.exit(1)

# ── pyJoules energy measurement (optional) ───────────────────────────────────
# If pyJoules / Intel RAPL is unavailable the benchmark falls back to a
# 1 W time-based energy proxy (energy_mJ ≈ time_ms).
try:
    from pyJoules.energy_meter import EnergyContext as _EnergyContext
    from pyJoules.device.rapl_device import RaplPackageDomain as _RaplPackageDomain
    from pyJoules.handler.energy_handler import EnergyHandler as _BaseEnergyHandler

    PYJOULES_AVAILABLE = True

    class _AccumulatingHandler(_BaseEnergyHandler):
        """Accumulates energy (µJ) across every process() call from pyJoules."""

        def __init__(self) -> None:
            super().__init__()
            self.total_uj: float = 0.0

        def process(self, sample) -> None:  # type: ignore[override]
            try:
                e = sample.energy
                # energy may be a list or a dict depending on pyJoules version
                self.total_uj += sum(e.values() if hasattr(e, "values") else e)
            except Exception:
                pass

except Exception:
    PYJOULES_AVAILABLE = False
    _EnergyContext = None        # type: ignore[assignment,misc]
    _RaplPackageDomain = None    # type: ignore[assignment,misc]
    _AccumulatingHandler = None  # type: ignore[assignment]


# ============================================================================
# PUBLICATION-QUALITY STYLE CONFIGURATION
# ============================================================================

# Colorblind-safe, publication-quality palette
RSA_COLOR   = "#1A5F99"   # Deep steel blue  — RSA-PSS
ECDSA_COLOR = "#C0392B"   # Crimson red       — ECDSA
RATIO_COLOR = "#1E8C45"   # Forest green      — ratio line
GRID_COLOR  = "#D5D8DC"   # Subtle grid
SPINE_COLOR = "#7F8C8D"   # Axis spines


def setup_publication_style() -> None:
    """Apply a clean, IEEE-publication-compatible matplotlib style."""
    plt.rcParams.update({
        # Figure
        "figure.dpi": 180,
        "figure.facecolor": "white",
        "figure.edgecolor": "none",
        # Fonts
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
        # Lines / markers
        "lines.linewidth": 2.0,
        "lines.markersize": 7,
        "errorbar.capsize": 4,
        # Save
        "savefig.bbox": "tight",
        "savefig.dpi": 180,
        "savefig.facecolor": "white",
    })


# ============================================================================
# CONFIGURATION
# ============================================================================

SECURITY_LEVELS = [
    # ── 112-bit security level — commented out, not producing output ───────
    # {
    #     "bits": 112,
    #     "rsa": 2048,
    #     "ecdsa": "secp224r1",
    #     "notes": "secp224r1 baseline (~112-bit)",
    # },

    # ── 128-bit security level — ACTIVE ────────────────────────────────────
    {
        "bits": 128,
        "rsa": 3072,
        "ecdsa": "P-256",
        "notes": "Modern standard baseline",
    },

    # ── 192-bit security level — commented out, not producing output ───────
    # {
    #     "bits": 192,
    #     "rsa": 7680,
    #     "ecdsa": "P-384",
    #     "notes": "High security",
    # },
]

CURVES: dict = {
    "secp224r1": ec.SECP224R1(),
    "P-256":     ec.SECP256R1(),
    "P-384":     ec.SECP384R1(),
}

WARMUP_ITERATIONS: dict[int, int] = {2048: 20,  3072: 20,  7680: 10}
TIMED_ITERATIONS:  dict[int, int] = {2048: 200, 3072: 200, 7680: 100}
SIG_POOL_SIZE = 50

# Number of verify calls used once to estimate energy rate (then scaled).
ENERGY_RATE_SAMPLE_SIZE = 2_000

TEST_MESSAGE = b"Blockchain transaction data for signing and verification benchmark"

OUTPUT_DIR        = Path(__file__).parent / "results"
GRAPHS_DIR        = OUTPUT_DIR / "graphs"
CSV_PATH          = OUTPUT_DIR / "benchmark_results_comprehensive.csv"
BATCH_CSV_PATH    = OUTPUT_DIR / "batch_verification_results.csv"
EXPONENT_VALUES_PATH = (
    Path(__file__).parent / "exponent_values" / "exponent_values.txt"
)

TRANSACTION_COUNTS         = [5_000, 10_000, 15_000, 20_000, 25_000, 30_000]
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
    n       = len(samples)
    sorted_s = sorted(samples)
    p95_idx  = min(int(0.95 * n), n - 1)
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
    print(f"   pyJoules     : {'enabled (RAPL)' if PYJOULES_AVAILABLE else 'disabled (1 W fallback)'}")
    print()


def measure_batch_milestones(verify_fn, tx_counts: list[int]) -> dict[int, float]:
    """
    Single continuous verification pass; snapshot wall-clock elapsed time
    (ms) at each milestone.  Total work = max(tx_counts), not the sum.
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


def measure_energy_rate_mj_per_op(verify_fn) -> float:
    """
    Estimate energy per single verification operation (mJ / op).

    Strategy: execute ENERGY_RATE_SAMPLE_SIZE operations inside a single
    pyJoules RAPL measurement window; return the per-operation average.
    If RAPL is unavailable the 1 W time model is used (1 ms ≈ 1 mJ).

    Callers scale to arbitrary transaction counts as:
        energy_mj(N) = measure_energy_rate_mj_per_op(fn) * N
    """
    n = ENERGY_RATE_SAMPLE_SIZE

    # Warm up the CPU to a stable frequency before measuring.
    for _ in range(min(100, n // 10)):
        verify_fn()

    if PYJOULES_AVAILABLE and _AccumulatingHandler is not None:
        try:
            handler = _AccumulatingHandler()
            with _EnergyContext(                          # type: ignore[arg-type]
                domains=[_RaplPackageDomain(0)],         # type: ignore[arg-type]
                handler=handler,
            ):
                for _ in range(n):
                    verify_fn()
            # handler.total_uj is in micro-joules; convert to mJ/op
            return handler.total_uj / (1_000.0 * n)
        except Exception as exc:
            print(f"   ⚠️  pyJoules RAPL read failed ({exc}); "
                  "switching to 1 W time-based energy model.")

    # ── Fallback: 1 W model ──────────────────────────────────────────────
    t0 = time.perf_counter()
    for _ in range(n):
        verify_fn()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return elapsed_ms / n   # ms / op  ≈  mJ / op  @ 1 W


def load_exponent_values(path: Path) -> list[tuple[int, int]]:
    """Return sorted (k, e) pairs from exponent_values.txt."""
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
    Build an RSA private key with a custom odd public exponent.
    The cryptography library only directly supports e=3 and e=65537, so we
    generate a seed key to obtain suitable primes then reconstruct manually.
    """
    if exponent <= 1 or exponent % 2 == 0:
        raise ValueError(
            f"public exponent must be an odd integer > 1, got {exponent}")
    for _ in range(max_attempts):
        seed_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size, backend=default_backend())
        nums = seed_key.private_numbers()
        p, q = nums.p, nums.q
        phi  = (p - 1) * (q - 1)
        if math.gcd(exponent, phi) != 1:
            continue
        d    = pow(exponent, -1, phi)
        dmp1 = d % (p - 1)
        dmq1 = d % (q - 1)
        iqmp = pow(q, -1, p)
        private_numbers = rsa.RSAPrivateNumbers(
            p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
            public_numbers=rsa.RSAPublicNumbers(exponent, p * q),
        )
        return private_numbers.private_key(default_backend())
    raise ValueError(
        f"unable to construct {key_size}-bit RSA key with exponent {exponent} "
        f"after {max_attempts} attempts")


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

        print(f"✅  Sign {ss['mean']:.3f} ms ±{ss['stdev']:.3f}"
              f" | Verify {vs['mean']:.3f} ms ±{vs['stdev']:.3f}")
        return {
            "rsa_sign_mean_ms":     ss["mean"],
            "rsa_sign_median_ms":   ss["median"],
            "rsa_sign_stdev_ms":    ss["stdev"],
            "rsa_sign_p95_ms":      ss["p95"],
            "rsa_verify_mean_ms":   vs["mean"],
            "rsa_verify_median_ms": vs["median"],
            "rsa_verify_stdev_ms":  vs["stdev"],
            "rsa_verify_p95_ms":    vs["p95"],
            "rsa_cpu_time_s":       cpu_elapsed,
            "rsa_memory_delta_mb":  mem_delta,
            "rsa_public_key_size":  len(pub_pem),
            "rsa_signature_size":   len(signatures[0]),
            "rsa_verify_fn":        verify_fn,
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

        print(f"✅  Sign {ss['mean']:.3f} ms ±{ss['stdev']:.3f}"
              f" | Verify {vs['mean']:.3f} ms ±{vs['stdev']:.3f}")
        return {
            "ecdsa_sign_mean_ms":     ss["mean"],
            "ecdsa_sign_median_ms":   ss["median"],
            "ecdsa_sign_stdev_ms":    ss["stdev"],
            "ecdsa_sign_p95_ms":      ss["p95"],
            "ecdsa_verify_mean_ms":   vs["mean"],
            "ecdsa_verify_median_ms": vs["median"],
            "ecdsa_verify_stdev_ms":  vs["stdev"],
            "ecdsa_verify_p95_ms":    vs["p95"],
            "ecdsa_cpu_time_s":       cpu_elapsed,
            "ecdsa_memory_delta_mb":  mem_delta,
            "ecdsa_public_key_size":  len(pub_pem),
            "ecdsa_signature_size":   len(signatures[0]),
            "ecdsa_verify_fn":        verify_fn,
        }
    except Exception as exc:
        print(f"❌  {exc}")
        return None


# ============================================================================
# MAIN BENCHMARK ORCHESTRATION
# ============================================================================

def run_exponent_batch_benchmark() -> list[dict]:
    """
    Measure RSA batch verification time and energy for each public exponent
    defined in exponent_values.txt across all TRANSACTION_COUNTS.

    Energy is estimated via a single pyJoules RAPL measurement window of
    ENERGY_RATE_SAMPLE_SIZE operations; the per-op rate is then scaled
    linearly to each transaction count.
    """
    exponent_pairs = load_exponent_values(EXPONENT_VALUES_PATH)
    if not exponent_pairs:
        print("⚠️   No exponent values found; skipping exponent benchmark.")
        return []

    print("🔣  RSA Exponent Benchmark")
    print(f"    Key size   : {EXPONENT_BENCHMARK_KEY_SIZE}-bit")
    print(f"    Exponents  : {', '.join(f'k={k}' for k, _ in exponent_pairs)}")
    print(f"    pyJoules   : {'enabled (RAPL)' if PYJOULES_AVAILABLE else 'disabled (1 W fallback)'}")
    print(f"    {'─' * 74}")

    benchmark_data: list[dict] = []

    for k_val, exponent in exponent_pairs:
        print(f"   🔓 RSA k={k_val} (e={exponent})...", end=" ", flush=True)
        try:
            private_key = build_rsa_private_key_for_exponent(
                key_size=EXPONENT_BENCHMARK_KEY_SIZE, exponent=exponent)
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
                public_key.verify(
                    next(pool_iter), TEST_MESSAGE, verify_pad, hash_alg)

            # ── Time: single continuous pass, snapshot at milestones ───────
            milestones = measure_batch_milestones(verify_fn, TRANSACTION_COUNTS)

            # ── Energy: one RAPL window → per-op rate → scale to each tx ──
            rate_mj_per_op = measure_energy_rate_mj_per_op(verify_fn)

            print("✅")
            for tx_count in TRANSACTION_COUNTS:
                total_ms  = milestones.get(tx_count, 0.0)
                energy_mj = rate_mj_per_op * tx_count
                benchmark_data.append({
                    "k":                    k_val,
                    "public_exponent":      exponent,
                    "tx_count":             tx_count,
                    "rsa_verify_total_ms":  round(total_ms,  2),
                    "rsa_verify_energy_mj": round(energy_mj, 4),
                })
                print(f"       {tx_count:>6,} tx  "
                      f"time={total_ms:>8.0f} ms  "
                      f"energy={energy_mj:>8.2f} mJ")

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

    results:       list[dict] = []
    batch_results: list[dict] = []

    for level in SECURITY_LEVELS:
        bits        = level["bits"]
        rsa_size    = level["rsa"]
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

        sign_ratio   = rsa_r["rsa_sign_mean_ms"]  / ecdsa_r["ecdsa_sign_mean_ms"]
        verify_ratio = rsa_r["rsa_verify_mean_ms"] / ecdsa_r["ecdsa_verify_mean_ms"]

        result_row: dict = {
            "security_bits":          bits,
            "rsa_key_size":           rsa_size,
            "ecdsa_curve":            ecdsa_curve,
            "notes":                  level["notes"],
            "rsa_sign_mean_ms":       round(rsa_r["rsa_sign_mean_ms"],    4),
            "rsa_sign_median_ms":     round(rsa_r["rsa_sign_median_ms"],  4),
            "rsa_sign_stdev_ms":      round(rsa_r["rsa_sign_stdev_ms"],   4),
            "rsa_sign_p95_ms":        round(rsa_r["rsa_sign_p95_ms"],     4),
            "rsa_verify_mean_ms":     round(rsa_r["rsa_verify_mean_ms"],  4),
            "rsa_verify_median_ms":   round(rsa_r["rsa_verify_median_ms"],4),
            "rsa_verify_stdev_ms":    round(rsa_r["rsa_verify_stdev_ms"], 4),
            "rsa_verify_p95_ms":      round(rsa_r["rsa_verify_p95_ms"],   4),
            "rsa_cpu_time_s":         round(rsa_r["rsa_cpu_time_s"],      4),
            "rsa_memory_delta_mb":    round(rsa_r["rsa_memory_delta_mb"], 4),
            "rsa_public_key_size":    rsa_r["rsa_public_key_size"],
            "rsa_signature_size":     rsa_r["rsa_signature_size"],
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

        # ── Batch verification: time ───────────────────────────────────────
        print(f"\n    ⏳  Batch verification "
              f"({', '.join(f'{t // 1000}k' for t in TRANSACTION_COUNTS)} tx) …")
        rsa_milestones   = measure_batch_milestones(
            rsa_r["rsa_verify_fn"],   TRANSACTION_COUNTS)
        ecdsa_milestones = measure_batch_milestones(
            ecdsa_r["ecdsa_verify_fn"], TRANSACTION_COUNTS)

        # ── Batch verification: energy (one rate estimate, then scale) ─────
        print("    ⚡  Measuring energy rates …")
        rsa_rate_mj   = measure_energy_rate_mj_per_op(rsa_r["rsa_verify_fn"])
        ecdsa_rate_mj = measure_energy_rate_mj_per_op(ecdsa_r["ecdsa_verify_fn"])

        for tx in TRANSACTION_COUNTS:
            rsa_total   = rsa_milestones.get(tx,   0.0)
            ecdsa_total = ecdsa_milestones.get(tx, 0.0)
            ratio       = rsa_total / ecdsa_total if ecdsa_total else 0.0
            batch_results.append({
                "security_bits":          bits,
                "tx_count":               tx,
                "rsa_verify_total_ms":    round(rsa_total,          2),
                "ecdsa_verify_total_ms":  round(ecdsa_total,        2),
                "verify_ratio_rsa_ecdsa": round(ratio,              4),
                "rsa_verify_energy_mj":   round(rsa_rate_mj   * tx, 4),
                "ecdsa_verify_energy_mj": round(ecdsa_rate_mj * tx, 4),
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
# GRAPH GENERATION
# ─────────────────────────────────────────────────────────────────────────────
# All charts are line graphs.  No in-chart text annotations, value labels,
# speedup badges, or insight boxes are rendered.  Each figure contains only
# axis labels, axis ticks, a title, and a legend.
# ============================================================================

def _save(fig: plt.Figure, name: str) -> None:
    path = GRAPHS_DIR / name
    fig.savefig(path, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"✅  {name}")


def generate_graphs(
    results: list[dict],
    batch_results: list[dict],
    exponent_batch_results: list[dict],
) -> None:
    GRAPHS_DIR.mkdir(parents=True, exist_ok=True)
    setup_publication_style()

    # ── Per-security-level graphs (dynamically use whichever levels are in
    #    results — currently only 128-bit is active) ──────────────────────
    if results:
        sec_bits = [r["security_bits"] for r in results]
        xtick_labels = [
            f"{r['security_bits']}-bit\n(RSA-{r['rsa_key_size']} / {r['ecdsa_curve']})"
            for r in results
        ]

        # ── 1. SIGNING TIME ───────────────────────────────────────────────
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.errorbar(
            sec_bits,
            [r["rsa_sign_mean_ms"]   for r in results],
            yerr=[r["rsa_sign_stdev_ms"]  for r in results],
            fmt="-o", color=RSA_COLOR,   capsize=4, label="RSA-PSS", linewidth=2,
        )
        ax.errorbar(
            sec_bits,
            [r["ecdsa_sign_mean_ms"]  for r in results],
            yerr=[r["ecdsa_sign_stdev_ms"] for r in results],
            fmt="-s", color=ECDSA_COLOR, capsize=4, label="ECDSA",   linewidth=2,
        )
        ax.set_xticks(sec_bits)
        ax.set_xticklabels(xtick_labels, fontsize=9)
        ax.set_xlabel("Security Level (RSA key size / ECDSA curve)")
        ax.set_ylabel("Mean Signing Time (ms) ± 1σ")
        ax.set_title("Signing Time: RSA-PSS vs ECDSA")
        ax.legend()
        _save(fig, "signing_time.png")

        # ── 2. SINGLE-OPERATION VERIFICATION TIME ─────────────────────────
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.errorbar(
            sec_bits,
            [r["rsa_verify_mean_ms"]   for r in results],
            yerr=[r["rsa_verify_stdev_ms"]  for r in results],
            fmt="-o", color=RSA_COLOR,   capsize=4, label="RSA-PSS", linewidth=2,
        )
        ax.errorbar(
            sec_bits,
            [r["ecdsa_verify_mean_ms"]  for r in results],
            yerr=[r["ecdsa_verify_stdev_ms"] for r in results],
            fmt="-s", color=ECDSA_COLOR, capsize=4, label="ECDSA",   linewidth=2,
        )
        ax.set_xticks(sec_bits)
        ax.set_xticklabels(xtick_labels, fontsize=9)
        ax.set_xlabel("Security Level (RSA key size / ECDSA curve)")
        ax.set_ylabel("Mean Verification Time (ms) ± 1σ")
        ax.set_title("Single-Operation Verification Time: RSA-PSS vs ECDSA")
        ax.legend()
        _save(fig, "verification_time_single.png")

        # ── 3. CPU TIME ────────────────────────────────────────────────────
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.plot(sec_bits, [r["rsa_cpu_time_s"]   for r in results],
                "-o", color=RSA_COLOR,   label="RSA-PSS", linewidth=2)
        ax.plot(sec_bits, [r["ecdsa_cpu_time_s"] for r in results],
                "-s", color=ECDSA_COLOR, label="ECDSA",   linewidth=2)
        ax.set_xticks(sec_bits)
        ax.set_xticklabels(xtick_labels, fontsize=9)
        ax.set_xlabel("Security Level (RSA key size / ECDSA curve)")
        ax.set_ylabel("Total CPU Time — Sign + Verify Phase (s)")
        ax.set_title("CPU Time: RSA-PSS vs ECDSA")
        ax.legend()
        _save(fig, "cpu_time.png")

        # ── 4. MEMORY USAGE ────────────────────────────────────────────────
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.plot(sec_bits, [r["rsa_memory_delta_mb"]   for r in results],
                "-o", color=RSA_COLOR,   label="RSA-PSS", linewidth=2)
        ax.plot(sec_bits, [r["ecdsa_memory_delta_mb"] for r in results],
                "-s", color=ECDSA_COLOR, label="ECDSA",   linewidth=2)
        ax.set_xticks(sec_bits)
        ax.set_xticklabels(xtick_labels, fontsize=9)
        ax.set_xlabel("Security Level (RSA key size / ECDSA curve)")
        ax.set_ylabel("Process RSS Increase (MB)")
        ax.set_title("Memory Footprint: RSA-PSS vs ECDSA")
        ax.legend()
        _save(fig, "memory_usage.png")

        # ── 5. PUBLIC KEY SIZE ─────────────────────────────────────────────
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.plot(sec_bits, [r["rsa_public_key_size"]   / 1024 for r in results],
                "-o", color=RSA_COLOR,   label="RSA-PSS", linewidth=2)
        ax.plot(sec_bits, [r["ecdsa_public_key_size"] / 1024 for r in results],
                "-s", color=ECDSA_COLOR, label="ECDSA",   linewidth=2)
        ax.set_xticks(sec_bits)
        ax.set_xticklabels(xtick_labels, fontsize=9)
        ax.set_xlabel("Security Level (RSA key size / ECDSA curve)")
        ax.set_ylabel("Public Key Size (KB)")
        ax.set_title("Public Key Size: RSA-PSS vs ECDSA")
        ax.legend()
        _save(fig, "key_size.png")

        # ── 6. SIGNATURE SIZE ──────────────────────────────────────────────
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.plot(sec_bits, [r["rsa_signature_size"]   for r in results],
                "-o", color=RSA_COLOR,   label="RSA-PSS", linewidth=2)
        ax.plot(sec_bits, [r["ecdsa_signature_size"] for r in results],
                "-s", color=ECDSA_COLOR, label="ECDSA",   linewidth=2)
        ax.set_xticks(sec_bits)
        ax.set_xticklabels(xtick_labels, fontsize=9)
        ax.set_xlabel("Security Level (RSA key size / ECDSA curve)")
        ax.set_ylabel("Signature Size (bytes)")
        ax.set_title("Signature Size: RSA-PSS vs ECDSA")
        ax.legend()
        _save(fig, "signature_size.png")

    # ── 7. BATCH VERIFICATION — total time, 128-bit, tx_count on x-axis ───
    batch_128 = sorted(
        [r for r in batch_results if r["security_bits"] == 128],
        key=lambda r: r["tx_count"],
    )
    if batch_128:
        xs         = [r["tx_count"]              for r in batch_128]
        rsa_totals = [r["rsa_verify_total_ms"]   for r in batch_128]
        ec_totals  = [r["ecdsa_verify_total_ms"] for r in batch_128]
        ratios     = [r["verify_ratio_rsa_ecdsa"]for r in batch_128]

        # 7a. Total verification time vs transaction count
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.plot(xs, rsa_totals, "-o", color=RSA_COLOR,
                label="RSA-PSS (128-bit)", linewidth=2)
        ax.plot(xs, ec_totals,  "-s", color=ECDSA_COLOR,
                label="ECDSA P-256 (128-bit)", linewidth=2)
        ax.set_xticks(xs)
        ax.set_xticklabels([f"{x:,}" for x in xs], fontsize=9)
        ax.set_xlabel("Transaction Count")
        ax.set_ylabel("Total Verification Time (ms)")
        ax.set_title("Batch Verification Time: RSA-PSS vs ECDSA (128-bit Security)")
        ax.legend()
        _save(fig, "batch_verification_128bit.png")

        # 7b. Verification time ratio vs transaction count
        fig, ax = plt.subplots(figsize=(9, 5))
        ax.plot(xs, ratios, "-D", color=RATIO_COLOR,
                label="RSA / ECDSA ratio", linewidth=2,
                markerfacecolor="white", markeredgewidth=2,
                markeredgecolor=RATIO_COLOR)
        ax.axhline(1.0, color="#E74C3C", linewidth=1.0,
                   linestyle="--", alpha=0.7, label="Parity (ratio = 1.0)")
        ax.set_xticks(xs)
        ax.set_xticklabels([f"{x:,}" for x in xs], fontsize=9)
        ax.set_xlabel("Transaction Count")
        ax.set_ylabel("Verification Time Ratio (RSA / ECDSA)")
        ax.set_title("Batch Verification Ratio: RSA-PSS vs ECDSA (128-bit Security)")
        ax.legend()
        _save(fig, "verification_ratio_summary.png")

    # ── 8 & 9. EXPONENT BENCHMARK GRAPHS ─────────────────────────────────
    if exponent_batch_results:
        k_values = sorted({r["k"]        for r in exponent_batch_results})
        tx_ticks = sorted({r["tx_count"] for r in exponent_batch_results})

        # Distinct colour per exponent via tab10
        cmap    = cm.get_cmap("tab10", len(k_values))
        markers = ["o", "s", "D", "^", "v", "P", "X", "*"]

        # ── 8. Verification TIME vs transaction count ──────────────────
        fig, ax = plt.subplots(figsize=(9, 5))
        for idx, k_val in enumerate(k_values):
            rows = sorted(
                [r for r in exponent_batch_results if r["k"] == k_val],
                key=lambda r: r["tx_count"],
            )
            ax.plot(
                [r["tx_count"]            for r in rows],
                [r["rsa_verify_total_ms"] for r in rows],
                marker=markers[idx % len(markers)],
                color=cmap(idx), linewidth=2,
                label=f"RSA k={k_val} (e={rows[0]['public_exponent']})",
            )

        # Overlay ECDSA P-256 128-bit
        if batch_128:
            ax.plot(
                [r["tx_count"]            for r in batch_128],
                [r["ecdsa_verify_total_ms"]for r in batch_128],
                marker="s", linewidth=2.4, linestyle="--",
                color=ECDSA_COLOR,
                markerfacecolor="white", markeredgewidth=1.8,
                label="ECDSA P-256 (128-bit)",
            )

        ax.set_xticks(tx_ticks)
        ax.set_xticklabels([f"{x:,}" for x in tx_ticks], fontsize=9)
        ax.set_xlabel("Transaction Count")
        ax.set_ylabel("Total Verification Time (ms)")
        ax.set_title("Verification Time vs Transaction Count (128-bit Security)")
        ax.legend(fontsize=8, ncol=2)
        _save(fig, "verification_time_exponent_line.png")

        # ── 9. Verification ENERGY vs transaction count (pyJoules) ────
        fig, ax = plt.subplots(figsize=(9, 5))
        for idx, k_val in enumerate(k_values):
            rows = sorted(
                [r for r in exponent_batch_results if r["k"] == k_val],
                key=lambda r: r["tx_count"],
            )
            ax.plot(
                [r["tx_count"]               for r in rows],
                [r["rsa_verify_energy_mj"]   for r in rows],
                marker=markers[idx % len(markers)],
                color=cmap(idx), linewidth=2,
                label=f"RSA k={k_val} (e={rows[0]['public_exponent']})",
            )

        # Overlay ECDSA P-256 128-bit energy
        if batch_128 and "ecdsa_verify_energy_mj" in batch_128[0]:
            ax.plot(
                [r["tx_count"]               for r in batch_128],
                [r["ecdsa_verify_energy_mj"] for r in batch_128],
                marker="s", linewidth=2.4, linestyle="--",
                color=ECDSA_COLOR,
                markerfacecolor="white", markeredgewidth=1.8,
                label="ECDSA P-256 (128-bit)",
            )

        ax.set_xticks(tx_ticks)
        ax.set_xticklabels([f"{x:,}" for x in tx_ticks], fontsize=9)
        ax.set_xlabel("Transaction Count")
        energy_src = "RAPL via pyJoules" if PYJOULES_AVAILABLE else "1 W time model"
        ax.set_ylabel(f"Estimated Verification Energy (mJ)\n[{energy_src}]")
        ax.set_title("Verification Energy vs Transaction Count (128-bit Security)")
        ax.legend(fontsize=8, ncol=2)
        _save(fig, "verification_energy_exponent_line.png")

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
        print(f"               ratio RSA/ECDSA: {r['sign_ratio_rsa_ecdsa']:.2f}×")
        print(f"    Verify     RSA: {r['rsa_verify_mean_ms']:.3f} ms "
              f"(med {r['rsa_verify_median_ms']:.3f}, "
              f"±{r['rsa_verify_stdev_ms']:.3f}, "
              f"p95 {r['rsa_verify_p95_ms']:.3f})")
        print(f"               ECDSA: {r['ecdsa_verify_mean_ms']:.3f} ms "
              f"(med {r['ecdsa_verify_median_ms']:.3f}, "
              f"±{r['ecdsa_verify_stdev_ms']:.3f}, "
              f"p95 {r['ecdsa_verify_p95_ms']:.3f})")
        print(f"               ratio RSA/ECDSA: {r['verify_ratio_rsa_ecdsa']:.2f}×")
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
