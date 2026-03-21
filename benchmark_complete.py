#!/usr/bin/env python3
"""
COMPREHENSIVE ECDSA vs Probabilistic RSA (PSS) Benchmark
=======================================================
Full cryptographic performance comparison across 5 security levels
Generates CSV results + matplotlib graphs (incl. verification-time
transaction scaling + ratio analysis)

USAGE:
    python3 benchmark_complete.py

REQUIREMENTS:
    pip install cryptography matplotlib psutil

RUNTIME:
    ~30-60 minutes (depending on hardware, especially RSA-30720)
    Can be run on lab computers with more processing power

OUTPUT:
    - benchmark_results_comprehensive.csv
    - graphs/ folder with PNG files
"""

import time
import csv
import json
import psutil
import os
import sys
from pathlib import Path
from datetime import datetime

# Cryptography imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

# Matplotlib for graphs
try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend
except ImportError:
    print("❌ matplotlib not found. Install with: pip install matplotlib")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

SECURITY_LEVELS = [
    {'bits': 112, 'rsa': 2048, 'ecdsa': 'secp224r1', 'notes': 'secp256k1 stronger (~128-bit)'},
    {'bits': 128, 'rsa': 3072, 'ecdsa': 'P-256', 'notes': 'Modern standard baseline'},
    {'bits': 192, 'rsa': 7680, 'ecdsa': 'P-384', 'notes': 'High security'},
    {'bits': 256, 'rsa': 15360, 'ecdsa': 'P-521', 'notes': 'Max standardized ECDSA'},
    {'bits': 512, 'rsa': 30720, 'ecdsa': 'P-521', 'notes': 'Ultra-high security'},
]

CURVES = {
    'secp224r1': ec.SECP224R1(),
    'P-256': ec.SECP256R1(),
    'P-384': ec.SECP384R1(),
    'P-521': ec.SECP521R1(),
}

# For large RSA keys, reduce iterations
ITERATIONS = {
    2048: 3,
    3072: 3,
    7680: 3,
    15360: 1,  # Large keys: 1 iteration
    30720: 1,  # Ultra-large: 1 iteration only
}

TEST_MESSAGE = b"Blockchain transaction data for signing and verification benchmark"

OUTPUT_DIR = Path(__file__).parent / "results"
GRAPHS_DIR = OUTPUT_DIR / "graphs"
CSV_PATH = OUTPUT_DIR / "benchmark_results_comprehensive.csv"

# Transaction scaling for verification-time graphs
TRANSACTION_COUNTS = [5000, 10000, 15000, 20000, 25000, 30000]

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_memory_mb():
    """Get current process memory in MB"""
    try:
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / (1024 * 1024)
    except:
        return 0

def get_cpu_time():
    """Get current process CPU time in seconds"""
    try:
        process = psutil.Process(os.getpid())
        return process.cpu_num() if hasattr(process, 'cpu_num') else 0
    except:
        return 0

# ============================================================================
# BENCHMARK FUNCTIONS
# ============================================================================

def benchmark_rsa(key_size, security_bits):
    """Benchmark probabilistic RSA (PSS) operations"""
    print(f"   🔓 RSA-PSS ({key_size}-bit)...", end=" ", flush=True)

    try:
        iterations = ITERATIONS.get(key_size, 1)

        # Key generation
        start_keygen = time.perf_counter()
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        keygen_time = time.perf_counter() - start_keygen
        public_key = private_key.public_key()

        # Key sizes
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_size = len(public_pem)

        # Signing
        mem_before = get_memory_mb()
        sign_times = []
        signatures = []

        for _ in range(iterations):
            start = time.perf_counter()
            # Use PSS for signing (probabilistic padding)
            sig = private_key.sign(
                TEST_MESSAGE,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            sign_times.append(time.perf_counter() - start)
            signatures.append(sig)

        avg_sign = sum(sign_times) / len(sign_times) * 1000  # ms
        sig_size = len(signatures[0])

        # Verification
        verify_times = []
        for sig in signatures:
            start = time.perf_counter()
            public_key.verify(
                sig,
                TEST_MESSAGE,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            verify_times.append(time.perf_counter() - start)

        avg_verify = sum(verify_times) / len(verify_times) * 1000  # ms
        mem_after = get_memory_mb()
        peak_memory = max(mem_before, mem_after)

        cpu_time = get_cpu_time()

        print(f"✅ (Sign: {avg_sign:.2f}ms, Verify: {avg_verify:.2f}ms)")

        return {
            'rsa_sign_ms': avg_sign,
            'rsa_verify_ms': avg_verify,
            'rsa_cpu_time': cpu_time,
            'rsa_memory_mb': peak_memory,
            'rsa_public_key_size': public_key_size,
            'rsa_signature_size': sig_size,
        }

    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def benchmark_ecdsa(curve_name, security_bits):
    """Benchmark ECDSA operations"""
    print(f"   🔑 ECDSA ({curve_name})...", end=" ", flush=True)

    try:
        iterations = ITERATIONS.get(SECURITY_LEVELS[[l['ecdsa'] for l in SECURITY_LEVELS].index(curve_name)]['rsa'], 3)

        # Key generation
        start_keygen = time.perf_counter()
        private_key = ec.generate_private_key(CURVES[curve_name], default_backend())
        keygen_time = time.perf_counter() - start_keygen
        public_key = private_key.public_key()

        # Key sizes
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_size = len(public_pem)

        # Signing
        mem_before = get_memory_mb()
        sign_times = []
        signatures = []

        for _ in range(iterations):
            start = time.perf_counter()
            sig = private_key.sign(TEST_MESSAGE, ec.ECDSA(hashes.SHA256()))
            sign_times.append(time.perf_counter() - start)
            signatures.append(sig)

        avg_sign = sum(sign_times) / len(sign_times) * 1000  # ms
        sig_size = len(signatures[0])

        # Verification
        verify_times = []
        for sig in signatures:
            start = time.perf_counter()
            public_key.verify(sig, TEST_MESSAGE, ec.ECDSA(hashes.SHA256()))
            verify_times.append(time.perf_counter() - start)

        avg_verify = sum(verify_times) / len(verify_times) * 1000  # ms
        mem_after = get_memory_mb()
        peak_memory = max(mem_before, mem_after)

        cpu_time = get_cpu_time()

        print(f"✅ (Sign: {avg_sign:.2f}ms, Verify: {avg_verify:.2f}ms)")

        return {
            'ecdsa_sign_ms': avg_sign,
            'ecdsa_verify_ms': avg_verify,
            'ecdsa_cpu_time': cpu_time,
            'ecdsa_memory_mb': peak_memory,
            'ecdsa_public_key_size': public_key_size,
            'ecdsa_signature_size': sig_size,
        }

    except Exception as e:
        print(f"❌ Error: {e}")
        return None

# ============================================================================
# MAIN BENCHMARK
# ============================================================================

def run_benchmark():
    """Run comprehensive benchmark"""

    print("=" * 80)
    print("🔐 COMPREHENSIVE ECDSA vs RSA-PSS Benchmark")
    print("=" * 80)
    print(f"Started: {datetime.now()}\n")

    results = []

    for level in SECURITY_LEVELS:
        bits = level['bits']
        rsa_size = level['rsa']
        ecdsa_curve = level['ecdsa']

        print(f"🔑 Security Level: {bits}-bit")
        print(f"   RSA: {rsa_size}-bit | ECDSA: {ecdsa_curve}")
        print(f"   {level['notes']}")
        print(f"   {'─'*76}")

        # RSA benchmark
        rsa_result = benchmark_rsa(rsa_size, bits)

        # ECDSA benchmark
        ecdsa_result = benchmark_ecdsa(ecdsa_curve, bits)

        if rsa_result and ecdsa_result:
            # Calculate ratios
            sign_ratio = rsa_result['rsa_sign_ms'] / ecdsa_result['ecdsa_sign_ms']
            verify_ratio = rsa_result['rsa_verify_ms'] / ecdsa_result['ecdsa_verify_ms']

            result_row = {
                'security_bits': bits,
                'rsa_key_size': rsa_size,
                'ecdsa_curve': ecdsa_curve,
                'notes': level['notes'],
                'rsa_sign_ms': round(rsa_result['rsa_sign_ms'], 2),
                'rsa_verify_ms': round(rsa_result['rsa_verify_ms'], 2),
                'rsa_cpu_time': round(rsa_result['rsa_cpu_time'], 2),
                'rsa_memory_mb': round(rsa_result['rsa_memory_mb'], 2),
                'rsa_public_key_size': rsa_result['rsa_public_key_size'],
                'rsa_signature_size': rsa_result['rsa_signature_size'],
                'ecdsa_sign_ms': round(ecdsa_result['ecdsa_sign_ms'], 2),
                'ecdsa_verify_ms': round(ecdsa_result['ecdsa_verify_ms'], 2),
                'ecdsa_cpu_time': round(ecdsa_result['ecdsa_cpu_time'], 2),
                'ecdsa_memory_mb': round(ecdsa_result['ecdsa_memory_mb'], 2),
                'ecdsa_public_key_size': ecdsa_result['ecdsa_public_key_size'],
                'ecdsa_signature_size': ecdsa_result['ecdsa_signature_size'],
                'sign_ratio_rsa_ecdsa': round(sign_ratio, 2),
                'verify_ratio_rsa_ecdsa': round(verify_ratio, 2),
            }
            results.append(result_row)

        print()

    return results

# ============================================================================
# SAVE & GRAPH
# ============================================================================

def save_results(results):
    """Save results to CSV"""
    OUTPUT_DIR.mkdir(exist_ok=True)

    with open(CSV_PATH, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    print(f"✅ CSV saved: {CSV_PATH}\n")

def generate_graphs(results):
    """Generate comparison graphs + verification-time transaction scaling"""
    GRAPHS_DIR.mkdir(exist_ok=True)

    security_bits = [r['security_bits'] for r in results]
    rsa_sign = [r['rsa_sign_ms'] for r in results]
    ecdsa_sign = [r['ecdsa_sign_ms'] for r in results]
    rsa_verify = [r['rsa_verify_ms'] for r in results]
    ecdsa_verify = [r['ecdsa_verify_ms'] for r in results]
    rsa_cpu = [r['rsa_cpu_time'] for r in results]
    ecdsa_cpu = [r['ecdsa_cpu_time'] for r in results]
    rsa_mem = [r['rsa_memory_mb'] for r in results]
    ecdsa_mem = [r['ecdsa_memory_mb'] for r in results]
    rsa_key = [r['rsa_public_key_size'] / 1024 for r in results]  # KB
    ecdsa_key = [r['ecdsa_public_key_size'] / 1024 for r in results]
    rsa_sig = [r['rsa_signature_size'] for r in results]
    ecdsa_sig = [r['ecdsa_signature_size'] for r in results]

    x = range(len(security_bits))
    width = 0.35

    # 1. Signing Time
    plt.figure(figsize=(12, 6))
    plt.bar([i - width/2 for i in x], rsa_sign, width, label='RSA-PSS', alpha=0.8)
    plt.bar([i + width/2 for i in x], ecdsa_sign, width, label='ECDSA', alpha=0.8)
    plt.xlabel('Security Level (bits)')
    plt.ylabel('Sign Time (ms)')
    plt.title('Signing Time Comparison')
    plt.xticks(x, security_bits)
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'signing_time.png', dpi=150)
    plt.close()
    print("✅ signing_time.png")

    # 2. Verification Time (single-op)
    plt.figure(figsize=(12, 6))
    plt.bar([i - width/2 for i in x], rsa_verify, width, label='RSA-PSS', alpha=0.8)
    plt.bar([i + width/2 for i in x], ecdsa_verify, width, label='ECDSA', alpha=0.8)
    plt.xlabel('Security Level (bits)')
    plt.ylabel('Verify Time (ms)')
    plt.title('Verification Time Comparison (Single Operation)')
    plt.xticks(x, security_bits)
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'verification_time_single.png', dpi=150)
    plt.close()
    print("✅ verification_time_single.png")

    # 3. CPU Time
    plt.figure(figsize=(12, 6))
    plt.bar([i - width/2 for i in x], rsa_cpu, width, label='RSA-PSS', alpha=0.8)
    plt.bar([i + width/2 for i in x], ecdsa_cpu, width, label='ECDSA', alpha=0.8)
    plt.xlabel('Security Level (bits)')
    plt.ylabel('CPU Time (s)')
    plt.title('CPU Time Consumption')
    plt.xticks(x, security_bits)
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'cpu_time.png', dpi=150)
    plt.close()
    print("✅ cpu_time.png")

    # 4. Memory Usage
    plt.figure(figsize=(12, 6))
    plt.bar([i - width/2 for i in x], rsa_mem, width, label='RSA-PSS', alpha=0.8)
    plt.bar([i + width/2 for i in x], ecdsa_mem, width, label='ECDSA', alpha=0.8)
    plt.xlabel('Security Level (bits)')
    plt.ylabel('Peak Memory (MB)')
    plt.title('Memory Usage')
    plt.xticks(x, security_bits)
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'memory_usage.png', dpi=150)
    plt.close()
    print("✅ memory_usage.png")

    # 5. Public Key Size
    plt.figure(figsize=(12, 6))
    plt.bar([i - width/2 for i in x], rsa_key, width, label='RSA-PSS', alpha=0.8)
    plt.bar([i + width/2 for i in x], ecdsa_key, width, label='ECDSA', alpha=0.8)
    plt.xlabel('Security Level (bits)')
    plt.ylabel('Key Size (KB)')
    plt.title('Public Key Size Comparison')
    plt.xticks(x, security_bits)
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'key_size.png', dpi=150)
    plt.close()
    print("✅ key_size.png")

    # 6. Signature Size
    plt.figure(figsize=(12, 6))
    plt.bar([i - width/2 for i in x], rsa_sig, width, label='RSA-PSS', alpha=0.8)
    plt.bar([i + width/2 for i in x], ecdsa_sig, width, label='ECDSA', alpha=0.8)
    plt.xlabel('Security Level (bits)')
    plt.ylabel('Signature Size (bytes)')
    plt.title('Signature Size Comparison')
    plt.xticks(x, security_bits)
    plt.legend()
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'signature_size.png', dpi=150)
    plt.close()
    print("✅ signature_size.png")

    # 7. Verification Time (Transaction Scaling) + Ratio
    verify_ratios = [r['verify_ratio_rsa_ecdsa'] for r in results]
    for tx_count in TRANSACTION_COUNTS:
        rsa_verify_total = [v * tx_count for v in rsa_verify]  # ms
        ecdsa_verify_total = [v * tx_count for v in ecdsa_verify]  # ms

        fig, ax1 = plt.subplots(figsize=(12, 6))
        ax1.bar([i - width/2 for i in x], rsa_verify_total, width, label='RSA-PSS', alpha=0.8)
        ax1.bar([i + width/2 for i in x], ecdsa_verify_total, width, label='ECDSA', alpha=0.8)
        ax1.set_xlabel('Security Level (bits)')
        ax1.set_ylabel('Total Verify Time (ms)')
        ax1.set_title(f'Verification Time for {tx_count:,} Transactions')
        ax1.set_xticks(list(x))
        ax1.set_xticklabels(security_bits)
        ax1.grid(axis='y', alpha=0.3)

        ax2 = ax1.twinx()
        ax2.plot(list(x), verify_ratios, color='black', marker='o', label='RSA/ECDSA Ratio')
        ax2.set_ylabel('Verify Time Ratio (RSA / ECDSA)')

        lines_1, labels_1 = ax1.get_legend_handles_labels()
        lines_2, labels_2 = ax2.get_legend_handles_labels()
        ax1.legend(lines_1 + lines_2, labels_1 + labels_2, loc='upper left')

        plt.tight_layout()
        fname = GRAPHS_DIR / f'verification_time_{tx_count//1000}k.png'
        plt.savefig(fname, dpi=150)
        plt.close()
        print(f"✅ {fname.name}")

    # 8. Verification Ratio Summary (across transaction counts)
    plt.figure(figsize=(12, 6))
    for tx_count in TRANSACTION_COUNTS:
        plt.plot(security_bits, verify_ratios, marker='o', label=f'{tx_count//1000}k tx')
    plt.xlabel('Security Level (bits)')
    plt.ylabel('Verify Time Ratio (RSA / ECDSA)')
    plt.title('Verification Time Ratio Across Security Levels (All Tx Counts)')
    plt.xticks(security_bits)
    plt.grid(axis='y', alpha=0.3)
    plt.legend(ncol=3)
    plt.tight_layout()
    plt.savefig(GRAPHS_DIR / 'verification_ratio_summary.png', dpi=150)
    plt.close()
    print("✅ verification_ratio_summary.png")

    print(f"\n✅ All graphs saved to: {GRAPHS_DIR}\n")

def print_summary(results):
    """Print results summary"""
    print("=" * 80)
    print("📊 BENCHMARK RESULTS SUMMARY")
    print("=" * 80 + "\n")

    for r in results:
        print(f"🔐 Security {r['security_bits']}-bit: RSA-{r['rsa_key_size']} vs ECDSA-{r['ecdsa_curve']}")
        print(f"   {r['notes']}")
        print(f"   ┌─ Signing:")
        print(f"   │  RSA:   {r['rsa_sign_ms']:>7.2f}ms")
        print(f"   │  ECDSA: {r['ecdsa_sign_ms']:>7.2f}ms")
        print(f"   │  Ratio: {r['sign_ratio_rsa_ecdsa']:.1f}x")
        print(f"   ├─ Verification:")
        print(f"   │  RSA:   {r['rsa_verify_ms']:>7.2f}ms")
        print(f"   │  ECDSA: {r['ecdsa_verify_ms']:>7.2f}ms")
        print(f"   │  Ratio: {r['verify_ratio_rsa_ecdsa']:.1f}x")
        print(f"   ├─ Key Size:")
        print(f"   │  RSA:   {r['rsa_public_key_size']:>7d} bytes")
        print(f"   │  ECDSA: {r['ecdsa_public_key_size']:>7d} bytes")
        print(f"   └─ Signature Size:")
        print(f"      RSA:   {r['rsa_signature_size']:>7d} bytes")
        print(f"      ECDSA: {r['ecdsa_signature_size']:>7d} bytes")
        print()

if __name__ == '__main__':
    print(f"\n⏱️  Starting benchmark at {datetime.now()}\n")

    # Run benchmark
    results = run_benchmark()

    if results:
        # Save CSV
        save_results(results)

        # Generate graphs
        print("📊 Generating graphs...")
        generate_graphs(results)

        # Print summary
        print_summary(results)

        print("=" * 80)
        print(f"✅ Benchmark complete at {datetime.now()}")
        print(f"   CSV: {CSV_PATH}")
        print(f"   Graphs: {GRAPHS_DIR}")
        print("=" * 80)
    else:
        print("❌ Benchmark failed - no results")
        sys.exit(1)
