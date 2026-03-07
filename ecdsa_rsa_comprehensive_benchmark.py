import time
import csv
import tracemalloc
import os
import sys
import psutil
from memory_profiler import memory_usage
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import matplotlib.pyplot as plt
from math import ceil

# Ensure we are running in the workspace/venv env
dir_path = os.path.dirname(os.path.realpath(__file__))
venv_python = os.path.join(dir_path, "Blockchain-signature-benchmark/venv/bin/python")
if sys.executable != venv_python and os.path.exists(venv_python):
    os.execv(venv_python, [venv_python, __file__])

# (Security Level, RSA bits, ECDSA Curve, ECDSA Curve Name)
SECURITY_LEVELS = [
    ("112-bit", 2048, ec.SECP224R1(), "secp224r1"),
    ("128-bit", 3072, ec.SECP256R1(), "P-256"),
    ("192-bit", 7680, ec.SECP384R1(), "P-384"),
    ("256-bit", 15360, ec.SECP521R1(), "P-521"),
    ("512-bit", 30720, ec.SECP521R1(), "P-521 (high)")
]

MESSAGE = b"Benchmark message for digital signature performance test." * 3
ITER = 3 # repeat sign & verify for timing avg

results = [
    [
        "Security Level", "RSA Bits", "ECDSA Curve", "rsa_public_key_size", "ecdsa_public_key_size", "Sign Time RSA (ms)", "Sign Time ECDSA (ms)", "Verify Time RSA (ms)", "Verify Time ECDSA (ms)", "CPU Time RSA (s)", "CPU Time ECDSA (s)", "Peak Mem RSA (MB)", "Peak Mem ECDSA (MB)", "Key Size RSA (bytes)", "Key Size ECDSA (bytes)", "Sig Size RSA (bytes)", "Sig Size ECDSA (bytes)", "Sign Ratio (RSA/ECDSA)", "Verify Ratio (RSA/ECDSA)"
    ]
]

def measure_peak_memory(func, *args, **kwargs):
    mem, ret = None, None
    def wrapper():
        nonlocal ret
        ret = func(*args, **kwargs)
        return ret
    mem = max(memory_usage(wrapper, interval=0.01, timeout=30))
    return ret, mem

def rsa_oaep_sign(privkey, message):
    # OAEP is an encryption scheme; RSA signatures use PKCS1v15 or PSS.
    # We'll use PSS, as OAEP is not standard for signatures!
    return privkey.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_oaep_verify(pubkey, signature, message):
    try:
        pubkey.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def bench_signature(security_label, rsa_bits, ecdsa_curve, curve_name):
    # RSA Keygen
    rsa_private, rsa_public = None, None
    t0 = time.perf_counter()
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    rsa_public = rsa_private.public_key()
    kgen_rsa_time = time.perf_counter() - t0

    # ECDSA Keygen
    t0 = time.perf_counter()
    ecdsa_private = ec.generate_private_key(ecdsa_curve)
    ecdsa_public = ecdsa_private.public_key()
    kgen_ecdsa_time = time.perf_counter() - t0

    # Serialize keys for size
    rsa_pub_bytes = rsa_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ecdsa_pub_bytes = ecdsa_public.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    rsa_key_size = len(rsa_pub_bytes)
    ecdsa_key_size = len(ecdsa_pub_bytes)

    # Measure signature size
    rsa_sig = rsa_oaep_sign(rsa_private, MESSAGE)
    ecdsa_sig = ecdsa_private.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
    rsa_sig_size = len(rsa_sig)
    ecdsa_sig_size = len(ecdsa_sig)

    # Sign timings and memory:
    rsa_sign_times, ecdsa_sign_times = [], []
    rsa_cpu_times, ecdsa_cpu_times = [], []
    for i in range(ITER):
        p = psutil.Process()
        t0 = time.perf_counter(); cpu0 = p.cpu_times().user
        _, mem_rsa = measure_peak_memory(rsa_oaep_sign, rsa_private, MESSAGE)
        t1 = time.perf_counter(); cpu1 = p.cpu_times().user
        rsa_sign_times.append((t1-t0)*1e3)
        rsa_cpu_times.append(cpu1-cpu0)

        t0 = time.perf_counter(); cpu0 = p.cpu_times().user
        _, mem_ecdsa = measure_peak_memory(lambda: ecdsa_private.sign(MESSAGE, ec.ECDSA(hashes.SHA256())))
        t1 = time.perf_counter(); cpu1 = p.cpu_times().user
        ecdsa_sign_times.append((t1-t0)*1e3)
        ecdsa_cpu_times.append(cpu1-cpu0)

    avg_rsa_sign = sum(rsa_sign_times)/ITER
    avg_ecdsa_sign = sum(ecdsa_sign_times)/ITER
    cpu_rsa = sum(rsa_cpu_times)/ITER
    cpu_ecdsa = sum(ecdsa_cpu_times)/ITER
    # Memory: use the larger of the 3 runs
    rsa_mem_max = mem_rsa
    ecdsa_mem_max = mem_ecdsa

    # Verify timings
    rsa_verify_times, ecdsa_verify_times = [], []
    rsa_cpu_verify, ecdsa_cpu_verify = [], []
    for i in range(ITER):
        p = psutil.Process()
        t0 = time.perf_counter(); cpu0 = p.cpu_times().user
        _, mem_v_rsa = measure_peak_memory(rsa_oaep_verify, rsa_public, rsa_sig, MESSAGE)
        t1 = time.perf_counter(); cpu1 = p.cpu_times().user
        rsa_verify_times.append((t1-t0)*1e3)
        rsa_cpu_verify.append(cpu1-cpu0)

        t0 = time.perf_counter(); cpu0 = p.cpu_times().user
        def ecdsa_verify():
            try:
                ecdsa_public.verify(ecdsa_sig, MESSAGE, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                return False
        _, mem_v_ecdsa = measure_peak_memory(ecdsa_verify)
        t1 = time.perf_counter(); cpu1 = p.cpu_times().user
        ecdsa_verify_times.append((t1-t0)*1e3)
        ecdsa_cpu_verify.append(cpu1-cpu0)

    avg_rsa_verify = sum(rsa_verify_times)/ITER
    avg_ecdsa_verify = sum(ecdsa_verify_times)/ITER
    cpu_rsa_v = sum(rsa_cpu_verify)/ITER
    cpu_ecdsa_v = sum(ecdsa_cpu_verify)/ITER
    rsa_mem_max = max(rsa_mem_max, mem_v_rsa)
    ecdsa_mem_max = max(ecdsa_mem_max, mem_v_ecdsa)

    sign_ratio = avg_rsa_sign/avg_ecdsa_sign if avg_ecdsa_sign else float('inf')
    verify_ratio = avg_rsa_verify/avg_ecdsa_verify if avg_ecdsa_verify else float('inf')

    results.append([
        security_label, rsa_bits, curve_name,
        rsa_key_size, ecdsa_key_size,
        round(avg_rsa_sign, 2), round(avg_ecdsa_sign, 2), round(avg_rsa_verify, 2), round(avg_ecdsa_verify, 2),
        round(cpu_rsa, 4), round(cpu_ecdsa, 4), round(rsa_mem_max, 2), round(ecdsa_mem_max, 2),
        rsa_key_size, ecdsa_key_size, rsa_sig_size, ecdsa_sig_size,
        round(sign_ratio, 2), round(verify_ratio, 2)
    ])

# Main benchmark loop
for security_label, rsa_bits, ecdsa_curve, curve_name in SECURITY_LEVELS:
    bench_signature(security_label, rsa_bits, ecdsa_curve, curve_name)

with open("Blockchain-signature-benchmark/benchmark_results_comprehensive.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerows(results)

# Load data for plotting
import pandas as pd
df = pd.read_csv("Blockchain-signature-benchmark/benchmark_results_comprehensive.csv")
x_labels = df["Security Level"].to_list()

# ------ GRAPHS ------

os.makedirs("Blockchain-signature-benchmark/graphs", exist_ok=True)
def bar_dual(y1, y2, ylbl, fname, legend=("RSA", "ECDSA")):
    width = 0.35
    x = range(len(x_labels))
    plt.figure(figsize=(8,5))
    plt.bar([i-width/2 for i in x], y1, width, label=legend[0])
    plt.bar([i+width/2 for i in x], y2, width, label=legend[1])
    plt.xticks(list(x), x_labels, rotation=16)
    plt.ylabel(ylbl)
    plt.xlabel("Security Level")
    plt.title(f"{ylbl} vs Security Level")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"Blockchain-signature-benchmark/graphs/{fname}")
    plt.close()

bar_dual(df["Sign Time RSA (ms)"], df["Sign Time ECDSA (ms)"], "Signing Time (ms)", "signing_time.png")
bar_dual(df["Verify Time RSA (ms)"], df["Verify Time ECDSA (ms)"], "Verification Time (ms)", "verification_time.png")
bar_dual(df["CPU Time RSA (s)"], df["CPU Time ECDSA (s)"], "CPU Time (s)", "cpu_time.png")
bar_dual(df["Peak Mem RSA (MB)"], df["Peak Mem ECDSA (MB)"], "Peak Memory (MB)", "memory_usage.png")
bar_dual(df["Key Size RSA (bytes)"], df["Key Size ECDSA (bytes)"], "Public Key Size (bytes)", "key_size.png")
bar_dual(df["Sig Size RSA (bytes)"], df["Sig Size ECDSA (bytes)"], "Signature Size (bytes)", "signature_size.png")

print("=== Benchmark Results Summary ===")
for row in results[1:]:
    print(f"{row[0]} | RSA-{row[1]} vs {row[2]} | Sign (ms): {row[3]:.2f} vs {row[4]:.2f} | Verify (ms): {row[5]:.2f} vs {row[6]:.2f} | Key size: {row[11]} vs {row[12]} | Sig size: {row[13]} vs {row[14]}")
print(f"\nFull CSV: Blockchain-signature-benchmark/benchmark_results_comprehensive.csv\nGraphs in Blockchain-signature-benchmark/graphs/")
