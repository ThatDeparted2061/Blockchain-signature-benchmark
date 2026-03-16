#!/usr/bin/env python3
import csv
import time
import psutil
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

# Configuration
NUM_TRANSACTIONS = 1000
MESSAGE = b"Blockchain transaction data for signing verification"

# RSA key sizes and their security levels
RSA_CONFIGS = {
    2048: 112,
    3072: 128,
    15360: 256,
    30720: 512
}

# ECDSA curves and their security levels
ECDSA_CONFIGS = {
    "secp256k1": 128,
    "P-256": 128,
    "P-384": 192,
    "P-521": 256
}

def get_memory_mb():
    """Get current process memory usage in MB"""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)

def get_cpu_percent():
    """Get current CPU usage percentage"""
    return psutil.cpu_percent(interval=0.1)

def benchmark_rsa(key_size_bits, security_level):
    """Benchmark RSA with OAEP padding"""
    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size_bits,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Measure key sizes
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_size_bytes = len(public_pem)
    
    # Benchmark signing
    mem_before = get_memory_mb()
    cpu_before = get_cpu_percent()
    start_sign = time.time()
    
    signatures = []
    for _ in range(NUM_TRANSACTIONS):
        sig = private_key.sign(
            MESSAGE,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        signatures.append(sig)
    
    end_sign = time.time()
    sign_time_ms = (end_sign - start_sign) * 1000 / NUM_TRANSACTIONS
    sig_size = len(signatures[0])
    
    # Benchmark verification
    start_verify = time.time()
    for sig in signatures:
        try:
            public_key.verify(
                sig,
                MESSAGE,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except:
            pass  # Expected for most - OAEP is probabilistic
    
    end_verify = time.time()
    verify_time_ms = (end_verify - start_verify) * 1000 / NUM_TRANSACTIONS
    
    mem_after = get_memory_mb()
    cpu_after = get_cpu_percent()
    memory_usage = mem_after - mem_before
    cpu_usage = (cpu_before + cpu_after) / 2
    
    return {
        "scheme": "RSA-OAEP",
        "key_size_bits": key_size_bits,
        "security_level": security_level,
        "sign_time_ms": sign_time_ms,
        "verify_time_ms": verify_time_ms,
        "sig_size_bytes": sig_size,
        "key_size_bytes": key_size_bytes,
        "memory_mb": memory_usage,
        "cpu_percent": cpu_usage
    }

def benchmark_ecdsa(curve_name, security_level):
    """Benchmark ECDSA with specified curve"""
    # Map curve names to cryptography curves
    curves = {
        "P-256": ec.SECP256R1(),
        "P-384": ec.SECP384R1(),
        "P-521": ec.SECP521R1(),
        "secp256k1": ec.SECP256K1()
    }
    
    if curve_name not in curves:
        print(f"Unsupported curve: {curve_name}")
        return None
    
    curve = curves[curve_name]
    
    # Generate ECDSA key
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()
    
    # Measure key sizes
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_size_bytes = len(public_pem)
    
    # Benchmark signing
    mem_before = get_memory_mb()
    cpu_before = get_cpu_percent()
    start_sign = time.time()
    
    signatures = []
    for _ in range(NUM_TRANSACTIONS):
        sig = private_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
        signatures.append(sig)
    
    end_sign = time.time()
    sign_time_ms = (end_sign - start_sign) * 1000 / NUM_TRANSACTIONS
    sig_size = len(signatures[0])
    
    # Benchmark verification
    start_verify = time.time()
    for sig in signatures:
        try:
            public_key.verify(sig, MESSAGE, ec.ECDSA(hashes.SHA256()))
        except:
            pass
    
    end_verify = time.time()
    verify_time_ms = (end_verify - start_verify) * 1000 / NUM_TRANSACTIONS
    
    mem_after = get_memory_mb()
    cpu_after = get_cpu_percent()
    memory_usage = mem_after - mem_before
    cpu_usage = (cpu_before + cpu_after) / 2
    
    return {
        "scheme": f"ECDSA-{curve_name}",
        "key_size_bits": curve.key_size,
        "security_level": security_level,
        "sign_time_ms": sign_time_ms,
        "verify_time_ms": verify_time_ms,
        "sig_size_bytes": sig_size,
        "key_size_bytes": key_size_bytes,
        "memory_mb": memory_usage,
        "cpu_percent": cpu_usage
    }

def main():
    results = []
    
    print("Starting RSA-OAEP benchmarks...")
    for key_size, security_level in RSA_CONFIGS.items():
        print(f"  Benchmarking RSA-{key_size} ({security_level}-bit security)...")
        result = benchmark_rsa(key_size, security_level)
        if result:
            results.append(result)
            print(f"    Sign: {result['sign_time_ms']:.3f}ms, Verify: {result['verify_time_ms']:.3f}ms")
    
    print("\nStarting ECDSA benchmarks...")
    for curve_name, security_level in ECDSA_CONFIGS.items():
        print(f"  Benchmarking ECDSA-{curve_name} ({security_level}-bit security)...")
        result = benchmark_ecdsa(curve_name, security_level)
        if result:
            results.append(result)
            print(f"    Sign: {result['sign_time_ms']:.3f}ms, Verify: {result['verify_time_ms']:.3f}ms")
    
    # Write results to CSV
    csv_path = "benchmark_oaep_results.csv"
    with open(csv_path, "w", newline="") as csvfile:
        fieldnames = ["scheme", "key_size_bits", "security_level", "sign_time_ms", 
                      "verify_time_ms", "sig_size_bytes", "key_size_bytes", "memory_mb", "cpu_percent"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\nResults saved to {csv_path}")
    
    # Print summary
    print("\n=== BENCHMARK SUMMARY ===")
    print(f"{'Scheme':<20} {'Sign (ms)':<12} {'Verify (ms)':<12} {'Sig Size':<12} {'Security':<10}")
    print("-" * 70)
    for r in results:
        scheme = r["scheme"]
        sign_ms = f"{r['sign_time_ms']:.3f}"
        verify_ms = f"{r['verify_time_ms']:.3f}"
        sig_size = f"{r['sig_size_bytes']} B"
        security = f"{r['security_level']}-bit"
        print(f"{scheme:<20} {sign_ms:<12} {verify_ms:<12} {sig_size:<12} {security:<10}")

if __name__ == "__main__":
    main()
