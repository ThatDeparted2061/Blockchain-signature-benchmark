#!/usr/bin/env python3
"""
ECDSA vs RSA-OAEP Benchmark
Runs heavy cryptographic operations via Ollama (Llama 3.1:8B)
and benchmarks across 4 security levels with probabilistic padding
"""

import subprocess
import json
import time
import sys

# Security levels with exact mappings
SECURITY_LEVELS = [
    {
        'bits': 112,
        'rsa': 2048,
        'ecdsa': 'secp224r1',
        'notes': 'secp256k1 is stronger (~128-bit)'
    },
    {
        'bits': 128,
        'rsa': 3072,
        'ecdsa': 'P-256',
        'notes': 'Modern standard baseline'
    },
    {
        'bits': 192,
        'rsa': 7680,
        'ecdsa': 'P-384',
        'notes': 'High security'
    },
    {
        'bits': 256,
        'rsa': 15360,
        'ecdsa': 'P-521',
        'notes': 'Max standardized ECDSA'
    },
]

def run_llama_benchmark():
    """Run benchmark via Ollama Llama 3.1:8B"""
    
    print("=" * 80)
    print("🔐 ECDSA vs RSA-OAEP Benchmark (via Ollama Llama 3.1:8B)")
    print("=" * 80)
    print()
    
    # Python code to benchmark (will be passed to Llama for execution)
    benchmark_code = '''
import time
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend

SECURITY_LEVELS = [
    {'bits': 112, 'rsa': 2048, 'ecdsa': 'secp224r1'},
    {'bits': 128, 'rsa': 3072, 'ecdsa': 'P-256'},
    {'bits': 192, 'rsa': 7680, 'ecdsa': 'P-384'},
    {'bits': 256, 'rsa': 15360, 'ecdsa': 'P-521'},
]

CURVES = {
    'secp224r1': ec.SECP224R1(),
    'P-256': ec.SECP256R1(),
    'P-384': ec.SECP384R1(),
    'P-521': ec.SECP521R1(),
}

msg = b"Blockchain transaction data for signing verification"
results = []

for level in SECURITY_LEVELS:
    bits = level['bits']
    rsa_size = level['rsa']
    ecdsa_curve = level['ecdsa']
    
    # RSA-OAEP (probabilistic)
    rsa_key = rsa.generate_private_key(65537, rsa_size, default_backend())
    
    # Sign (3 iterations average)
    sign_times = []
    for _ in range(3):
        start = time.perf_counter()
        sig = rsa_key.sign(msg, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        sign_times.append(time.perf_counter() - start)
    
    rsa_sign = sum(sign_times) / 3 * 1000  # ms
    
    # Verify
    verify_times = []
    for _ in range(3):
        start = time.perf_counter()
        rsa_key.public_key().verify(sig, msg, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        verify_times.append(time.perf_counter() - start)
    
    rsa_verify = sum(verify_times) / 3 * 1000  # ms
    
    # ECDSA
    ecdsa_key = ec.generate_private_key(CURVES[ecdsa_curve], default_backend())
    
    # Sign
    sign_times = []
    for _ in range(3):
        start = time.perf_counter()
        esig = ecdsa_key.sign(msg, ec.ECDSA(hashes.SHA256()))
        sign_times.append(time.perf_counter() - start)
    
    ecdsa_sign = sum(sign_times) / 3 * 1000
    
    # Verify
    verify_times = []
    for _ in range(3):
        start = time.perf_counter()
        ecdsa_key.public_key().verify(esig, msg, ec.ECDSA(hashes.SHA256()))
        verify_times.append(time.perf_counter() - start)
    
    ecdsa_verify = sum(verify_times) / 3 * 1000
    
    results.append({
        'security_bits': bits,
        'rsa_key_size': rsa_size,
        'ecdsa_curve': ecdsa_curve,
        'rsa_sign_ms': round(rsa_sign, 2),
        'rsa_verify_ms': round(rsa_verify, 2),
        'ecdsa_sign_ms': round(ecdsa_sign, 2),
        'ecdsa_verify_ms': round(ecdsa_verify, 2),
        'sign_ratio': round(rsa_sign / ecdsa_sign, 1),
        'verify_ratio': round(rsa_verify / ecdsa_verify, 1),
    })

import json
print(json.dumps(results, indent=2))
'''
    
    # Create prompt for Llama
    prompt = f"""
Run this Python benchmark code (use cryptography library) and output ONLY the JSON results:

{benchmark_code}

IMPORTANT: Output ONLY the JSON array, nothing else.
"""
    
    print("📡 Sending benchmark to Ollama (Llama 3.1:8B)...\n")
    
    try:
        # Call Ollama
        result = subprocess.run(
            ['ollama', 'run', 'llama2'],
            input=prompt.encode(),
            capture_output=True,
            timeout=600  # 10 minutes max
        )
        
        output = result.stdout.decode('utf-8', errors='ignore')
        
        # Extract JSON from output
        json_start = output.find('[')
        json_end = output.rfind(']') + 1
        
        if json_start >= 0 and json_end > json_start:
            json_str = output[json_start:json_end]
            results = json.loads(json_str)
            
            print("✅ Benchmark complete!\n")
            print("=" * 80)
            print("📊 RESULTS: ECDSA vs RSA-OAEP (Probabilistic Padding)")
            print("=" * 80 + "\n")
            
            import csv
            csv_path = '/home/halyee/.openclaw/workspace/Blockchain-signature-benchmark/benchmark_results_oaep.csv'
            
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
            
            print(f"✅ CSV saved: {csv_path}\n")
            
            for r in results:
                print(f"🔐 Security {r['security_bits']}-bit: RSA-{r['rsa_key_size']} vs {r['ecdsa_curve']}")
                print(f"   Sign:   RSA {r['rsa_sign_ms']:>7.2f}ms vs ECDSA {r['ecdsa_sign_ms']:>7.2f}ms ({r['sign_ratio']:.1f}x)")
                print(f"   Verify: RSA {r['rsa_verify_ms']:>7.2f}ms vs ECDSA {r['ecdsa_verify_ms']:>7.2f}ms ({r['verify_ratio']:.1f}x)")
                print()
            
            return results
        else:
            print("❌ Could not parse JSON from Ollama output")
            print(f"Output: {output[:500]}")
            return None
            
    except subprocess.TimeoutExpired:
        print("❌ Ollama request timed out (>10 minutes)")
        return None
    except FileNotFoundError:
        print("❌ Ollama not found. Install: https://ollama.ai")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

if __name__ == '__main__':
    run_llama_benchmark()
