import time
import csv
import argparse
import resource
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

security_levels = [
    {
        'security_bits': 112,
        'rsa_key_size': 2048,
        'ecdsa_curve': ec.SECP224R1(),
    },
    {
        'security_bits': 128,
        'rsa_key_size': 3072,
        'ecdsa_curve': ec.SECP256R1(),
    },
    {
        'security_bits': 192,
        'rsa_key_size': 7680,
        'ecdsa_curve': ec.SECP384R1(),
    },
    {
        'security_bits': 256,
        'rsa_key_size': 15360,
        'ecdsa_curve': ec.SECP521R1(),
    },
]


def measure_memory_cpu(func, *args, **kwargs):
    """Run func and return (wall_ms, cpu_ms, peak_rss_kb, result, extra)"""
    start_wall = time.time()
    start_cpu = time.process_time()
    result = func(*args, **kwargs)
    end_cpu = time.process_time()
    end_wall = time.time()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # ru_maxrss is in kilobytes on Linux
    peak_rss = usage.ru_maxrss
    wall_ms = (end_wall - start_wall) * 1000
    cpu_ms = (end_cpu - start_cpu) * 1000
    return wall_ms, cpu_ms, peak_rss, result


def rsa_generate_sign_verify(rsa_key_size, message):
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=rsa_key_size,
        backend=default_backend()
    )
    pub_key = priv_key.public_key()

    signature = priv_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # verify once to ensure correctness
    pub_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    pub_der = pub_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_size = len(pub_der)
    return priv_key, pub_key, signature, pub_size


def ecdsa_generate_sign_verify(curve, message):
    priv_key = ec.generate_private_key(curve, default_backend())
    pub_key = priv_key.public_key()
    signature = priv_key.sign(message, ec.ECDSA(hashes.SHA256()))
    pub_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    pub_der = pub_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_size = len(pub_der)
    return priv_key, pub_key, signature, pub_size


def benchmark_rsa(rsa_key_size, message, warmups=1, iterations=3):
    # keygen measurement
    wall_k, cpu_k, peak_k, priv_pub_sig = measure_memory_cpu(lambda: rsa_generate_sign_verify(rsa_key_size, message))
    priv_key, pub_key, signature_example, pub_size = priv_pub_sig
    sig_len = len(signature_example)
    pub_bytes = pub_key.public_bytes

    # warmups
    for _ in range(warmups):
        priv_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

    sign_ws = []
    sign_cps = []
    verify_ws = []
    verify_cps = []
    for _ in range(iterations):
        w_s, c_s, p_s, sig = measure_memory_cpu(lambda: priv_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))
        sign_ws.append(w_s); sign_cps.append(c_s)
        w_v, c_v, p_v, _ = measure_memory_cpu(lambda: pub_key.verify(sig, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()))
        verify_ws.append(w_v); verify_cps.append(c_v)

    return {
        'key_size_bits': rsa_key_size,
        'keygen_wall_ms': round(wall_k, 3),
        'keygen_cpu_ms': round(cpu_k, 3),
        'sign_wall_ms_median': round(median(sign_ws), 3),
        'sign_cpu_ms_median': round(median(sign_cps), 3),
        'verify_wall_ms_median': round(median(verify_ws), 3),
        'verify_cpu_ms_median': round(median(verify_cps), 3),
        'signature_size_bytes': sig_len,
        'public_key_size_bytes': pub_size,
        'peak_rss_kb': peak_k
    }


def benchmark_ecdsa(curve, message, warmups=1, iterations=3):
    wall_k, cpu_k, peak_k, priv_pub_sig = measure_memory_cpu(lambda: ecdsa_generate_sign_verify(curve, message))
    priv_key, pub_key, signature_example, pub_size = priv_pub_sig
    sig_len = len(signature_example)

    for _ in range(warmups):
        priv_key.sign(message, ec.ECDSA(hashes.SHA256()))

    sign_ws = []
    sign_cps = []
    verify_ws = []
    verify_cps = []
    for _ in range(iterations):
        w_s, c_s, p_s, sig = measure_memory_cpu(lambda: priv_key.sign(message, ec.ECDSA(hashes.SHA256())))
        sign_ws.append(w_s); sign_cps.append(c_s)
        w_v, c_v, p_v, _ = measure_memory_cpu(lambda: pub_key.verify(sig, message, ec.ECDSA(hashes.SHA256())))
        verify_ws.append(w_v); verify_cps.append(c_v)

    return {
        'curve': curve.name,
        'keygen_wall_ms': round(wall_k, 3),
        'keygen_cpu_ms': round(cpu_k, 3),
        'sign_wall_ms_median': round(median(sign_ws), 3),
        'sign_cpu_ms_median': round(median(sign_cps), 3),
        'verify_wall_ms_median': round(median(verify_ws), 3),
        'verify_cpu_ms_median': round(median(verify_cps), 3),
        'signature_size_bytes': sig_len,
        'public_key_size_bytes': pub_size,
        'peak_rss_kb': peak_k
    }


# small helper median

def median(lst):
    if not lst:
        return 0
    s = sorted(lst)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return s[mid]
    return (s[mid - 1] + s[mid]) / 2


def main():
    parser = argparse.ArgumentParser(description='ECDSA vs RSA benchmark (comprehensive)')
    parser.add_argument('--warmup', type=int, default=1, help='Warm-up iterations')
    parser.add_argument('--iters', type=int, default=3, help='Measured iterations')
    parser.add_argument('--max-rsa', type=int, default=15360, help='Maximum RSA key size to test')
    parser.add_argument('--out', type=str, default='results/benchmark_results_comprehensive.csv', help='CSV output path')
    args = parser.parse_args()

    results = []
    message = b'benchmark-test-message'
    for level in security_levels:
        if level['rsa_key_size'] > args.max_rsa:
            continue
        rsa_metrics = benchmark_rsa(level['rsa_key_size'], message, warmups=args.warmup, iterations=args.iters)
        ecdsa_metrics = benchmark_ecdsa(level['ecdsa_curve'], message, warmups=args.warmup, iterations=args.iters)

        results.append({
            'security_bits': level['security_bits'],
            'rsa_key_size': rsa_metrics['key_size_bits'],
            'ecdsa_curve': ecdsa_metrics['curve'],
            'rsa_public_key_size': rsa_metrics.get('public_key_size_bytes'),
            'rsa_keygen_wall_ms': rsa_metrics['keygen_wall_ms'],
            'rsa_keygen_cpu_ms': rsa_metrics['keygen_cpu_ms'],
            'rsa_sign_wall_ms_median': rsa_metrics['sign_wall_ms_median'],
            'rsa_sign_cpu_ms_median': rsa_metrics['sign_cpu_ms_median'],
            'rsa_verify_wall_ms_median': rsa_metrics['verify_wall_ms_median'],
            'rsa_verify_cpu_ms_median': rsa_metrics['verify_cpu_ms_median'],
            'rsa_signature_size': rsa_metrics['signature_size_bytes'],
            'rsa_peak_rss_kb': rsa_metrics['peak_rss_kb'],
            'ecdsa_keygen_wall_ms': ecdsa_metrics['keygen_wall_ms'],
            'ecdsa_keygen_cpu_ms': ecdsa_metrics['keygen_cpu_ms'],
            'ecdsa_public_key_size': ecdsa_metrics.get('public_key_size_bytes'),
            'ecdsa_sign_wall_ms_median': ecdsa_metrics['sign_wall_ms_median'],
            'ecdsa_sign_cpu_ms_median': ecdsa_metrics['sign_cpu_ms_median'],
            'ecdsa_verify_wall_ms_median': ecdsa_metrics['verify_wall_ms_median'],
            'ecdsa_verify_cpu_ms_median': ecdsa_metrics['verify_cpu_ms_median'],
            'ecdsa_signature_size': ecdsa_metrics['signature_size_bytes'],
            'ecdsa_peak_rss_kb': ecdsa_metrics['peak_rss_kb'],
        })

    # write CSV
    keys = ['security_bits','rsa_key_size','ecdsa_curve',
            'rsa_keygen_wall_ms','rsa_keygen_cpu_ms','rsa_sign_wall_ms_median','rsa_sign_cpu_ms_median','rsa_verify_wall_ms_median','rsa_verify_cpu_ms_median','rsa_signature_size','rsa_peak_rss_kb',
            'ecdsa_keygen_wall_ms','ecdsa_keygen_cpu_ms','ecdsa_sign_wall_ms_median','ecdsa_sign_cpu_ms_median','ecdsa_verify_wall_ms_median','ecdsa_verify_cpu_ms_median','ecdsa_signature_size','ecdsa_peak_rss_kb']
    with open(args.out, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            writer.writerow(r)

    print(f"Wrote results to {args.out}")


if __name__ == "__main__":
    main()
