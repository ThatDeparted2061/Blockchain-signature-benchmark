import time
import csv
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils

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

def benchmark_rsa(rsa_key_size, message):
    priv_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=rsa_key_size,
        backend=default_backend()
    )
    pub_key = priv_key.public_key()

    # RSA-OAEP Signing (actually using RSA-PSS, as OAEP is for encryption, but task wants OAEP for sign/verify)
    # For signature, use RSASSA-PSS, which is the standard secure scheme. OAEP is for encryption not signing.
    # For best alignment, note in sheet as RSA-OAEP/PSS

    sign_times = []
    for _ in range(3):
        start = time.time()
        signature = priv_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        sign_times.append((time.time() - start) * 1000)
    avg_sign = sum(sign_times) / len(sign_times)

    verify_times = []
    signature = priv_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    for _ in range(3):
        start = time.time()
        pub_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verify_times.append((time.time() - start) * 1000)
    avg_verify = sum(verify_times) / len(verify_times)

    return avg_sign, avg_verify

def benchmark_ecdsa(curve, message):
    priv_key = ec.generate_private_key(curve, default_backend())
    pub_key = priv_key.public_key()

    sign_times = []
    for _ in range(3):
        start = time.time()
        signature = priv_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        sign_times.append((time.time() - start) * 1000)
    avg_sign = sum(sign_times) / len(sign_times)

    verify_times = []
    signature = priv_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    for _ in range(3):
        start = time.time()
        pub_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        verify_times.append((time.time() - start) * 1000)
    avg_verify = sum(verify_times) / len(verify_times)

    return avg_sign, avg_verify

def main():
    results = []
    message = b'benchmark-test-message'
    for level in security_levels:
        rsa_sign_ms, rsa_verify_ms = benchmark_rsa(level['rsa_key_size'], message)
        ecdsa_sign_ms, ecdsa_verify_ms = benchmark_ecdsa(level['ecdsa_curve'], message)
        sign_ratio = rsa_sign_ms / ecdsa_sign_ms if ecdsa_sign_ms else 0
        verify_ratio = rsa_verify_ms / ecdsa_verify_ms if ecdsa_verify_ms else 0
        results.append([
            level['security_bits'],
            level['rsa_key_size'],
            level['ecdsa_curve'].name,
            round(rsa_sign_ms, 3),
            round(rsa_verify_ms, 3),
            round(ecdsa_sign_ms, 3),
            round(ecdsa_verify_ms, 3),
            round(sign_ratio, 3),
            round(verify_ratio, 3)
        ])
    with open('Blockchain-signature-benchmark/benchmark_results_comprehensive.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'security_bits', 'rsa_key_size', 'ecdsa_curve',
            'rsa_sign_ms', 'rsa_verify_ms', 'ecdsa_sign_ms', 'ecdsa_verify_ms',
            'sign_ratio', 'verify_ratio'
        ])
        writer.writerows(results)

if __name__ == "__main__":
    main()
