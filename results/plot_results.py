import csv
import os
import matplotlib.pyplot as plt
import argparse

VERIFICATION_COUNTS = [5000, 10000, 15000, 20000, 30000]
REFERENCE_COUNT = 25000
EPSILON = 1e-9


def read_csv(path):
    rows = []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def to_float(x):
    try:
        return float(x)
    except:
        return None


def plot_bar(x_labels, rsa_vals, ecdsa_vals, title, ylabel, out_path):
    x = range(len(x_labels))
    width = 0.35
    plt.figure(figsize=(10,6))
    plt.bar([i - width/2 for i in x], rsa_vals, width=width, label='RSA')
    plt.bar([i + width/2 for i in x], ecdsa_vals, width=width, label='ECDSA')
    plt.xticks(x, x_labels)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_lines(x_vals, rsa_vals, ecdsa_vals, title, ylabel, out_path):
    if any(val is None for val in rsa_vals + ecdsa_vals):
        return
    plt.figure(figsize=(10, 6))
    plt.plot(x_vals, rsa_vals, marker='o', label='RSA')
    plt.plot(x_vals, ecdsa_vals, marker='o', label='ECDSA')
    plt.xlabel('Verifications')
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def calculate_total_verification_seconds(median_ms, count):
    if median_ms is None:
        return None
    return (median_ms / 1000.0) * count


def calculate_verifications_per_second(median_ms, count):
    if median_ms is None or median_ms == 0:
        return None
    total_time = calculate_total_verification_seconds(median_ms, count)
    if total_time == 0:
        return None
    return count / total_time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', default='results/benchmark_results_comprehensive.csv')
    parser.add_argument('--outdir', default='results')
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    rows = read_csv(args.csv)
    if not rows:
        print('No rows found in', args.csv)
        return

    labels = [r.get('security_label') or r['security_bits'] for r in rows]

    # Signing time (wall)
    rsa_sign = [to_float(r['rsa_sign_wall_ms_median']) for r in rows]
    ecdsa_sign = [to_float(r['ecdsa_sign_wall_ms_median']) for r in rows]
    plot_bar(labels, rsa_sign, ecdsa_sign, 'Signing Time (ms) by Security Level', 'Signing time (ms)', os.path.join(args.outdir, 'signing_time.png'))

    # Verification time (wall)
    rsa_verify = [to_float(r['rsa_verify_wall_ms_median']) for r in rows]
    ecdsa_verify = [to_float(r['ecdsa_verify_wall_ms_median']) for r in rows]
    plot_bar(labels, rsa_verify, ecdsa_verify, 'Verification Time (ms) by Security Level', 'Verification time (ms)', os.path.join(args.outdir, 'verification_time.png'))

    # Key size (bits) and public key size (bytes)
    rsa_key_sizes = [to_float(r.get('rsa_key_size')) for r in rows]
    rsa_pub_sizes = [to_float(r.get('rsa_public_key_size')) for r in rows]
    ecdsa_pub_sizes = [to_float(r.get('ecdsa_public_key_size')) for r in rows]

    plt.figure(figsize=(10,6))
    plt.bar(labels, rsa_key_sizes, label='RSA key size (bits)')
    plt.ylabel('Key size (bits)')
    plt.title('RSA Key Sizes by Security Level')
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, 'key_sizes.png'))
    plt.close()

    # Public key sizes (bytes)
    plot_bar(labels, rsa_pub_sizes, ecdsa_pub_sizes, 'Public Key Size (bytes) by Security Level', 'Public key size (bytes)', os.path.join(args.outdir, 'public_key_sizes.png'))

    # Signature size
    rsa_sig = [to_float(r['rsa_signature_size']) for r in rows]
    ecdsa_sig = [to_float(r['ecdsa_signature_size']) for r in rows]
    plot_bar(labels, rsa_sig, ecdsa_sig, 'Signature Size (bytes) by Security Level', 'Signature size (bytes)', os.path.join(args.outdir, 'signature_sizes.png'))

    # CPU time (signing) comparison
    rsa_sign_cpu = [to_float(r['rsa_sign_cpu_ms_median']) for r in rows]
    ecdsa_sign_cpu = [to_float(r['ecdsa_sign_cpu_ms_median']) for r in rows]
    plot_bar(labels, rsa_sign_cpu, ecdsa_sign_cpu, 'Signing CPU Time (ms) by Security Level', 'CPU ms', os.path.join(args.outdir, 'signing_cpu_time.png'))

    # Verification scaling graphs (time + CPU) by security level
    for row in rows:
        security_bits = row['security_bits']
        rsa_verify_wall = to_float(row['rsa_verify_wall_ms_median'])
        ecdsa_verify_wall = to_float(row['ecdsa_verify_wall_ms_median'])
        rsa_verify_cpu = to_float(row['rsa_verify_cpu_ms_median'])
        ecdsa_verify_cpu = to_float(row['ecdsa_verify_cpu_ms_median'])

        rsa_verify_totals = [calculate_total_verification_seconds(rsa_verify_wall, count) for count in VERIFICATION_COUNTS]
        ecdsa_verify_totals = [calculate_total_verification_seconds(ecdsa_verify_wall, count) for count in VERIFICATION_COUNTS]
        plot_lines(
            VERIFICATION_COUNTS,
            rsa_verify_totals,
            ecdsa_verify_totals,
            f"Verification Time vs Verifications ({security_bits}-bit)",
            "Total verification time (s)",
            os.path.join(args.outdir, f"verification_time_{security_bits}bit.png"),
        )

        rsa_verify_cpu_totals = [calculate_total_verification_seconds(rsa_verify_cpu, count) for count in VERIFICATION_COUNTS]
        ecdsa_verify_cpu_totals = [calculate_total_verification_seconds(ecdsa_verify_cpu, count) for count in VERIFICATION_COUNTS]
        plot_lines(
            VERIFICATION_COUNTS,
            rsa_verify_cpu_totals,
            ecdsa_verify_cpu_totals,
            f"Verification CPU Time vs Verifications ({security_bits}-bit)",
            "Total verification CPU time (s)",
            os.path.join(args.outdir, f"verification_cpu_time_{security_bits}bit.png"),
        )

    # Verification speed comparison for 25k verifications across security levels
    rsa_speed_25k = [calculate_verifications_per_second(to_float(r['rsa_verify_wall_ms_median']), REFERENCE_COUNT) for r in rows]
    ecdsa_speed_25k = [calculate_verifications_per_second(to_float(r['ecdsa_verify_wall_ms_median']), REFERENCE_COUNT) for r in rows]
    ratio_labels = []
    for security_label, rsa_speed, ecdsa_speed in zip(labels, rsa_speed_25k, ecdsa_speed_25k):
        if rsa_speed is None or ecdsa_speed is None or ecdsa_speed <= EPSILON:
            ratio_label = "R/E N/A"
        else:
            ratio_label = f"R/E {rsa_speed / ecdsa_speed:.2f}x"
        ratio_labels.append(f"{security_label}\n{ratio_label}")
    plt.figure(figsize=(10, 7))
    x = range(len(labels))
    width = 0.35
    plt.bar([i - width / 2 for i in x], rsa_speed_25k, width=width, label='RSA')
    plt.bar([i + width / 2 for i in x], ecdsa_speed_25k, width=width, label='ECDSA')
    plt.xticks(x, ratio_labels)
    plt.ylabel("Verifications per second")
    plt.title(f"Verification Speed for {REFERENCE_COUNT} Verifications (verifications/sec) by Security Level")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, f"verification_speed_{REFERENCE_COUNT}.png"))
    plt.close()

    print('Saved graphs to', args.outdir)

if __name__ == '__main__':
    main()
