import csv
import os
import matplotlib.pyplot as plt
import argparse

VERIFICATION_COUNTS = [5000, 10000, 15000, 20000, 30000]
SPEED_COUNT = 25000


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


def total_seconds(median_ms, count):
    if median_ms is None:
        return None
    return (median_ms / 1000.0) * count


def verification_speed(median_ms):
    if median_ms is None or median_ms == 0:
        return None
    return 1000.0 / median_ms


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

    labels = [r['security_bits'] for r in rows]

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

        rsa_verify_totals = [total_seconds(rsa_verify_wall, count) for count in VERIFICATION_COUNTS]
        ecdsa_verify_totals = [total_seconds(ecdsa_verify_wall, count) for count in VERIFICATION_COUNTS]
        plot_lines(
            VERIFICATION_COUNTS,
            rsa_verify_totals,
            ecdsa_verify_totals,
            f"Verification Time vs Verifications ({security_bits}-bit)",
            "Total verification time (s)",
            os.path.join(args.outdir, f"verification_time_{security_bits}bit.png"),
        )

        rsa_verify_cpu_totals = [total_seconds(rsa_verify_cpu, count) for count in VERIFICATION_COUNTS]
        ecdsa_verify_cpu_totals = [total_seconds(ecdsa_verify_cpu, count) for count in VERIFICATION_COUNTS]
        plot_lines(
            VERIFICATION_COUNTS,
            rsa_verify_cpu_totals,
            ecdsa_verify_cpu_totals,
            f"Verification CPU Time vs Verifications ({security_bits}-bit)",
            "Total verification CPU time (s)",
            os.path.join(args.outdir, f"verification_cpu_time_{security_bits}bit.png"),
        )

    # Verification speed comparison for 25k verifications across security levels
    rsa_speed_25k = [verification_speed(to_float(r['rsa_verify_wall_ms_median'])) for r in rows]
    ecdsa_speed_25k = [verification_speed(to_float(r['ecdsa_verify_wall_ms_median'])) for r in rows]
    ratio_labels = []
    for security_bits, rsa_speed, ecdsa_speed in zip(labels, rsa_speed_25k, ecdsa_speed_25k):
        if rsa_speed is None or ecdsa_speed is None:
            ratio_label = "R/E N/A"
        else:
            ratio_label = f"R/E {rsa_speed / ecdsa_speed:.2f}x"
        ratio_labels.append(f"{security_bits}\n{ratio_label}")
    plt.figure(figsize=(10, 7))
    x = range(len(labels))
    width = 0.35
    plt.bar([i - width / 2 for i in x], rsa_speed_25k, width=width, label='RSA')
    plt.bar([i + width / 2 for i in x], ecdsa_speed_25k, width=width, label='ECDSA')
    plt.xticks(x, ratio_labels)
    plt.ylabel("Verifications per second")
    plt.title(f"Verification Speed for {SPEED_COUNT} Verifications by Security Level")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, f"verification_speed_{SPEED_COUNT}.png"))
    plt.close()

    print('Saved graphs to', args.outdir)

if __name__ == '__main__':
    main()
