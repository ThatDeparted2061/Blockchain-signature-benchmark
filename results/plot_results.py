import csv
import os
import matplotlib.pyplot as plt
import argparse


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', default='results/benchmark_results_comprehensive.csv')
    parser.add_argument('--outdir', default='results')
    args = parser.parse_args()

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

    # Key size (bits)
    rsa_key_sizes = [to_float(r['rsa_key_size']) for r in rows]
    ecdsa_key_sizes = rsa_key_sizes  # for plotting symmetry, labels suffice
    plt.figure(figsize=(10,6))
    plt.bar(labels, rsa_key_sizes, label='RSA key size (bits)')
    plt.ylabel('Key size (bits)')
    plt.title('RSA Key Sizes by Security Level')
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, 'key_sizes.png'))
    plt.close()

    # Signature size
    rsa_sig = [to_float(r['rsa_signature_size']) for r in rows]
    ecdsa_sig = [to_float(r['ecdsa_signature_size']) for r in rows]
    plot_bar(labels, rsa_sig, ecdsa_sig, 'Signature Size (bytes) by Security Level', 'Signature size (bytes)', os.path.join(args.outdir, 'signature_sizes.png'))

    # CPU time (signing) comparison
    rsa_sign_cpu = [to_float(r['rsa_sign_cpu_ms_median']) for r in rows]
    ecdsa_sign_cpu = [to_float(r['ecdsa_sign_cpu_ms_median']) for r in rows]
    plot_bar(labels, rsa_sign_cpu, ecdsa_sign_cpu, 'Signing CPU Time (ms) by Security Level', 'CPU ms', os.path.join(args.outdir, 'signing_cpu_time.png'))

    print('Saved graphs to', args.outdir)

if __name__ == '__main__':
    main()
