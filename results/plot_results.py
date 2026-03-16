import argparse
import csv
import os

import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Transaction counts used for scaling analyses.
OPERATION_COUNTS = [5000, 10000, 15000, 20000, 25000, 30000]
REFERENCE_COUNT = 25000
EPSILON = 1e-9
ANNOTATION_OFFSET_SMALL = 8
ANNOTATION_OFFSET_LARGE = 14
DEFAULT_OUTDIR = os.path.join('results', 'benchmark_results')


def read_csv(path):
    rows = []
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def pick_value(row, *keys):
    for key in keys:
        value = row.get(key)
        if value not in (None, ''):
            return value
    return None


def normalize_memory_mb(row, mb_key, kb_key):
    mb_value = to_float(row.get(mb_key))
    if mb_value is not None:
        return mb_value
    kb_value = to_float(row.get(kb_key))
    if kb_value is not None:
        return kb_value / 1024.0
    return None


def normalize_rows(rows):
    normalized = []
    for row in rows:
        security_bits_value = pick_value(row, 'security_bits')
        if security_bits_value is None:
            continue
        security_bits = int(float(security_bits_value))
        label = row.get('security_label') or str(security_bits)
        normalized.append({
            'security_bits': security_bits,
            'security_label': label,
            'rsa_sign_ms': to_float(pick_value(row, 'rsa_sign_ms', 'rsa_sign_wall_ms_median')),
            'ecdsa_sign_ms': to_float(pick_value(row, 'ecdsa_sign_ms', 'ecdsa_sign_wall_ms_median')),
            'rsa_verify_ms': to_float(pick_value(row, 'rsa_verify_ms', 'rsa_verify_wall_ms_median')),
            'ecdsa_verify_ms': to_float(pick_value(row, 'ecdsa_verify_ms', 'ecdsa_verify_wall_ms_median')),
            'rsa_public_key_size': to_float(pick_value(row, 'rsa_public_key_size')),
            'ecdsa_public_key_size': to_float(pick_value(row, 'ecdsa_public_key_size')),
            'rsa_signature_size': to_float(pick_value(row, 'rsa_signature_size')),
            'ecdsa_signature_size': to_float(pick_value(row, 'ecdsa_signature_size')),
            'rsa_keygen_ms': to_float(pick_value(row, 'rsa_keygen_wall_ms')),
            'ecdsa_keygen_ms': to_float(pick_value(row, 'ecdsa_keygen_wall_ms')),
            'rsa_cpu_ms': to_float(pick_value(row, 'rsa_sign_cpu_ms_median', 'rsa_cpu_time')),
            'ecdsa_cpu_ms': to_float(pick_value(row, 'ecdsa_sign_cpu_ms_median', 'ecdsa_cpu_time')),
            'rsa_memory_mb': normalize_memory_mb(row, 'rsa_memory_mb', 'rsa_peak_rss_kb'),
            'ecdsa_memory_mb': normalize_memory_mb(row, 'ecdsa_memory_mb', 'ecdsa_peak_rss_kb'),
            'rsa_verify_cpu_ms': to_float(pick_value(row, 'rsa_verify_cpu_ms_median')),
            'ecdsa_verify_cpu_ms': to_float(pick_value(row, 'ecdsa_verify_cpu_ms_median')),
        })
    return sorted(normalized, key=lambda r: r['security_bits'])


def calculate_total_seconds(median_ms, count):
    if median_ms is None:
        return None
    return (median_ms / 1000.0) * count


def calculate_verifications_per_second(median_ms, count):
    if median_ms is None or median_ms == 0:
        return None
    total_time = calculate_total_seconds(median_ms, count)
    if total_time is None or total_time == 0:
        return None
    return count / total_time


def annotate_ratios(ax, x_vals, rsa_vals, ecdsa_vals, color=None):
    for x_val, rsa_val, ecdsa_val in zip(x_vals, rsa_vals, ecdsa_vals):
        annotate_single_ratio(ax, x_val, rsa_val, ecdsa_val, color=color)


def annotate_single_ratio(ax, x_val, rsa_val, ecdsa_val, color=None):
    if rsa_val is None or ecdsa_val is None or ecdsa_val <= EPSILON:
        return
    ratio = rsa_val / ecdsa_val
    y_val = max(rsa_val, ecdsa_val)
    # Use a larger offset when RSA dominates to reduce annotation overlap.
    offset = ANNOTATION_OFFSET_LARGE if rsa_val >= ecdsa_val else ANNOTATION_OFFSET_SMALL
    ax.annotate(
        f"{ratio:.2f}x",
        xy=(x_val, y_val),
        xytext=(0, offset),
        textcoords='offset points',
        ha='center',
        fontsize=8,
        color=color,
    )


def plot_comparison_lines(x_vals, rsa_vals, ecdsa_vals, xlabel, ylabel, title, out_path):
    if any(val is None for val in rsa_vals + ecdsa_vals):
        return
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.plot(x_vals, rsa_vals, marker='o', label='RSA-PSS')
    ax.plot(x_vals, ecdsa_vals, marker='o', label='ECDSA')
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x_vals)
    ax.grid(axis='y', alpha=0.3)
    annotate_ratios(ax, x_vals, rsa_vals, ecdsa_vals)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_transaction_scaling(rows, out_path, rsa_field, ecdsa_field, title, ylabel):
    fig, ax = plt.subplots(figsize=(11, 7))
    cmap = plt.get_cmap('tab10')

    color_index = 0
    for row in rows:
        rsa_ms = row[rsa_field]
        ecdsa_ms = row[ecdsa_field]
        if rsa_ms is None or ecdsa_ms is None:
            continue
        color = cmap(color_index % cmap.N)
        color_index += 1
        rsa_totals = [calculate_total_seconds(rsa_ms, count) for count in OPERATION_COUNTS]
        ecdsa_totals = [calculate_total_seconds(ecdsa_ms, count) for count in OPERATION_COUNTS]
        security_bits = row['security_bits']
        ax.plot(
            OPERATION_COUNTS,
            rsa_totals,
            marker='o',
            linestyle='-',
            color=color,
            label=f"{security_bits}-bit RSA-PSS",
        )
        ax.plot(
            OPERATION_COUNTS,
            ecdsa_totals,
            marker='o',
            linestyle='--',
            color=color,
            label=f"{security_bits}-bit ECDSA",
        )
        annotate_single_ratio(ax, OPERATION_COUNTS[-1], rsa_totals[-1], ecdsa_totals[-1], color=color)

    ax.set_xlabel('Transaction Count')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(OPERATION_COUNTS)
    ax.grid(axis='y', alpha=0.3)
    ax.legend(fontsize=8, ncol=2)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--csv', default='results/benchmark_results_comprehensive.csv')
    parser.add_argument('--outdir', default=DEFAULT_OUTDIR)
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    rows = normalize_rows(read_csv(args.csv))
    if not rows:
        print('No rows found in', args.csv)
        return

    security_levels = [row['security_bits'] for row in rows]

    metrics = [
        (
            'signing_time.png',
            'Signing Time vs Security Level',
            'Signing time (ms)',
            'rsa_sign_ms',
            'ecdsa_sign_ms',
        ),
        (
            'verification_time.png',
            'Verification Time vs Security Level',
            'Verification time (ms)',
            'rsa_verify_ms',
            'ecdsa_verify_ms',
        ),
        (
            'public_key_sizes.png',
            'Public Key Size vs Security Level',
            'Public key size (bytes)',
            'rsa_public_key_size',
            'ecdsa_public_key_size',
        ),
        (
            'signature_sizes.png',
            'Signature Size vs Security Level',
            'Signature size (bytes)',
            'rsa_signature_size',
            'ecdsa_signature_size',
        ),
        (
            'keygen_time.png',
            'Key Generation Time vs Security Level',
            'Key generation time (ms)',
            'rsa_keygen_ms',
            'ecdsa_keygen_ms',
        ),
        (
            'signing_cpu_time.png',
            'Signing CPU Time vs Security Level',
            'CPU time (ms)',
            'rsa_cpu_ms',
            'ecdsa_cpu_ms',
        ),
        (
            'memory_usage.png',
            'Peak Memory Usage vs Security Level',
            'Peak memory (MB)',
            'rsa_memory_mb',
            'ecdsa_memory_mb',
        ),
    ]

    for filename, title, ylabel, rsa_key, ecdsa_key in metrics:
        rsa_vals = [row[rsa_key] for row in rows]
        ecdsa_vals = [row[ecdsa_key] for row in rows]
        plot_comparison_lines(
            security_levels,
            rsa_vals,
            ecdsa_vals,
            'Security level (bits)',
            ylabel,
            title,
            os.path.join(args.outdir, filename),
        )

    plot_transaction_scaling(
        rows,
        os.path.join(args.outdir, 'transaction_scaling_computation_time.png'),
        'rsa_sign_ms',
        'ecdsa_sign_ms',
        'Signing Time vs Transaction Count (All Security Levels)',
        'Total computation time (s)',
    )
    plot_transaction_scaling(
        rows,
        os.path.join(args.outdir, 'transaction_scaling_verification_time.png'),
        'rsa_verify_ms',
        'ecdsa_verify_ms',
        'Verification Time vs Transaction Count (All Security Levels)',
        'Total verification time (s)',
    )

    for row in rows:
        security_bits = row['security_bits']
        rsa_verify_wall = row['rsa_verify_ms']
        ecdsa_verify_wall = row['ecdsa_verify_ms']
        rsa_verify_cpu = row['rsa_verify_cpu_ms']
        ecdsa_verify_cpu = row['ecdsa_verify_cpu_ms']

        rsa_verify_totals = [calculate_total_seconds(rsa_verify_wall, count) for count in OPERATION_COUNTS]
        ecdsa_verify_totals = [calculate_total_seconds(ecdsa_verify_wall, count) for count in OPERATION_COUNTS]
        plot_comparison_lines(
            OPERATION_COUNTS,
            rsa_verify_totals,
            ecdsa_verify_totals,
            'Transaction Count',
            'Total verification time (s)',
            f"Verification Time vs Transaction Count ({security_bits}-bit)",
            os.path.join(args.outdir, f"verification_time_{security_bits}bit.png"),
        )

        rsa_verify_cpu_totals = [calculate_total_seconds(rsa_verify_cpu, count) for count in OPERATION_COUNTS]
        ecdsa_verify_cpu_totals = [calculate_total_seconds(ecdsa_verify_cpu, count) for count in OPERATION_COUNTS]
        plot_comparison_lines(
            OPERATION_COUNTS,
            rsa_verify_cpu_totals,
            ecdsa_verify_cpu_totals,
            'Transaction Count',
            'Total verification CPU time (s)',
            f"Verification CPU Time vs Transaction Count ({security_bits}-bit)",
            os.path.join(args.outdir, f"verification_cpu_time_{security_bits}bit.png"),
        )

    rsa_speed_25k = [calculate_verifications_per_second(row['rsa_verify_ms'], REFERENCE_COUNT) for row in rows]
    ecdsa_speed_25k = [calculate_verifications_per_second(row['ecdsa_verify_ms'], REFERENCE_COUNT) for row in rows]
    ratio_labels = []
    for security_label, rsa_speed, ecdsa_speed in zip(security_levels, rsa_speed_25k, ecdsa_speed_25k):
        if rsa_speed is None or ecdsa_speed is None or ecdsa_speed <= EPSILON:
            ratio_label = 'R/E N/A'
        else:
            ratio_label = f"R/E {rsa_speed / ecdsa_speed:.2f}x"
        ratio_labels.append(f"{security_label}\n{ratio_label}")

    plt.figure(figsize=(10, 7))
    x_vals = range(len(security_levels))
    width = 0.35
    plt.bar([i - width / 2 for i in x_vals], rsa_speed_25k, width=width, label='RSA-PSS')
    plt.bar([i + width / 2 for i in x_vals], ecdsa_speed_25k, width=width, label='ECDSA')
    plt.xticks(x_vals, ratio_labels)
    plt.ylabel('Verifications per second')
    plt.title(f"Verification Speed for {REFERENCE_COUNT} Verifications by Security Level")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(args.outdir, f"verification_speed_{REFERENCE_COUNT}.png"), dpi=150)
    plt.close()

    print('Saved graphs to', args.outdir)


if __name__ == '__main__':
    main()
