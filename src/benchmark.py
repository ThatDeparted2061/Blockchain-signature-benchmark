from __future__ import annotations

import csv
import os
import time
from typing import Iterable, List, Dict

import psutil
import pandas as pd
import matplotlib.pyplot as plt

from .crypto_utils import generate_rsa, generate_ecdsa_secp256k1
from .transaction import Transaction

RESULTS_PATH = os.path.join("results", "benchmark_results.csv")
GRAPHS_DIR = os.path.join("results", "graphs")


def generate_transactions(count: int) -> List[Transaction]:
    return [
        Transaction.create("Alice", "Bob", amount=1.0 + (i % 10))
        for i in range(count)
    ]


def run_benchmark(transaction_counts: Iterable[int]) -> List[Dict[str, object]]:
    schemes = [
        generate_rsa(2048),
        generate_rsa(3072),
        generate_ecdsa_secp256k1(),
    ]

    results: List[Dict[str, object]] = []
    process = psutil.Process()

    for scheme in schemes:
        signature_sample = scheme.sign(b"sample")
        signature_size = len(signature_sample)
        public_key_size = scheme.public_key_size()

        for count in transaction_counts:
            print(f"Running {scheme.name} with {count} transactions...", flush=True)
            transactions = generate_transactions(count)

            start_cpu = time.process_time()
            start_wall = time.perf_counter()
            max_rss = process.memory_info().rss

            signatures = []
            for idx, tx in enumerate(transactions, start=1):
                signatures.append(scheme.sign(tx.hash_id_bytes()))
                if idx % 1000 == 0:
                    max_rss = max(max_rss, process.memory_info().rss)

            signing_total = time.perf_counter() - start_wall

            verify_start = time.perf_counter()
            for idx, (tx, sig) in enumerate(zip(transactions, signatures), start=1):
                scheme.verify(sig, tx.hash_id_bytes())
                if idx % 1000 == 0:
                    max_rss = max(max_rss, process.memory_info().rss)

            verification_total = time.perf_counter() - verify_start
            total_cpu = time.process_time() - start_cpu

            total_wall = time.perf_counter() - start_wall
            print(f"Completed in {total_wall:.2f}s", flush=True)

            results.append(
                {
                    "scheme": scheme.name,
                    "transactions": count,
                    "signing_total_s": signing_total,
                    "signing_avg_ms": (signing_total / count) * 1000,
                    "verification_total_s": verification_total,
                    "verification_avg_ms": (verification_total / count) * 1000,
                    "cpu_time_s": total_cpu,
                    "memory_max_mb": max_rss / (1024 * 1024),
                    "signature_size_bytes": signature_size,
                    "public_key_size_bytes": public_key_size,
                }
            )

    return results


def save_results(rows: List[Dict[str, object]]) -> None:
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def plot_graphs(df: pd.DataFrame) -> None:
    os.makedirs(GRAPHS_DIR, exist_ok=True)

    def save_line(metric: str, title: str, filename: str) -> None:
        plt.figure()
        for scheme in df["scheme"].unique():
            subset = df[df["scheme"] == scheme]
            plt.plot(subset["transactions"], subset[metric], marker="o", label=scheme)
        plt.title(title)
        plt.xlabel("Transactions")
        plt.ylabel(metric.replace("_", " "))
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, filename))
        plt.close()

    def save_bar(metric: str, title: str, filename: str) -> None:
        plt.figure()
        latest = df[df["transactions"] == df["transactions"].max()]
        plt.bar(latest["scheme"], latest[metric])
        plt.title(title)
        plt.ylabel(metric.replace("_", " "))
        plt.tight_layout()
        plt.savefig(os.path.join(GRAPHS_DIR, filename))
        plt.close()

    save_line("signing_total_s", "Signing time vs transactions", "signing_time.png")
    save_line("verification_total_s", "Verification time vs transactions", "verification_time.png")
    save_bar("signature_size_bytes", "Signature size comparison", "signature_size.png")
    save_bar("public_key_size_bytes", "Public key size comparison", "key_size.png")
    save_bar("cpu_time_s", "CPU usage comparison", "cpu_time.png")
    save_bar("memory_max_mb", "Memory usage comparison", "memory_usage.png")


def run_all() -> None:
    transaction_counts = [1000, 10000, 50000, 100000]
    results = run_benchmark(transaction_counts)
    save_results(results)
    df = pd.DataFrame(results)
    plot_graphs(df)
