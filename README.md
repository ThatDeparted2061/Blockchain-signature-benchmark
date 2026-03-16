# Blockchain-signature-benchmark

A performance comparison between RSA and ECDSA digital signature algorithms across equivalent security levels.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the benchmark

The new comprehensive benchmark script compares RSA (PSS) and ECDSA across mapped security levels and emits CSV results.

```bash
# run full benchmark (may be slow for large RSA keys, includes 512-bit RSA-30720)
python ecdsa_vs_rsa_benchmark.py --warmup 1 --iters 3 --max-rsa 30720 --out results/benchmark_results_comprehensive.csv

# run smoke test (quick, good for CI)
python ecdsa_vs_rsa_benchmark.py --warmup 1 --iters 1 --max-rsa 2048 --out results/benchmark_results_comprehensive.csv
```

## Generate graphs

After running the benchmark, generate graphs from the CSV output (saved to `results/` by default):

```bash
python results/plot_results.py --csv results/benchmark_results_comprehensive.csv --outdir results
```

This will produce PNG graphs in the results directory:

- signing_time.png
- verification_time.png
- verification_time_112bit.png (and other security levels)
- verification_cpu_time_112bit.png (and other security levels)
- verification_speed_25000.png
- key_sizes.png
- signature_sizes.png
- signing_cpu_time.png

## Metrics Explained

- rsa_key_size / ecdsa_curve: Key parameters used for the experiment.
- *_keygen_wall_ms / *_keygen_cpu_ms: Time to generate keys (wall and CPU time).
- *_sign_wall_ms_median / *_verify_wall_ms_median: Median wall time (ms) for sign/verify operations across measured iterations.
- *_sign_cpu_ms_median / *_verify_cpu_ms_median: Median CPU time (ms) for sign/verify operations.
- *_signature_size: Signature size in bytes.
- *_peak_rss_kb: Peak RSS memory used (kilobytes) measured during operation.

## Notes

- RSA signing uses RSASSA-PSS (padding.PSS with SHA-256) — OAEP is for encryption and not used for signatures.
- Large RSA keys (>= 7680 bits) are slow to generate; use `--max-rsa` to limit experiments for faster runs.
- The scripts are intended to be run on a machine with sufficient CPU for high-key benchmarks. For long-running benchmarks, run on a dedicated server or CI with more CPU cores.

## Commit & Branch

The benchmarking additions (comprehensive benchmark and plotting) are on branch `copilot/benchmark-updates`. They will be merged to `main` on request.
