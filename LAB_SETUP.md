# 🔐 Blockchain Signature Benchmark - Lab Computer Setup

## Quick Start

### 1. Install Dependencies
```bash
pip install cryptography matplotlib psutil
```

### 2. Run the Benchmark
```bash
cd /path/to/Blockchain-signature-benchmark
python3 benchmark_complete.py
```

### 3. Wait (30-60+ minutes depending on hardware)
- RSA-2048/3072: ~1-2 mins each
- RSA-7680: ~5-10 mins
- RSA-15360: ~10-20 mins
- RSA-30720: **20-45+ mins** (ultra-heavy)

---

## Output Files

**CSV Data:**
```
results/benchmark_results_comprehensive.csv
```

**Graphs:**
```
results/graphs/
├── signing_time.png
├── verification_time.png
├── cpu_time.png
├── memory_usage.png
├── key_size.png
└── signature_size.png
```

---

## What It Benchmarks

| Metric | Description |
|---|---|
| **Sign Time** | Average signing time (ms) |
| **Verify Time** | Average verification time (ms) |
| **CPU Time** | CPU consumed during each algorithm benchmark (user + system seconds) |
| **Memory** | Memory delta during each benchmarked operation set (MB) |
| **Public Key Size** | Key size in bytes |
| **Signature Size** | Signature size in bytes |

---

## Security Levels Tested

| Security | RSA | ECDSA | Notes |
|---|---|---|---|
| 112-bit | 2048 | secp224r1 | Basic |
| 128-bit | 3072 | P-256 | Standard |
| 192-bit | 7680 | P-384 | High |

---

## Optimization Tips

**If running on less powerful hardware:**

Edit `benchmark_complete.py` and change iterations for large keys:

```python
ITERATIONS = {
    2048: 3,
    3072: 3,
    7680: 2,      # Reduce from 3
    15360: 1,     # Keep at 1
    30720: 1,     # Keep at 1 (key gen is the bottleneck)
}
```

Or **skip RSA-30720 entirely**:

```python
SECURITY_LEVELS = [
    # Remove the last entry:
    # {'bits': 512, 'rsa': 30720, 'ecdsa': 'P-521', 'notes': 'Ultra-high security'},
]
```

---

## Hardware Requirements

| Level | CPU | RAM | Time |
|---|---|---|---|
| Fast PC | i7+ | 16GB+ | 30 mins |
| Laptop | i5+ | 8GB | 45 mins |
| Lab Server | Xeon | 32GB+ | 20 mins |

---

## Example Output

```
   🔐 Security Level: 192-bit
   RSA: 7680-bit | ECDSA: P-384
   High security
   ----
   🔓 RSA-PSS (7680-bit)... ✅ (Sign: 42.29ms, Verify: 0.29ms)
   🔑 ECDSA (P-384)... ✅ (Sign: 0.93ms, Verify: 0.77ms)
```

---

## Post-Benchmark

After running, commit to GitHub:

```bash
cd /path/to/Blockchain-signature-benchmark
git add results/benchmark_results_comprehensive.csv results/graphs/*
git commit -m "Benchmark: Complete ECDSA vs RSA-PSS (3 security levels, all metrics)"
git push origin master
```

---

## Troubleshooting

**ModuleNotFoundError: No module named 'cryptography'**
```bash
pip install cryptography
```

**matplotlib error**
```bash
pip install matplotlib
```

**Script hangs on RSA-30720**
- Normal - key generation takes 20+ minutes
- Can press Ctrl+C and edit to skip that level

**Out of memory**
- Reduce iterations in ITERATIONS dict
- Close other applications
- Consider skipping RSA-30720

---

**Good luck! Results will be worth the wait.** 🚀
