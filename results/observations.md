# Observations

These observations align the benchmark results with the project goal: comparing RSA (2048, 3072) vs ECDSA (secp256k1) for blockchain-style transaction signing and verification.

## Summary vs. Project Goal
- **Goal:** Compare signing/verification performance, CPU, memory, and key/signature sizes for blockchain-like transactions.
- **Outcome:** The results directly show how each scheme scales with transaction count (1k → 100k), and the graphs visualize the tradeoffs that matter for blockchain throughput and storage.

## Key Takeaways
1. **ECDSA is the most space‑efficient.**
   - ECDSA signatures and public keys are smaller than RSA‑2048/3072.
   - In blockchains, this matters for on‑chain storage and network bandwidth.

2. **RSA‑3072 is the heaviest.**
   - It consistently shows higher signing/verification time and larger key/signature sizes.
   - This aligns with the security level increase vs. RSA‑2048 but at a bigger performance cost.

3. **RSA‑2048 is faster than RSA‑3072 but still larger than ECDSA.**
   - If using RSA, 2048 is less costly, but ECDSA still gives better size efficiency.

4. **Scaling trend is clear.**
   - Signing/verification times scale roughly linearly with transaction count, which is expected.
   - The graphs reinforce which scheme scales best for high‑throughput blockchain workloads.

## Which Is Better (and Why)
- **Best overall for blockchains:** **ECDSA (secp256k1)**
  - Smaller keys/signatures → less storage + bandwidth.
  - Faster verification in practice at scale → better throughput.
- **RSA‑2048:** acceptable if you need RSA interoperability, but it costs more space.
- **RSA‑3072:** strongest of the RSA options here, but it’s the slowest + largest, so it’s the least practical for high‑volume chains.

## Why This Fits a Blockchain Use‑Case
- Blockchains need **fast verification**, **small signatures**, and **low bandwidth use**.
- The benchmark confirms why **ECDSA (secp256k1)** is standard in many blockchain systems (e.g., Bitcoin/Ethereum): strong security with compact keys and signatures.
- RSA works, but its larger size and slower performance make it less suitable for large‑scale transaction systems.

## Files Referenced
- `results/benchmark_results.csv` — raw benchmark data
- `results/graphs/` — visual comparisons of time, size, CPU, and memory
