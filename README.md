# Blockchain-signature-benchmark

A performance comparison between RSA (2048, 3072) and ECDSA (secp256k1) for signing and verifying simulated blockchain transactions.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the benchmark

```bash
python main.py
```

Live progress will print to the console as each scheme/transaction count completes.

## Metrics Explained

- **signing_total_s / signing_avg_ms**: Total and average time to sign all transactions.
- **verification_total_s / verification_avg_ms**: Total and average time to verify all signatures.
- **cpu_time_s**: CPU process time consumed for sign + verify.
- **memory_max_mb**: Peak memory observed during the run.
- **signature_size_bytes**: Size of a signature in bytes.
- **public_key_size_bytes**: Size of the public key in bytes.

## Example Output (CSV)

```
scheme,transactions,signing_total_s,signing_avg_ms,verification_total_s,verification_avg_ms,cpu_time_s,memory_max_mb,signature_size_bytes,public_key_size_bytes
RSA-2048,1000,1.23,1.23,0.88,0.88,2.11,145.2,256,294
```

## Graphs

Graphs are saved in `results/graphs/`:

- Signing time vs transactions
- Verification time vs transactions
- Signature size comparison
- Key size comparison
- CPU usage comparison
- Memory usage comparison

## Notes

- Keys are generated once per scheme per experiment (not per transaction).
- Transactions include sender, receiver, amount, timestamp, and transaction ID.
- Transaction ID is the SHA256 hash of the serialized transaction.
