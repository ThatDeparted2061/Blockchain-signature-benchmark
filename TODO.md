# Cryptographic Benchmark: RSA vs ECDSA

## Objective

This project benchmarks the performance of **RSA and ECDSA digital
signature algorithms** across different security levels.

The goal is to analyze trade-offs between:

-   Signing time
-   Verification time
-   Key size
-   Signature size
-   Memory usage
-   CPU usage

The study focuses on whether **RSA can outperform ECDSA in
verification-heavy environments**, despite RSA having larger keys and
slower signing.

------------------------------------------------------------------------

# Security Level Mapping

Cryptographic algorithms must be compared at **equivalent security
strengths**.\
The following mapping is based on **NIST SP 800-57 recommendations**.

  Security Level (bits)   RSA Key Size   ECDSA Curve
  ----------------------- -------------- -------------
  \~112-bit               RSA-2048       ECDSA-224
  \~128-bit               RSA-3072       ECDSA-256
  \~192-bit               RSA-7680       ECDSA-384
  \~256-bit               RSA-15360      ECDSA-521

These pairs ensure that RSA and ECDSA provide **comparable cryptographic
strength**.

------------------------------------------------------------------------

# Benchmark Comparisons

Each security level compares the following pair:

  Pair     RSA         ECDSA
  -------- ----------- -----------
  Pair 1   RSA-2048    ECDSA-224
  Pair 2   RSA-3072    ECDSA-256
  Pair 3   RSA-7680    ECDSA-384
  Pair 4   RSA-15360   ECDSA-521

------------------------------------------------------------------------

# Metrics Evaluated

The benchmark evaluates the following metrics:

## 1. Signing Time

Time required to generate a digital signature.

Expected behavior: - RSA signing is **slower** - ECDSA signing is
**faster**

------------------------------------------------------------------------

## 2. Verification Time

Time required to verify a signature.

Expected behavior: - RSA verification is **very fast** - ECDSA
verification is **moderately fast**

This metric is particularly important for **transaction validation
systems**.

------------------------------------------------------------------------

## 3. Key Size

Size of the public/private key in bits.

Expected behavior: - RSA keys are **much larger** - ECDSA keys are
**much smaller**

------------------------------------------------------------------------

## 4. Signature Size

Size of the generated signature.

  Algorithm   Typical Size
  ----------- --------------
  RSA         Large
  ECDSA       Small

This affects **bandwidth and storage requirements**.

------------------------------------------------------------------------

## 5. Memory Usage

Memory consumed during signing and verification operations.

------------------------------------------------------------------------

## 6. CPU Time

Processor time required for cryptographic operations.

------------------------------------------------------------------------

# Graphs

The following graphs are generated from benchmark results.

## Signing Time

X-axis : Security Level\
Y-axis : Signing Time (ms)

Bars: - RSA - ECDSA

Security levels shown on x-axis:

-   112
-   128
-   192
-   256

Each level represents the **equivalent RSA--ECDSA pair**.

------------------------------------------------------------------------

## Verification Time

X-axis : Security Level\
Y-axis : Verification Time (ms)

Bars: - RSA - ECDSA

This graph demonstrates **RSA's verification advantage**.

------------------------------------------------------------------------

## Key Size

X-axis : Security Level\
Y-axis : Key Size (bits)

Bars: - RSA - ECDSA

------------------------------------------------------------------------

## Signature Size

X-axis : Security Level\
Y-axis : Signature Size (bytes)

Bars: - RSA - ECDSA

------------------------------------------------------------------------

## CPU Time

X-axis : Security Level\
Y-axis : CPU Time (ms)

------------------------------------------------------------------------

## Memory Usage

X-axis : Security Level\
Y-axis : Memory Usage (MB)

------------------------------------------------------------------------

# Final Comparison Table

At the end of the report, results are summarized in the following
format.

  --------------------------------------------------------------------------------------------
  Security   RSA Key     ECDSA Curve RSA     ECDSA   RSA      ECDSA    RSA         ECDSA
  Level                              Sign    Sign    Verify   Verify   Signature   Signature
                                     (ms)    (ms)    (ms)     (ms)     Size        Size
  ---------- ----------- ----------- ------- ------- -------- -------- ----------- -----------
  112        RSA-2048    ECDSA-224                                                 

  128        RSA-3072    ECDSA-256                                                 

  192        RSA-7680    ECDSA-384                                                 

  256        RSA-15360   ECDSA-521                                                 
  --------------------------------------------------------------------------------------------

------------------------------------------------------------------------

# Conclusion

This benchmark evaluates RSA and ECDSA across equivalent security
levels.\
While RSA typically has **larger keys and slower signing**, it may offer
**very fast verification performance**, which can be advantageous in
systems where verification operations dominate, such as transaction
validation or distributed authentication systems.
