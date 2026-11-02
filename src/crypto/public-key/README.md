# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

Many advanced CTF cryptography challenges involve RSA, elliptic-curve cryptography (ECC), ECDSA, lattices, or weak randomness.

## Recommended tooling

- [SageMath](https://www.sagemath.org/) for modular arithmetic, elliptic curves, and lattice reduction<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) for testing common RSA weaknesses<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) for checking whether an integer has known factors<sup>[[3]](#references)</sup>
- The Python [`ecdsa` library](https://ecdsa.readthedocs.io/) for key parsing, signing, and verification<sup>[[7]](#references)</sup>

## RSA

Start here when a challenge provides `n`, `e`, and `c` plus a hint such as a shared modulus, low exponent, partial key bits, or related messages.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

If signatures are involved, test for nonce reuse, bias, or leakage before assuming that the underlying discrete-logarithm problem must be solved.

### ECDSA nonce reuse / bias

ECDSA requires a fresh per-message secret number `k`. If the same `k` signs two different message hashes, the private key can be recovered from the public signature values.<sup>[[4]](#references)</sup>

Even when `k` is not identical, bias or leakage of nonce bits across many signatures may enable lattice-based recovery.<sup>[[5]](#references)</sup>

Technical recovery when `k` is reused:<sup>[[4]](#references)</sup>

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

If the same `k` is reused for two messages `m1, m2` producing signatures `(r, s1)` and `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

If a protocol fails to validate that an input point lies on the expected curve and in the correct subgroup, an attacker may force operations in a weaker group and recover information about a secret scalar. SEC 1 specifies public-key validation checks intended to prevent such inputs.<sup>[[6]](#references)</sup>

Technical note:

- Validate that points are not the point at infinity, have valid coordinates, satisfy the curve equation, and belong to the required subgroup.<sup>[[6]](#references)</sup>
- In CTF challenges, this is often modeled as a server multiplying an attacker-chosen point by a secret scalar and returning a derived value.

## Malformed ML-DSA signing keys and rejection-sampling leakage

An ML-DSA expanded private key encodes secret polynomial vectors `s1` and `s2` whose coefficients must be in `[-η, η]`. If an attacker can alter serialized private-key bytes **before import and signing**, flip packed coefficient bits so the key remains parseable but a coefficient falls outside that interval. Compare import and signing behavior across libraries using the [cryptographic differential-fuzzing workflow](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings). This is not an attack from submitting a malformed public key to a verifier: the altered **signing** key must actually be used.<sup>[[10]](#references)</sup>

Signing computes `z = y + c·s1` and uses rejection sampling to keep returned `z` coefficients inside the parameter-set-dependent interval `[-γ1 + β + 1, γ1 - β - 1]`. It similarly rejects on `r = w - c·s2` outside `[-γ2 + β + 1, γ2 - β - 1]`. These bounds hide the small valid secret coefficients. With an out-of-range coefficient, some otherwise valid outputs become unreachable, so accepted signatures can have a secret-dependent distribution. This is a conditional leakage mechanism, not a demonstrated full-key recovery from the reported discrepancy.<sup>[[10]](#references)</sup>

The distinction is **key validation**, not basic signature verification. OpenSSL, BoringSSL, and SymCrypt add private-key checks; the reported liboqs signing API accepted malformed expanded keys, while its underlying `mldsa-native` implementation has a `pk_from_sk()` validator that liboqs did not expose.<sup>[[9]](#references)[[10]](#references)</sup>

FIPS 204 warns that unpacking untrusted encodings can yield out-of-range coefficients, but it does not mandate these extra private-key checks.<sup>[[8]](#references)[[9]](#references)</sup>

A fault that changes secret coefficients is another prerequisite for the same bias, independent of key import.<sup>[[10]](#references)</sup>

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — Lattice Attacks against Weak ECDSA Signatures](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [Missing ML-DSA and ML-KEM key checks - liboqs issue #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [State of Post-Quantum Cryptography Implementations](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)

{{#include ../../banners/hacktricks-training.md}}
