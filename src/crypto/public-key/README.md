# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

Changamoto nyingi za advanced za CTF cryptography zinahusisha RSA, elliptic-curve cryptography (ECC), ECDSA, lattices, au weak randomness.

## Zana zinazopendekezwa

- [SageMath](https://www.sagemath.org/) kwa modular arithmetic, elliptic curves, na lattice reduction<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) kwa kutest common RSA weaknesses<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) kwa kuangalia ikiwa integer ina known factors<sup>[[3]](#references)</sup>
- Python [`ecdsa` library](https://ecdsa.readthedocs.io/) kwa key parsing, signing, na verification<sup>[[7]](#references)</sup>

## RSA

Anza hapa wakati challenge inatoa `n`, `e`, na `c`, pamoja na hint kama shared modulus, low exponent, partial key bits, au related messages.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Ikiwa signatures zinahusika, test nonce reuse, bias, au leakage kabla ya kudhani kwamba underlying discrete-logarithm problem lazima isuluhishwe.

### ECDSA nonce reuse / bias

ECDSA inahitaji secret number mpya ya kila message `k`. Ikiwa `k` hiyo hiyo itatumika kusign message hashes mbili tofauti, private key inaweza kurejeshwa kutoka kwenye public signature values.<sup>[[4]](#references)</sup>

Hata wakati `k` si identical, bias au leakage ya nonce bits kwenye signatures nyingi inaweza kuwezesha lattice-based recovery.<sup>[[5]](#references)</sup>

Technical recovery wakati `k` imetumika tena:<sup>[[4]](#references)</sup>

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Ikiwa `k` hiyo hiyo itatumika tena kwa messages mbili `m1, m2`, na kutoa signatures `(r, s1)` na `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Ikiwa protocol inashindwa kuthibitisha kwamba input point iko kwenye expected curve na katika correct subgroup, attacker anaweza kulazimisha operations kwenye weaker group na kurejesha taarifa kuhusu secret scalar. SEC 1 inabainisha public-key validation checks zilizokusudiwa kuzuia inputs kama hizo.<sup>[[6]](#references)</sup>

Technical note:

- Thibitisha kwamba points si point at infinity, zina valid coordinates, zinatimiza curve equation, na ni za required subgroup.<sup>[[6]](#references)</sup>
- Katika CTF challenges, hii mara nyingi huwakilishwa kama server inayomultiply attacker-chosen point kwa secret scalar na kurudisha derived value.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Kiwango cha Digital Signature](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner na Heninger: Biased Nonce Sense — Lattice Attacks dhidi ya Weak ECDSA Signatures](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
