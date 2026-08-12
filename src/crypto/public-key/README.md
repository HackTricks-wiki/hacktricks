# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

कई advanced CTF cryptography challenges में RSA, elliptic-curve cryptography (ECC), ECDSA, lattices या weak randomness शामिल होते हैं।

## Recommended tooling

- modular arithmetic, elliptic curves और lattice reduction के लिए [SageMath](https://www.sagemath.org/)<sup>[[1]](#references)</sup>
- common RSA weaknesses की testing के लिए [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)<sup>[[2]](#references)</sup>
- किसी integer के known factors हैं या नहीं, यह जांचने के लिए [FactorDB](https://factordb.com/)<sup>[[3]](#references)</sup>
- key parsing, signing और verification के लिए Python [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

जब किसी challenge में `n`, `e` और `c` दिए हों, साथ में shared modulus, low exponent, partial key bits या related messages जैसा कोई hint हो, तो यहां से शुरू करें।

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

यदि signatures शामिल हों, तो यह मानने से पहले कि underlying discrete-logarithm problem हल करनी होगी, nonce reuse, bias या leakage की जांच करें।

### ECDSA nonce reuse / bias

ECDSA के लिए प्रत्येक message के लिए एक नया secret number `k` आवश्यक होता है। यदि एक ही `k` से दो अलग-अलग message hashes sign किए जाते हैं, तो private key को public signature values से recover किया जा सकता है।<sup>[[4]](#references)</sup>

जब `k` समान न भी हो, तब भी कई signatures में nonce bits का bias या leakage lattice-based recovery को संभव बना सकता है।<sup>[[5]](#references)</sup>

जब `k` reuse किया गया हो, तब technical recovery:<sup>[[4]](#references)</sup>

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

यदि एक ही `k` को दो messages `m1, m2` के लिए reuse किया गया हो और signatures `(r, s1)` तथा `(r, s2)` प्राप्त हों:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

यदि कोई protocol यह validate करने में विफल रहता है कि input point expected curve पर और correct subgroup में स्थित है, तो attacker operations को एक weaker group में force कर सकता है और secret scalar के बारे में information recover कर सकता है। SEC 1 ऐसे inputs को रोकने के लिए public-key validation checks निर्दिष्ट करता है।<sup>[[6]](#references)</sup>

Technical note:

- Validate करें कि points point at infinity न हों, उनके coordinates valid हों, वे curve equation को satisfy करते हों और required subgroup से belong करते हों।<sup>[[6]](#references)</sup>
- CTF challenges में इसे अक्सर इस रूप में model किया जाता है कि server attacker द्वारा चुने गए point को secret scalar से multiply करता है और एक derived value return करता है।

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — Lattice Attacks against Weak ECDSA Signatures](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
