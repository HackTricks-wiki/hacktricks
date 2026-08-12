# 공개 키 암호

{{#include ../../banners/hacktricks-training.md}}

많은 고급 CTF cryptography challenge에는 RSA, elliptic-curve cryptography (ECC), ECDSA, lattices 또는 weak randomness가 포함됩니다.

## 권장 도구

- 모듈러 산술, elliptic curves 및 lattice reduction을 위한 [SageMath](https://www.sagemath.org/)<sup>[[1]](#references)</sup>
- 일반적인 RSA weaknesses를 테스트하기 위한 [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)<sup>[[2]](#references)</sup>
- 정수에 알려진 인수가 있는지 확인하기 위한 [FactorDB](https://factordb.com/)<sup>[[3]](#references)</sup>
- key parsing, signing 및 verification을 위한 Python [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

challenge에서 `n`, `e`, `c`와 함께 shared modulus, low exponent, partial key bits 또는 related messages와 같은 hint를 제공하는 경우 여기서 시작합니다.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

signatures가 관련된 경우 underlying discrete-logarithm problem을 해결해야 한다고 가정하기 전에 nonce reuse, bias 또는 leakage를 테스트합니다.

### ECDSA nonce reuse / bias

ECDSA는 각 message마다 새로운 secret number `k`를 필요로 합니다. 동일한 `k`가 서로 다른 두 message hash에 sign되는 경우 public signature values에서 private key를 복구할 수 있습니다.<sup>[[4]](#references)</sup>

`k`가 동일하지 않더라도 여러 signatures에서 nonce bits의 bias 또는 leakage가 발생하면 lattice-based recovery가 가능할 수 있습니다.<sup>[[5]](#references)</sup>

`k`가 재사용된 경우의 technical recovery:<sup>[[4]](#references)</sup>

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

동일한 `k`가 두 message `m1`, `m2`에 재사용되어 signatures `(r, s1)` 및 `(r, s2)`를 생성하는 경우:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

protocol이 input point가 expected curve 위에 있고 올바른 subgroup에 속하는지 검증하지 못하면, attacker는 더 약한 group에서 operations를 강제하고 secret scalar에 대한 정보를 복구할 수 있습니다. SEC 1은 이러한 input을 방지하기 위한 public-key validation checks를 지정합니다.<sup>[[6]](#references)</sup>

Technical note:

- points가 point at infinity가 아니고, valid coordinates를 가지며, curve equation을 만족하고, required subgroup에 속하는지 검증합니다.<sup>[[6]](#references)</sup>
- CTF challenges에서는 attacker가 선택한 point에 secret scalar를 곱하고 derived value를 반환하는 server로 모델링되는 경우가 많습니다.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Weak ECDSA Signatures에 대한 Biased Nonce Sense — Lattice Attacks](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
