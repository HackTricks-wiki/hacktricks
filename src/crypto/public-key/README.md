# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

多くの高度な CTF cryptography challenge では、RSA、elliptic-curve cryptography (ECC)、ECDSA、lattice、または weak randomness が関係します。

## 推奨ツール

- [SageMath](https://www.sagemath.org/)（modular arithmetic、elliptic curve、lattice reduction 用）<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)（一般的な RSA weakness のテスト用）<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/)（整数に既知の factor があるか確認するため）<sup>[[3]](#references)</sup>
- key parsing、signing、verification 用の Python [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

challenge で `n`、`e`、`c` が提示され、shared modulus、low exponent、partial key bits、related messages などの hint がある場合は、ここから始めます。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

signatures が関係する場合は、underlying discrete-logarithm problem を解く必要があると考える前に、nonce reuse、bias、または leak をテストします。

### ECDSA nonce reuse / bias

ECDSA では、message ごとに新しい secret number `k` が必要です。同じ `k` で異なる message hash に署名すると、public signature values から private key を復元できます。<sup>[[4]](#references)</sup>

`k` が同一でない場合でも、多数の signatures にわたる nonce bits の bias や leak によって、lattice-based recovery が可能になることがあります。<sup>[[5]](#references)</sup>

`k` が再利用された場合の technical recovery:<sup>[[4]](#references)</sup>

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

同じ `k` が2つの messages `m1, m2` で再利用され、signatures `(r, s1)` と `(r, s2)` が生成された場合:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

protocol が、input point が想定された curve 上にあり、正しい subgroup に属していることを検証しない場合、attacker はより弱い group での operations を強制し、secret scalar に関する情報を復元できる可能性があります。SEC 1 では、このような inputs を防ぐことを目的とした public-key validation checks が規定されています。<sup>[[6]](#references)</sup>

Technical note:

- points が point at infinity ではなく、valid coordinates を持ち、curve equation を満たし、必要な subgroup に属していることを検証します。<sup>[[6]](#references)</sup>
- CTF challenges では、これは多くの場合、server が attacker の選択した point に secret scalar を掛け、その derived value を返す形で model 化されます。

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — Lattice Attacks against Weak ECDSA Signatures](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
