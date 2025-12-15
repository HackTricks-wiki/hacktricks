# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

大多数 CTF 中难度较高的 crypto 问题集中在此：RSA、ECC/ECDSA、lattices，以及 bad randomness。

## Recommended tooling

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (quick factor checks): http://factordb.com/

## RSA

当你有 `n,e,c` 以及一些额外提示（shared modulus、low exponent、partial bits、related messages）时，从这里开始。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

如果涉及签名，先测试 nonce 问题（reuse/bias/leaks），再假设是复杂数学问题。

### ECDSA nonce reuse / bias

如果两个签名重用相同的 nonce `k`，私钥就可以被恢复。

即使 `k` 并非完全相同，跨签名的 nonce 比特的 **bias/leakage** 也可能足以通过格方法恢复私钥（常见的 CTF 主题）。

Technical recovery when `k` is reused:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

If the same `k` is reused for two messages `m1, m2` producing signatures `(r, s1)` and `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

If a protocol fails to validate that points are on the expected curve (or subgroup), an attacker may force operations in a weak group and recover secrets.

Technical note:

- Validate points are on-curve and in the correct subgroup.
- Many CTF tasks model this as "server multiplies attacker-chosen point by secret scalar and returns something."

### Tooling

- SageMath for curve arithmetic / lattices
- `ecdsa` Python library for parsing/verification

{{#include ../../banners/hacktricks-training.md}}
