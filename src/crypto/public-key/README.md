# 公钥密码学

{{#include ../../banners/hacktricks-training.md}}

许多高级 CTF cryptography 挑战涉及 RSA、椭圆曲线密码学（ECC）、ECDSA、lattices 或弱随机性。

## 推荐工具

- [SageMath](https://www.sagemath.org/)：用于模运算、椭圆曲线和 lattice reduction<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)：用于测试常见的 RSA 弱点<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/)：用于检查某个整数是否存在已知因子<sup>[[3]](#references)</sup>
- 用于密钥解析、签名和验证的 Python [`ecdsa` library](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

当挑战提供 `n`、`e` 和 `c`，并附带 shared modulus、low exponent、partial key bits 或 related messages 等提示时，从这里开始。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

如果涉及签名，在假设必须解决底层 discrete-logarithm problem 之前，先测试 nonce reuse、bias 或 nonce leakage。

### ECDSA nonce reuse / bias

ECDSA 要求每条消息使用一个新的 secret number `k`。如果相同的 `k` 为两个不同的 message hashes 生成签名，则可以根据公开的 signature values 恢复 private key。<sup>[[4]](#references)</sup>

即使 `k` 不完全相同，在大量签名中出现 nonce bits 的 bias 或 leakage，也可能支持基于 lattice 的恢复。<sup>[[5]](#references)</sup>

`k` 被重复使用时的技术恢复方法：<sup>[[4]](#references)</sup>

ECDSA signature equations（group order `n`）：

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

如果相同的 `k` 被重复用于两个 message `m1, m2`，并生成签名 `(r, s1)` 和 `(r, s2)`：

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

如果协议未验证输入点是否位于预期曲线上且属于正确的 subgroup，攻击者可能迫使操作在较弱的 group 中执行，并恢复有关 secret scalar 的信息。SEC 1 规定了用于防止此类输入的 public-key validation checks。<sup>[[6]](#references)</sup>

技术说明：

- 验证点不是 point at infinity，具有有效坐标，满足 curve equation，并属于所需的 subgroup。<sup>[[6]](#references)</sup>
- 在 CTF 挑战中，这通常被建模为：服务器将攻击者选择的点与 secret scalar 相乘，并返回一个 derived value。

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — Lattice Attacks against Weak ECDSA Signatures](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` documentation](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
