# 公钥密码学

{{#include ../../banners/hacktricks-training.md}}

许多高级 CTF 密码学挑战涉及 RSA、椭圆曲线密码学（ECC）、ECDSA、格或弱随机性。

## 推荐工具

- [SageMath](https://www.sagemath.org/)：用于模运算、椭圆曲线和格约简<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)：用于测试常见的 RSA 弱点<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/)：用于检查整数是否有已知因子<sup>[[3]](#references)</sup>
- Python [`ecdsa` library](https://ecdsa.readthedocs.io/)：用于密钥解析、签名和验证<sup>[[7]](#references)</sup>

## RSA

如果挑战提供了 `n`、`e` 和 `c`，并附有共享模数、低指数、部分密钥位或相关消息等提示，可以从这里入手。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

如果涉及签名，应先检查 nonce 是否重复使用、存在偏差或泄露，再假设必须解决底层的离散对数问题。

### ECDSA nonce 重用 / 偏差

ECDSA 要求每条消息使用一个新的秘密数 `k`。如果同一个 `k` 用于签署两个不同的消息哈希值，就可以根据公开的签名值恢复私钥。<sup>[[4]](#references)</sup>

即使 `k` 不完全相同，多个签名中的 nonce 位若存在偏差或泄露，也可能让基于格的恢复成为可能。<sup>[[5]](#references)</sup>

`k` 重用时的技术性恢复方法：<sup>[[4]](#references)</sup>

ECDSA 签名方程（群阶为 `n`）：

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

如果同一个 `k` 被用于两条消息 `m1, m2`，并生成签名 `(r, s1)` 和 `(r, s2)`：

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

如果协议未验证输入点是否位于预期曲线上且属于正确的子群，攻击者就可能强制在较弱的群中执行运算，并恢复有关秘密标量的信息。SEC 1 规定了用于防止此类输入的公钥验证检查。<sup>[[6]](#references)</sup>

技术说明：

- 验证点不是无穷远点、坐标有效、满足曲线方程，且属于所需子群。<sup>[[6]](#references)</sup>
- 在 CTF 挑战中，这通常表现为服务器将攻击者选择的点乘以秘密标量，并返回一个派生值。

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5：数字签名标准](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner 和 Heninger：有偏的 Nonce Sense——针对弱 ECDSA 签名的格攻击](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0：椭圆曲线密码学](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` 文档](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
