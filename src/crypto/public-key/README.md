# 公钥密码学

{{#include ../../banners/hacktricks-training.md}}

许多高级 CTF 密码学挑战涉及 RSA、椭圆曲线密码学（ECC）、ECDSA、格或弱随机数。

## 推荐工具

- [SageMath](https://www.sagemath.org/)：用于模运算、椭圆曲线和格规约<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)：用于测试常见 RSA 弱点<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/)：用于检查某个整数是否有已知因子<sup>[[3]](#references)</sup>
- 用于密钥解析、签名和验证的 Python [`ecdsa` 库](https://ecdsa.readthedocs.io/)<sup>[[7]](#references)</sup>

## RSA

当挑战提供 `n`、`e` 和 `c`，并提示共享模数、低指数、部分密钥位或相关消息时，可以从这里开始。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

如果涉及签名，应先检查 nonce 是否复用、存在偏差或泄漏，再假设必须解决底层离散对数问题。

### ECDSA nonce 复用 / 偏差

ECDSA 要求每条消息使用一个新的秘密数 `k`。如果同一个 `k` 为两个不同的消息哈希签名，可以从公开签名值中恢复私钥。<sup>[[4]](#references)</sup>

即使 `k` 不完全相同，多个签名中的 nonce 位偏差或泄漏也可能使基于格的恢复成为可能。<sup>[[5]](#references)</sup>

复用 `k` 时的技术性恢复方法：<sup>[[4]](#references)</sup>

ECDSA 签名方程（群阶为 `n`）：

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

如果同一个 `k` 被用于两条消息 `m1, m2`，并生成签名 `(r, s1)` 和 `(r, s2)`：

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### 无效曲线攻击

如果协议未验证输入点是否位于预期曲线上且属于正确的子群，攻击者可能迫使运算在较弱的群中进行，并恢复有关秘密标量的信息。SEC 1 规定了旨在防止此类输入的公钥验证检查。<sup>[[6]](#references)</sup>

技术说明：

- 验证点不是无穷远点、坐标有效、满足曲线方程，并且属于所需子群。<sup>[[6]](#references)</sup>
- 在 CTF 挑战中，这通常表现为服务器将攻击者选择的点乘以秘密标量，并返回一个派生值。

## 格式错误的 ML-DSA 签名密钥与拒绝采样泄漏

ML-DSA 的展开私钥将多项式向量 `s1` 和 `s2` 编码为系数位于 `[-η, η]` 范围内的形式。FIPS 204 指出，解码格式错误的私钥字节可能产生超出此范围的系数。签名算法本身不要求额外进行私钥一致性检查。<sup>[[8]](#references)</sup>

相关前提是能够控制**导入或用于签名之前的展开签名密钥**，而不是向验证器提交格式错误的公钥。宽松的导入路径可能接受经过篡改的打包系数，并仍然生成可通过验证的签名。可使用[密码学密钥编码 fuzzing 工作流](../../generic-methodologies-and-resources/fuzzing.md#differential-fuzzing-of-cryptographic-key-encodings)，比较导入和签名时的接受情况，然后检查生成的签名。<sup>[[9]](#references)[[10]](#references)</sup>

签名过程计算 `z = y + c·s1` 和 `r0 = LowBits(w − c·s2)`，并在 `||z||∞ ≥ γ1 − β` 或 `||r0||∞ ≥ γ2 − β` 时拒绝候选值。这些检查使被接受的输出与有效的小系数秘密无关。超出范围的秘密系数可能破坏这一拒绝采样论证，并引入依赖于秘密的偏差。这是一种有条件的信息泄漏机制，**并非**已证实能从所报告的库差异中恢复完整密钥。<sup>[[8]](#references)[[10]](#references)</sup>

私钥验证与签名验证是不同的。在所报告的对比中，OpenSSL、BoringSSL 和 SymCrypt 执行了额外的私钥检查，而 liboqs 在签名时接受了格式错误的展开密钥；其底层的 `mldsa-native` 提供了 `pk_from_sk()` 验证器，但 liboqs 未将其公开。FIPS 204 并未强制要求这些额外的验证检查。<sup>[[9]](#references)[[10]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5：数字签名标准](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner 和 Heninger：有偏差的 nonce——针对弱 ECDSA 签名的格攻击](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0：椭圆曲线密码学](https://www.secg.org/sec1-v2.pdf)
- [7] [Python `ecdsa` 文档](https://ecdsa.readthedocs.io/)
- [8] [NIST FIPS 204：基于模块格的数字签名标准](https://doi.org/10.6028/NIST.FIPS.204)
- [9] [缺少 ML-DSA 和 ML-KEM 密钥检查——liboqs issue #2517](https://github.com/open-quantum-safe/liboqs/issues/2517)
- [10] [后量子密码学实现现状](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
