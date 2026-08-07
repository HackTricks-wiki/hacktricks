# 公钥密码学

{{#include ../../banners/hacktricks-training.md}}


大多数 CTF 高难度密码题最终都会涉及这些内容：RSA、ECC/ECDSA、lattices 以及糟糕的随机性。

## 推荐工具

- SageMath（LLL/lattices、模运算）：https://www.sagemath.org/
- RsaCtfTool（瑞士军刀）：https://github.com/Ganapati/RsaCtfTool
- factordb（快速因数分解检查）：http://factordb.com/

## RSA

当你拥有 `n,e,c` 以及一些额外提示（shared modulus、low exponent、partial bits、related messages）时，从这里开始。

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

如果涉及签名，首先测试 nonce 问题（reuse/bias/leaks），再考虑复杂的数学问题。

### ECDSA nonce reuse / bias

如果两个签名复用了相同的 nonce `k`，就可以恢复私钥。

即使 `k` 并不完全相同，跨多个签名的 nonce bits **bias/leakage** 也可能足以通过 lattice recovery 恢复密钥（常见 CTF 主题）。

`k` 被复用时的技术恢复过程：

ECDSA 签名方程（group order `n`）：

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

如果相同的 `k` 被用于两个消息 `m1, m2`，并生成签名 `(r, s1)` 和 `(r, s2)`：

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

如果协议未验证点是否位于预期曲线上（或属于正确的 subgroup），攻击者可能迫使运算在弱群中进行，从而恢复秘密。

技术注意事项：

- 验证点位于曲线上且属于正确的 subgroup。
- 许多 CTF 任务会将其建模为“server 将 attacker-chosen point 与 secret scalar 相乘，并返回某些结果”。

### 工具

- SageMath：用于 curve arithmetic / lattices
- `ecdsa` Python library：用于解析/验证

{{#include ../../banners/hacktricks-training.md}}
