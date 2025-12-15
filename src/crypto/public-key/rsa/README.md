# RSA 攻击

{{#include ../../../banners/hacktricks-training.md}}

## 快速初筛

收集：

- `n`, `e`, `c` (以及任何额外的密文)
- 任何消息之间的关系（相同明文？共享模数？结构化明文？）
- Any leaks (部分 `p/q`，`d` 的位，`dp/dq`，已知 padding)

然后尝试：

- 因式分解检查（Factordb / `sage: factor(n)` 用于较小的情况）
- 低指数模式（`e=3`，broadcast）
- 共用模数 / 重复质数
- 格方法（Coppersmith/LLL），当某些信息几乎已知时

## 常见 RSA 攻击

### 共用模数

如果两个密文 `c1, c2` 在相同模数 `n` 下加密了 **相同的消息**，但使用不同的指数 `e1, e2`（且 `gcd(e1,e2)=1`），可以使用扩展欧几里得算法恢复 `m`：

`m = c1^a * c2^b mod n` 其中 `a*e1 + b*e2 = 1`。

示例步骤：

1. 计算 `(a, b) = xgcd(e1, e2)`，使得 `a*e1 + b*e2 = 1`
2. 如果 `a < 0`，将 `c1^a` 视为 `inv(c1)^{-a} mod n`（`b` 同理）
3. 相乘并对 `n` 取模

### 模数间共享质因数

如果在同一题目中有多个 RSA 模数，检查它们是否共享质因数：

- `gcd(n1, n2) != 1` 意味着严重的密钥生成失败。

这在 CTFs 中经常出现，通常是“我们快速生成了很多密钥”或“随机性不足”。

### Håstad broadcast / low exponent

如果相同明文被发送给多个接收方，使用很小的 `e`（通常 `e=3`）并且没有正确的 padding，你可以通过 CRT 和整数根恢复 `m`。

技术条件：

如果你有 `e` 个针对相同消息、模数两两互素的密文 `n_i`：

- 使用 CRT 在乘积 `N = Π n_i` 上恢复 `M = m^e`
- 如果 `m^e < N`，则 `M` 即为真正的整数幂，`m = integer_root(M, e)`

### Wiener attack: small private exponent

如果 `d` 太小，连分数（continued fractions）可以从 `e/n` 中恢复它。

### Textbook RSA 陷阱

如果你看到：

- 没有 OAEP/PSS，原始模幂运算
- 确定性加密

那么代数攻击和 oracle 滥用的可能性大大增加。

### 工具

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## 相关消息模式

如果在相同模数下看到两个密文，其明文在代数上相关（例如 `m2 = a*m1 + b`），查找诸如 Franklin–Reiter 的 "related-message" 攻击。这类攻击通常需要：

- 相同模数 `n`
- 相同指数 `e`
- 已知的明文之间的关系

在实践中，通常用 Sage 建立模 `n` 的多项式并计算 GCD 来解决此类问题。

## 格 / Coppersmith

当你有部分已知位、结构化明文，或使未知量很小时的紧密关系时，使用此类方法。

当存在部分信息时，格方法（LLL/Coppersmith）会派上用场：

- 部分已知明文（带未知尾部的结构化消息）
- 部分已知 `p`/`q`（高位 leak）
- 相关值之间的小未知差异

### 识别提示

题目中的典型提示：

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### 工具链

实际操作中，你会使用 Sage 做 LLL，并针对具体实例使用已知模板。

良好起点：

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
