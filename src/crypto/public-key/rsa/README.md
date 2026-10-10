# RSA 攻击

{{#include ../../../banners/hacktricks-training.md}}

## 快速初步排查

收集：

- `n`、`e`、`c`（以及任何其他密文）
- 消息之间的任何关联（明文相同？模数相同？明文结构化？）
- 任何 leak（部分 `p/q`、`d` 的位、`dp/dq`、已知填充方式）

然后尝试：

- 因数分解检查（Factordb / 对较小的 `n` 使用 `sage: factor(n)`）
- 低指数模式（`e=3`、广播）
- Common modulus / 重复素数
- 当部分信息已知时，尝试格方法（Coppersmith/LLL）

## 常见 RSA 攻击

### Common modulus

如果两个密文 `c1, c2` 在**相同模数** `n` 下、使用不同指数 `e1, e2`（且 `gcd(e1,e2)=1`）加密了**同一条消息**，可以使用扩展欧几里得算法恢复 `m`：

`m = c1^a * c2^b mod n`，其中 `a*e1 + b*e2 = 1`。

示例步骤：

1. 计算 `(a, b) = xgcd(e1, e2)`，使得 `a*e1 + b*e2 = 1`
2. 如果 `a < 0`，则将 `c1^a` 解释为 `inv(c1)^{-a} mod n`（`b` 同理）
3. 相乘并对 `n` 取模

### 模数之间共享素数

如果同一个挑战中有多个 RSA 模数，请检查它们是否共享一个素数：

- `gcd(n1, n2) != 1` 表示密钥生成出现了灾难性故障。

在 CTF 中，这种情况经常出现在“我们快速生成了很多密钥”或“随机数质量差”的场景。

### 稀疏 / 短袖模数

某些有缺陷的大整数生成器会将结构直接泄露到公钥模数中：每个 limb 只包含一个很小的随机子字段，其余位都是 `0`。实际上，这通常表现为 `n` 中**间隔规律的零块**，而且这些零块往往与 32 位或 128 位 limb 对齐。<sup>[[1]](#references)</sup>

快速检查：

- 将 `n` 转储为十六进制，查找按固定间隔重复出现的零区段。
- 将 `n` 重新切分为 limb（`2^32`、`2^64`、`2^128`），检查每个 limb 是否异常小。
- 怀疑主机密钥生成存在弱点时，可使用 **badkeys** 等工具审计公开的 SSH/TLS 密钥。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

这比统计偏差更严重：如果私有因子 `p` 和 `q` 都是短袖的，模数可能会**很容易分解**。<sup>[[1]](#references)</sup>

### 结构化 RSA 密钥的多项式因式分解

对于怀疑的 limb 宽度 `w`，将模数按 `B = 2^w` 进制表示：

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

由于求值具有乘法性质，`f_a(B) * f_c(B) = (f_a * f_c)(B)`。如果因子的 limb 系数也足够稀疏，那么：

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

攻击步骤：

1. 猜测 limb 宽度 `w`。
2. 使用底数 `2^w` 将公钥模数 `n` 转换为 `f_n(x)`。
3. 在整数范围内分解 `f_n(x)`。
4. 将候选因子代入 `B = 2^w` 求值。
5. 验证哪些候选因子的乘积等于 `n`。

这**不会破解正常的 RSA**。只有当素数因子本身的 limb 系数非常小且具有高度结构化特征时，这种方法才有效。<sup>[[1]](#references)</sup>

### 移位的 limb 泄露

稀疏字节不一定总是与每个 limb 的低位对齐。如果直接按 `2^w` 进制转换会产生较大的系数，可以搜索移位量 `i,j`，使得 `2^i p` 和 `2^j q` 在该 limb 进制下变得稀疏。仍然可以从公钥模数推导出乘积多项式，对其进行因式分解，再组合还原出原始整数因子。<sup>[[1]](#references)</sup>

### 实现隐患：byte-to-limb RNG bug

一种危险的模式是：计算 **32 位 limb** 的数量，只分配这么多**字节**，然后将它们复制到 limb 数组中：

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

这使得每个 32-bit limb 只有 **8 bits 的熵**，并且最后一个 limb 的最高位被强制置位。仅凭公钥通常就能识别并分解由此生成的 RSA 素数。<sup>[[1]](#references)</sup>

### 相关的 DSA 故障模式

如果 DSA 私有指数生成也复用了同一个有缺陷的大整数例程，那么公钥 `y = g^x` 可能会泄露一个**大幅缩小且具有特定结构**的 `x` 搜索空间。一旦已知 limb 模式，baby-step giant-step 等离散对数攻击就可能适用于这些公开参数。<sup>[[1]](#references)</sup>

### Håstad 广播 / 低指数

如果同一明文在没有适当填充的情况下发送给多个接收方，且使用较小的 `e`（通常为 `e=3`），你可以通过 CRT 和整数开方恢复 `m`。

技术条件：

如果你有同一消息在两两互素的模数 `n_i` 下的 `e` 个密文：

- 使用 CRT 在乘积 `N = Π n_i` 上恢复 `M = m^e`
- 如果 `m^e < N`，那么 `M` 就是真实的整数幂，且 `m = integer_root(M, e)`

### Wiener 攻击：私有指数过小

如果 `d` 太小，可以通过对 `e/n` 使用连分数来恢复它。

### 教科书式 RSA 的陷阱

如果你发现：

- 没有 OAEP/PSS，使用原始模幂运算
- 确定性加密

那么代数攻击和滥用 oracle 的可能性会大得多。

### 工具

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath（CRT、开方、CF）: https://www.sagemath.org/

## 相关消息模式

如果你发现同一模数下有两个密文，且其消息之间存在代数关系（例如 `m2 = a*m1 + b`），可以寻找 Franklin–Reiter 等“related-message”攻击。这类攻击通常要求：

- 相同的模数 `n`
- 相同的指数 `e`
- 明文之间的关系已知

实际上，通常可以通过 Sage 设置模 `n` 的多项式并计算 GCD 来解决。

## 格与 Coppersmith

当你掌握部分位、结构化明文或使未知数较小的紧密关系时，可以考虑使用这种方法。

只要存在部分信息，就可能用到格方法（LLL/Coppersmith）：

- 部分已知的明文（带有未知尾部的结构化消息）
- 部分已知的 `p`/`q`（高位已泄露）
- 相关值之间未知但较小的差值

### 如何识别

挑战中常见的提示：

- “我们泄露了 p 的高位/低位”
- “flag 的嵌入方式是：`m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`”
- “我们使用了 RSA，但随机填充很短”

### 工具

实际使用时，你会用 Sage 运行 LLL，并采用适用于特定实例的已知模板。

推荐的起点：

- Sage CTF crypto 模板: https://github.com/defund/coppersmith
- 一篇综述式参考资料: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - 使用多项式分解“短袖”RSA 密钥](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys 独立工具](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

