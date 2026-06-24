# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

收集：

- `n`, `e`, `c`（以及任何额外的 ciphertexts）
- 消息之间的任何关系（相同 plaintext？共享 modulus？structured plaintext？）
- 任何 leak（`p/q` 的部分信息、`d` 的位、`dp/dq`、已知 padding）

然后尝试：

- Factorization 检查（小一点的用 Factordb / `sage: factor(n)`）
- 低指数模式（`e=3`，broadcast）
- common modulus / repeated primes
- 当某些内容几乎已知时，使用 lattice methods（Coppersmith/LLL）

## Common RSA attacks

### Common modulus

如果两个 ciphertexts `c1`, `c2` 在**相同 modulus** `n` 下、使用不同 exponent `e1`, `e2` 加密了**同一条 message**（且 `gcd(e1,e2)=1`），可以使用扩展 Euclidean algorithm 恢复 `m`：

`m = c1^a * c2^b mod n`，其中 `a*e1 + b*e2 = 1`.

示例步骤：

1. 计算 `(a, b) = xgcd(e1, e2)`，使得 `a*e1 + b*e2 = 1`
2. 如果 `a < 0`，将 `c1^a` 解释为 `inv(c1)^{-a} mod n`（`b` 同理）
3. 相乘并对 `n` 取模

### Shared primes across moduli

如果你有同一 challenge 的多个 RSA moduli，检查它们是否共享一个 prime：

- `gcd(n1, n2) != 1` 表示密钥生成发生了灾难性失败。

这在 CTFs 中很常见，表现为“我们快速生成了很多 keys”或“bad randomness”。

### Sparse / short-sleeve moduli

某些有问题的 big-integer generators 会把结构直接泄漏到 public modulus 中：每个 limb 只包含一个很小的 random subfield，其余 bits 都是 `0`。实际中这表现为 `n` 上**规则间隔的零块**，通常按 32-bit 或 128-bit limbs 对齐。

快速检查：

- 将 `n` 以 hex 转储，查看是否存在固定步长重复出现的零窗口。
- 按 limbs（`2^32`、`2^64`、`2^128`）重新切分 `n`，检查每个 limb 是否异常地小。
- 当你怀疑 host-key 生成薄弱时，使用 **badkeys** 等工具审计公开的 SSH/TLS keys。

这比统计偏差更严重：如果私钥因子 `p` 和 `q` 都是 short-sleeved，那么 modulus 可能会**很容易被分解**。

### Polynomial factorization of structured RSA keys

对于怀疑 limb 宽度为 `w` 的情况，将 modulus 写成基数 `B = 2^w`：

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

因为求值满足乘法性，`f_a(B) * f_c(B) = (f_a * f_c)(B)`。如果因子也具有稀疏的 limb 系数，那么：

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

攻击步骤：

1. 猜测 limb 宽度 `w`。
2. 使用基数 `2^w` 将 public modulus `n` 转换为 `f_n(x)`。
3. 在整数上对 `f_n(x)` 分解。
4. 将候选因子重新代回 `B = 2^w` 计算。
5. 验证哪些候选值相乘等于 `n`。

这**不会破坏正常的 RSA**。它只在 prime factors 本身具有非常小、且高度结构化的 limb 系数时有效。

### Shifted limb leakage

稀疏 bytes 并不总是对齐在每个 limb 的低位端。如果直接做基于 `2^w` 的转换得到很大的系数，就搜索偏移 `i,j`，使得 `2^i p` 和 `2^j q` 在该 limb 基下变得稀疏。乘积 polynomial 仍然可以从 public modulus 导出、分解，并重新组合成原始整数因子。

### Implementation smell: byte-to-limb RNG bug

一个危险模式是：计算 **32-bit limbs** 的数量，却只分配那么多 **bytes**，然后把它们复制到 limb array 中：
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
这会让每个 32-bit limb 只有 **8 bits of entropy**，并且在最后一个 limb 里强制设置最高位。因此得到的 RSA primes 往往可以仅凭 public key 就被识别并分解。

### Related DSA failure mode

如果同一个有问题的 big-integer routine 被复用到 DSA private exponent 生成，public key `y = g^x` 可能会泄露一个 **明显缩小且结构化的** `x` 搜索空间。一旦 limb pattern 已知，像 **baby-step giant-step** 这样的 discrete-log attacks 就可能对 public parameters 变得可行。

### Håstad broadcast / low exponent

如果同一个 plaintext 以较小的 `e`（通常 `e=3`）且没有正确 padding 的方式发送给多个接收者，你可以通过 CRT 和 integer root 恢复 `m`。

Technical condition:

如果你有 `e` 个相同消息的 ciphertexts，且对应的模数 `n_i` 两两互素：

- 使用 CRT 恢复 `M = m^e`，其模数积为 `N = Π n_i`
- 如果 `m^e < N`，那么 `M` 就是真实的整数幂，而 `m = integer_root(M, e)`

### Wiener attack: small private exponent

如果 `d` 太小，continued fractions 可以从 `e/n` 恢复它。

### Textbook RSA pitfalls

如果你看到：

- 没有 OAEP/PSS，直接做 raw modular exponentiation
- Deterministic encryption

那么 algebraic attacks 和 oracle abuse 就会更容易发生。

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

如果你看到同一 modulus 下的两个 ciphertexts，其 messages 之间存在代数相关关系（例如 `m2 = a*m1 + b`），就要寻找诸如 Franklin–Reiter 这类 "related-message" attacks。这类攻击通常需要：

- same modulus `n`
- same exponent `e`
- 已知 plaintexts 之间的关系

在实践中，这通常可以用 Sage 通过在 `n` 下建立 polynomials 并计算 GCD 来解决。

## Lattices / Coppersmith

当你掌握了部分 bits、structured plaintext，或能形成使未知量较小的接近关系时，就该用这个方法。

Lattice methods (LLL/Coppersmith) 会在你拥有部分信息时出现：

- 部分已知 plaintext（structured message 但尾部未知）
- 部分已知 `p`/`q`（high bits leaked）
- 相关值之间存在较小的未知差值

### What to recognize

挑战中的典型提示：

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

实际上你会用 Sage 来做 LLL，并针对具体实例使用已知模板。

好的起点：

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
