# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## 快速分诊

收集：

- `n`、`e`、`c`（以及任何额外的 ciphertext）
- 消息之间的任何关系（相同明文？共享 modulus？结构化明文？）
- 任何 leaks（部分 `p/q`、`d` 的 bit、`dp/dq`、已知 padding）

然后尝试：

- Factorization 检查（Factordb / 对较小的值使用 `sage: factor(n)`）
- 低 exponent 模式（`e=3`、broadcast）
- Common modulus / 重复 primes
- 当部分内容几乎已知时使用 lattice methods（Coppersmith/LLL）

## 常见 RSA attacks

### Common modulus

如果两个 ciphertext `c1, c2` 在相同的 modulus `n` 下、使用不同的 exponents `e1, e2` 加密**同一条消息**（且 `gcd(e1,e2)=1`），则可以使用 extended Euclidean algorithm 恢复 `m`：

`m = c1^a * c2^b mod n`，其中 `a*e1 + b*e2 = 1`。

示例步骤：

1. 计算 `(a, b) = xgcd(e1, e2)`，使 `a*e1 + b*e2 = 1`
2. 如果 `a < 0`，将 `c1^a` 解释为 `inv(c1)^{-a} mod n`（`b` 同理）
3. 相乘并对 `n` 取模

### 不同 modulus 之间共享 primes

如果你从同一个 challenge 中获得多个 RSA modulus，检查它们是否共享一个 prime：

- `gcd(n1, n2) != 1` 表示灾难性的 key-generation failure。

这通常会在 CTF 中以“我们快速生成了许多 keys”或“随机性很差”的形式出现。

### Sparse / short-sleeve moduli

某些损坏的 big-integer generators 会将结构直接泄露到 public modulus 中：每个 limb 只包含一个很小的随机子字段，其余 bit 都是 `0`。实际表现通常是 `n` 中存在**规律间隔的 zero blocks**，并且经常与 32-bit 或 128-bit limbs 对齐。<sup>[[1]](#references)</sup>

快速检查：

- 将 `n` 转储为 hex，寻找固定 stride 上重复出现的 zero windows。
- 将 `n` 重新切分为 limbs（`2^32`、`2^64`、`2^128`），检查每个 limb 是否异常地小。
- 当怀疑 host-key generation 较弱时，使用 **badkeys** 等 tooling 审计 public SSH/TLS keys。<sup>[[2]](#references)[[3]](#references)</sup>

这比 statistical bias 更严重：如果两个 private factors `p` 和 `q` 都是 short-sleeved，modulus 可能会变得**很容易 factor**。<sup>[[1]](#references)</sup>

### 结构化 RSA keys 的 Polynomial factorization

对于疑似的 limb width `w`，在 base `B = 2^w` 下表示 modulus：

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

由于 evaluation 具有 multiplicative 性质，`f_a(B) * f_c(B) = (f_a * f_c)(B)`。如果 factors 也具有 sparse limb coefficients，则：

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack 步骤：

1. 猜测 limb width `w`。
2. 使用 base `2^w` 将 public modulus `n` 转换为 `f_n(x)`。
3. 在 integers 上 factor `f_n(x)`。
4. 在 `B = 2^w` 下重新 evaluation 候选 factors。
5. 验证哪些候选 factors 相乘后等于 `n`。

这**不会 break normal RSA**。它只在 prime factors 本身具有非常小且高度结构化的 limb coefficients 时有效。<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse bytes 并不总是与每个 limb 的低位对齐。如果直接进行 base-`2^w` 转换会产生较大的 coefficients，则搜索满足以下条件的 shifts `i,j`：`2^i p` 和 `2^j q` 在该 limb basis 下变得 sparse。仍然可以从 public modulus 推导 product polynomial，将其 factor，然后 recombine 成原始 integer factors。<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

一种危险模式是计算 **32-bit limbs** 的数量、只分配那么多 **bytes**，然后将它们复制到 limb array 中：
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
这使得每个 32-bit limb 只有 **8 bits of entropy**，并且最后一个 limb 的最高位被强制设置。生成的 RSA 素数通常可以仅凭 public key 识别并分解。<sup>[[1]](#references)</sup>

### Related DSA failure mode

如果同一个损坏的 big-integer routine 被复用于生成 DSA private exponent，public key `y = g^x` 可能会泄露一个**大幅缩小且具有结构化的** `x` 搜索空间。一旦已知 limb pattern，诸如 **baby-step giant-step** 的 discrete-log attacks 就可能针对 public parameters 变得可行。<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

如果同一明文在使用较小 `e`（通常为 `e=3`）且没有 proper padding 的情况下发送给多个 recipients，你可以通过 CRT 和 integer root 恢复 `m`。

技术条件：

如果你拥有同一消息在两两互素的模数 `n_i` 下对应的 `e` 个 ciphertext：

- 使用 CRT 在乘积 `N = Π n_i` 上恢复 `M = m^e`
- 如果 `m^e < N`，那么 `M` 就是真实的 integer power，并且 `m = integer_root(M, e)`

### Wiener attack: small private exponent

如果 `d` 太小，可以通过 continued fractions 从 `e/n` 中恢复它。

### Textbook RSA pitfalls

如果你看到：

- 没有 OAEP/PSS，使用 raw modular exponentiation
- Deterministic encryption

那么 algebraic attacks 和 oracle abuse 的可能性会大幅增加。

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

如果你看到两个 ciphertext 使用同一个 modulus，且其消息存在代数关系（例如 `m2 = a*m1 + b`），请关注 Franklin–Reiter 等 "related-message" attacks。这些攻击通常要求：

- same modulus `n`
- same exponent `e`
- 已知 plaintext 之间的关系

实践中，通常可以使用 Sage 设置模 `n` 的 polynomials，并计算 GCD 来解决。

## Lattices / Coppersmith

当你拥有 partial bits、structured plaintext，或使未知量变小的 closely related relations 时，可以考虑使用这一方法。

Lattice methods (LLL/Coppersmith) 会在你拥有 partial information 时出现：

- Partially known plaintext（具有结构、但尾部未知的 message）
- Partially known `p`/`q`（high bits 已 leak）
- Related values 之间较小的 unknown differences

### What to recognize

Challenges 中的典型提示：

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

实践中，你会使用 Sage 进行 LLL，并针对具体 instance 使用已知 template。

良好的起点：

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
