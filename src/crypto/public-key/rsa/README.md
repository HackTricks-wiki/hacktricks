# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

以下を収集します。

- `n`、`e`、`c`（および追加の ciphertext）
- メッセージ間の関係（同じ plaintext、shared modulus、structured plaintext など）
- あらゆる leak（`p/q` の一部、`d` のビット、`dp/dq`、既知の padding）

次に試します。

- Factorization check（Factordb / 小さめの値なら `sage: factor(n)`）
- Low exponent patterns（`e=3`、broadcast）
- Common modulus / repeated primes
- ほぼ既知の情報がある場合は lattice methods（Coppersmith/LLL）

## Common RSA attacks

### Common modulus

2つの ciphertext `c1, c2` が、異なる exponent `e1, e2`（かつ `gcd(e1,e2)=1`）で、同じ modulus `n` の下で **同じ message** を暗号化している場合、extended Euclidean algorithm を使って `m` を復元できます。

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Example outline:

1. `(a, b) = xgcd(e1, e2)` を計算し、`a*e1 + b*e2 = 1` とする
2. `a < 0` の場合、`c1^a` を `inv(c1)^{-a} mod n` として解釈する（`b` についても同様）
3. 乗算し、`n` を法として reduce する

### Shared primes across moduli

同じ challenge から複数の RSA moduli を入手した場合、prime を共有していないか確認します。

- `gcd(n1, n2) != 1` は、catastrophic な key-generation failure を意味します。

これは、"we generated many keys quickly" や "bad randomness" といった CTFs で頻繁に現れます。

### Sparse / short-sleeve moduli

壊れた big-integer generators の中には、public modulus に構造を直接 leak するものがあります。各 limb に小さな random subfield しか含まれず、残りの bits が `0` になります。実際には、これは `n` 全体にわたって **規則的な間隔で配置された zero blocks** として現れ、多くの場合 32-bit または 128-bit limbs に揃っています。<sup>[[1]](#references)</sup>

Quick checks:

- `n` を hex で dump し、固定 stride で繰り返される zero windows を探す。
- `n` を limbs（`2^32`、`2^64`、`2^128`）として再度 slice し、各 limb が異常に小さくないか確認する。
- host-key generation が弱いと疑われる場合は、**badkeys** などの tooling を使って public SSH/TLS keys を audit する。<sup>[[2]](#references)[[3]](#references)</sup>

これは statistical bias よりも深刻です。private factors `p` と `q` の両方が short-sleeved である場合、modulus が **factor しやすくなる** 可能性があります。<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

疑わしい limb width `w` に対して、modulus を base `B = 2^w` で表します。

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

evaluation は multiplicative であるため、`f_a(B) * f_c(B) = (f_a * f_c)(B)` となります。factors にも sparse な limb coefficients がある場合、次のようになります。

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. limb width `w` を推測する。
2. base `2^w` を使い、public modulus `n` を `f_n(x)` に変換する。
3. `f_n(x)` を integers 上で factor する。
4. candidate factors を `B = 2^w` に戻して evaluate する。
5. どの candidates の積が `n` になるか verify する。

これは **normal RSA を break するものではありません**。prime factors 自体が非常に小さく、高度に構造化された limb coefficients を持つ場合にのみ機能します。<sup>[[1]](#references)</sup>

### Shifted limb leakage

sparse bytes は、必ずしも各 limb の low end に揃っているとは限りません。base-`2^w` による直接変換で大きな coefficients が生成される場合は、`2^i p` と `2^j q` がその limb basis で sparse になるような shifts `i,j` を探索します。product polynomial は引き続き public modulus から導出して factor し、元の integer factors に recombine できます。<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

危険な pattern は、**32-bit limbs** の数を計算し、それだけの **bytes** しか allocate せず、それらを limb array に copy することです。
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
This gives each 32-bit limb only **8ビットのエントロピー**に加え、最後の limb には強制的に最上位ビットが設定されます。その結果生成される RSA 素数は、公開鍵だけから特定・素因数分解できることがよくあります。<sup>[[1]](#references)</sup>

### DSA の関連する failure mode

同じ壊れた big-integer routine が DSA の秘密指数生成にも再利用されている場合、公開鍵 `y = g^x` によって、`x` の探索空間が**大幅に縮小され、構造化されている**ことが leak する可能性があります。limb のパターンが判明すると、**baby-step giant-step** などの discrete-log attacks が公開パラメータに対して実用的になることがあります。<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

同じ plaintext が、小さな `e`（多くの場合 `e=3`）および適切な padding なしで複数の recipient に送信されている場合、CRT と integer root によって `m` を復元できます。

Technical condition:

pairwise-coprime な modulus `n_i` の下で、同じ message の `e` 個の ciphertexts がある場合:

- CRT を使って、積 `N = Π n_i` 上で `M = m^e` を復元する
- `m^e < N` なら、`M` は真の integer power であり、`m = integer_root(M, e)` となる

### Wiener attack: small private exponent

`d` が小さすぎる場合、continued fractions によって `e/n` から復元できます。

### Textbook RSA pitfalls

以下が見られる場合:

- OAEP/PSS なしの raw modular exponentiation
- Deterministic encryption

algebraic attacks や oracle abuse がはるかに起こりやすくなります。

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

同じ modulus の下に、代数的に関連する messages（例: `m2 = a*m1 + b`）を持つ 2 つの ciphertexts がある場合、Franklin–Reiter などの "related-message" attacks を探します。通常、以下が必要です:

- 同じ modulus `n`
- 同じ exponent `e`
- plaintexts 間の既知の関係

実際には、Sage で polynomials を `n` modulo で設定し、GCD を計算して解決することがよくあります。

## Lattices / Coppersmith

partial bits、structured plaintext、または unknown を小さくする close relations がある場合に使用します。

Lattice methods (LLL/Coppersmith) は、partial information がある場合に登場します:

- Partially known plaintext（unknown tail を含む structured message）
- Partially known `p`/`q`（high bits が leak している）
- 関連する values 間の small unknown differences

### What to recognize

challenges における典型的なヒント:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

実際には、LLL と特定の instance 用の既知の template に Sage を使用します。

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
