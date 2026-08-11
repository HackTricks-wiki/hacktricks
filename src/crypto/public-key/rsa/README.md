# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

以下を収集します:

- `n`、`e`、`c`（および追加の ciphertext）
- メッセージ間の関係（同じ plaintext？shared modulus？structured plaintext？）
- あらゆる leak（`p/q` の一部、`d` のビット、`dp/dq`、既知の padding）

次に試します:

- Factorization check（Factordb / 小さめの値なら `sage: factor(n)`）
- Low exponent patterns（`e=3`、broadcast）
- Common modulus / repeated primes
- 何かがほぼ判明している場合の lattice methods（Coppersmith/LLL）

## Common RSA attacks

### Common modulus

2つの ciphertext `c1, c2` が、異なる exponent `e1, e2`（かつ `gcd(e1,e2)=1`）を使用して、同じ modulus `n` の下で **同じ message** を暗号化している場合、拡張 Euclidean algorithm を使って `m` を復元できます:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Example outline:

1. `(a, b) = xgcd(e1, e2)` を計算し、`a*e1 + b*e2 = 1` とする
2. `a < 0` の場合、`c1^a` を `inv(c1)^{-a} mod n` として扱う（`b` についても同様）
3. 乗算し、`n` を法として reduce する

### Shared primes across moduli

同じ challenge から複数の RSA modulus を入手した場合、prime の共有を確認します:

- `gcd(n1, n2) != 1` は、壊滅的な key-generation failure を意味します。

これは CTFs で、「many keys quickly を生成した」または「bad randomness」といった状況で頻繁に発生します。

### Sparse / short-sleeve moduli

一部の壊れた big-integer generators は、public modulus に直接 structure を leak します。各 limb には小さな random subfield だけが含まれ、残りの bits は `0` になります。実際には、これは `n` 全体にわたる **regularly spaced zero blocks** として現れ、多くの場合 32-bit または 128-bit limbs に整列しています。<sup>[[1]](#references)</sup>

Quick checks:

- `n` を hex で dump し、固定 stride で繰り返される zero windows を探す。
- `n` を limbs（`2^32`、`2^64`、`2^128`）として再分割し、各 limb が異常に小さくないか調べる。
- host-key generation が弱い疑いがある場合、**badkeys** などの tooling で public SSH/TLS keys を audit する。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

これは statistical bias よりも深刻です。private factors `p` と `q` の両方が short-sleeved の場合、modulus が **easy to factor** になる可能性があります。<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

想定される limb width を `w` とし、modulus を base `B = 2^w` で表します:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

evaluation は multiplicative であるため、`f_a(B) * f_c(B) = (f_a * f_c)(B)` となります。factor にも sparse limb coefficients がある場合:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. limb width `w` を推測する。
2. base `2^w` を使用して、public modulus `n` を `f_n(x)` に変換する。
3. `f_n(x)` を integers 上で factor する。
4. candidate factors を `B = 2^w` で evaluate する。
5. どの candidates の積が `n` になるか verify する。

これは **normal RSA を break するものではありません**。prime factors 自体が非常に小さく、高度に structured な limb coefficients を持つ場合にのみ機能します。<sup>[[1]](#references)</sup>

### Shifted limb leakage

sparse bytes は、常に各 limb の low end に整列しているとは限りません。base-`2^w` による直接 conversion で大きな coefficients が生成される場合は、`2^i p` と `2^j q` がその limb basis で sparse になるような shifts `i,j` を探索します。product polynomial は引き続き public modulus から導出して factor でき、元の integer factors に recombine できます。<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

危険な pattern は、**32-bit limbs** の数を計算し、それだけの数の **bytes** しか allocate せず、それらを limb array に copy することです:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
これにより、各 32-bit limb には **8 ビットのエントロピー**しかなく、最後の limb には強制的に最上位ビットが設定されます。その結果生成される RSA 素数は、公開鍵だけから認識して factor できることがよくあります。<sup>[[1]](#references)</sup>

### Related DSA failure mode

同じ壊れた big-integer routine が DSA の private exponent 生成にも再利用されている場合、公開鍵 `y = g^x` から `x` の探索空間が**劇的に縮小され、構造化されている**ことが leak する可能性があります。limb pattern が判明すると、**baby-step giant-step** などの discrete-log attacks が公開パラメータに対して実用的になる場合があります。<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

同じ plaintext が、小さい `e`（多くの場合 `e=3`）を使用する複数の recipient に、適切な padding なしで送信されている場合、CRT と integer root により `m` を復元できます。

Technical condition:

pairwise-coprime な modulus `n_i` の下で、同じ message の `e` 個の ciphertexts がある場合:

- CRT を使用して、積 `N = Π n_i` 上で `M = m^e` を復元する
- `m^e < N` の場合、`M` は真の integer power であり、`m = integer_root(M, e)` となる

### Wiener attack: small private exponent

`d` が小さすぎる場合、continued fractions により `e/n` から復元できます。

### Textbook RSA pitfalls

以下のようなものを見つけた場合:

- OAEP/PSS なしの raw modular exponentiation
- Deterministic encryption

algebraic attacks や oracle abuse が発生する可能性が大幅に高くなります。

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

同じ modulus の下に、algebraically related な messages（例: `m2 = a*m1 + b`）を含む 2 つの ciphertexts がある場合、Franklin–Reiter などの "related-message" attacks を探します。通常、以下が必要です:

- 同じ modulus `n`
- 同じ exponent `e`
- plaintexts 間の既知の relationship

実際には、Sage で `n` を法とする polynomials を設定し、GCD を計算して解決することがよくあります。

## Lattices / Coppersmith

partial bits、structured plaintext、または unknown を小さくする close relations がある場合に使用します。

Lattice methods (LLL/Coppersmith) は、partial information があるときに登場します:

- Partially known plaintext (unknown tail を含む structured message)
- Partially known `p`/`q` (high bits が leak している)
- Related values 間の small unknown differences

### What to recognize

Challenges における典型的な hints:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

実際には、LLL と特定の instance 用の既知の template に Sage を使用します。

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - polynomials による「short-sleeve」RSA keys の factoring](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
