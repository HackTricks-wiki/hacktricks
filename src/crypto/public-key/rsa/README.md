# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

収集するもの:

- `n`, `e`, `c`（および追加のciphertexts）
- message同士の関係（同じplaintext? shared modulus? structured plaintext?）
- any leaks（部分的な `p/q`、`d` のビット、`dp/dq`、既知のpadding）

次に試すもの:

- Factorization check（Factordb / `sage: factor(n)` for small-ish）
- 低指数パターン（`e=3`、broadcast）
- Common modulus / repeated primes
- Lattice methods（Coppersmith/LLL）で、何かがほぼ既知な場合

## Common RSA attacks

### Common modulus

2つのciphertexts `c1, c2` が、**同じmessage** を **同じmodulus** `n` で、ただし異なるexponents `e1, e2`（かつ `gcd(e1,e2)=1`）でencryptしているなら、拡張Euclidean algorithmを使って `m` を復元できます:

`m = c1^a * c2^b mod n` ただし `a*e1 + b*e2 = 1`.

例:

1. `(a, b) = xgcd(e1, e2)` を計算して `a*e1 + b*e2 = 1` にする
2. `a < 0` なら、`c1^a` を `inv(c1)^{-a} mod n` と解釈する（`b` も同様）
3. 掛け算して `n` でmodする

### Shared primes across moduli

同じchallengeから複数のRSA moduliがあるなら、primeを共有していないか確認します:

- `gcd(n1, n2) != 1` は、致命的なkey-generation failure を意味します。

これはCTFで「たくさんのkeysを素早く生成した」「bad randomness」として頻出します。

### Sparse / short-sleeve moduli

壊れたbig-integer generatorの中には、public modulus に直接構造が漏れるものがあります: 各limbが小さなrandom subfieldしか持たず、残りのbitsが `0` です。実際には、`n` 全体に**規則的に並んだzero blocks**として現れ、しばしば 32-bit または 128-bit limb に揃っています。

簡単な確認:

- `n` をhexで出力し、一定のstrideで繰り返すzero windowがないか見る。
- `n` を limb（`2^32`, `2^64`, `2^128`）として再分割し、各 limb が異常に小さくないか調べる。
- 弱いhost-key generation が疑われるなら、**badkeys** のようなツールで public SSH/TLS keys を監査する。

これは統計的なbiasより深刻です: もし private factors `p` と `q` の両方が short-sleeved なら、modulus は**簡単にfactor**できる可能性があります。

### Polynomial factorization of structured RSA keys

疑わしい limb width `w` に対して、modulus を base `B = 2^w` で書きます:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

評価は乗法的なので、`f_a(B) * f_c(B) = (f_a * f_c)(B)` です。factor も sparse limb coefficients を持つなら、次が成り立ちます:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

攻撃の流れ:

1. limb width `w` を推測する。
2. public modulus `n` を base `2^w` で `f_n(x)` に変換する。
3. `f_n(x)` を整数上でfactorする。
4. 候補factorを `B = 2^w` で再評価する。
5. どの候補が `n` と掛けて一致するか確認する。

これは**通常のRSAは破りません**。prime factors 自体が非常に小さく、強く構造化された limb coefficients を持つ場合だけ機能します。

### Shifted limb leakage

sparse bytes が必ずしも各 limb の下位端に揃っているとは限りません。base-`2^w` への直接変換で大きな係数が出るなら、`2^i p` と `2^j q` がその limb basis で sparse になるような shift `i,j` を探します。product polynomial は public modulus から導出でき、factor して元のinteger factors に再結合できます。

### Implementation smell: byte-to-limb RNG bug

危険なパターンは、**32-bit limbs** の数を計算し、**bytes** をその数だけしか確保せず、それを limb array にコピーすることです:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
このため、各32-bit limbに含まれるエントロピーは**8 bits**だけになり、さらに最後の limb には強制的に上位ビットが立ちます。その結果、RSA primes は public key だけからしばしば認識でき、factoring できます。

### Related DSA failure mode

同じ壊れた big-integer routine が DSA private exponent generation に再利用されると、public key `y = g^x` が `x` に対する**大幅に縮小され構造化された**探索空間を漏らす可能性があります。limb pattern が分かれば、**baby-step giant-step** のような discrete-log attacks が public parameters に対して実用的になることがあります。

### Håstad broadcast / low exponent

同じ plaintext が小さい `e`（多くは `e=3`）で、proper padding なしに複数の受信者へ送られる場合、CRT と整数 root を使って `m` を復元できます。

Technical condition:

pairwise-coprime な moduli `n_i` の下で、同じ message の `e` ciphertexts がある場合:

- CRT を使って積 `N = Π n_i` 上で `M = m^e` を復元する
- もし `m^e < N` なら、`M` は真の整数べきであり、`m = integer_root(M, e)`

### Wiener attack: small private exponent

`d` が小さすぎる場合、continued fractions で `e/n` からそれを復元できます。

### Textbook RSA pitfalls

次のような場合:

- OAEP/PSS なし、raw modular exponentiation
- Deterministic encryption

algebraic attacks や oracle abuse がはるかに起こりやすくなります。

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

同じ modulus の下で、代数的に関連する message を持つ2つの ciphertexts が見つかったら（例: `m2 = a*m1 + b`）、Franklin–Reiter のような "related-message" attacks を探してください。これらは通常、次を必要とします:

- same modulus `n`
- same exponent `e`
- plaintext 間の既知の関係

実際には、Sage で `n` を法とする多項式を設定し、GCD を計算することで解決されることが多いです。

## Lattices / Coppersmith

未知部分が小さい、partial bits、structured plaintext、または近い関係がある場合にこれを使います。

Lattice methods (LLL/Coppersmith) は、partial information があるときに現れます:

- 一部だけ既知の plaintext（未知の末尾を持つ構造化 message）
- 一部だけ既知の `p`/`q`（上位ビットが漏えい）
- 関連する値の間の小さな未知差分

### What to recognize

challenge での典型的なヒント:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

実践では、LLL 用に Sage を使い、特定の instance に対する既知の template を使います。

良い開始点:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
