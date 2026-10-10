# RSA攻撃

{{#include ../../../banners/hacktricks-training.md}}

## 迅速なトリアージ

収集する情報:

- `n`、`e`、`c`（および追加の暗号文）
- メッセージ間の関係（同じ平文か、法を共有しているか、構造化された平文か）
- あらゆる leak（`p/q` の一部、`d` のビット、`dp/dq`、既知のパディング）

次に試すこと:

- 素因数分解の確認（Factordb / 小さめの数なら `sage: factor(n)`）
- 小さい指数のパターン（`e=3`、broadcast）
- Common modulus / 素因数の再利用
- ほぼ既知の情報がある場合は格子法（Coppersmith/LLL）

## RSAの一般的な攻撃

### Common modulus

2つの暗号文 `c1, c2` が、異なる指数 `e1, e2`（かつ `gcd(e1,e2)=1`）を使い、**同じ法** `n` の下で**同じメッセージ**を暗号化している場合、拡張ユークリッドの互除法を使って `m` を復元できます。

`m = c1^a * c2^b mod n` ただし `a*e1 + b*e2 = 1`

手順の概要:

1. `(a, b) = xgcd(e1, e2)` を計算し、`a*e1 + b*e2 = 1` を求める
2. `a < 0` の場合、`c1^a` を `inv(c1)^{-a} mod n` として解釈する（`b` も同様）
3. 乗算し、`n` で剰余を取る

### 法をまたいで共有される素因数

同じチャレンジから複数のRSA法を入手した場合、素因数を共有していないか確認します。

- `gcd(n1, n2) != 1` は、鍵生成に致命的な問題があることを意味します。

CTFでは「多数の鍵を短時間で生成した」や「乱数が不適切」といった状況で、よく発生します。

### Sparse / short-sleeve moduli

壊れた一部の多倍長整数ジェネレーターでは、公開法に構造が直接漏れます。各limbに含まれるのは小さなランダムサブフィールドだけで、残りのビットは `0` です。実際には、`n` の中に**一定間隔で並んだゼロブロック**として現れ、多くの場合、32ビットまたは128ビットのlimbに揃っています。<sup>[[1]](#references)</sup>

すばやく確認する方法:

- `n` を16進数で表示し、一定の間隔で繰り返されるゼロのまとまりを探す。
- `n` をlimb（`2^32`、`2^64`、`2^128`）に分割し、各limbが異常に小さくないか確認する。
- ホスト鍵の生成が弱いと疑われる場合、**badkeys** などのツールで公開SSH/TLS鍵を監査する。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

これは単なる統計的な偏りより深刻です。秘密の因数 `p` と `q` がどちらもshort-sleeveなら、法を**容易に素因数分解できる**可能性があります。<sup>[[1]](#references)</sup>

### 構造化されたRSA鍵の多項式因数分解

limb幅を `w` と推定したら、法を底 `B = 2^w` で表します。

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

評価は乗法的なので、`f_a(B) * f_c(B) = (f_a * f_c)(B)` が成り立ちます。因数の係数も疎なlimbであれば、次のようになります。

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

攻撃の概要:

1. limb幅 `w` を推定する。
2. 底 `2^w` を使い、公開法 `n` を `f_n(x)` に変換する。
3. 整数上で `f_n(x)` を因数分解する。
4. 候補となる因数を `B = 2^w` に代入する。
5. どの候補の積が `n` になるか検証する。

これは**通常のRSAを破るものではありません**。素因数自体のlimb係数が非常に小さく、高度に構造化されている場合にのみ有効です。<sup>[[1]](#references)</sup>

### シフトされたlimbのleak

疎なバイト列が、各limbの下位側に揃っているとは限りません。底 `2^w` による直接変換で大きな係数が生じる場合は、そのlimb基数で `2^i p` と `2^j q` が疎になるようなシフト `i,j` を探します。公開法から積の多項式を導出して因数分解し、元の整数の因数に再構成することができます。<sup>[[1]](#references)</sup>

### 実装上の問題の兆候: バイトからlimbへのRNGバグ

危険なパターンとして、**32ビットlimb**の個数を計算し、その数だけの**バイト**しか確保せず、それらをlimb配列にコピーする実装があります。

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

これにより、各32ビット limb のエントロピーはわずか **8 bits** となり、最後の limb には強制的に最上位 bit が設定されます。この方法で生成された RSA 素数は、公開鍵だけから特定して素因数分解できることがよくあります。<sup>[[1]](#references)</sup>

### 関連する DSA の故障モード

同じ壊れた big-integer routine が DSA の秘密指数生成にも再利用されている場合、公開鍵 `y = g^x` から、`x` の探索空間が**大幅に縮小され、特定の構造を持つ**ことが leak する可能性があります。limb のパターンが判明すれば、**baby-step giant-step** などの離散対数攻撃が公開パラメータに対して実用的になることがあります。<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

同じ平文が、適切な padding なしで小さな `e`（多くの場合 `e=3`）を使う複数の受信者に送信されている場合、CRT と整数根を使って `m` を復元できます。

技術的な条件:

同じメッセージの `e` 個の暗号文が、互いに素な法 `n_i` の下で得られている場合:

- CRT を使い、積 `N = Π n_i` に対して `M = m^e` を復元する
- `m^e < N` なら、`M` は真の整数べき乗であり、`m = integer_root(M, e)` となる

### Wiener attack: 小さすぎる秘密指数

`d` が小さすぎる場合、連分数を使って `e/n` から復元できます。

### 教科書的 RSA の落とし穴

次のような場合:

- OAEP/PSS を使わず、生の modular exponentiation を使用している
- Deterministic encryption を使用している

代数的攻撃や oracle の悪用がはるかに容易になります。

### ツール

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT、roots、CF): https://www.sagemath.org/

## 関連メッセージのパターン

同じ modulus の下で、代数的に関連するメッセージ（例: `m2 = a*m1 + b`）の暗号文が2つある場合は、Franklin–Reiter などの「related-message」攻撃を検討してください。通常、次の条件が必要です:

- 同じ modulus `n`
- 同じ exponent `e`
- 平文間の関係が既知

実際には、Sage で `n` を法とする多項式を設定し、GCD を計算して解くことがよくあります。

## Lattices / Coppersmith

部分ビット、構造化された平文、または未知の値が小さくなるような近い関係がある場合に使います。

Lattice 手法 (LLL/Coppersmith) は、部分的な情報がある場合に使われます:

- 一部が既知の平文（末尾が未知の構造化メッセージ）
- 一部が既知の `p`/`q`（上位 bits が leak している）
- 関連する値同士の未知の差が小さい

### 見分けるポイント

チャレンジでよくあるヒント:

- 「p の上位/下位 bits を leak した」
- 「flag は次のように埋め込まれている: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`」
- 「RSA を使ったが、小さなランダム padding を付けた」

### ツール

実際には、LLL には Sage を使い、特定の問題に合った既知の template を利用します。

参考になる出発点:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- サーベイ形式の参考資料: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - 多項式を使った「short-sleeve」RSA key の素因数分解](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys 単体ツール](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

