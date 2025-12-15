# RSA 攻撃

{{#include ../../../banners/hacktricks-training.md}}

## 迅速なトリアージ

収集するもの:

- `n`, `e`, `c`（および追加の暗号文）
- メッセージ間の関係（同一の平文か？ モジュラスを共有しているか？ 構造化された平文か？）
- 任意の leaks（部分的な `p/q`、`d` のビット、`dp/dq`、既知のパディング）

次に試すこと:

- 因数分解の確認 (Factordb / `sage: factor(n)` — 小規模向け)
- 低指数パターン（`e=3`、broadcast）
- 共通モジュラス / 繰り返しの素因数
- 何かがほぼ既知の場合は Lattice methods (Coppersmith/LLL)

## 一般的な RSA 攻撃

### Common modulus

もし2つの暗号文 `c1, c2` が同じモジュラス `n` の下で（異なる指数 `e1, e2` を使って）同じメッセージを暗号化しており（かつ `gcd(e1,e2)=1`）、拡張ユークリッド算法で `m` を復元できます:

`m = c1^a * c2^b mod n` ただし `a*e1 + b*e2 = 1`。

例（概要）:

1. `(a, b) = xgcd(e1, e2)` を計算して `a*e1 + b*e2 = 1` を得る
2. `a < 0` の場合、`c1^a` は `inv(c1)^{-a} mod n` と解釈する（`b` も同様）
3. 掛け合わせて `n` で剰余を取る

### Shared primes across moduli

同一のチャレンジから得た複数の RSA モジュラスがあるなら、素因数を共有していないかチェックする:

- `gcd(n1, n2) != 1` は致命的な鍵生成の失敗を意味する。

CTFs では「多数の鍵を素早く生成した」や「ランダム性が弱い」といったケースでよく見られる。

### Håstad broadcast / low exponent

同一の平文が複数受信者に対して小さい `e`（しばしば `e=3`）で、適切なパディングなしに送られている場合、CRT と integer_root を使って `m` を復元できます。

技術的条件:

互いに素なモジュラス `n_i` 下で同一メッセージの暗号文が `e` 個ある場合:

- CRT を使って積 `N = Π n_i` 上で `M = m^e` を復元する
- もし `m^e < N` なら、`M` は真の整数冪なので `m = integer_root(M, e)`

### Wiener attack: small private exponent

もし `d` が小さすぎると、連分数を用いて `e/n` から `d` を復元できる。

### Textbook RSA pitfalls

もし次のような状態が見られるなら:

- OAEP/PSS がなく、生のモジュラ冪乗を使っている
- 決定論的な暗号化

代数的攻撃やオラクルの悪用がずっと現実的になる。

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## 関連メッセージのパターン

もし同じモジュラス下で、メッセージが代数的に関連している（例: `m2 = a*m1 + b`）2つの暗号文を見たら、Franklin–Reiter のような related-message 攻撃を疑ってください。通常必要なのは:

- 同じモジュラス `n`
- 同じ指数 `e`
- 平文間の既知の関係

実務では、Sage で `n` を法とする多項式を立てて GCD を計算することで解くことが多いです。

## Lattices / Coppersmith

部分的なビット、構造化された平文、あるいは未知量が小さくなる近似関係がある場合に使います。

Lattice methods (LLL/Coppersmith) は部分情報があるときに出てきます:

- 部分的に既知の平文（未知の末尾がある構造化メッセージ）
- 部分的に既知の `p`/`q`（上位ビットが leak しているなど）
- 関連値間の小さな未知差

### 見分けるべき点

チャレンジでよくあるヒント:

- 「p の上位/下位ビットを leak した」
- 「The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`」
- 「RSA を使っているが小さなランダム padding を入れている」

### ツール類

実際には LLL 用に Sage を使い、特定のインスタンス向けの既知テンプレートを適用します。

出発点として有用なもの:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
