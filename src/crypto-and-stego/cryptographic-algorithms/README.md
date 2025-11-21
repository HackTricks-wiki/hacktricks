# 暗号/圧縮アルゴリズム

{{#include ../../banners/hacktricks-training.md}}

## アルゴリズムの特定方法

もしコードが **右シフト・左シフト、XOR、そしていくつかの算術演算** を多用している場合、それは **暗号アルゴリズム** の実装である可能性が高いです。ここでは、各ステップをすべてリバースすることなく、どのアルゴリズムが使われているかを**特定する方法**をいくつか紹介します。

### API 関数

**CryptDeriveKey**

この関数が使われている場合、2番目のパラメータの値を確認することで、どの**algorithm**が使われているかを特定できます:

![](<../../images/image (156).png>)

possible algorithms とそれに割り当てられた値の一覧はここを参照してください: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

指定されたバッファを圧縮・展開します。

**CryptAcquireContext**

[the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta) によると: **CryptAcquireContext** 関数は、特定の cryptographic service provider (CSP) 内の特定の key container へのハンドルを取得するために使用されます。**この返されたハンドルは CryptoAPI を使う呼び出しで使用されます。**

**CryptCreateHash**

データストリームのハッシュ処理を開始します。この関数が使われている場合、2番目のパラメータの値を確認することでどの**algorithm**が使われているかを特定できます:

![](<../../images/image (549).png>)

\
possible algorithms とそれに割り当てられた値の一覧はここを参照してください: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### コード内の定数

特定かつ一意の値を使う必要があるため、定数のおかげでアルゴリズムを簡単に特定できることがあります。

![](<../../images/image (833).png>)

最初の定数を Google で検索すると次のような結果が得られます:

![](<../../images/image (529).png>)

したがって、その decompiled 関数は **sha256 calculator** であると推定できます。\
他の定数を検索しても、（おそらく）同様の結果が得られます。

### データ情報

もしコードに有意な定数がない場合、.data セクションから情報を**ロードしている**可能性があります。\
そのデータにアクセスし、**最初の dword をグループ化**して前節と同様に Google で検索できます:

![](<../../images/image (531).png>)

この場合、**0xA56363C6** を検索すると、それが **AES のテーブル**に関連していることがわかります。

## RC4 **(Symmetric Crypt)**

### 特徴

主に3つの部分で構成されます:

- **Initialization stage/**: **0x00 から 0xFF** までの値のテーブル（合計256バイト、0x100）を生成します。このテーブルは一般に **Substitution Box（SBox）** と呼ばれます。
- **Scrambling stage**: 前に作成したテーブルを **ループ（0x100 回のイテレーション）** して、各値を **半ランダムなバイト** で変更します。この半ランダムなバイトを生成するために RC4 の **key** が使用されます。RC4 の **keys** は **1〜256 バイト** の長さにできますが、通常は 5 バイト以上が推奨されます。一般的には 16 バイトのキーが使われます。
- **XOR stage**: 最後に、プレーンテキストまたは暗号文を前に作成した値で **XOR** します。暗号化と復号は同じ関数で行われます。そのため、作成した 256 バイトを必要な回数だけループします。decompiled code では通常 **%256 (mod 256)** を使っている箇所で認識されます。

> [!TIP]
> **disassembly/decompiled code 内で RC4 を識別するには、キーを使ったサイズ 0x100 のループが2回あり、その後入力データを先に作成した 256 値で XOR している（おそらく %256 を使用）箇所を探すと良いです。**

### **Initialization stage/Substitution Box:** (カウンタに 256 が使われ、256 文字の各位置に 0 が書かれている点に注意)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **特徴**

- **Substitution boxes と lookup tables** の使用
- 特定の lookup table 値（定数）の使用によって **AES を識別できる**ことがある。_定数はバイナリ内に**格納**されている場合と、_**動的に作成**される場合があります。_
- **暗号鍵**は**16 の倍数**でなければならない（通常は32B）こと、通常 16B の **IV** が使われる点に注意。

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### 特徴

- マルウェアで使われている例は稀ですが、例（Ursnif）があります
- 長さに基づいて Serpent を判別するのは比較的簡単（非常に長い関数）

### 特定方法

以下の画像で **0x9E3779B9** という定数が使われていることに注目してください（この定数は **TEA** など他の暗号アルゴリズムでも使われます）。\
また、ループの**サイズ（132）**と disassembly 命令やコード例に見られる **XOR 操作の数** に注目してください:

![](<../../images/image (547).png>)

前述の通り、このコードは decompiler 上では **ジャンプがほとんどない非常に長い関数**として表示されます。decompiled code は次のように見えることがあります:

![](<../../images/image (513).png>)

したがって、このアルゴリズムは **マジックナンバー** と **初期の XOR** を確認し、非常に長い関数を見つけて、その関数内のいくつかの命令（例えば 7 ビット左シフトや 22 ビットの左ローテート）を実装と**比較**することで特定できます。

## RSA **(Asymmetric Crypt)**

### 特徴

- 対称アルゴリズムより複雑
- 定数が存在しないことが多い（カスタム実装は判別が難しい）
- KANAL（crypto analyzer）は定数に依存しているため、RSA に対してヒントを出せないことがある

### 比較による特定

![](<../../images/image (1113).png>)

- 左の行11には `+7) >> 3` があり、右の行35では同じく `+7) / 8` になっている
- 左の行12は `modulus_len < 0x040` をチェックしており、右の行36は `inputLen+11 > modulusLen` をチェックしている

## MD5 & SHA (hash)

### 特徴

- 3 つの関数: Init, Update, Final
- 初期化関数は似ている

### 特定方法

**Init**

定数を確認することで両方を識別できます。sha_init には MD5 にない定数が 1 つあります:

![](<../../images/image (406).png>)

**MD5 Transform**

より多くの定数が使われている点に注意してください

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- 偶発的なデータの変更を検出するための関数であるため、より小さく効率的
- lookup table を使用する（したがって定数で識別可能）

### 特定方法

**lookup table constants** を確認してください:

![](<../../images/image (508).png>)

CRC ハッシュアルゴリズムは次のように見えます:

![](<../../images/image (391).png>)

## APLib (Compression)

### 特徴

- 目立った定数がない
- Python でアルゴリズムを書いてオンラインで類似を検索してみると良い

### 特定方法

グラフはかなり大きいです:

![](<../../images/image (207) (2) (1).png>)

識別のための **3 つの比較** を確認してください:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 は、HashEdDSA の verifier が署名 `sig = R || s` を分割し、群の位数 `n` に対して `s \geq n` であるようなスカラーを拒否することを要求しています。`elliptic` JS ライブラリはその境界チェックを省略していたため、有効なペア `(msg, R || s)` を知っている攻撃者は、別の署名 `s' = s + k·n` を生成して `sig' = R || s'` として再エンコードすることができました。
- 検証ルーチンは `s mod n` のみを消費するため、`s` と合同なすべての `s'` が受け入れられます（バイト列としては異なっていても）。署名を正準トークンとして扱うシステム（ブロックチェーンのコンセンサス、replay キャッシュ、DB のキーなど）は、厳密な実装が `s'` を拒否するために非同期になる可能性があります。
- 他の HashEdDSA 実装を監査する際は、パーサが点 `R` とスカラー長の両方を検証することを確認してください。既知の有効な `s` に対して `n` の倍数を追加してみて、verifier がクローズドに失敗することを確認してみてください。

### ECDSA truncation vs. leading-zero hashes

- ECDSA の verifier はメッセージハッシュ `H` の左端から `log2(n)` ビットだけを使用しなければなりません。`elliptic` では truncation ヘルパーが `delta = (BN(msg).byteLength()*8) - bitlen(n)` を計算していましたが、`BN` コンストラクタは先頭のゼロオクテットを削るため、secp192r1（192-bit order）のような曲線では先頭が ≥4 バイトのゼロで始まるハッシュが 224 ビットと扱われ、256 ビットではないように見えてしまいました。
- verifier は 64 ビットではなく 32 ビット右シフトしてしまい、signer が使用した値と一致しない `E` を生成しました。したがって、これらのハッシュに対する有効な署名は SHA-256 入力に対しておよそ `2^-32` の確率で失敗します。
- “通常のベクトル” と先頭ゼロのバリアント（例: Wycheproof の `ecdsa_secp192r1_sha256_test.json` のケース `tc296`）の両方をターゲット実装に与えてみてください。verifier が signer と一致しなければ、truncation に起因する脆弱性が見つかったことになります。

### Exercising Wycheproof vectors against libraries
- Wycheproof は malformed points、malleable scalars、特殊なハッシュやその他のコーナーケースをエンコードした JSON テストセットを提供しています。`elliptic`（または任意の crypto library）に対するハーネスを構築するのは簡単です: JSON を読み込み、各テストケースをデシリアライズし、実装が期待される `result` フラグと一致するかアサートしてください。
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- 失敗は仕様違反と誤検知（false positives）を区別するようトリアージするべきです。上の2つのバグでは、失敗したWycheproofのケースが即座にスカラー範囲チェックの欠如（EdDSA）と不適切なハッシュの切り詰め（ECDSA）を指摘しました。
- ハーネスをCIに統合して、スカラーのパース、ハッシュ処理、または座標の有効性に関する回帰が導入され次第テストを起動するようにしてください。これは、微妙なbignum変換を間違えやすい高級言語（JS、Python、Go）で特に有用です。

## 参考文献

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
