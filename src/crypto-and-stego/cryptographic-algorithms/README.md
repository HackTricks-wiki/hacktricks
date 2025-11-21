# 暗号/圧縮アルゴリズム

{{#include ../../banners/hacktricks-training.md}}

## アルゴリズムの特定

コードに右シフト・左シフト、XOR、複数の算術演算が含まれている場合、それは暗号アルゴリズムの実装である可能性が高い。ここでは、各ステップをすべてリバースすることなく使用されているアルゴリズムを特定するいくつかの方法を示す。

### API functions

**CryptDeriveKey**

この関数が使われている場合、2番目のパラメータの値を確認することで、どの**algorithmが使われているか**を特定できる:

![](<../../images/image (156).png>)

可能なアルゴリズムと割り当てられた値の表はここを参照: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

**RtlCompressBuffer/RtlDecompressBuffer**

指定したバッファのデータを圧縮/解凍する。

**CryptAcquireContext**

From [the docs](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta): **CryptAcquireContext** 関数は、特定の cryptographic service provider (CSP) 内の特定の key container に対するハンドルを取得するために使用される。**この返されたハンドルは、選択した CSP を使用する CryptoAPI 関数への呼び出しで使用される。**

**CryptCreateHash**

データストリームのハッシュを開始する。この関数が使用されている場合、2番目のパラメータの値を確認することで、どの**algorithmが使われているか**を特定できる:

![](<../../images/image (549).png>)

\
可能なアルゴリズムと割り当てられた値の表はここを参照: [https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id](https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id)

### Code constants

特殊で一意な値を使用するため、アルゴリズムを特定しやすいことがある。

![](<../../images/image (833).png>)

最初の定数を Google で検索すると次のようになる:

![](<../../images/image (529).png>)

したがって、デコンパイルされた関数は**sha256の計算関数**であると推定できる。\
他の定数のいずれかを検索すれば（おそらく）同じ結果を得られる。

### data info

コードに特に目立つ定数がない場合、.data セクションから情報を読み込んでいる可能性がある。\
そのデータにアクセスし、最初の dword をまとめて Google で検索すると、前節と同様に特定できる:

![](<../../images/image (531).png>)

この場合、**0xA56363C6** を検索すると AES アルゴリズムの **tables** に関連していることがわかる。

## RC4 **(Symmetric Crypt)**

### 特徴

主に3つの部分で構成される:

- **Initialization stage/**: **0x00 から 0xFF** までの値のテーブル（合計256バイト、0x100）を作成する。このテーブルは一般に **Substitution Box**（または SBox）と呼ばれる。
- **Scrambling stage**: 前段で作成したテーブルをループ（0x100 回の反復）して走査し、各値を**半ランダムな**バイトで変更する。この半ランダムなバイトを生成するために、RC4 の **key** が使用される。RC4 の **keys** は **1〜256 バイト** の長さになり得るが、通常は 5 バイト以上が推奨される。一般的には RC4 キーは 16 バイトであることが多い。
- **XOR stage**: 最後に、plain-text または cyphertext を、前段で作成した値と **XOR** する。暗号化と復号化の関数は同じである。このため、作成された 256 バイトを入力データに対して必要な回数だけループして処理する。デコンパイルされたコードでは通常 **%256 (mod 256)** が使われていることで認識できる。

> [!TIP]
> **Disassembly/Decompiler 内で RC4 を識別するには、キーを使ったサイズ 0x100 のループが 2 回あり、その後に入力データを前の 2 つのループで作られた 256 値で XOR している（おそらく %256 を使用）ことを確認するとよい。**

### **Initialization stage/Substitution Box:** (カウンタに 256 が使われ、256 個それぞれに 0 が書き込まれていることに注目)

![](<../../images/image (584).png>)

### **Scrambling Stage:**

![](<../../images/image (835).png>)

### **XOR Stage:**

![](<../../images/image (904).png>)

## **AES (Symmetric Crypt)**

### **特徴**

- substitution boxes と lookup tables の使用
- 特定の lookup table 値（定数）の使用により AES を識別できることがある。_定数はバイナリに**格納されている場合**や、_**動的に生成される場合**_がある点に注意。_
- 暗号化キーは **16 で割り切れる** 必要がある（通常 32B）で、通常 16B の IV が使用される。

### SBox constants

![](<../../images/image (208).png>)

## Serpent **(Symmetric Crypt)**

### 特徴

- マルウェアで使われることは稀だが、例（Ursnif）が存在する
- 長さ（非常に長い関数）に基づいて Serpent か否かを判定しやすい

### 識別

以下の画像で定数 **0x9E3779B9** が使われているのに注意（この定数は **TEA** のような他の暗号にも使われる）。\
また、ループの **サイズ（132）** と、disassembly 命令およびコード例における **XOR 操作の数** に注目:

![](<../../images/image (547).png>)

前述のとおり、このコードは decompiler では **ジャンプがほとんどなく非常に長い関数** として表示されることが多い。デコンパイルされたコードは次のように見えることがある:

![](<../../images/image (513).png>)

したがって、このアルゴリズムはマジックナンバーと初期の XOR、非常に長い関数の存在、そして長い関数内のいくつかの命令（例: 左シフト by 7 や 左ローテート by 22）を実装例と比較して確認することで識別できる。

## RSA **(Asymmetric Crypt)**

### 特徴

- 対称アルゴリズムより複雑
- 定数がない！(カスタム実装は判定が難しい)
- KANAL（crypto analyzer）は定数に依存しているため RSA にはヒントを示さないことがある

### 比較による識別

![](<../../images/image (1113).png>)

- 左の行11には `+7) >> 3` があり、右の行35には同じ意味の `+7) / 8` がある
- 左の行12は `modulus_len < 0x040` をチェックしており、右の行36は `inputLen+11 > modulusLen` をチェックしている

## MD5 & SHA (hash)

### 特徴

- 3 つの関数：Init、Update、Final
- 初期化関数は類似している

### 識別

**Init**

定数を確認することで両者を識別できる。sha_init は MD5 にない定数を一つ持っている点に注意:

![](<../../images/image (406).png>)

**MD5 Transform**

より多くの定数の使用に注目

![](<../../images/image (253) (1) (1).png>)

## CRC (hash)

- 偶発的なデータ変更を検出する目的のため、小さく効率的
- lookup table を使用する（したがって定数で識別可能）

### 識別

lookup table の定数を確認:

![](<../../images/image (508).png>)

CRC ハッシュアルゴリズムは次のようになる:

![](<../../images/image (391).png>)

## APLib (Compression)

### 特徴

- 目立つ定数がないことが多い
- 自分で python に実装してオンラインで類似例を検索してみるとよい

### 識別

グラフはかなり大きい:

![](<../../images/image (207) (2) (1).png>)

識別のための **3 つの比較** を確認:

![](<../../images/image (430).png>)

## Elliptic-Curve Signature Implementation Bugs

### EdDSA scalar range enforcement (HashEdDSA malleability)

- FIPS 186-5 §7.8.2 は、HashEdDSA の verifier が署名 sig = R || s を分割し、群の位数 n に対して s \geq n の任意のスカラーを拒否することを要求している。`elliptic` JS ライブラリはその境界チェックを省略していたため、有効なペア `(msg, R || s)` を知っている攻撃者は、別の署名 s' = s + k·n を生成して再エンコードした `sig' = R || s'` を作成できる。
- 検証ルーチンは s mod n のみを消費するため、バイト列として異なるにもかかわらず s と合同なすべての s' が受け入れられる。署名を正規トークン（ブロックチェーンのコンセンサス、replay キャッシュ、DB キーなど）として扱うシステムは、strict な実装が s' を拒否するため非同期化され得る。
- 他の HashEdDSA 実装を監査する際は、パーサが点 R とスカラー長の両方を検証していることを確認すること；既知の有効な s に n の倍数を追加して、verifier がクローズドに失敗するかを試してみる。

### ECDSA truncation vs. leading-zero hashes

- ECDSA verifier はメッセージハッシュ H の左端から log2(n) ビットのみを用いなければならない。`elliptic` では truncation ヘルパが delta = (BN(msg).byteLength()*8) - bitlen(n) を計算していたが、`BN` コンストラクタが前置のゼロオクテットを落とすため、secp192r1（192-bit order）のような曲線では 先頭に ≥4 バイトのゼロを持つハッシュが 256 ビットではなく 224 ビットであるかのように扱われた。
- verifier は 64 ビットではなく 32 ビット右シフトしており、signer が使った値と一致しない E を生成した。そのため、そのようなハッシュに対する有効な署名は SHA-256 入力の場合 約 2^-32 の確率で失敗する。
- 正常なベクトルと先頭ゼロ入りのバリアント（例: Wycheproof `ecdsa_secp192r1_sha256_test.json` のケース `tc296`）の両方を対象実装に入力してみること；もし verifier が signer と一致しなければ、truncation の脆弱性を発見したことになる。

### Exercising Wycheproof vectors against libraries
- Wycheproof は malformed points、malleable scalars、非標準なハッシュその他のコーナーケースをエンコードした JSON テストセットを提供している。`elliptic`（または任意の crypto ライブラリ）のハーネスを構築するのは簡単：JSON を読み込み、各テストケースをデシリアライズし、実装が期待される `result` フラグと一致するかをアサートする。
```javascript
for (const tc of ecdsaVectors.testGroups) {
const curve = new EC(tc.curve);
const pub = curve.keyFromPublic(tc.key, 'hex');
const ok = curve.verify(tc.msg, tc.sig, pub, 'hex', tc.msgSize);
assert.strictEqual(ok, tc.result === 'valid');
}
```
- 失敗は仕様違反と誤検知を区別するためにトリアージされるべきです。上記の2件のバグでは、失敗した Wycheproof ケースがスカラー範囲チェックの欠如 (EdDSA) とハッシュ切り詰めの誤り (ECDSA) を即座に示しました。
- テストハーネスを CI に組み込み、スカラー解析、ハッシュ処理、または座標の有効性における回帰が導入され次第テストが起動するようにしてください。これは、微妙な bignum 変換を誤りやすい高水準言語 (JS, Python, Go) で特に有用です。

## References

- [Trail of Bits - We found cryptography bugs in the elliptic library using Wycheproof](https://blog.trailofbits.com/2025/11/18/we-found-cryptography-bugs-in-the-elliptic-library-using-wycheproof/)
- [Wycheproof Test Suite](https://github.com/C2SP/wycheproof)

{{#include ../../banners/hacktricks-training.md}}
