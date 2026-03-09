# 対称暗号

{{#include ../../banners/hacktricks-training.md}}

## CTFで探すべきもの

- **モードの誤用**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: 不正なパディングに対する異なるエラー/タイミング。
- **MAC confusion**: 可変長メッセージでの CBC-MAC の使用や、MAC-then-encrypt のミス。
- **XOR everywhere**: ストリーム暗号やカスタム構成は多くの場合 keystream との XOR に還元される。

## AESモードと誤用

### ECB: Electronic Codebook

ECB はパターンを leak する：同一の plaintext ブロック → 同一の ciphertext ブロック。これにより以下が可能になる：

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

もし plaintext を制御でき、ciphertext（または cookies）を観測できるなら、繰り返しブロック（例：多数の `A`）を作成して繰り返しを探してみる。

### CBC: Cipher Block Chaining

- CBC は **malleable**：`C[i-1]` のビットを反転させると `P[i]` の予測可能なビットが反転する。
- システムが有効なパディングと無効なパディングを区別して露出している場合、**padding oracle** が存在する可能性がある。

### CTR

CTR は AES をストリーム暗号に変える：`C = P XOR keystream`。

同じキーで nonce/IV が再利用されると：

- `C1 XOR C2 = P1 XOR P2`（古典的な keystream 再利用）
- 既知の plaintext があれば、keystream を復元して他を復号できる。

**Nonce/IV 再利用の悪用パターン**

- 既知または推測可能な plaintext のある箇所で keystream を復元する：

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

復元した keystream バイトを適用すれば、同じ key+IV で同じオフセットで生成された他の ciphertext を復号できる。
- 構造化されたデータ（例：ASN.1/X.509 certificates、ファイルヘッダ、JSON/CBOR）は大きな既知 plaintext 領域を提供する。証明書の ciphertext を予測可能な証明書本体と XOR して keystream を導き出し、再利用された IV の下で暗号化された他の秘密を復号できることが多い。典型的な証明書レイアウトは [TLS & Certificates](../tls-and-certificates/README.md) を参照。
- 同じシリアライズ形式/サイズの複数の秘密が同じ key+IV の下で暗号化されている場合、完全な既知 plaintext がなくてもフィールド整列による情報漏洩が起きる。例：同じモジュラスサイズの PKCS#8 RSA 鍵は素因数を一致するオフセットに配置する（2048 ビットで約 99.6% の整列）。再利用された keystream の下で二つの ciphertext を XOR すると `p ⊕ p'` / `q ⊕ q'` が分離され、数秒で総当たり復元できることがある。
- ライブラリのデフォルト IV（例：定数 `000...01`）は致命的な落とし穴である：各暗号化で同じ keystream が繰り返され、CTR が再利用された one-time pad になる。

**CTR の malleability**

- CTR は機密性のみを提供する：ciphertext のビットを反転させると plaintext の同じビットが決定論的に反転する。認証タグがなければ、攻撃者はデータ（例：キー、フラグ、メッセージ）を検出されずに改竄できる。
- AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) を使用し、タグ検証を強制してビット反転を検出せよ。

### GCM

GCM は nonce を再利用すると深刻に破綻する。 同じ key+nonce が複数回使われると通常以下が起きる：

- 暗号化における keystream の再利用（CTR と同様）、既知の plaintext があれば復号が可能になる。
- 完全性保証の喪失。露出する情報（同じ nonce 下での複数の message/tag ペア）によってはタグの偽造が可能になる場合がある。

運用上のガイダンス：

- AEAD における "nonce reuse" は重大な脆弱性として扱え。
- misuse-resistant な AEAD（例：GCM-SIV）は nonce の誤使用による影響を軽減するが、それでも一意の nonces/IVs が必要。
- 同じ nonce の下で複数の ciphertext がある場合、まず `C1 XOR C2 = P1 XOR P2` のような関係を確認する。

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) は各ブロックを独立して暗号化する：

- equal plaintext blocks → equal ciphertext blocks
- これが構造を leak し、cut-and-paste 型の攻撃を可能にする

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 検出のアイデア：トークン/クッキーのパターン

何度かログインして **常に同じ cookie を受け取る** 場合、ciphertext が決定的（ECB または固定 IV）である可能性がある。

ほぼ同一のプレーンテキストレイアウト（例：長い繰り返し文字）で二つのユーザを作成し、同じオフセットに繰り返しの ciphertext ブロックが見られれば、ECB の可能性が高い。

### 悪用パターン

#### Removing entire blocks

トークン形式が `<username>|<password>` のようになっていてブロック境界が揃っている場合、`admin` ブロックが揃うようにユーザを作成し、前のブロックを削除して `admin` の有効なトークンを得られることがある。

#### Moving blocks

バックエンドがパディングや余分なスペース（`admin` vs `admin    `）を許容する場合、次のようなことができる：

- `admin   ` を含むブロックを揃える
- その ciphertext ブロックを別のトークンに差し替える/再利用する

## Padding Oracle

### What it is

CBC モードでは、サーバが（直接的または間接的に）復号された plaintext が **valid PKCS#7 padding** であるかを明らかにする場合、しばしば以下が可能になる：

- キー無しで ciphertext を復号する
- 選択した plaintext を暗号化（ciphertext を偽造）する

オラクルは次のようなものになり得る：

- 特定のエラーメッセージ
- 異なる HTTP ステータス / レスポンスサイズ
- タイミング差

### Practical exploitation

PadBuster は古典的なツールである：

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

例：
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
メモ:

- ブロックサイズはしばしば `16`（AESの場合）。
- `-encoding 0` は Base64 を意味します。
- Oracle が特定の文字列の場合は `-error` を使用してください。

### なぜ動くのか

CBC の復号は `P[i] = D(C[i]) XOR C[i-1]` を計算します。`C[i-1]` のバイトを変更してパディングが有効かどうかを観察することで、`P[i]` をバイト単位で復元することができます。

## Bit-flipping in CBC

パディングオラクルがなくても、CBC は改変可能です。暗号文ブロックを変更でき、アプリケーションが復号されたプレーンテキストを構造化データ（例: `role=user`）として使用する場合、次のブロックの選んだ位置にあるプレーンテキストの特定バイトを変更するためにビットを反転させることができます。

典型的な CTF パターン:

- Token = `IV || C1 || C2 || ...`
- あなたは `C[i]` のバイトを制御する
- 目標は `P[i+1]` のプレーンテキストバイト（`P[i+1] = D(C[i+1]) XOR C[i]` のため）

これは単独では機密性の破壊ではありませんが、整合性が欠如している場合の一般的な privilege-escalation primitive です。

## CBC-MAC

CBC-MAC は特定の条件下（特に **固定長メッセージ** と正しいドメイン分離）でのみ安全です。

### Classic variable-length forgery pattern

CBC-MAC は通常次のように計算されます:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

選択したメッセージに対するタグを取得できる場合、CBC のブロック連鎖の仕組みを利用して、鍵を知らなくても連結（または関連する構成）のタグを作成できることがよくあります。

これはユーザー名や role を CBC-MAC で MAC している CTF の cookies/tokens に頻出します。

### より安全な代替案

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- メッセージ長の含有 / ドメイン分離の導入

## Stream ciphers: XOR and RC4

### 基本モデル

ほとんどのストリーム暗号の状況は次の式に帰着します:

`ciphertext = plaintext XOR keystream`

したがって:

- 平文が分かれば、keystream を復元できる。
- keystream が再利用される（同じ key+nonce）と、`C1 XOR C2 = P1 XOR P2`。

### XOR-based encryption

位置 `i` の平文セグメントが分かっていれば、keystream バイトを復元してその位置の他の暗号文を復号できます。

自動解読ツール:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 はストリーム暗号であり、暗号化と復号化は同じ操作です。

同じ鍵で既知平文の RC4 暗号文を取得できる場合、keystream を復元して同じ長さ/オフセットの他のメッセージを復号できます。

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
