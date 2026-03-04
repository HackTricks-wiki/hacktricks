# 対称暗号

{{#include ../../banners/hacktricks-training.md}}

## CTFsで注目すべき点

- **Mode misuse**: ECB patterns、CBCの改変可能性（malleability）、CTR/GCMのnonce再利用。
- **Padding oracles**: 不正なパディングに対する異なるエラー／タイミング。
- **MAC confusion**: 可変長メッセージに対するCBC-MACの使用、またはMAC-then-encryptの誤り。
- **XOR everywhere**: ストリーム暗号やカスタム構成は多くの場合 keystream との XOR に還元される。

## AESのモードと誤用

### ECB: Electronic Codebook

ECB leaks patterns: 等しい平文ブロック → 等しい暗号文ブロック。これにより以下が可能になる:

- Cut-and-paste / block reordering
- Block deletion（フォーマットが有効なままなら）

もし平文を制御でき、暗号文（または cookies）を観測できるなら、繰り返しブロック（例: 多くの `A`）を作って繰り返しを探してみてください。

### CBC: Cipher Block Chaining

- CBC は **改変可能（malleable）**: `C[i-1]` のビットを反転させると `P[i]` の予測可能なビットが反転する。
- システムが有効なパディングと無効なパディングを区別して露出している場合、**padding oracle** を持っている可能性があります。

### CTR

CTR は AES をストリーム暗号に変える: `C = P XOR keystream`。

同じキーで nonce/IV が再利用されると:

- `C1 XOR C2 = P1 XOR P2`（古典的な keystream 再利用）
- 既知平文があれば keystream を回復して他を復号できる。

**Nonce/IV 再利用の悪用パターン**

- 既知もしくは推測可能な平文がある箇所で keystream を回復する:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

回復した keystream バイトを使って、同じ key+IV で同じオフセットに対して生成された他の暗号文を復号します。
- 高度に構造化されたデータ（例: ASN.1/X.509 certificates、file headers、JSON/CBOR）は大きな既知平文領域を提供します。証明書の暗号文を予測可能な証明書本体と XOR して keystream を導出し、再利用された IV の下で暗号化された他の秘密を復号できることが多いです。典型的な証明書レイアウトは [TLS & Certificates](../tls-and-certificates/README.md) を参照してください。
- 同じシリアライズ形式/サイズの複数のシークレットが同じ key+IV で暗号化されると、完全な既知平文がなくてもフィールドのアラインメントがリークします。例: 同じモジュラスサイズの PKCS#8 RSA 鍵は素因子を同じオフセットに配置します（2048ビットで約99.6%のアラインメント）。再利用された keystream の下で2つの暗号文を XOR すると `p ⊕ p'` / `q ⊕ q'` が分離され、数秒で総当たり復元できる場合があります。
- ライブラリのデフォルト IV（例: 定数 `000...01`）は重大な落とし穴です：すべての暗号化が同じ keystream を繰り返し、CTR を使い回されたワンタイムパッドにしてしまいます。

**CTR の改変可能性**

- CTR は機密性のみを提供します：暗号文のビットを反転させると平文の同じビットが決定論的に反転します。認証タグがなければ攻撃者はデータを改ざん（例: キー、フラグ、メッセージの改変）しても検出されません。
- AEAD（GCM、GCM-SIV、ChaCha20-Poly1305 など）を使用し、タグ検証を強制してビット反転を検出してください。

### GCM

GCM は nonce 再利用で深刻に破綻します。同じ key+nonce が複数回使われると、通常は:

- 暗号化における keystream 再利用（CTR と同様）、既知平文があれば平文復元が可能になる。
- 完全性保証の喪失。露出されているもの（同じ nonce の下の複数の message/tag ペア）によっては、攻撃者がタグを偽造できる場合があります。

運用上の指針:

- AEAD における "nonce reuse" を重大な脆弱性として扱ってください。
- Misuse-resistant な AEAD（例: GCM-SIV）は nonce 誤用の影響を軽減しますが、それでもユニークな nonces/IVs が必要です。
- 同じ nonce の下に複数の暗号文がある場合は、まず `C1 XOR C2 = P1 XOR P2` のような関係をチェックしてください。

### Tools

- CyberChef をクイックな実験に: https://gchq.github.io/CyberChef/
- Python: スクリプト作成に `pycryptodome`

## ECB の活用パターン

ECB (Electronic Code Book) は各ブロックを独立して暗号化します:

- 等しい平文ブロック → 等しい暗号文ブロック
- これにより構造が leaks し、cut-and-paste スタイルの攻撃が可能になります

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 検出のアイデア: token/cookie パターン

もし何度かログインして **常に同じ cookie を得る** なら、暗号文は決定論的（ECB または固定 IV）かもしれません。

ほぼ同一の平文レイアウト（例: 長い繰り返し文字）で2つのユーザを作り、同じオフセットで暗号文ブロックが繰り返されるのを見れば、ECB が有力な疑いです。

### 活用パターン

#### Removing entire blocks

トークンフォーマットが `<username>|<password>` のようでブロック境界が整う場合、`admin` ブロックが整列するようなユーザを作成し、先行ブロックを削除して `admin` の有効なトークンを取得できることがあります。

#### Moving blocks

バックエンドがパディング／余分なスペース（`admin` と `admin    `）を許容するなら、次のことができます:

- `admin   ` を含むブロックを整列させる
- その暗号文ブロックを別のトークンに差し替え／再利用する

## Padding Oracle

### What it is

CBC モードでは、サーバが復号された平文が **有効な PKCS#7 パディング** かどうかを（直接的または間接的に）示す場合、多くの場合以下が可能になります:

- 鍵なしで暗号文を復号する
- 任意の平文を暗号化する（暗号文を偽造する）

オラクルは次のようなものになり得ます:

- 特定のエラーメッセージ
- 異なる HTTP ステータス / レスポンスサイズ
- タイミング差

### Practical exploitation

PadBuster は古典的なツールです:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

例:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Why it works

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. By modifying bytes in `C[i-1]` and watching whether the padding is valid, you can recover `P[i]` byte-by-byte.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. If you can modify ciphertext blocks and the application uses the decrypted plaintext as structured data (e.g., `role=user`), you can flip specific bits to change selected plaintext bytes at a chosen position in the next block.

Typical CTF pattern:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

This is not a break of confidentiality by itself, but it is a common privilege-escalation primitive when integrity is missing.

## CBC-MAC

CBC-MAC is secure only under specific conditions (notably **fixed-length messages** and correct domain separation).

### Classic variable-length forgery pattern

CBC-MAC is usually computed as:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

If you can obtain tags for chosen messages, you can often craft a tag for a concatenation (or related construction) without knowing the key, by exploiting how CBC chains blocks.

This frequently appears in CTF cookies/tokens that MAC username or role with CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

So:

- If you know plaintext, you recover keystream.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

If you know any plaintext segment at position `i`, you can recover keystream bytes and decrypt other ciphertexts at those positions.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

If you can get RC4 encryption of known plaintext under the same key, you can recover the keystream and decrypt other messages of the same length/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
