# 対称暗号

{{#include ../../banners/hacktricks-training.md}}

## CTFで見るべき点

- **モードの誤用**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: 不正なパディングに対してエラーやタイミングが異なる。
- **MAC confusion**: CBC-MACを可変長メッセージに使っている、またはMAC-then-encryptの誤り。
- **XOR everywhere**: ストリーム暗号やカスタム構成はしばしばkeystreamとのXORに帰着する。

## AES モードと誤用

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. これにより次が可能になります:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

もし平文を制御できて暗号文（またはcookies）を観察できるなら、繰り返しブロック（例: 多くの `A`s）を作って繰り返しを探してみてください。

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- システムが有効なpaddingと無効なpaddingを区別して露出している場合、**padding oracle**が存在する可能性があります。

### CTR

CTRはAESをストリーム暗号に変えます: `C = P XOR keystream`.

同じキーでnonce/IVが再利用されると:

- `C1 XOR C2 = P1 XOR P2` (古典的なkeystream再利用)
- 既知の平文があれば、keystreamを回復して他を復号できます。

### GCM

GCMもnonce再利用で大きく破綻します。同じkey+nonceが複数回使われると、通常次が発生します:

- 暗号化でのkeystream再利用（CTRと同様）、既知平文があれば平文回復が可能。
- 整合性保証の喪失。何が公開されているか（同じnonce下の複数のmessage/tagペアなど）によっては、タグを偽造できる可能性があります。

運用上の指針:

- AEADにおける"nonce reuse"は重大な脆弱性と扱ってください。
- 同じnonce下の複数の暗号文がある場合は、まず `C1 XOR C2 = P1 XOR P2` のような関係を確認してください。

### ツール

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) は各ブロックを独立して暗号化します:

- equal plaintext blocks → equal ciphertext blocks
- これにより構造が漏れ、cut-and-pasteスタイルの攻撃が可能になります

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 検出のアイデア: token/cookie のパターン

何度かログインして常に同じcookieが返ってくる場合、暗号文が決定的（ECBまたは固定IV）である可能性があります。

ほぼ同じプレーンテキスト構造（例: 長い繰り返し文字）を持つ2つのユーザを作成し、同じオフセットで繰り返し暗号文ブロックが見られるなら、ECBが有力な疑いです。

### 攻略パターン

#### Removing entire blocks

トークン形式が `<username>|<password>` のようでブロック境界が合っている場合、`admin` ブロックが整列するようなユーザを作り、先行ブロックを削除して `admin` の有効なトークンを得られることがあります。

#### Moving blocks

バックエンドがパディングや余分なスペース（`admin` vs `admin    `）を許容するなら:

- `admin   ` を含むブロックを整列させる
- その暗号文ブロックを別のトークンに差し替え/再利用する

## Padding Oracle

### 概要

CBCモードでは、サーバが復号された平文が**valid PKCS#7 padding**かどうかを（直接的にあるいは間接的に）判別可能にしていると、しばしば次が可能になります:

- 鍵無しで暗号文を復号する
- 選択した平文を暗号化（暗号文を偽造）する

オラクルは次のような形で現れることがあります:

- 特定のエラーメッセージ
- 異なるHTTPステータス / レスポンスサイズ
- タイミング差

### 実践的な攻撃

PadBusterは古典的なツールです:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- ブロックサイズは AES ではしばしば `16` です。
- `-encoding 0` は Base64 を意味します。
- oracle が特定の文字列の場合は `-error` を使用してください。

### なぜ機能するのか

CBC 復号は `P[i] = D(C[i]) XOR C[i-1]` を計算します。`C[i-1]` のバイトを変更してパディングが有効かどうかを監視することで、`P[i]` をバイト単位で復元できます。

## CBC におけるビットフリッピング

padding oracle がなくても、CBC は改変可能です。暗号文ブロックを変更でき、アプリケーションが復号したプレーンテキストを構造化データ（例: `role=user`）として使用する場合、特定のビットを反転させて次のブロックの所定位置のプレーンテキストバイトを変更できます。

典型的な CTF パターン:

- Token = `IV || C1 || C2 || ...`
- あなたは `C[i]` のバイトを制御できます
- `P[i+1]` を狙います。なぜなら `P[i+1] = D(C[i+1]) XOR C[i]` だからです

これはそれ自体で機密性の破壊ではありませんが、整合性が欠如している場合には一般的な権限昇格のプリミティブになります。

## CBC-MAC

CBC-MAC は特定の条件下（特に **固定長メッセージ** と適切なドメイン分離）でのみ安全です。

### Classic variable-length forgery pattern

CBC-MAC は通常次のように計算されます:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

選択したメッセージのタグを取得できる場合、CBC がブロックをどのように連鎖させるかを利用して、鍵を知らなくても連結（または関連する構造）のタグを作成できることがよくあります。

これは、username や role を CBC-MAC で MAC する CTF のクッキー/トークンによく見られます。

### より安全な代替案

- HMAC (SHA-256/512) を使用する
- CMAC (AES-CMAC) を正しく使用する
- メッセージ長 / ドメイン分離を含める

## Stream ciphers: XOR and RC4

### 基本概念

ほとんどのストリーム暗号の状況は次の形に帰着します:

`ciphertext = plaintext XOR keystream`

したがって:

- プレーンテキストが分かっていれば、キーストリームを復元できます。
- キーストリームが再利用されている場合（同じ key+nonce）、`C1 XOR C2 = P1 XOR P2`。

### XOR-based encryption

位置 `i` の任意のプレーンテキストセグメントが分かっていれば、キーストリームバイトを復元して、同じ位置の他の暗号文を復号できます。

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 はストリーム暗号で、暗号化と復号は同じ操作です。

同じ鍵で既知のプレーンテキストの RC4 暗号化を得られる場合、キーストリームを復元して同じ長さ/オフセットの他のメッセージを復号できます。

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
