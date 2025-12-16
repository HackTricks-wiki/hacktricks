# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFsで確認すべき点

- **Mode misuse**: ECBパターン、CBCの可変性、CTR/GCMのnonceの再利用。
- **Padding oracles**: 不正なpaddingに対する異なるエラー／タイミング。
- **MAC confusion**: CBC-MACを可変長メッセージで使う、またはMAC-then-encryptのミス。
- **XOR everywhere**: ストリーム暗号やカスタム実装はしばしばkeystreamとのXORに還元される。

## AESのモードと誤用

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. これにより次のことが可能になる:

- Cut-and-paste / ブロックの並べ替え
- ブロック削除（フォーマットが有効なままなら）

プレーンテキストを制御してciphertext（またはcookie）を観察できる場合は、繰り返しのブロック（例: 多数の`A`）を作成して繰り返しを探してみる。

### CBC: Cipher Block Chaining

- CBCは**malleable**: `C[i-1]`のビットを反転すると`P[i]`の予測可能なビットが反転する。
- システムが有効なpaddingと無効なpaddingを区別して露出する場合、**padding oracle**が存在する可能性がある。

### CTR

CTRはAESをストリーム暗号に変える: `C = P XOR keystream`。

同じkeyでnonce/IVが再利用されると:

- `C1 XOR C2 = P1 XOR P2`（古典的なkeystream再利用）
- 既知のplaintextがあれば、keystreamを回復して他を復号できる。

### GCM

GCMもnonce再利用でひどく壊れる。same key+nonceが複数回使われると、通常次が発生する:

- 暗号化でのkeystream再利用（CTRと同様）、既知のplaintextがあれば復号可能。
- 整合性保証の喪失。露出するもの（同一nonce下の複数のmessage/tagペア）によっては、攻撃者がtagをforgeできる場合がある。

運用上の指針:

- AEADでの "nonce reuse" を重大な脆弱性として扱う。
- 同一nonce下で複数のciphertextがある場合は、まず `C1 XOR C2 = P1 XOR P2` のような関係を確認する。

### ツール

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECBの利用パターン

ECB (Electronic Code Book) は各ブロックを独立に暗号化する:

- equal plaintext blocks → equal ciphertext blocks
- これが構造を露出し、cut-and-paste型の攻撃を可能にする

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 検出アイデア: token/cookieのパターン

何度かログインして**常に同じcookieが返る**なら、ciphertextが決定的（ECBまたは固定IV）な可能性がある。

長い繰り返し文字などでほぼ同一のplaintextレイアウトを持つ2つのユーザを作成し、同じオフセットで繰り返しのciphertextブロックが見られるなら、ECBが有力な疑い。

### 利用パターン

#### ブロック全体の削除

トークン形式が `<username>|<password>` のようでブロック境界が整う場合、`admin`ブロックが整列するようにユーザを作り、前のブロックを削除して有効な`admin`トークンを得られる場合がある。

#### ブロックの移動

バックエンドがpaddingや余分なスペース（`admin` vs `admin    `）を許容するなら:

- `admin   `を含むブロックを整列させ
- そのciphertextブロックを別のトークンへ差し替え／再利用する

## Padding Oracle

### それが何か

CBCモードでは、サーバが復号されたplaintextが**PKCS#7 padding**として有効かどうかを（直接または間接に）明らかにする場合、多くの場合:

- keyなしでciphertextを復号できる
- 選択したplaintextを暗号化（ciphertextをforge）できる

オラクルは次のような形で現れる:

- 特定のエラーメッセージ
- 異なるHTTPステータス／レスポンスサイズ
- タイミング差

### 実践的な悪用

PadBusterは古典的なツール:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- ブロックサイズはしばしば `16` for AES.
- `-encoding 0` は Base64 を意味します。
- oracle が特定の文字列の場合は `-error` を使用してください。

### なぜ動作するか

CBC の復号は `P[i] = D(C[i]) XOR C[i-1]` を計算します。`C[i-1]` のバイトを変更し、パディングが有効かどうかを観察することで、`P[i]` をバイト単位で復元できます。

## CBC におけるビットフリップ

padding oracle がなくても、CBC は変更可能です。暗号文ブロックを改変でき、アプリケーションが復号された plaintext を構造化データ（例: `role=user`）として扱う場合、次のブロックの指定位置にある特定の plaintext バイトを変更するためにビットを反転できます。

典型的な CTF パターン:

- Token = `IV || C1 || C2 || ...`
- あなたが `C[i]` のバイトを制御できる
- `P[i+1] = D(C[i+1]) XOR C[i]` のため、`P[i+1]` の plaintext バイトを狙います

これはそれ自体で confidentiality の破壊ではありませんが、integrity がない環境では一般的な privilege-escalation のプリミティブになります。

## CBC-MAC

CBC-MAC は特定の条件下でのみ安全です（特に **固定長メッセージ** と正しいドメイン分離）。

### 古典的な可変長偽造パターン

CBC-MAC は通常次のように計算されます:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

選択したメッセージの tag を取得できる場合、CBC がブロックを連鎖させる仕組みを利用して、キーを知らなくても結合（または関連する構成）の tag を作成できることがよくあります。

これは、ユーザ名や role を CBC-MAC で MAC するような CTF の cookie/token に頻繁に現れます。

### より安全な代替

- HMAC（SHA-256/512）を使用する
- CMAC（AES-CMAC）を正しく使用する
- メッセージ長 / ドメイン分離を含める

## Stream ciphers: XOR and RC4

### 基本的な考え方

`ciphertext = plaintext XOR keystream`

つまり:

- plaintext を知っていれば、keystream を復元できる。
- keystream が再利用される（同じ key+nonce）の場合、`C1 XOR C2 = P1 XOR P2`。

### XOR ベースの暗号

`i` の位置で任意の plaintext セグメントを知っていれば、keystream バイトを復元し、同じ位置の他の ciphertext を復号できます。

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 はストリーム暗号で、暗号化と復号は同じ操作です。

同じキーで既知の plaintext の RC4 暗号化を得られる場合、keystream を復元して同じ長さ/オフセットの他のメッセージを復号できます。

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
