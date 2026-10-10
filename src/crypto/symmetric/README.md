# 対称暗号

{{#include ../../banners/hacktricks-training.md}}

## CTFで確認すること

- **モードの誤用**: ECBのパターン、CBCの改ざん可能性、CTR/GCMのnonce再利用。
- **Padding oracle**: 不正なpaddingに対するエラーや処理時間の違い。
- **MACの混同**: 可変長メッセージでのCBC-MACの使用や、MAC-then-encryptの誤り。
- **あらゆる場面でのXOR**: ストリーム暗号や独自の構成は、多くの場合、キーストリームとのXORに帰着する。

## AESのモードと誤用

NISTはSP 800-38AでECB、CBC、CTRの機密性モードを、SP 800-38DでGCM認証付き暗号化を規定しています。<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB leaks パターン: 同じ平文ブロック → 同じ暗号文ブロック。これにより、次のことが可能になります。

- Cut-and-paste / ブロックの並べ替え
- ブロックの削除（フォーマットが有効なままの場合）

平文を制御して暗号文（またはcookie）を確認できる場合は、同じブロックを繰り返す（例: `A`を多数並べる）ようにし、繰り返しが現れるか確認してください。

### CBC: Cipher Block Chaining

- CBCは**改ざん可能**です: `C[i-1]`のビットを反転すると、`P[i]`の予測可能なビットが反転すると同時に、`P[i-1]`も破損します。IVを変更すると、先行する平文ブロックを破損させずに最初の平文ブロックを狙えます。
- システムがpaddingの有効・無効を外部に示す場合、**padding oracle**が存在する可能性があります。

### CTR

CTRはAESをストリーム暗号に変換します: `C = P XOR keystream`。

同じkeyでnonce/IVが再利用されると:

- `C1 XOR C2 = P1 XOR P2`（典型的なキーストリーム再利用）
- 既知平文があれば、キーストリームを復元して他のデータを復号できます。

**Nonce/IV再利用の悪用パターン**

- 平文が既知または推測可能な範囲でキーストリームを復元する:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  同じ key+IV を同じオフセットで使って生成された他の ciphertext を復号するには、復元した keystream のバイトを適用します。
- 構造が高度に規則的なデータ（例: ASN.1/X.509 certificates、file headers、JSON/CBOR）には、既知平文が大量に含まれます。certificate の ciphertext と予測可能な certificate body を XOR して keystream を導出し、IV が再利用された状態で暗号化された他の秘密情報を復号できる場合があります。一般的な certificate の構造については [TLS & Certificates](../tls-and-certificates/README.md) も参照してください。<sup>[[1]](#references)</sup>
- **同じシリアライズ形式/サイズ**の複数の秘密情報が同じ key+IV で暗号化されている場合、完全な既知平文がなくてもフィールドの配置が漏えいします。例: 同じ modulus サイズの PKCS#8 RSA keys では、素因数が同じオフセットに配置されます（2048-bit で約 99.6% の配置一致）。再利用された keystream で暗号化された2つの ciphertext を XOR すると `p ⊕ p'` / `q ⊕ q'` が得られ、数秒で総当たりにより復元できます。<sup>[[1]](#references)</sup>
- ライブラリのデフォルト IV（例: 固定値 `000...01`）は重大な落とし穴です。暗号化のたびに同じ keystream が使われ、CTR が one-time pad の再利用状態になります。<sup>[[1]](#references)</sup>

**CTR の改ざん可能性**

- CTR が提供するのは機密性のみです。ciphertext のビットを反転させると、plaintext の同じビットが決定的に反転します。認証タグがなければ、攻撃者はデータ（例: keys、flags、メッセージ）を検知されずに改ざんできます。
- AEAD（GCM、GCM-SIV、ChaCha20-Poly1305 など）を使用し、ビット反転を検出するためにタグ検証を必ず行ってください。

### GCM

GCM も nonce が再利用されると深刻な問題が起きます。同じ key+nonce が複数回使われると、通常は次の問題が発生します。

- 暗号化時に keystream が再利用される（CTR と同様）。平文が一部でも既知なら、plaintext を復元できます。
- integrity guarantees が失われます。同じ nonce での複数の message/tag ペアなど、露出している情報によっては、攻撃者がタグを偽造できる場合があります。

運用上の指針:

- AEAD における「nonce の再利用」は重大な脆弱性として扱ってください。
- AES-GCM-SIV などの misuse-resistant AEAD は、nonce 再利用の影響を軽減します。それでも呼び出し側は、その方式の interface で求められるように一意な nonce を指定してください。通常の GCM と比べ、誤って再利用した場合の影響は限定されます。<sup>[[3]](#references)[[4]](#references)</sup>
- 同じ nonce で暗号化された複数の ciphertext がある場合は、まず `C1 XOR C2 = P1 XOR P2` のような関係が成り立つか確認してください。

### Tools

- 手早い実験には [CyberChef](https://gchq.github.io/CyberChef/) を使用します。<sup>[[8]](#references)</sup>
- スクリプト作成には Python の [PyCryptodome](https://www.pycryptodome.org/) package を使用します。<sup>[[9]](#references)</sup>

## ECB の悪用パターン

ECB（Electronic Code Book）は各 block を個別に暗号化します。

- 同一の plaintext block → 同一の ciphertext block
- これにより構造が漏えいし、cut-and-paste style attack が可能になります

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### 検出の考え方: token/cookie のパターン

複数回ログインして**毎回同じ cookie が返ってくる**場合、ciphertext は決定的に生成されている（ECB または固定 IV）可能性があります。

ほぼ同じ plaintext layout（例: 長い文字列の繰り返し）を持つ2人のユーザーを作成し、同じオフセットに繰り返し現れる ciphertext block があれば、ECB が強く疑われます。

### 悪用パターン

#### block 全体を削除する

token の形式が `<username>|<password>` のようなもので、block boundary が一致していれば、`admin` block が境界に合うようにユーザーを作成し、先行する block を削除して `admin` の有効な token を取得できることがあります。

#### block を移動する

backend が padding/余分なスペース（`admin` と `admin    ` など）を許容する場合、次のことができます。

- `admin   ` を含む block を配置する
- その ciphertext block を別の token に入れ替える/再利用する

## Padding Oracle

### 概要

CBC mode で、サーバーが復号後の plaintext に**有効な PKCS#7 padding があるかどうか**を（直接または間接的に）明らかにする場合、次のことができる可能性があります。<sup>[[7]](#references)</sup>

- key を使わずに ciphertext を復号する
- 細工した先行 block または IV を送信でき、アプリケーションが padding の有効なメッセージを受け入れる場合、選択した plaintext に復号される ciphertext を作成する

oracle となる情報には、次のようなものがあります。

- 特定の error message
- 異なる HTTP status / response size
- timing の違い

### 実際の悪用

PadBuster は定番の tool です。

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

例:

```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
  -encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```

メモ:

- AESでは、ブロックサイズは`16`であることがよくあります。
- `-encoding 0`はBase64を意味します。
- oracleが特定の文字列を返す場合は、`-error`を使用します。

### 仕組み

CBCの復号では`P[i] = D(C[i]) XOR C[i-1]`が計算されます。`C[i-1]`のバイトを変更し、paddingが有効かどうかを観察することで、`P[i]`を1バイトずつ復元できます。

## CBCでのBit-flipping

padding oracleがなくても、CBCにはmalleabilityがあります。暗号文ブロックを変更でき、アプリケーションが復号した平文を構造化データ（例: `role=user`）として使う場合、次のブロックの指定した位置にある平文バイトの特定のビットを反転できます。

CTFでよくあるパターン:

- Token = `IV || C1 || C2 || ...`
- `C[i]`のバイトを制御できる
- `P[i+1] = D(C[i+1]) XOR C[i]`なので、`P[i+1]`の平文バイトを標的にする

これはそれ自体で機密性を破るものではありませんが、完全性が欠如している場合によく使われる権限昇格の手段です。

## CBC-MAC

CBC-MACが安全なのは、特定の条件（特に**メッセージ長が固定されていること**と、適切なdomain separation）を満たす場合に限られます。AES-CMACは、可変長入力を安全に処理する標準化された構成です。<sup>[[5]](#references)</sup>

### 可変長での古典的な偽造パターン

CBC-MACは通常、次のように計算されます。

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

選択したメッセージのtagを取得できる場合、CBCのブロック連鎖の仕組みを悪用することで、鍵を知らなくても連結したメッセージ（または関連する構成）のtagを作成できることがあります。

これは、ユーザー名やroleをCBC-MACで認証するCTFのcookieやtokenでよく見られます。

### より安全な代替手段

- HMAC (SHA-256/512)を使う
- CMAC (AES-CMAC)を正しく使う
- メッセージ長やdomain separationを含める

## ストリーム暗号: XORとRC4

### 基本的な考え方

ストリーム暗号を使う状況の多くは、次の式に帰着します。

`ciphertext = plaintext XOR keystream`

つまり:

- 平文がわかれば、keystreamを復元できます。
- keystreamが再利用されている（同じkey+nonce）場合、`C1 XOR C2 = P1 XOR P2`となります。

### XORベースの暗号化

位置`i`の平文の一部がわかれば、keystreamのバイトを復元し、その位置にある他の暗号文を復号できます。

自動解読ツール:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4は旧式のストリーム暗号で、暗号化と復号は同じXOR演算です。既知のbiasがあるため、新しいシステムには適しておらず、TLSではそのcipher suiteが明示的に禁止されています。<sup>[[6]](#references)</sup>

同じ鍵で既知の平文をRC4で暗号化させることができれば、keystreamを復元し、同じ長さ・オフセットの他のメッセージを復号できます。

参考writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – 暗号技術における不注意と熟練の技](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - ブロック暗号の動作モードに関する推奨事項](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM)およびGMACに関する推奨事項](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: nonceの誤用に耐性のある認証付き暗号化](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMACアルゴリズム](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - RC4 cipher suiteの禁止](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Padding Oracleのテスト](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodomeドキュメント](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
