# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFsで探すもの

- **Mode misuse**: ECB patterns、CBC malleability、CTR/GCM nonce reuse。
- **Padding oracles**: 不正な padding に対する異なるエラーやタイミング。
- **MAC confusion**: 可変長メッセージで CBC-MAC を使用する、または MAC-then-encrypt の誤り。
- **XOR everywhere**: stream ciphers や custom constructions は、多くの場合 keystream との XOR に帰着する。

## AES modes and misuse

NIST は SP 800-38A で ECB、CBC、CTR の confidentiality modes を、SP 800-38D で GCM authenticated encryption を規定している。<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB は patterns を leak する: 同一の plaintext blocks → 同一の ciphertext blocks。これにより、以下が可能になる:

- Cut-and-paste / block reordering
- Block deletion（format が有効なままの場合）

plaintext を制御して ciphertext（または cookies）を観測できる場合は、repeated blocks（例: 多数の `A`）を作成し、繰り返しを探す。

### CBC: Cipher Block Chaining

- CBC は **malleable**: `C[i-1]` の bits を反転すると、`P[i]` の予測可能な bits が反転すると同時に、`P[i-1]` も壊れる。IV を変更すると、前の plaintext block を壊さずに最初の plaintext block を狙える。
- システムが valid padding と invalid padding を区別して公開する場合、**padding oracle** が存在する可能性がある。

### CTR

CTR は AES を stream cipher に変換する: `C = P XOR keystream`。

同じ key で nonce/IV が再利用されると:

- `C1 XOR C2 = P1 XOR P2`（classic keystream reuse）
- known plaintext があれば、keystream を復元して他の ciphertext を decrypt できる。

**Nonce/IV reuse exploitation patterns**

- plaintext が既知または推測可能な箇所の keystream を復元する:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

復元した keystream bytes を、同じ key+IV で同じ offsets において生成された他の ciphertext に適用して decrypt する。
- 構造化されたデータ（例: ASN.1/X.509 certificates、file headers、JSON/CBOR）は、大きな known-plaintext regions を提供する。certificate の ciphertext と予測可能な certificate body を XOR して keystream を導出し、その後、再利用された IV で暗号化された他の secrets を decrypt できる場合が多い。一般的な certificate layouts については [TLS & Certificates](../tls-and-certificates/README.md) も参照。<sup>[[1]](#references)</sup>
- **同じ serialized format/size** の複数の secrets が同じ key+IV で暗号化される場合、full known plaintext がなくても field alignment が leak する。例: 同じ modulus size の PKCS#8 RSA keys では、prime factors が一致する offsets に配置される（2048-bit では約 99.6% の alignment）。再利用された keystream の下で 2 つの ciphertext を XOR すると、`p ⊕ p'` / `q ⊕ q'` が分離され、数秒で brute-recover できる。<sup>[[1]](#references)</sup>
- Libraries の default IV（例: constant `000...01`）は critical footgun である: すべての encryption が同じ keystream を繰り返すため、CTR が reused one-time pad になる。<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR は confidentiality のみを提供する: ciphertext の bits を反転すると、plaintext の同じ bits が deterministic に反転する。authentication tag がなければ、attackers は検知されずに data（例: keys、flags、messages）を tamper できる。
- AEAD（GCM、GCM-SIV、ChaCha20-Poly1305 など）を使用し、tag verification を強制して bit-flips を検知する。

### GCM

GCM も nonce reuse によって大きく破綻する。同じ key+nonce が複数回使用されると、通常は以下が発生する:

- Encryption における keystream reuse（CTR と同様）。いずれかの plaintext が既知であれば、plaintext recovery が可能になる。
- Integrity guarantees の喪失。何が公開されているか（同じ nonce の下にある複数の message/tag pairs）によっては、attackers が tags を forge できる可能性がある。

Operational guidance:

- AEAD における "nonce reuse" は critical vulnerability として扱う。
- AES-GCM-SIV などの misuse-resistant AEADs は、nonce-reuse による被害を軽減する。callers は construction の interface が要求する unique nonces を引き続き提供すべきである。accidental reuse の影響は、通常の GCM と比較して bounded consequences になる。<sup>[[3]](#references)[[4]](#references)</sup>
- 同じ nonce の下に複数の ciphertexts がある場合は、まず `C1 XOR C2 = P1 XOR P2` style relations を確認する。

### Tools

- 素早い実験には [CyberChef](https://gchq.github.io/CyberChef/)。<sup>[[8]](#references)</sup>
- Scripting には Python の [PyCryptodome](https://www.pycryptodome.org/) package。<sup>[[9]](#references)</sup>

## ECB exploitation patterns

ECB（Electronic Code Book）は各 block を独立して encrypt する:

- 同一の plaintext blocks → 同一の ciphertext blocks
- これにより structure が leak し、cut-and-paste style attacks が可能になる

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

何度も login して **常に同じ cookie を取得する** 場合、ciphertext は deterministic（ECB または fixed IV）かもしれない。

ほぼ同一の plaintext layouts（例: 長く繰り返す characters）を持つ 2 人の users を作成し、同じ offsets に repeated ciphertext blocks が現れる場合、ECB が有力な suspect である。

### Exploitation patterns

#### Removing entire blocks

token format が `<username>|<password>` のようなもので block boundary が一致する場合、`admin` block が aligned になるように user を craft し、先行する blocks を削除して `admin` 用の valid token を取得できる場合がある。

#### Moving blocks

backend が padding/extra spaces（`admin` と `admin    `）を許容する場合、以下ができる:

- `admin   ` を含む block を Align する
- その ciphertext block を別の token に Swap/reuse する

## Padding Oracle

### What it is

CBC mode で、server が decrypted plaintext に **valid PKCS#7 padding** があるかどうかを直接または間接的に明らかにする場合、以下が可能になることが多い:<sup>[[7]](#references)</sup>

- key なしで ciphertext を decrypt する
- craft した preceding blocks または IVs を submit でき、application が結果として validly padded message を受け入れる場合に、chosen plaintext に decrypt される ciphertext を construct する

oracle は以下の形を取る:

- Specific error message
- 異なる HTTP status / response size
- Timing difference

### Practical exploitation

PadBuster は classic tool である:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Block size は AES では `16` であることが多いです。
- `-encoding 0` は Base64 を意味します。
- oracle が特定の文字列の場合は `-error` を使用します。

### 仕組み

CBC の復号では `P[i] = D(C[i]) XOR C[i-1]` が計算されます。`C[i-1]` のバイトを変更し、padding が有効かどうかを監視することで、`P[i]` をバイト単位で復元できます。

## CBC での Bit-flipping

padding oracle がなくても、CBC は malleable です。ciphertext ブロックを変更でき、アプリケーションが復号後の plaintext を構造化データ（例: `role=user`）として使用している場合、特定のビットを反転させることで、次のブロックの選択した位置にある plaintext のバイトを変更できます。

典型的な CTF のパターン:

- Token = `IV || C1 || C2 || ...`
- `C[i]` のバイトを制御できる
- `P[i+1]` の plaintext バイトを標的にする。これは `P[i+1] = D(C[i+1]) XOR C[i]` であるため

これは単独では confidentiality の破りではありませんが、integrity が存在しない場合によく使われる privilege-escalation primitive です。

## CBC-MAC

CBC-MAC は、特定の条件（特に **fixed-length messages** と正しい domain separation）の下でのみ secure です。AES-CMAC は variable-length inputs を安全に処理できる標準化された construction です。<sup>[[5]](#references)</sup>

### Classic variable-length forgery pattern

CBC-MAC は通常、次のように計算されます:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

選択した messages に対する tags を取得できる場合、CBC がブロックを chain する仕組みを悪用することで、key を知らなくても concatenation（または関連する construction）に対する tag を作成できることがあります。

これは、username または role を CBC-MAC で MAC する CTF の cookies/tokens で頻繁に見られます。

### Safer alternatives

- HMAC (SHA-256/512) を使用する
- CMAC (AES-CMAC) を正しく使用する
- message length / domain separation を含める

## Stream ciphers: XOR and RC4

### The mental model

多くの stream cipher の状況は、次の形に帰着します:

`ciphertext = plaintext XOR keystream`

したがって:

- plaintext が分かれば、keystream を復元できる
- keystream が再利用される場合（同じ key+nonce）、`C1 XOR C2 = P1 XOR P2`

### XOR-based encryption

位置 `i` の plaintext segment が分かれば、keystream のバイトを復元し、その位置にある他の ciphertexts を復号できます。

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 は legacy の stream cipher です。encrypt/decrypt は同じ XOR operation です。既知の biases があるため新しい systems には不適切であり、TLS はその cipher suites を明示的に禁止しています。<sup>[[6]](#references)</sup>

同じ key を使った既知の plaintext の RC4 encryption を取得できれば、keystream を復元し、同じ length/offset の他の messages を復号できます。

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – cryptography における不注意と職人技](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Block Cipher Modes of Operation に関する推奨事項](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) および GMAC に関する推奨事項](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - The AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Prohibiting RC4 Cipher Suites](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Padding Oracle のテスト](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome documentation](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
