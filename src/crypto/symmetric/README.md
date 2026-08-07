# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTFsで探すもの

- **Mode misuse**: ECB patterns、CBC malleability、CTR/GCM nonce reuse。
- **Padding oracles**: 不正な padding に対するエラーやタイミングの違い。
- **MAC confusion**: 可変長メッセージで CBC-MAC を使用する、または MAC-then-encrypt のミス。
- **XOR everywhere**: stream ciphers や custom constructions は、しばしば keystream との XOR に帰着する。

## AES modes と misuse

### ECB: Electronic Codebook

ECB は patterns を leak する: equal plaintext blocks → equal ciphertext blocks。これにより、以下が可能になる:

- Cut-and-paste / block reordering
- Block deletion（format が有効なままの場合）

plaintext を制御して ciphertext（または cookies）を観測できる場合、repeated blocks（例: 多数の `A`）を作成し、繰り返しを探す。

### CBC: Cipher Block Chaining

- CBC は **malleable**: `C[i-1]` の bits を反転すると、`P[i]` の予測可能な bits が反転する。
- system が valid padding と invalid padding を区別して公開する場合、**padding oracle** が存在する可能性がある。

### CTR

CTR は AES を stream cipher に変換する: `C = P XOR keystream`。

同じ key で nonce/IV が再利用されると:

- `C1 XOR C2 = P1 XOR P2`（classic keystream reuse）
- known plaintext があれば、keystream を復元して他のものを decrypt できる。

**Nonce/IV reuse exploitation patterns**

- plaintext が known/guessable である箇所の keystream を復元する:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

復元した keystream bytes を、同じ key+IV で同じ offsets において生成された他の ciphertext に適用し、decrypt する。
- Highly structured data（例: ASN.1/X.509 certificates、file headers、JSON/CBOR）には、大きな known-plaintext regions が存在する。certificate の ciphertext と predictable な certificate body を XOR して keystream を導出し、再利用された IV で暗号化された他の secrets を decrypt できる場合が多い。[TLS & Certificates](../tls-and-certificates/README.md) も、一般的な certificate layouts を参照。<sup>[[1]](#references)</sup>
- **同じ serialized format/size** の複数の secrets が同じ key+IV で暗号化されている場合、full known plaintext がなくても field alignment が leak する。例: 同じ modulus size の PKCS#8 RSA keys では、prime factors が一致する offsets に配置される（2048-bit では約 99.6% の alignment）。再利用された keystream の下で2つの ciphertext を XOR すると、`p ⊕ p'` / `q ⊕ q'` が分離され、seconds で brute-recover できる。<sup>[[1]](#references)</sup>
- Libraries の default IV（例: constant `000...01`）は critical footgun: すべての encryption で同じ keystream が繰り返され、CTR が reused one-time pad になる。<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR が提供するのは confidentiality のみ: ciphertext の bits を反転すると、plaintext の同じ bits が deterministic に反転する。authentication tag がなければ、attackers は tamper data（例: keys、flags、messages の変更）を検知されずに行える。
- AEAD（GCM、GCM-SIV、ChaCha20-Poly1305 など）を使用し、bit-flips を検出するため tag verification を強制する。

### GCM

GCM も nonce reuse により深刻に破綻する。同じ key+nonce が複数回使用されると、通常は以下が発生する:

- Encryption における keystream reuse（CTR と同様）。known plaintext があれば plaintext recovery が可能になる。
- Integrity guarantees の loss。何が公開されているか（同じ nonce 下の複数の message/tag pairs）によっては、attackers が tags を forge できる可能性がある。

Operational guidance:

- AEAD における "nonce reuse" は critical vulnerability として扱う。
- Misuse-resistant AEADs（例: GCM-SIV）は nonce misuse の影響を軽減するが、それでも unique nonces/IVs が必要。
- 同じ nonce 下の複数の ciphertexts がある場合、まず `C1 XOR C2 = P1 XOR P2` style の relations を確認する。

### Tools

- Quick experiments には CyberChef: https://gchq.github.io/CyberChef/
- Python: scripting には `pycryptodome`

## ECB exploitation patterns

ECB（Electronic Code Book）は各 block を independently encrypt する:

- equal plaintext blocks → equal ciphertext blocks
- これにより structure が leak し、cut-and-paste style attacks が可能になる

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

何度か login して **always get the same cookie** なら、ciphertext は deterministic（ECB または fixed IV）かもしれない。

ほぼ同一の plaintext layouts（例: 長い repeated characters）を持つ2つの users を作成し、同じ offsets に repeated ciphertext blocks が現れる場合、ECB が prime suspect となる。

### Exploitation patterns

#### Removing entire blocks

token format が `<username>|<password>` のようなもので block boundary が alignment している場合、`admin` block が alignment するよう user を craft し、preceding blocks を remove することで、`admin` 用の valid token を取得できる場合がある。

#### Moving blocks

backend が padding/extra spaces（`admin` vs `admin    `）を tolerate する場合、以下が可能:

- `admin   ` を含む block を Align する
- その ciphertext block を別の token に Swap/reuse する

## Padding Oracle

### What it is

CBC mode で、server が decrypted plaintext に **valid PKCS#7 padding** があるかどうかを直接または間接的に reveal する場合、以下が可能になることが多い:

- key なしで ciphertext を Decrypt する
- chosen plaintext を Encrypt する（ciphertext を forge）

oracle には以下がある:

- Specific error message
- Different HTTP status / response size
- Timing difference

### Practical exploitation

PadBuster は classic tool:

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

CBC 復号では `P[i] = D(C[i]) XOR C[i-1]` が計算されます。`C[i-1]` のバイトを変更し、padding が有効かどうかを監視することで、`P[i]` を 1 バイトずつ復元できます。

## CBC での Bit-flipping

padding oracle がなくても、CBC は malleable です。ciphertext ブロックを変更でき、アプリケーションが復号した plaintext を構造化データ（例: `role=user`）として使用している場合、特定のビットを反転させて、次のブロック内の選択した plaintext バイトを変更できます。

典型的な CTF パターン:

- Token = `IV || C1 || C2 || ...`
- `C[i]` のバイトを制御できる
- `P[i+1]` の plaintext バイトを標的にする。これは `P[i+1] = D(C[i+1]) XOR C[i]` であるためです。

これは単独では confidentiality の破壊ではありませんが、integrity がない場合によくある privilege-escalation primitive です。

## CBC-MAC

CBC-MAC は、特定の条件（特に **fixed-length messages** と正しい domain separation）がある場合にのみ secure です。

### Classic variable-length forgery pattern

CBC-MAC は通常、次のように計算されます。

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

選択した message に対する tag を取得できる場合、CBC がブロックを chain する仕組みを悪用することで、key を知らなくても concatenation（または関連する construction）に対する tag を作成できることがあります。

これは、username または role に CBC-MAC を付ける CTF の cookies/tokens で頻繁に見られます。

### より安全な代替手段

- HMAC (SHA-256/512) を使用する
- CMAC (AES-CMAC) を正しく使用する
- message length / domain separation を含める

## Stream ciphers: XOR and RC4

### メンタルモデル

多くの stream cipher の状況は、次の式に集約できます。

`ciphertext = plaintext XOR keystream`

したがって:

- plaintext が分かっていれば、keystream を復元できます。
- keystream が再利用されている場合（同じ key+nonce）、`C1 XOR C2 = P1 XOR P2` となります。

### XOR-based encryption

位置 `i` の plaintext segment が分かっていれば、keystream のバイトを復元し、同じ位置にある他の ciphertext を復号できます。

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 は stream cipher であり、encrypt/decrypt は同じ operation です。

同じ key を使った既知の plaintext の RC4 encryption を取得できれば、keystream を復元し、同じ length/offset の他の messages を復号できます。

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
