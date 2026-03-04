# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## На що звертати увагу в CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: different errors/timings for bad padding.
- **MAC confusion**: using CBC-MAC with variable-length messages, or MAC-then-encrypt mistakes.
- **XOR everywhere**: stream ciphers and custom constructions often reduce to XOR with a keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Це дозволяє:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Якщо ви можете контролювати plaintext і спостерігати ciphertext (або cookies), спробуйте зробити повторювані блоки (наприклад, багато `A`s) і шукати повтори.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Якщо система розкриває valid padding vs invalid padding, ви можете мати **padding oracle**.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

If a nonce/IV is reused with the same key:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- With known plaintext, you can recover the keystream and decrypt others.

**Nonce/IV reuse exploitation patterns**

- Recover keystream wherever plaintext is known/guessable:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Apply the recovered keystream bytes to decrypt any other ciphertext produced with the same key+IV at the same offsets.
- Highly structured data (e.g., ASN.1/X.509 certificates, file headers, JSON/CBOR) gives large known-plaintext regions. You can often XOR the ciphertext of the certificate with the predictable certificate body to derive keystream, then decrypt other secrets encrypted under the reused IV. See also [TLS & Certificates](../tls-and-certificates/README.md) for typical certificate layouts.
- When multiple secrets of the **same serialized format/size** are encrypted under the same key+IV, field alignment leaks even without full known plaintext. Example: PKCS#8 RSA keys of the same modulus size place prime factors at matching offsets (~99.6% alignment for 2048-bit). XORing two ciphertexts under the reused keystream isolates `p ⊕ p'` / `q ⊕ q'`, which can be brute-recovered in seconds.
- Default IVs in libraries (e.g., constant `000...01`) are a critical footgun: every encryption repeats the same keystream, turning CTR into a reused one-time pad.

**CTR malleability**

- CTR provides confidentiality only: flipping bits in ciphertext deterministically flips the same bits in plaintext. Without an authentication tag, attackers can tamper data (e.g., tweak keys, flags, or messages) undetected.
- Використовуйте AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) і забезпечуйте перевірку тегу, щоб виявляти bit-flips.

### GCM

GCM also breaks badly under nonce reuse. If the same key+nonce is used more than once, you typically get:

- Keystream reuse for encryption (like CTR), enabling plaintext recovery when any plaintext is known.
- Loss of integrity guarantees. Depending on what is exposed (multiple message/tag pairs under the same nonce), attackers may be able to forge tags.

Operational guidance:

- Treat "nonce reuse" in AEAD as a critical vulnerability.
- Misuse-resistant AEADs (e.g., GCM-SIV) reduce nonce-misuse fallout but still require unique nonces/IVs.
- If you have multiple ciphertexts under the same nonce, start by checking `C1 XOR C2 = P1 XOR P2` style relations.

### Tools

- CyberChef для швидких експериментів: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) encrypts each block independently:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ідея виявлення: token/cookie pattern

If you login several times and **always get the same cookie**, the ciphertext may be deterministic (ECB or fixed IV).

Якщо ви створите двох користувачів з майже ідентичним макетом plaintext (наприклад, довгі повторювані символи) і побачите повторювані ciphertext блоки в тих самих офсетах, ECB — головний підозрюваний.

### Exploitation patterns

#### Removing entire blocks

If the token format is something like `<username>|<password>` and the block boundary aligns, you can sometimes craft a user so the `admin` block appears aligned, then remove preceding blocks to obtain a valid token for `admin`.

#### Moving blocks

If the backend tolerates padding/extra spaces (`admin` vs `admin    `), you can:

- Align a block that contains `admin   `
- Swap/reuse that ciphertext block into another token

## Padding Oracle

### What it is

In CBC mode, if the server reveals (directly or indirectly) whether decrypted plaintext has **valid PKCS#7 padding**, you can often:

- Розшифрувати ciphertext без ключа
- Зашифрувати вибраний plaintext (підробити ciphertext)

The oracle can be:

- A specific error message
- A different HTTP status / response size
- A timing difference

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Примітки:

- Розмір блоку часто `16` для AES.
- `-encoding 0` означає Base64.
- Використовуйте `-error`, якщо oracle є конкретним рядком.

### Чому це працює

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Модифікуючи байти в `C[i-1]` і спостерігаючи, чи є padding валідним, можна відновити `P[i]` по байту.

## Bit-flipping in CBC

Навіть без padding oracle, CBC піддатливий до модифікацій. Якщо ви можете змінювати блоки ciphertext і застосунок використовує декодований plaintext як структуровані дані (наприклад, `role=user`), ви можете інвертувати конкретні біти, щоб змінити вибрані байти plaintext у заданій позиції наступного блоку.

Типовий CTF pattern:

- Token = `IV || C1 || C2 || ...`
- Ви контролюєте байти в `C[i]`
- Ви націлюєте байти plaintext в `P[i+1]`, оскільки `P[i+1] = D(C[i+1]) XOR C[i]`

Саме по собі це не порушення конфіденційності, але це звичний примітив ескалації привілеїв, коли відсутня цілісність.

## CBC-MAC

CBC-MAC є безпечним лише за певних умов (зокрема **fixed-length messages** та правильне domain separation).

### Classic variable-length forgery pattern

CBC-MAC зазвичай обчислюється як:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Якщо ви можете отримати теги для вибраних повідомлень, часто можна сфабрикувати тег для конкатенації (або спорідненої конструкції) без знання ключа, експлуатуючи спосіб зв'язування блоків у CBC.

Це часто зустрічається в CTF cookies/tokens, які MAC username або role за допомогою CBC-MAC.

### Більш безпечні альтернативи

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Включіть довжину повідомлення / domain separation

## Stream ciphers: XOR and RC4

### Ментальна модель

Більшість ситуацій зі stream cipher зводяться до:

`ciphertext = plaintext XOR keystream`

Отже:

- Якщо ви знаєте plaintext, ви відновлюєте keystream.
- Якщо keystream повторно використовується (той самий key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Якщо ви знаєте будь-який сегмент plaintext на позиції `i`, ви можете відновити байти keystream і розшифрувати інші ciphertext на тих позиціях.

Автосолвери:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 — це stream cipher; encrypt/decrypt — одна й та сама операція.

Якщо ви можете отримати RC4 encryption відомого plaintext під тим самим ключем, ви можете відновити keystream і розшифрувати інші повідомлення тієї ж довжини/зсуву.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
