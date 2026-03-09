# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTF'lerde ne aranır

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: kötü padding için farklı hata/zamanlama davranışları.
- **MAC confusion**: CBC-MAC'in değişken uzunluklu mesajlarla kullanılması veya MAC-then-encrypt hataları.
- **XOR everywhere**: stream ciphers ve custom constructions genellikle keystream ile XOR'a indirgenir.

## AES modları ve yanlış kullanımı

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. That enables:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Eğer plaintext'i kontrol edip ciphertext'i (veya cookies) gözlemleyebiliyorsanız, tekrarlı bloklar (örn. birçok `A`) oluşturup tekrarları arayın.

### CBC: Cipher Block Chaining

- CBC is **malleable**: `C[i-1]`'de bitleri değiştirmenin `P[i]`'de öngörülebilir bitleri değiştirmesi.
- Sistem geçerli padding ile geçersiz padding'i ayırıyorsa, bir **padding oracle**'ınız olabilir.

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
- Use AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, etc.) and enforce tag verification to catch bit-flips.

### GCM

GCM also breaks badly under nonce reuse. If the same key+nonce is used more than once, you typically get:

- Keystream reuse for encryption (like CTR), enabling plaintext recovery when any plaintext is known.
- Loss of integrity guarantees. Depending on what is exposed (multiple message/tag pairs under the same nonce), attackers may be able to forge tags.

Operasyonel öneriler:

- Treat "nonce reuse" in AEAD as a critical vulnerability.
- Misuse-resistant AEADs (e.g., GCM-SIV) reduce nonce-misuse fallout but still require unique nonces/IVs.
- If you have multiple ciphertexts under the same nonce, start by checking `C1 XOR C2 = P1 XOR P2` style relations.

### Araçlar

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) encrypts each block independently:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

If you login several times and **always get the same cookie**, the ciphertext may be deterministic (ECB or fixed IV).

If you create two users with mostly identical plaintext layouts (e.g., long repeated characters) and see repeated ciphertext blocks at the same offsets, ECB is a prime suspect.

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

- Decrypt ciphertext without the key
- Encrypt chosen plaintext (forge ciphertext)

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
Notlar:

- Blok boyutu genellikle `16`'dır (AES).
- `-encoding 0` Base64 anlamına gelir.
- Eğer oracle belirli bir string ise `-error` kullanın.

### Why it works

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. `C[i-1]` içindeki byte'ları değiştirip padding'in geçerli olup olmadığını izleyerek `P[i]`'yi byte byte geri elde edebilirsiniz.

## Bit-flipping in CBC

Padding oracle olmadan bile, CBC değiştirilebilir (malleable). Eğer ciphertext bloklarını değiştirebiliyorsanız ve uygulama decrypt edilmiş plaintext'i yapılandırılmış veri olarak kullanıyorsa (ör. `role=user`), belirli bitleri çevirerek sonraki bloktaki seçili plaintext byte'larını istenen pozisyonda değiştirebilirsiniz.

Tipik CTF pattern:

- Token = `IV || C1 || C2 || ...`
- `C[i]` içindeki byte'ları siz kontrol ediyorsunuz
- Hedefiniz `P[i+1]` içindeki plaintext byte'larıdır çünkü `P[i+1] = D(C[i+1]) XOR C[i]`

Bu tek başına confidentiality ihlali değildir, ancak integrity eksik olduğunda yaygın bir privilege-escalation primitive'dir.

## CBC-MAC

CBC-MAC yalnızca belirli koşullar altında güvenlidir (özellikle **sabit-uzunluklu mesajlar** ve doğru domain ayrımı).

### Classic variable-length forgery pattern

CBC-MAC genellikle şu şekilde hesaplanır:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Eğer seçtiğiniz mesajlar için tag'lar alabiliyorsanız, CBC'nin blokları nasıl zincirlediğini kullanarak anahtarı bilmeden birleştirme (veya ilgili yapı) için sıklıkla bir tag oluşturabilirsiniz.

Bu durum genellikle username veya role'u CBC-MAC ile MAC'leyen CTF cookie/token'larında görülür.

### Safer alternatives

- HMAC (SHA-256/512) kullanın
- CMAC (AES-CMAC) doğru şekilde kullanın
- Mesaj uzunluğunu / domain separation'ı dahil edin

## Stream ciphers: XOR and RC4

### The mental model

Çoğu stream cipher durumu şu ifadeye indirgenir:

`ciphertext = plaintext XOR keystream`

Yani:

- Eğer plaintext'i biliyorsanız, keystream'i geri elde edersiniz.
- Eğer keystream yeniden kullanılıyorsa (aynı key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Pozisyon `i`'deki herhangi bir plaintext segmentini biliyorsanız, keystream byte'larını geri elde edip o pozisyonlardaki diğer ciphertext'leri çözebilirsiniz.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 bir stream cipher'dır; encrypt/decrypt aynı işlemdir.

Aynı anahtar altında bilinen plaintext'in RC4 şifrelenmesini elde edebiliyorsanız, keystream'i geri elde edip aynı uzunluk/offset'teki diğer mesajları çözebilirsiniz.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
