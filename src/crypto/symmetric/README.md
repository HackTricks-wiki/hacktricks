# Simetrik Kriptografi

{{#include ../../banners/hacktricks-training.md}}

## CTF'lerde nelere bakmalı

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: farklı hatalar/zamanlamalar kötü padding için.
- **MAC confusion**: CBC-MAC'i değişken-uzunluk mesajlarla kullanmak veya MAC-then-encrypt hataları.
- **XOR everywhere**: stream ciphers ve custom constructions genellikle bir keystream ile XOR'a indirgenir.

## AES modları ve yanlış kullanım

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Bu şunları sağlar:

- Cut-and-paste / block reordering
- Block deletion (if the format remains valid)

Eğer plaintext'i kontrol edebiliyor ve ciphertext'i (veya cookies) gözlemleyebiliyorsanız, tekrar eden bloklar (örn. birçok `A`) oluşturmayı deneyin ve tekrarları arayın.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- If the system exposes valid padding vs invalid padding, you may have a **padding oracle**.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

If a nonce/IV is reused with the same key:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- With known plaintext, you can recover the keystream and decrypt others.

### GCM

GCM also breaks badly under nonce reuse. If the same key+nonce is used more than once, you typically get:

- Keystream reuse for encryption (like CTR), enabling plaintext recovery when any plaintext is known.
- Loss of integrity guarantees. Depending on what is exposed (multiple message/tag pairs under the same nonce), attackers may be able to forge tags.

Operasyonel öneriler:

- Treat "nonce reuse" in AEAD as a critical vulnerability.
- If you have multiple ciphertexts under the same nonce, start by checking `C1 XOR C2 = P1 XOR P2` style relations.

### Tools

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
Notes:

- Blok boyutu genellikle AES için `16`'dır.
- `-encoding 0` Base64 demektir.
- Oracle belirli bir string ise `-error` kullanın.

### Neden işe yarar

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. `C[i-1]` içindeki byte'ları değiştirip padding'in geçerli olup olmadığını gözlemleyerek `P[i]`'yi bayt bayt geri kazanabilirsiniz.

## CBC'de Bit-flipping

Padding oracle olmasa bile CBC değiştirilebilir (malleable). Eğer ciphertext bloklarını değiştirebiliyorsanız ve uygulama çözülen plaintext'i yapılandırılmış veri olarak kullanıyorsa (ör. `role=user`), belirli bitleri çevirerek bir sonraki blokta seçili plaintext baytlarını istediğiniz pozisyonda değiştirebilirsiniz.

Tipik CTF deseni:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

Bu tek başına gizliliğin ihlali değildir, fakat integrity eksik olduğunda yaygın bir privilege-escalation ilkesidir.

## CBC-MAC

CBC-MAC yalnızca belirli koşullar altında güvenlidir (özellikle **sabit-uzunluklu mesajlar** ve doğru domain separation).

### Klasik değişken-uzunluk sahtecilik deseni

CBC-MAC genellikle şu şekilde hesaplanır:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Seçtiğiniz mesajlar için tag'leri elde edebiliyorsanız, CBC'nin blokları nasıl zincirlediğini kullanarak anahtarı bilmeden genellikle birleştirme (veya ilgili bir yapı) için bir tag oluşturabilirsiniz.

Bu genellikle kullanıcı adı veya role'ü CBC-MAC ile MAC'leyen CTF cookie/token'larında görülür.

### Daha güvenli alternatifler

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Mesaj uzunluğunu ekleyin / domain separation uygulayın

## Akış şifreleri: XOR ve RC4

### Zihinsel model

Çoğu akış şifresi durumu şu forma indirgenir:

`ciphertext = plaintext XOR keystream`

Yani:

- Plaintext'i bilirseniz, keystream'i elde edersiniz.
- If keystream is reused (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR tabanlı şifreleme

Pozisyon `i`'deki herhangi bir plaintext segmentini biliyorsanız, keystream baytlarını geri kazanıp o pozisyonlardaki diğer ciphertext'leri çözebilirsiniz.

Otomatik çözücüler:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 bir akış şifresidir; şifreleme ve şifre çözme aynı işlemdir.

Aynı anahtar altında bilinen plaintext'in RC4 ile şifrelemesini elde edebiliyorsanız, keystream'i elde edip aynı uzunluk/offset'teki diğer mesajları çözebilirsiniz.

Referans yazısı (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
