# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTF'lerde ne aranmalı

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: hatalı padding için farklı hatalar/zamanlamalar.
- **MAC confusion**: variable-length messages ile CBC-MAC kullanımı veya MAC-then-encrypt hataları.
- **XOR everywhere**: stream ciphers ve custom constructions çoğunlukla keystream ile XOR işlemine indirgenir.

## AES modes and misuse

### ECB: Electronic Codebook

ECB patterns'i leak eder: eşit plaintext blokları → eşit ciphertext blokları. Bu, şunları mümkün kılar:

- Cut-and-paste / block reordering
- Block deletion (format geçerli kalıyorsa)

Plaintext'i kontrol edebiliyor ve ciphertext'i (veya cookies) gözlemleyebiliyorsanız, tekrarlanan bloklar oluşturmaya çalışın (ör. çok sayıda `A`) ve tekrarları arayın.

### CBC: Cipher Block Chaining

- CBC **malleable**'dır: `C[i-1]` içindeki bitleri değiştirmek, `P[i]` içindeki öngörülebilir bitleri değiştirir.
- Sistem valid padding ile invalid padding arasında ayrım yapıyorsa, bir **padding oracle** sahibi olabilirsiniz.

### CTR

CTR, AES'i bir stream cipher'a dönüştürür: `C = P XOR keystream`.

Bir nonce/IV aynı key ile yeniden kullanılırsa:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Known plaintext ile keystream'i kurtarabilir ve diğerlerini decrypt edebilirsiniz.

**Nonce/IV reuse exploitation patterns**

- Plaintext'in bilindiği/tahmin edilebildiği yerlerde keystream'i kurtarın:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Kurtarılan keystream byte'larını, aynı key+IV ile aynı offset'lerde üretilen diğer ciphertext'leri decrypt etmek için uygulayın.
- Highly structured data (ör. ASN.1/X.509 certificates, file headers, JSON/CBOR) geniş known-plaintext bölgeleri sağlar. Keystream'i elde etmek için çoğunlukla certificate ciphertext'ini predictable certificate body ile XOR edebilir, ardından reused IV altında encrypt edilmiş diğer secrets'ları decrypt edebilirsiniz. Typical certificate layouts için ayrıca [TLS & Certificates](../tls-and-certificates/README.md) bölümüne bakın.<sup>[[1]](#references)</sup>
- Birden fazla secret aynı serialized format/size ile aynı key+IV altında encrypt edildiğinde, full known plaintext olmadan bile field alignment leak eder. Örnek: aynı modulus size'a sahip PKCS#8 RSA keys, prime factors'ı matching offsets'lere yerleştirir (2048-bit için ~%99.6 alignment). Reused keystream altında iki ciphertext'i XOR'lamak `p ⊕ p'` / `q ⊕ q'` değerlerini izole eder; bunlar saniyeler içinde brute-force ile kurtarılabilir.<sup>[[1]](#references)</sup>
- Kütüphanelerdeki default IV'ler (ör. sabit `000...01`) kritik bir footgun'dır: her encryption aynı keystream'i tekrarlar ve CTR'yi reused one-time pad'e dönüştürür.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR yalnızca confidentiality sağlar: ciphertext içindeki bitleri değiştirmek, plaintext'teki aynı bitleri deterministically değiştirir. Authentication tag olmadan saldırganlar verileri fark edilmeden tamper edebilir (ör. keys, flags veya messages üzerinde değişiklik yapabilir).
- AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 vb.) kullanın ve bit-flip'leri yakalamak için tag verification uygulayın.

### GCM

GCM de nonce reuse durumunda ciddi şekilde bozulur. Aynı key+nonce birden fazla kez kullanılırsa genellikle şunları elde edersiniz:

- Encryption için keystream reuse (CTR gibi); herhangi bir plaintext bilindiğinde plaintext recovery mümkün olur.
- Integrity guarantees kaybı. Neyin açığa çıktığına (aynı nonce altındaki birden fazla message/tag pair) bağlı olarak saldırganlar tag forge edebilir.

Operational guidance:

- AEAD'de "nonce reuse" durumunu critical vulnerability olarak değerlendirin.
- Misuse-resistant AEAD'ler (ör. GCM-SIV), nonce-misuse etkilerini azaltır ancak yine de unique nonces/IVs gerektirir.
- Aynı nonce altında birden fazla ciphertext varsa, `C1 XOR C2 = P1 XOR P2` tarzı ilişkileri kontrol ederek başlayın.

### Tools

- Hızlı denemeler için CyberChef: https://gchq.github.io/CyberChef/
- Python: scripting için `pycryptodome`

## ECB exploitation patterns

ECB (Electronic Code Book) her block'u bağımsız olarak encrypt eder:

- eşit plaintext blokları → eşit ciphertext blokları
- bu durum structure'ı leak eder ve cut-and-paste style attacks'i mümkün kılar

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Birden fazla kez login oluyor ve **her zaman aynı cookie'yi alıyorsanız**, ciphertext deterministic olabilir (ECB veya fixed IV).

Mostly identical plaintext layouts'a sahip iki user oluşturur (ör. uzun repeated characters) ve aynı offset'lerde tekrarlanan ciphertext blocks görürseniz, ECB güçlü bir şüphelidir.

### Exploitation patterns

#### Removing entire blocks

Token formatı `<username>|<password>` gibiyse ve block boundary hizalanıyorsa, `admin` block'unun aligned görünmesini sağlayacak bir user craft edebilir, ardından preceding blocks'ları kaldırarak `admin` için valid bir token elde edebilirsiniz.

#### Moving blocks

Backend padding/extra spaces'ı (`admin` ile `admin    ` arasındaki farkı) tolere ediyorsa:

- `admin   ` içeren bir block'u align edin
- Bu ciphertext block'unu başka bir token'a swap/reuse edin

## Padding Oracle

### What it is

CBC mode'da server, decrypted plaintext'in **valid PKCS#7 padding** içerip içermediğini doğrudan veya dolaylı olarak açıklıyorsa çoğunlukla şunları yapabilirsiniz:

- Key olmadan ciphertext'i decrypt etmek
- Chosen plaintext encrypt etmek (ciphertext forge etmek)

Oracle şunlardan biri olabilir:

- Specific error message
- Farklı bir HTTP status / response size
- Timing difference

### Practical exploitation

PadBuster klasik tool'dur:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Örnek:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notlar:

- Block size AES için genellikle `16` olur.
- `-encoding 0`, Base64 anlamına gelir.
- Oracle belirli bir string ise `-error` kullanın.

### Neden çalışır

CBC decryption, `P[i] = D(C[i]) XOR C[i-1]` hesaplamasını yapar. `C[i-1]` içindeki byte'ları değiştirip padding'in geçerli olup olmadığını gözlemleyerek `P[i]` değerini byte byte kurtarabilirsiniz.

## CBC'de bit flipping

Padding oracle olmadan da CBC malleable'dır. Ciphertext block'larını değiştirebiliyor ve uygulama decrypted plaintext'i yapılandırılmış veri olarak kullanıyorsa (ör. `role=user`), sonraki block'ta seçilen plaintext byte'larını değiştirmek için belirli bit'leri flip edebilirsiniz.

Yaygın CTF pattern'i:

- Token = `IV || C1 || C2 || ...`
- `C[i]` içindeki byte'ları kontrol edersiniz
- `P[i+1]` içindeki plaintext byte'larını hedeflersiniz; çünkü `P[i+1] = D(C[i+1]) XOR C[i]`

Bu tek başına confidentiality'nin kırılması değildir, ancak integrity eksik olduğunda yaygın bir privilege-escalation primitive'idir.

## CBC-MAC

CBC-MAC yalnızca belirli koşullar altında güvenlidir (özellikle **sabit uzunluktaki mesajlar** ve doğru domain separation).

### Klasik variable-length forgery pattern'i

CBC-MAC genellikle şu şekilde hesaplanır:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Seçtiğiniz mesajlar için tag elde edebiliyorsanız, CBC'nin block'ları birbirine bağlama şeklinden yararlanarak key'i bilmeden bir concatenation (veya ilişkili bir construction) için tag oluşturabilirsiniz.

Bu durum, username veya role değerlerini CBC-MAC ile MAC'leyen CTF cookie/token'larında sıkça görülür.

### Daha güvenli alternatifler

- HMAC (SHA-256/512) kullanın
- CMAC'i (AES-CMAC) doğru şekilde kullanın
- Mesaj uzunluğunu / domain separation ekleyin

## Stream ciphers: XOR ve RC4

### Zihinsel model

Çoğu stream cipher durumu şu modele indirgenir:

`ciphertext = plaintext XOR keystream`

Buna göre:

- Plaintext'i biliyorsanız keystream'i kurtarırsınız.
- Keystream yeniden kullanılırsa (aynı key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

`i` konumundaki herhangi bir plaintext segmentini biliyorsanız keystream byte'larını kurtarabilir ve diğer ciphertext'leri aynı konumlarda decrypt edebilirsiniz.

Autosolver'lar:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 bir stream cipher'dır; encrypt/decrypt aynı işlemdir.

Aynı key altında bilinen plaintext'in RC4 encryption'ını elde edebiliyorsanız keystream'i kurtarabilir ve aynı uzunlukta/offset'teki diğer mesajları decrypt edebilirsiniz.

Referans writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
