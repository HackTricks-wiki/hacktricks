# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTF'lerde aranacaklar

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: hatalı padding için farklı hatalar/zamanlamalar.
- **MAC confusion**: variable-length mesajlarla CBC-MAC kullanımı veya MAC-then-encrypt hataları.
- **XOR everywhere**: stream cipher'lar ve özel yapılar çoğunlukla keystream ile XOR işlemine indirgenir.

## AES modları ve yanlış kullanım

NIST, SP 800-38A'da ECB, CBC ve CTR confidentiality modlarını; SP 800-38D'de ise GCM authenticated encryption'ı belirtir.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB pattern'leri leak eder: eşit plaintext block'ları → eşit ciphertext block'ları. Bu şunları mümkün kılar:

- Cut-and-paste / block reordering
- Block deletion (format geçerli kalıyorsa)

Plaintext'i kontrol edebiliyor ve ciphertext'i (veya cookie'leri) gözlemleyebiliyorsanız, tekrarlanan block'lar oluşturmaya çalışın (ör. çok sayıda `A`) ve tekrarları arayın.

### CBC: Cipher Block Chaining

- CBC **malleable**'dır: `C[i-1]` içindeki bitleri değiştirmek `P[i]` içindeki öngörülebilir bitleri değiştirirken `P[i-1]`'i de bozar. IV'yi değiştirmek, daha önceki bir plaintext block'unu bozmadan ilk plaintext block'unu hedefler.
- Sistem geçerli padding ile geçersiz padding'i ayırt edecek şekilde hata veriyorsa bir **padding oracle** elde etmiş olabilirsiniz.

### CTR

CTR, AES'i bir stream cipher'a dönüştürür: `C = P XOR keystream`.

Aynı key ile bir nonce/IV yeniden kullanılırsa:

- `C1 XOR C2 = P1 XOR P2` (klasik keystream reuse)
- Known plaintext ile keystream'i kurtarabilir ve diğerlerini decrypt edebilirsiniz.

**Nonce/IV reuse exploitation patterns**

- Plaintext'in bilindiği/tahmin edilebildiği her yerde keystream'i kurtarın:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Kurtarılan keystream byte'larını, aynı key+IV ile aynı offset'lerde üretilmiş diğer ciphertext'leri decrypt etmek için uygulayın.
- Highly structured data (ör. ASN.1/X.509 certificates, file headers, JSON/CBOR) büyük known-plaintext bölgeleri sağlar. Keystream'i türetmek için çoğu zaman certificate ciphertext'ini öngörülebilir certificate body ile XOR edebilir, ardından reused IV altında encrypt edilmiş diğer secret'ları decrypt edebilirsiniz. Tipik certificate layout'ları için ayrıca [TLS & Certificates](../tls-and-certificates/README.md) bölümüne bakın.<sup>[[1]](#references)</sup>
- Birden fazla secret aynı serialized format/size ile aynı key+IV altında encrypt edildiğinde, full known plaintext olmadan bile field alignment leak eder. Örnek: aynı modulus size'a sahip PKCS#8 RSA key'leri, prime factor'leri eşleşen offset'lere yerleştirir (2048-bit için yaklaşık %99,6 alignment). Reused keystream altında iki ciphertext'in XOR'lanması `p ⊕ p'` / `q ⊕ q'` değerlerini izole eder; bunlar saniyeler içinde brute-force ile kurtarılabilir.<sup>[[1]](#references)</sup>
- Kütüphanelerdeki default IV'ler (ör. sabit `000...01`) kritik bir footgun'dır: her encryption aynı keystream'i tekrarlar ve CTR'yi reused one-time pad'e dönüştürür.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR yalnızca confidentiality sağlar: ciphertext içindeki bitleri değiştirmek plaintext içindeki aynı bitleri deterministik olarak değiştirir. Authentication tag olmadan attacker'lar verileri (ör. key'leri, flag'leri veya mesajları) değiştirebilir ve bu durum fark edilmez.
- Bit flip'lerini yakalamak için AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 vb.) kullanın ve tag verification uygulayın.

### GCM

GCM de nonce reuse durumunda ciddi şekilde bozulur. Aynı key+nonce birden fazla kez kullanılırsa genellikle şunları elde edersiniz:

- Encryption için keystream reuse (CTR gibi); herhangi bir plaintext bilindiğinde plaintext recovery mümkün olur.
- Integrity guarantees kaybı. Aynı nonce altında birden fazla message/tag pair'in ne şekilde açığa çıktığına bağlı olarak attacker'lar tag forge edebilir.

Operational guidance:

- AEAD içindeki "nonce reuse" durumunu critical vulnerability olarak ele alın.
- AES-GCM-SIV gibi misuse-resistant AEAD'ler nonce-reuse fallout'u azaltır. Caller'lar yine de construction'ın interface'inin gerektirdiği şekilde unique nonce'lar sağlamalıdır; accidental reuse, ordinary GCM'e kıyasla sınırlı sonuçlara yol açar.<sup>[[3]](#references)[[4]](#references)</sup>
- Aynı nonce altında birden fazla ciphertext varsa `C1 XOR C2 = P1 XOR P2` tarzı ilişkileri kontrol ederek başlayın.

### Tools

- Hızlı deneyler için [CyberChef](https://gchq.github.io/CyberChef/).<sup>[[8]](#references)</sup>
- Scripting için Python'ın [PyCryptodome](https://www.pycryptodome.org/) paketi.<sup>[[9]](#references)</sup>

## ECB exploitation patterns

ECB (Electronic Code Book) her block'u bağımsız olarak encrypt eder:

- eşit plaintext block'ları → eşit ciphertext block'ları
- bu durum structure'ı leak eder ve cut-and-paste tarzı attack'leri mümkün kılar

![ECB mode decryption block diagram](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Birkaç kez login oluyor ve **her zaman aynı cookie'yi alıyorsanız**, ciphertext deterministic olabilir (ECB veya fixed IV).

Büyük ölçüde aynı plaintext layout'larına sahip iki user oluşturur (ör. uzun tekrarlanan karakterler) ve aynı offset'lerde tekrarlanan ciphertext block'ları görürseniz, ECB başlıca şüphelidir.

### Exploitation patterns

#### Removing entire blocks

Token formatı `<username>|<password>` gibi bir şeyse ve block boundary hizalanıyorsa, bazen `admin` block'unun hizalı şekilde görünmesini sağlayacak bir user oluşturabilir, ardından geçerli bir `admin` token'ı elde etmek için önceki block'ları kaldırabilirsiniz.

#### Moving blocks

Backend padding/extra spaces'leri tolere ediyorsa (`admin` ve `admin    `), şunları yapabilirsiniz:

- `admin   ` içeren bir block'u hizalayın
- Bu ciphertext block'unu başka bir token'a taşıyın/yeniden kullanın

## Padding Oracle

### What it is

CBC mode'da server, decrypt edilmiş plaintext'in **geçerli PKCS#7 padding** içerip içermediğini doğrudan veya dolaylı olarak açıklarsa, çoğu zaman şunları yapabilirsiniz:<sup>[[7]](#references)</sup>

- Ciphertext'i key olmadan decrypt etmek
- Crafted preceding block'lar veya IV'ler gönderebildiğiniz ve application sonucunda oluşan validly padded message'ı kabul ettiği durumlarda, seçtiğiniz plaintext'e decrypt edilen bir ciphertext oluşturmak

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

CBC decryption işlemi `P[i] = D(C[i]) XOR C[i-1]` hesaplar. `C[i-1]` içindeki byte'ları değiştirerek ve padding'in geçerli olup olmadığını izleyerek `P[i]` değerini byte byte kurtarabilirsiniz.

## CBC'de Bit-flipping

Bir padding oracle olmadan da CBC malleable'dır. Ciphertext block'larını değiştirebiliyor ve uygulama decrypted plaintext'i yapılandırılmış veri olarak kullanıyorsa (ör. `role=user`), sonraki block'ta seçilen bir konumdaki belirli plaintext byte'larını değiştirmek için belirli bit'leri flip edebilirsiniz.

Tipik CTF pattern'i:

- Token = `IV || C1 || C2 || ...`
- `C[i]` içindeki byte'ları kontrol edersiniz
- `P[i+1]` içindeki plaintext byte'larını hedeflersiniz; çünkü `P[i+1] = D(C[i+1]) XOR C[i]`

Bu, tek başına confidentiality'nin kırılması değildir; ancak integrity eksik olduğunda yaygın bir privilege-escalation primitive'idir.

## CBC-MAC

CBC-MAC yalnızca belirli koşullar altında güvenlidir (özellikle **sabit uzunluktaki mesajlar** ve doğru domain separation). AES-CMAC, variable-length input'ları güvenli şekilde işleyen standartlaştırılmış bir construction'dır.<sup>[[5]](#references)</sup>

### Klasik variable-length forgery pattern'i

CBC-MAC genellikle şu şekilde hesaplanır:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Seçtiğiniz mesajlar için tag elde edebiliyorsanız, CBC'nin block'ları nasıl zincirlediğinden yararlanarak key'i bilmeden bir concatenation (veya ilişkili bir construction) için tag oluşturabilirsiniz.

Bu durum, username veya role değerini CBC-MAC ile MAC eden CTF cookie/token'larında sıkça görülür.

### Daha güvenli alternatifler

- HMAC (SHA-256/512) kullanın
- CMAC'i (AES-CMAC) doğru şekilde kullanın
- Mesaj uzunluğunu / domain separation'ı ekleyin

## Stream ciphers: XOR and RC4

### Zihinsel model

Çoğu stream cipher durumu şu modele indirgenir:

`ciphertext = plaintext XOR keystream`

Dolayısıyla:

- Plaintext'i biliyorsanız keystream'i kurtarırsınız.
- Keystream yeniden kullanılırsa (aynı key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

`i` konumundaki herhangi bir plaintext segment'ini biliyorsanız keystream byte'larını kurtarabilir ve aynı konumlardaki diğer ciphertext'leri decrypt edebilirsiniz.

Otomatik çözücüler:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 legacy bir stream cipher'dır; encrypt/decrypt işlemleri aynı XOR operasyonudur. Bilinen bias'ları onu yeni sistemler için uygunsuz hale getirir ve TLS, cipher suite'lerini açıkça yasaklar.<sup>[[6]](#references)</sup>

Aynı key altında bilinen plaintext'in RC4 encryption'ını elde edebilirseniz keystream'i kurtarabilir ve aynı uzunlukta/offset'teki diğer mesajların şifresini çözebilirsiniz.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Cryptography'de dikkatsizlik ve ustalık](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Block Cipher Mode'larının Kullanımı için Öneri](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) ve GMAC için Öneri](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Nonce Misuse-Resistant Authenticated Encryption](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC Algorithm](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - RC4 Cipher Suite'lerinin Yasaklanması](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Padding Oracle Testi](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome documentation](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
