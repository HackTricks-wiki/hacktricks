# Simetrik Kripto

{{#include ../../banners/hacktricks-training.md}}

## CTF'lerde nelere bakılmalı

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: farklı hatalar/zamanlama ile kötü padding ayrımı.
- **MAC confusion**: variable-length mesajlarla CBC-MAC kullanımı veya MAC-then-encrypt hataları.
- **XOR everywhere**: stream cipher'lar ve custom yapılar sıklıkla bir keystream ile XOR'a indirgenir.

## AES modları ve yanlış kullanım

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Bu şunları mümkün kılar:

- Cut-and-paste / block reordering
- Block deletion (eğer format geçerli kalıyorsa)

Eğer plaintext'i kontrol edebiliyor ve ciphertext'i (veya cookies) gözlemleyebiliyorsanız, tekrar eden bloklar (ör. birçok `A`) oluşturmayı deneyin ve tekrarları arayın.

### CBC: Cipher Block Chaining

- CBC is **malleable**: `C[i-1]` içindeki bitleri fliplemek `P[i]` içindeki öngörülebilir bitleri flipler.
- Eğer sistem valid padding ile invalid padding'i ayırt ediyorsa, bir **padding oracle**'ınız olabilir.

### CTR

CTR, AES'i bir stream cipher'a çevirir: `C = P XOR keystream`.

Eğer aynı key ile nonce/IV tekrar kullanılırsa:

- `C1 XOR C2 = P1 XOR P2` (klasik keystream reuse)
- Bilinen plaintext ile keystream'i kurtarıp diğerlerini decrypt edebilirsiniz.

**Nonce/IV reuse exploitation patterns**

- Bilinen/tahmin edilebilir plaintext bulunduğu yerlerde keystream'i kurtarın:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Kurtarılan keystream byte'larını aynı key+IV ile aynı offset'lerde üretilmiş diğer ciphertext'leri decrypt etmek için uygulayın.
- Yüksek derecede yapılandırılmış veri (örn. ASN.1/X.509 certificates, file headers, JSON/CBOR) geniş known-plaintext bölgeleri verir. Sertifikanın tahmin edilebilir gövdesi ile sertifika ciphertext'ini XORlayarak keystream çıkarıp, aynı reused IV altında şifrelenmiş diğer sırları decrypt edebilirsiniz. Tipik certificate layout'ları için bkz. [TLS & Certificates](../tls-and-certificates/README.md).
- Aynı serialized format/size ile şifrelenmiş birden fazla secret olduğunda, alan hizalaması tam known plaintext olmadan bile bilgi sızdırır. Örnek: aynı modulus boyutuna sahip PKCS#8 RSA anahtarları prime faktörleri eşleşen offset'lere koyar (~2048-bit için ~%99.6 hizalanma). Tekrarlanan keystream altındaki iki ciphertext'i XORlamak `p ⊕ p'` / `q ⊕ q'`'yi izole eder ve bu, saniyeler içinde brute-force ile geri alınabilir.
- Kütüphanelerdeki varsayılan IV'ler (örn. sabit `000...01`) kritik bir footgun'dır: her encryption aynı keystream'i tekrarlar ve CTR'yi reused one-time pad'e çevirir.

**CTR malleability**

- CTR sadece gizlilik sağlar: ciphertext içindeki bitleri fliplemek plaintext içindeki aynı bitleri deterministik olarak flipler. Bir authentication tag yoksa, saldırganlar veriyi (örn. anahtarlar, flag'ler veya mesajlar) tespit edilmeden değiştirebilir.
- Bit-flip'leri yakalamak için AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, vb.) kullanın ve tag doğrulamasını zorunlu kılın.

### GCM

GCM de nonce reuse altında kötü biçimde bozulur. Aynı key+nonce birden fazla kez kullanılırsa genelde şunlar olur:

- Şifreleme için keystream reuse (CTR gibi), herhangi bir plaintext biliniyorsa plaintext kurtarma mümkün olur.
- Integrity garantilerinin kaybı. Neyin açığa çıktığına bağlı olarak (aynı nonce altında birden fazla message/tag çifti) saldırganlar tag forge edebilir.

Operasyonel rehber:

- AEAD'de "nonce reuse"u kritik bir zafiyet olarak değerlendirin.
- Misuse-resistant AEAD'ler (örn. GCM-SIV) nonce-misuse etkilerini azaltır ama yine de benzersiz nonceler/IV'ler gerektirir.
- Aynı nonce altında birden fazla ciphertext varsa, öncelikle `C1 XOR C2 = P1 XOR P2` tarzı ilişkileri kontrol edin.

### Araçlar

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) her bloğu bağımsız olarak şifreler:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Eğer birkaç kez login oluyorsanız ve **her zaman aynı cookie**'yi alıyorsanız, ciphertext deterministik olabilir (ECB veya sabit IV).

Eğer iki kullanıcı oluşturup büyük ölçüde aynı plaintext layout'una (örn. uzun tekrar eden karakterler) sahip yapar ve aynı offset'lerde tekrar eden ciphertext blokları görürseniz, ECB birinci şüphelidir.

### Exploitation patterns

#### Removing entire blocks

Token formatı `<username>|<password>` gibiyse ve block boundary hizalanıyorsa, bazen bir kullanıcı öyle craft edilebilir ki `admin` bloğu hizalanır, sonra önceki blokları kaldırarak `admin` için geçerli bir token elde edilebilir.

#### Moving blocks

Backend padding/extra spaces (`admin` vs `admin    `) toleranslıysa, şunları yapabilirsiniz:

- `admin   ` içeren bir bloğu hizalayın
- o ciphertext bloğunu başka bir token'a takas/yeniden kullanın

## Padding Oracle

### Nedir

CBC mode'da, sunucu çözülen plaintext'in **valid PKCS#7 padding**'e sahip olup olmadığını (doğrudan veya dolaylı) ifşa ediyorsa, genellikle şunları yapabilirsiniz:

- Anahtar olmadan ciphertext'i decrypt etmek
- Seçilen plaintext'i encrypt etmek (ciphertext forge etmek)

Oracle şunlar olabilir:

- Belirli bir hata mesajı
- Farklı bir HTTP status / response size
- Bir zamanlama farkı

### Pratik suistimal

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Örnek:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notlar:

- Block size is often `16` for AES.
- `-encoding 0` means Base64.
- Use `-error` if the oracle is a specific string.

### Neden işe yarar

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. `C[i-1]` içindeki byte'ları değiştirip padding'in geçerli olup olmadığını izleyerek, `P[i]`'yi byte byte geri elde edebilirsiniz.

## Bit-flipping in CBC

CBC değiştirilebilir (malleable) bir yapıdır. Padding oracle olmasa bile, ciphertext bloklarını değiştirebiliyorsanız ve uygulama çözülmüş plaintext'i yapılandırılmış veri olarak kullanıyorsa (ör. `role=user`), bir sonraki bloktaki seçili plaintext byte'larını istenen pozisyonda değiştirmek için belirli bitleri flip'leyebilirsiniz.

Tipik CTF paterni:

- Token = `IV || C1 || C2 || ...`
- Siz `C[i]` içindeki byte'ları kontrol ediyorsunuz
- Hedefiniz `P[i+1]` içindeki plaintext byte'larıdır çünkü `P[i+1] = D(C[i+1]) XOR C[i]`

Bu tek başına gizliliğin kırılması değildir, fakat bütünlük eksikse yaygın bir ayrıcalık yükseltme primitive'idir.

## CBC-MAC

CBC-MAC yalnızca belirli koşullar altında güvenlidir (özellikle **sabit-uzunluklu mesajlar** ve doğru alan ayrımı).

### Klasik değişken-uzunluk sahtecilik deseni

CBC-MAC genelde şu şekilde hesaplanır:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Seçtiğiniz mesajlar için tag elde edebiliyorsanız, CBC'nin blokları nasıl zincirlediğini kullanarak anahtarı bilmeden birleştirme (veya ilişkili bir yapı) için sıklıkla bir tag oluşturabilirsiniz.

Bu, kullanıcı adı veya role'u CBC-MAC ile MAC'leyen CTF cookie/token'larında sık görülür.

### Daha güvenli alternatifler

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Mesaj uzunluğunu / alan ayrımını dahil edin

## Stream ciphers: XOR and RC4

### Zihinsel model

Most stream cipher situations reduce to:

`ciphertext = plaintext XOR keystream`

Dolayısıyla:

- Eğer plaintext'i biliyorsanız, keystream'i elde edersiniz.
- Eğer keystream tekrar kullanılıyorsa (aynı key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Eğer bir pozisyon `i`'de herhangi bir plaintext segmentini biliyorsanız, keystream byte'larını kurtarıp o pozisyonlardaki diğer ciphertext'leri decrypt edebilirsiniz.

Autosolvers:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 bir stream cipher'dır; encrypt/decrypt aynı işlemdir.

Aynı key altında bilinen plaintext'in RC4 encryption'ını elde edebiliyorsanız, keystream'i kurtarıp aynı uzunluk/offset'teki diğer mesajları decrypt edebilirsiniz.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Referanslar

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
