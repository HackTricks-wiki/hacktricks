# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTF'lerde nelere bakmalı

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: kötü padding için farklı hata/tekrar zamanları.
- **MAC confusion**: variable-length mesajlarla CBC-MAC kullanımı veya MAC-then-encrypt hataları.
- **XOR everywhere**: stream cipher'lar ve custom konstrüksiyonlar genellikle keystream ile XOR'a indirgenir.

## AES modları ve yanlış kullanımı

### ECB: Electronic Codebook

ECB desenleri leak eder: equal plaintext blokları → equal ciphertext blokları. Bu şunları mümkün kılar:

- Cut-and-paste / block reordering
- Block deletion (format geçerli kaldığı sürece)

Eğer plaintext üzerinde kontrolünüz varsa ve ciphertext'i (veya cookie'leri) gözlemleyebiliyorsanız, tekrarlanan bloklar (ör. birçok `A`) üretip tekrarları arayın.

### CBC: Cipher Block Chaining

- CBC **malleable**'dır: `C[i-1]` içindeki bitleri flip etmek `P[i]` içindeki öngörülebilir bitleri flip eder.
- Sistem decrypt edilmiş plaintext için valid padding ile invalid padding'i ayırıyorsa, bir **padding oracle**'ınız olabilir.

### CTR

CTR, AES'i bir stream cipher haline getirir: `C = P XOR keystream`.

Aynı nonce/IV aynı anahtar ile tekrar kullanılırsa:

- `C1 XOR C2 = P1 XOR P2` (klasik keystream reuse)
- Bilinen plaintext ile keystream'i recovery edip diğerlerini decrypt edebilirsiniz.

### GCM

GCM de nonce reuse altında kötü kırılır. Aynı key+nonce birden fazla kez kullanılırsa genellikle şunlar olur:

- Şifreleme için keystream reuse (CTR gibi), herhangi bir plaintext biliniyorsa plaintext recovery mümkün olur.
- Integrity garantilerinin kaybı. Aynı nonce altında birden fazla message/tag çifti açığa çıkarsa, saldırganlar tag forge edebilir.

Operasyonel tavsiye:

- AEAD'de "nonce reuse" kritik bir zafiyet olarak değerlendirilmelidir.
- Aynı nonce altında birden fazla ciphertext varsa, `C1 XOR C2 = P1 XOR P2` tarzı ilişkileri kontrol etmeye başlayın.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` for scripting

## ECB exploitation patterns

ECB (Electronic Code Book) her bloğu bağımsız olarak şifreler:

- equal plaintext blokları → equal ciphertext blokları
- bu yapı sızdırır ve cut-and-paste tarzı saldırılara izin verir

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Tespit fikri: token/cookie deseni

Eğer birkaç kez login olup **hep aynı cookie**'yi alıyorsanız, ciphertext deterministik (ECB veya sabit IV) olabilir.

İki kullanıcı oluşturup plaintext layout'ları büyük ölçüde aynı yaparsanız (ör. uzun tekrarlanan karakterler) ve aynı offset'lerde tekrar eden ciphertext blokları görürseniz, ECB ana şüphelidir.

### Exploitation patterns

#### Removing entire blocks

Token formatı `<username>|<password>` gibiyse ve block boundary hizalanıyorsa, bazen `admin` bloğunun hizalanmasını sağlayıp önceki blokları çıkararak geçerli bir `admin` token'ı elde edebilirsiniz.

#### Moving blocks

Backend padding/extra spaces (`admin` vs `admin    `) tolere ediyorsa, şunları yapabilirsiniz:

- `admin   ` içeren bloğu hizalayın
- o ciphertext bloğunu başka bir tokene takas/tekrar kullanın

## Padding Oracle

### Nedir

CBC modunda, eğer server decrypt edilmiş plaintext'in **valid PKCS#7 padding** olup olmadığını (doğrudan veya dolaylı) ifşa ediyorsa, genellikle şunları yapabilirsiniz:

- Anahtar olmadan ciphertext'i decrypt etmek
- Seçilen plaintext'i encrypt etmek (ciphertext forge etmek)

Oracle şunlar olabilir:

- Belirli bir hata mesajı
- Farklı HTTP status / response boyutu
- Zamanlama farkı

### Pratik istismar

PadBuster klasik araçtır:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Örnek:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notlar:

- Blok boyutu genellikle `16`'dır AES için.
- `-encoding 0` Base64 anlamına gelir.
- oracle belirli bir dizeyse `-error` kullanın.

### Neden işe yarar

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. `C[i-1]` içindeki baytları değiştirip padding'in geçerli olup olmadığını gözlemleyerek, `P[i]`'yi bayt bayt geri kazanabilirsiniz.

## Bit-flipping in CBC

Padding oracle olmasa bile, CBC değiştirilebilir. Eğer ciphertext bloklarını değiştirebiliyorsanız ve uygulama çözülen plaintext'i yapılandırılmış veri olarak kullanıyorsa (ör. `role=user`), belirli bitleri çevirerek sonraki bloktaki seçili plaintext baytlarını istediğiniz pozisyonda değiştirebilirsiniz.

Tipik CTF deseni:

- Token = `IV || C1 || C2 || ...`
- `C[i]` içindeki baytları kontrol ediyorsunuz
- `P[i+1]`'deki plaintext baytlarını hedeflersiniz çünkü `P[i+1] = D(C[i+1]) XOR C[i]`

Bu tek başına gizliliğin ihlali değildir, ancak integrity eksik olduğunda yaygın bir privilege-escalation ilkelidir.

## CBC-MAC

CBC-MAC sadece belirli koşullar altında güvenlidir (özellikle **sabit-uzunluklu mesajlar** ve doğru domain separation).

### Klasik değişken-uzunluklu sahtecilik deseni

CBC-MAC genellikle şu şekilde hesaplanır:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Seçilen mesajlar için tag'leri elde edebiliyorsanız, CBC'nin blokları nasıl zincirlediğini kullanarak anahtarı bilmeden bir birleştirme (veya ilgili bir yapı) için genellikle bir tag oluşturabilirsiniz.

Bu durum genellikle username veya role'u CBC-MAC ile MAC'leyen CTF cookie/token'larında görülür.

### Daha güvenli alternatifler

- HMAC kullanın (SHA-256/512)
- CMAC (AES-CMAC) doğru şekilde kullanın
- Mesaj uzunluğunu ve/veya domain separation ekleyin

## Akış şifreleri: XOR and RC4

### Zihinsel model

Çoğu stream cipher durumu şu eşitliğe indirgenir:

`ciphertext = plaintext XOR keystream`

Yani:

- Plaintext'i biliyorsanız, keystream'i geri çıkarırsınız.
- Keystream yeniden kullanılıyorsa (aynı key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR tabanlı şifreleme

Eğer `i` pozisyonunda herhangi bir plaintext segmentini biliyorsanız, keystream baytlarını elde edip o pozisyonlardaki diğer ciphertext'leri çözebilirsiniz.

Otomatik çözücüler:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 bir stream cipher'dır; şifreleme/şifre çözme aynı işlemdir.

Aynı anahtar altında bilinen plaintext'in RC4 şifrelemesini elde edebiliyorsanız, keystream'i geri çıkarabilir ve aynı uzunluk/offset'teki diğer mesajları çözebilirsiniz.

Referans yazısı (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
