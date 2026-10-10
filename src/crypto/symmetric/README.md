# Symmetric Crypto

{{#include ../../banners/hacktricks-training.md}}

## CTF'lerde nelere bakmalı

- **Mode yanlış kullanımı**: ECB kalıpları, CBC malleability, CTR/GCM nonce tekrar kullanımı.
- **Padding oracle**: Hatalı padding için farklı hata mesajları/zamanlamalar.
- **MAC karışıklığı**: Değişken uzunlukta mesajlarla CBC-MAC kullanımı veya MAC-then-encrypt hataları.
- **Her yerde XOR**: Stream cipher'lar ve özel yapılar genellikle keystream ile XOR işlemine indirgenir.

## AES modları ve yanlış kullanımları

NIST, SP 800-38A'da ECB, CBC ve CTR gizlilik modlarını; SP 800-38D'de ise GCM authenticated encryption'ı tanımlar.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

ECB kalıpları leak eder: eşit plaintext blokları → eşit ciphertext blokları. Bu şunları mümkün kılar:

- Cut-and-paste / blokların yeniden sıralanması
- Blok silme (biçim geçerliliğini koruyorsa)

Plaintext'i kontrol edip ciphertext'i (veya çerezleri) gözlemleyebiliyorsanız, tekrarlanan bloklar oluşturmaya çalışın (ör. çok sayıda `A`) ve tekrarları arayın.

### CBC: Cipher Block Chaining

- CBC **malleable**'dır: `C[i-1]` içindeki bitleri değiştirmek, `P[i]` içindeki öngörülebilir bitleri değiştirirken `P[i-1]`'i de bozar. IV'yi değiştirmek, önceki bir plaintext bloğunu bozmadan ilk plaintext bloğunu hedefler.
- Sistem geçerli padding ile geçersiz padding'i birbirinden ayırıyorsa, bir **padding oracle**'ınız olabilir.

### CTR

CTR, AES'i bir stream cipher'a dönüştürür: `C = P XOR keystream`.

Aynı anahtarla bir nonce/IV tekrar kullanılırsa:

- `C1 XOR C2 = P1 XOR P2` (klasik keystream tekrar kullanımı)
- Bilinen plaintext ile keystream'i kurtarıp diğerlerini çözebilirsiniz.

**Nonce/IV tekrar kullanımını exploit etme kalıpları**

- Plaintext'in bilindiği/tahmin edilebildiği yerlerde keystream'i kurtarın:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Kurtarılan keystream byte’larını, aynı key+IV ve aynı offset’lerde üretilmiş diğer ciphertext’leri decrypt etmek için uygulayın.
- Yüksek düzeyde yapılandırılmış veriler (örn. ASN.1/X.509 sertifikaları, dosya başlıkları, JSON/CBOR) büyük bilinen-plaintext bölgeleri sağlar. Keystream’i elde etmek için genellikle sertifikanın ciphertext’ini tahmin edilebilir sertifika gövdesiyle XOR’layabilir, ardından aynı IV yeniden kullanılarak şifrelenmiş diğer sırları decrypt edebilirsiniz. Tipik sertifika düzenleri için ayrıca [TLS & Certificates](../tls-and-certificates/README.md) bölümüne bakın.<sup>[[1]](#references)</sup>
- **Aynı serileştirilmiş biçim/boyuttaki** birden fazla sır aynı key+IV ile şifrelendiğinde, tam bilinen plaintext olmasa bile alan hizalaması bilgi sızdırır. Örnek: aynı modulus boyutuna sahip PKCS#8 RSA key’lerinde asal çarpanlar aynı offset’lere denk gelir (~2048-bit için %99,6 hizalama). Yeniden kullanılan keystream altında iki ciphertext’i XOR’lamak `p ⊕ p'` / `q ⊕ q'` değerlerini ortaya çıkarır; bunlar saniyeler içinde brute-force ile kurtarılabilir.<sup>[[1]](#references)</sup>
- Kütüphanelerdeki varsayılan IV’ler (örn. sabit `000...01`) kritik bir footgun’dur: her şifreleme aynı keystream’i tekrar kullanır ve CTR’yi yeniden kullanılan bir one-time pad’e dönüştürür.<sup>[[1]](#references)</sup>

**CTR malleability**

- CTR yalnızca gizlilik sağlar: ciphertext’teki bitleri değiştirmek, plaintext’teki aynı bitleri deterministik olarak değiştirir. Authentication tag yoksa saldırganlar veriyi (örn. key’leri, flag’leri veya mesajları) fark edilmeden değiştirebilir.
- Bit-flip’leri yakalamak için AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 vb.) kullanın ve tag doğrulamasını zorunlu kılın.

### GCM

GCM de nonce yeniden kullanıldığında ciddi şekilde bozulur. Aynı key+nonce birden fazla kez kullanılırsa genellikle şunlar gerçekleşir:

- Şifrelemede keystream yeniden kullanılır (CTR’de olduğu gibi); bilinen herhangi bir plaintext olduğunda plaintext’in kurtarılmasını sağlar.
- Bütünlük garantileri kaybolur. Açığa çıkan verilere (aynı nonce altında birden fazla mesaj/tag çifti) bağlı olarak saldırganlar tag’leri forge edebilir.

Operasyonel yönlendirme:

- AEAD’de "nonce reuse" durumunu kritik bir zafiyet olarak değerlendirin.
- AES-GCM-SIV gibi misuse-resistant AEAD’ler, nonce yeniden kullanımının olumsuz etkilerini azaltır. Arayanlar yine de yapının arayüzünün gerektirdiği şekilde benzersiz nonce’lar sağlamalıdır; kazara yeniden kullanımın sonuçları, sıradan GCM’ye kıyasla sınırlıdır.<sup>[[3]](#references)[[4]](#references)</sup>
- Aynı nonce altında birden fazla ciphertext’iniz varsa, `C1 XOR C2 = P1 XOR P2` türündeki ilişkileri kontrol ederek başlayın.

### Araçlar

- Hızlı denemeler için [CyberChef](https://gchq.github.io/CyberChef/).<sup>[[8]](#references)</sup>
- Script yazmak için Python'ın [PyCryptodome](https://www.pycryptodome.org/) paketi.<sup>[[9]](#references)</sup>

## ECB exploit kalıpları

ECB (Electronic Code Book) her bloğu bağımsız olarak şifreler:

- eşit plaintext blokları → eşit ciphertext blokları
- bu, yapıyı açığa çıkarır ve cut-and-paste tarzı saldırıları mümkün kılar

![ECB modu decrypt işleminin blok diyagramı](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Tespit fikri: token/cookie kalıbı

Birden çok kez login olduğunuzda **her seferinde aynı cookie’yi alıyorsanız**, ciphertext deterministik olabilir (ECB veya sabit IV).

Büyük ölçüde aynı plaintext düzenine sahip iki kullanıcı oluşturursanız (örn. uzun, yinelenen karakterler) ve aynı offset’lerde tekrarlanan ciphertext blokları görürseniz, ECB güçlü bir şüphelidir.

### Exploit kalıpları

#### Tüm blokları kaldırma

Token biçimi `<username>|<password>` gibiyse ve blok sınırı hizalıysa, bazen `admin` bloğunun hizalı görünmesini sağlayacak bir kullanıcı oluşturabilir, ardından `admin` için geçerli bir token elde etmek üzere önceki blokları kaldırabilirsiniz.

#### Blokları taşıma

Backend padding/fazladan boşlukları kabul ediyorsa (`admin` ile `admin    ` gibi), şunları yapabilirsiniz:

- `admin   ` içeren bir bloğu hizalayın
- Bu ciphertext bloğunu başka bir token’a taşıyın/yeniden kullanın

## Padding Oracle

### Nedir?

CBC modunda sunucu, decrypt edilen plaintext’in **geçerli PKCS#7 padding** içerip içermediğini doğrudan veya dolaylı olarak açığa çıkarıyorsa, genellikle şunları yapabilirsiniz:<sup>[[7]](#references)</sup>

- Key olmadan ciphertext’i decrypt etmek
- El işiyle hazırlanmış önceki bloklar veya IV’ler gönderebildiğiniz ve uygulamanın sonuçta oluşan geçerli padding’e sahip mesajı kabul ettiği durumlarda, seçtiğiniz plaintext’e decrypt edilecek bir ciphertext oluşturmak

Oracle şu şekillerde olabilir:

- Belirli bir hata mesajı
- Farklı bir HTTP status / yanıt boyutu
- Zamanlama farkı

### Pratik exploit

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

- AES için blok boyutu genellikle `16`'dır.
- `-encoding 0`, Base64 anlamına gelir.
- Oracle belirli bir dizge döndürüyorsa `-error` kullanın.

### Neden işe yarar

CBC çözme işlemi `P[i] = D(C[i]) XOR C[i-1]` hesaplamasını yapar. `C[i-1]` içindeki baytları değiştirip padding'in geçerli olup olmadığını gözlemleyerek `P[i]` değerini bayt bayt kurtarabilirsiniz.

## CBC'de Bit-flipping

Padding oracle olmasa bile CBC, değiştirilebilir bir şifreleme modudur. Şifreli blokları değiştirebiliyorsanız ve uygulama çözülen düz metni yapılandırılmış veri olarak kullanıyorsa (ör. `role=user`), sonraki blokta seçtiğiniz konumdaki düz metin baytlarını değiştirmek için belirli bitleri çevirebilirsiniz.

Yaygın CTF örüntüsü:

- Token = `IV || C1 || C2 || ...`
- `C[i]` içindeki baytları kontrol edersiniz
- `P[i+1]` içindeki düz metin baytlarını hedeflersiniz; çünkü `P[i+1] = D(C[i+1]) XOR C[i]`

Bu, tek başına gizliliğin kırılması değildir; ancak bütünlük koruması olmadığında ayrıcalık yükseltmek için sık kullanılan bir ilk adımdır.

## CBC-MAC

CBC-MAC yalnızca belirli koşullar altında güvenlidir (özellikle **sabit uzunluklu mesajlar** ve doğru domain separation). AES-CMAC, değişken uzunluklu girdileri güvenli biçimde işleyen standartlaştırılmış bir yapıdır.<sup>[[5]](#references)</sup>

### Klasik değişken uzunluklu sahtecilik örüntüsü

CBC-MAC genellikle şöyle hesaplanır:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Seçtiğiniz mesajlar için tag alabiliyorsanız, CBC'nin blokları birbirine zincirleme biçiminden yararlanarak anahtarı bilmeden birleştirilmiş (veya ilişkili) bir mesaj için tag oluşturabilirsiniz.

Bu durum, CBC-MAC ile kullanıcı adını veya rolü doğrulayan CTF çerezlerinde/token'larında sık görülür.

### Daha güvenli alternatifler

- HMAC (SHA-256/512) kullanın
- CMAC'i (AES-CMAC) doğru şekilde kullanın
- Mesaj uzunluğunu / domain separation bilgisini ekleyin

## Akış şifreleri: XOR ve RC4

### Zihinsel model

Akış şifreleriyle ilgili çoğu durum şu işleme indirgenir:

`ciphertext = plaintext XOR keystream`

Yani:

- Düz metni biliyorsanız keystream'i kurtarırsınız.
- Keystream yeniden kullanılıyorsa (aynı key+nonce), `C1 XOR C2 = P1 XOR P2` olur.

### XOR tabanlı şifreleme

Herhangi bir konumdaki `i` düz metin parçasını biliyorsanız, keystream baytlarını kurtarabilir ve aynı konumlardaki diğer şifreli metinleri çözebilirsiniz.

Otomatik çözücüler:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 eski bir akış şifresidir; şifreleme ve çözme işlemleri aynı XOR işlemidir. Bilinen yanlılıkları, onu yeni sistemler için uygunsuz kılar ve TLS, RC4 şifre takımlarını açıkça yasaklar.<sup>[[6]](#references)</sup>

Aynı anahtar altında bilinen bir düz metnin RC4 şifrelemesini elde edebilirseniz, keystream'i kurtarıp aynı uzunluk/ofset değerlerine sahip diğer mesajları çözebilirsiniz.

Referans writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Kriptografide özensizlik ve ustalık](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Blok Şifreleme Modları için Öneri](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Galois/Counter Mode (GCM) ve GMAC için Öneri](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Nonce'un Yanlış Kullanımına Dayanıklı Kimlik Doğrulamalı Şifreleme](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - AES-CMAC Algoritması](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - RC4 Şifre Takımlarının Yasaklanması](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Güvenliği Test Rehberi - Padding Oracle Testi](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [PyCryptodome belgeleri](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
