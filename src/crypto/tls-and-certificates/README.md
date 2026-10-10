# TLS ve Sertifikalar

{{#include ../../banners/hacktricks-training.md}}

Bu bölümde X.509 incelemesi, kodlamalar, dönüştürmeler ve güvenlik açısından önemli doğrulama hataları ele alınır.

## X.509 Ayrıştırma

OpenSSL, bir sertifikanın çözülmüş alanlarını yazdırabilir; `asn1parse` ise temel ASN.1 yapısını gösterir.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

En azından şunları inceleyin:

- subject, issuer ve Subject Alternative Name (SAN);
- key usage ve extended key usage;
- basic constraints ve path-length constraints;
- geçerlilik zamanları olan `notBefore` ve `notAfter`;
- public-key parametreleri ve signature algorithm.

MD5 veya SHA-1 tabanlı certificate signature gibi eski imzalar özellikle önemli bulgulardır; ancak kabul edilip edilmeyecekleri ve etkileri validator'a ve güven bağlamına bağlıdır.<sup>[[3]](#references)</sup>

RFC 5280; SAN, key usage, name constraints ve basic constraints gibi uzantıların işlenmesine ilişkin kuralları ve Internet X.509 profilini tanımlar.<sup>[[3]](#references)</sup>

## Kodlamalar ve Container'lar

- **PEM tarzı metinsel kodlama:** `BEGIN` ve `END` sınırları arasında Base64 verisi.
- **DER:** binary Distinguished Encoding Rules gösterimi.
- **PKCS#7/CMS (`.p7b`):** genellikle certificates ve certificate chain içerir, ancak private keys içermez.
- **PKCS#12 (`.p12` veya `.pfx`):** private keys, certificates ve supporting certificates içerebilir.

RFC 7468, PKIX, PKCS ve CMS yapıları için kullanılan metinsel kodlamaları belirtir; OpenSSL'ın `pkcs12` komutu PKCS#12 dosyalarını oluşturur ve ayrıştırır.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

`out.pem` dosyasını hassas kabul edin: `-nokeys` gibi seçenekler kullanılmadığı sürece çıktı özel anahtar bilgileri içerebilir.<sup>[[5]](#references)</sup>

## Güvenlik İnceleme Kontrol Listesi

Bir doğrulayıcıyı veya güven kararını incelerken RFC 5280'deki sertifika işleme gerekliliklerini uygulayın.<sup>[[3]](#references)</sup>

- Zincirin tamamını açıkça güvenilen bir köke kadar doğrulayın; kullanıcı tarafından sağlanan köklere örtük olarak güvenmeyin.
- Ana makine adını veya hizmet kimliğini SAN değerleriyle karşılaştırarak doğrulayın.<sup>[[8]](#references)</sup>
- Temel kısıtlamaları, ad kısıtlamalarını, anahtar kullanımını ve genişletilmiş anahtar kullanımını uygulayın.
- Süresi dolmuş veya henüz geçerli olmayan sertifikaları ve izin verilmeyen anahtar ya da imza algoritmalarını reddedin.
- İstemci sertifikası kimliklerini doğru uygulama hesabına ve yetkilendirme bağlamına bağlayın.

## Certificate Transparency Günlükleri

Certificate Transparency, verilen sertifikaların herkese açık şekilde denetlenebilir günlüklerini sağlar.<sup>[[6]](#references)</sup> Yetkili varlık keşfi sırasında crt.sh ile bir alan adını arayın.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL belgeleri - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL belgeleri - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 Açık Anahtar Altyapısı Sertifika ve CRL Profili](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX, PKCS ve CMS Yapılarının Metinsel Kodlamaları](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL belgeleri - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Sürüm 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Sertifika Arama](https://crt.sh/)
- [8] [RFC 9525 - TLS'de Hizmet Kimliği](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
