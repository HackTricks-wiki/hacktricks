# TLS ve Certificates

{{#include ../../banners/hacktricks-training.md}}

Bu bölüm X.509 incelemesini, encoding'leri, dönüşümleri ve güvenlikle ilgili validation hatalarını ele alır.

## X.509 Ayrıştırma

OpenSSL bir certificate'ın decoded alanlarını yazdırabilirken, `asn1parse` temel ASN.1 yapısını gösterir.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
En azından şunları inceleyin:

- subject, issuer ve Subject Alternative Name (SAN);
- key usage ve extended key usage;
- basic constraints ve path-length constraints;
- `notBefore` ve `notAfter` geçerlilik zamanları;
- public-key parametreleri ve signature algorithm.

MD5 veya SHA-1 tabanlı certificate signature gibi legacy signature'lar özellikle önemli bulgulardır; ancak kesin kabul ve etki, validator ve trust context'e bağlıdır.<sup>[[3]](#references)</sup>

RFC 5280, Internet X.509 profilini ve SAN, key usage, name constraints ve basic constraints gibi extension'lar için işleme kurallarını tanımlar.<sup>[[3]](#references)</sup>

## Kodlamalar ve Konteynerler

- **PEM-style textual encoding:** `BEGIN` ve `END` sınırları arasındaki Base64 verisi.
- **DER:** binary Distinguished Encoding Rules gösterimi.
- **PKCS#7/CMS (`.p7b`):** yaygın olarak certificate'lar ve bir certificate chain taşır, ancak private key taşımaz.
- **PKCS#12 (`.p12` veya `.pfx`):** private key'ler, certificate'lar ve supporting certificate'lar taşıyabilir.

RFC 7468, PKIX, PKCS ve CMS yapıları için kullanılan textual encoding'leri belirtir; OpenSSL'in `pkcs12` komutu PKCS#12 dosyaları oluşturur ve ayrıştırır.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
`out.pem` dosyasını hassas kabul edin: `-nokeys` gibi seçenekler kullanılmadığı sürece çıktı private-key materyali içerebilir.<sup>[[5]](#references)</sup>

## Güvenlik İncelemesi Kontrol Listesi

Bir validator veya trust decision'ı incelerken RFC 5280'deki certificate-processing gereksinimlerini uygulayın.<sup>[[3]](#references)</sup>

- Explicitly trusted bir anchor'a kadar olan complete chain'i doğrulayın; user-supplied root'lara örtük olarak trust etmeyin.
- Hostname veya service identity'yi SAN değerleriyle doğrulayın.<sup>[[8]](#references)</sup>
- Basic constraints, name constraints, key usage ve extended key usage kurallarını uygulayın.
- Süresi dolmuş veya henüz geçerli olmayan certificate'ları ve izin verilmeyen key veya signature algorithm'larını reddedin.
- Client-certificate identity'lerini doğru application account ve authorization context'e bağlayın.

## Certificate Transparency Log'ları

Certificate Transparency, issued certificate'ların publicly auditable log'larını sağlar.<sup>[[6]](#references)</sup> Authorized asset discovery sırasında crt.sh ile bir domain arayın.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL documentation - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL documentation - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX, PKCS ve CMS Structures için Textual Encodings](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL documentation - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Certificate Search](https://crt.sh/)
- [8] [RFC 9525 - TLS'te Service Identity](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
