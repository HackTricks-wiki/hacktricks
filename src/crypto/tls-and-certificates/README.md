# TLS & Sertifikalar

{{#include ../../banners/hacktricks-training.md}}

Bu bölüm **X.509 ayrıştırma, formatlar, dönüşümler ve yaygın hatalar** ile ilgilidir.

## X.509: ayrıştırma, formatlar & yaygın hatalar

### Hızlı ayrıştırma
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
İncelenecek yararlı alanlar:

- Konu (Subject) / İmzalayan (Issuer) / SAN
- Anahtar Kullanımı (Key Usage) / EKU
- Temel Kısıtlamalar (Basic Constraints) (CA mı?)
- Geçerlilik aralığı (NotBefore/NotAfter)
- İmza algoritması (MD5? SHA1?)

### Formatlar ve dönüştürme

- PEM (Base64, BEGIN/END başlıkları ile)
- DER (ikili)
- PKCS#7 (`.p7b`) (sertifika zinciri, özel anahtar yok)
- PKCS#12 (`.pfx/.p12`) (sertifika + özel anahtar + zincir)

Dönüştürmeler:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Yaygın saldırı vektörleri

- Kullanıcı tarafından sağlanan root sertifikalara güvenme / zincir doğrulamasının eksik olması
- Zayıf imza algoritmaları (eski)
- İsim kısıtlamaları / SAN ayrıştırma hataları (uygulamaya özgü)
- Confused deputy sorunları ile client-certificate authentication misbinding

### CT logları

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
