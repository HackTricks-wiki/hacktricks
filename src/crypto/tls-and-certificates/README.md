# TLS ve Sertifikalar

{{#include ../../banners/hacktricks-training.md}}


Bu bölüm **X.509 ayrıştırma, formatlar, dönüşümler ve yaygın hatalar** hakkındadır.

## X.509: ayrıştırma, formatlar ve yaygın hatalar

### Hızlı ayrıştırma
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
İncelenmesi gereken faydalı alanlar:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (CA mi?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Formats & conversion

- PEM (BEGIN/END başlıklarıyla Base64)
- DER (binary)
- PKCS#7 (`.p7b`) (sertifika zinciri, private key içermez)
- PKCS#12 (`.pfx/.p12`) (sertifika + private key + zincir)

Conversions:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Yaygın saldırı vektörleri

- Kullanıcı tarafından sağlanan root'lara güvenme / eksik zincir doğrulaması
- Zayıf imza algoritmaları (legacy)
- Name constraints / SAN ayrıştırma hataları (uygulamaya özgü)
- Client-certificate authentication misbinding kaynaklı confused deputy sorunları

### CT logları

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
