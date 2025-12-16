# TLS & Sertifikalar

{{#include ../../banners/hacktricks-training.md}}

Bu bölüm **X.509 ayrıştırma, formatlar, dönüşümler ve yaygın hatalar** ile ilgilidir.

## X.509: ayrıştırma, formatlar & yaygın hatalar

### Hızlı ayrıştırma
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
İncelenecek faydalı alanlar:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (bir CA mı?)
- Geçerlilik aralığı (NotBefore/NotAfter)
- İmza algoritması (MD5? SHA1?)

### Formatlar & dönüşüm

- PEM (BEGIN/END başlıkları ile Base64)
- DER (ikili)
- PKCS#7 (`.p7b`) (sertifika zinciri, özel anahtar yok)
- PKCS#12 (`.pfx/.p12`) (sertifika + özel anahtar + zincir)

Dönüşümler:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Yaygın offensive açılar

- Kullanıcı tarafından sağlanan roots'a güvenme / zincir doğrulamasının eksik olması
- Zayıf signature algoritmaları (legacy)
- Name constraints / SAN parsing hataları (uygulamaya özgü)
- Confused deputy sorunları — client-certificate authentication misbinding ile ilişkili

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
