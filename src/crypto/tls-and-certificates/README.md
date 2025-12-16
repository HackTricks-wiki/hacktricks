# TLS & Vyeti

{{#include ../../banners/hacktricks-training.md}}

Eneo hili linahusu **Uchanganaji wa X.509, miundo, uongofu, na makosa ya kawaida**.

## X.509: uchanganaji, miundo & makosa ya kawaida

### Uchanganaji wa haraka
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Sehemu muhimu za kuchunguza:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (je, ni CA?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Miundo & uongofu

- PEM (Base64 na vichwa vya BEGIN/END)
- DER (binary)
- PKCS#7 (`.p7b`) (mnyororo wa cheti, hakuna funguo binafsi)
- PKCS#12 (`.pfx/.p12`) (cheti + funguo binafsi + mnyororo wa cheti)

Uongofu:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Njia za kawaida za mashambulizi

- Kumwamini mizizi iliyotolewa na mtumiaji / ukosefu wa uhakiki wa mnyororo
- Algoritimu dhaifu za saini (za zamani)
- Vikwazo vya majina / mdudu wa uchambuzi wa SAN (maalum kwa utekelezaji)
- Masuala ya confused deputy na client-certificate authentication misbinding

### Rekodi za CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
