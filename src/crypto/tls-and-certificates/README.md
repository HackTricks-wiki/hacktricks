# TLS na Vyeti

{{#include ../../banners/hacktricks-training.md}}

Eneo hili linahusu **uchambuzi wa X.509, miundo, uongofu, na makosa ya kawaida**.

## X.509: uchambuzi, miundo & makosa ya kawaida

### Uchambuzi wa haraka
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

- PEM (Base64 na header za BEGIN/END)
- DER (bainari)
- PKCS#7 (`.p7b`) (cert chain, hakuna private key)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Ubadilishaji:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Mwelekeo ya kawaida ya mashambulizi

- Kukubali mizizi zinazotolewa na mtumiaji / ukosefu wa uthibitishaji wa mnyororo
- Algoritimu za saini dhaifu (za zamani)
- Vizuizi vya majina / mende za kuchambua SAN (maalum kwa utekelezaji)
- Masuala ya Confused deputy na misbinding ya client-certificate authentication

### Logi za CT

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
