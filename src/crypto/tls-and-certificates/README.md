# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}


Eneo hili linahusu **uchanganuzi wa X.509, miundo, ubadilishaji, na makosa ya kawaida**.

## X.509: uchanganuzi, miundo na makosa ya kawaida

### Uchanganuzi wa haraka
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Sehemu muhimu za kukagua:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (je, ni CA?)
- Kipindi cha uhalali (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Miundo na ubadilishaji

- PEM (Base64 yenye vichwa vya BEGIN/END)
- DER (binary)
- PKCS#7 (`.p7b`) (cert chain, bila private key)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Ubadilishaji:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Mikabala ya kawaida ya mashambulizi

- Kuamini roots zinazotolewa na mtumiaji / ukosefu wa uthibitishaji wa chain
- Algorithms dhaifu za sahihi (legacy)
- Vikwazo vya majina / hitilafu za uchanganuzi wa SAN (maalum kwa implementation)
- Matatizo ya confused deputy yanayotokana na client-certificate authentication misbinding

### Kumbukumbu za CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
