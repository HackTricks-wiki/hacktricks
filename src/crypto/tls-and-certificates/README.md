# TLS i sertifikati

{{#include ../../banners/hacktricks-training.md}}


Ova oblast se bavi **X.509 parsiranjem, formatima, konverzijama i uobičajenim greškama**.

## X.509: parsiranje, formati i uobičajene greške

### Brzo parsiranje
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Korisna polja za proveru:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (da li je CA?)
- Period važenja (NotBefore/NotAfter)
- Algoritam potpisa (MD5? SHA1?)

### Formati i konverzija

- PEM (Base64 sa BEGIN/END zaglavljima)
- DER (binarni)
- PKCS#7 (`.p7b`) (cert chain, bez private key-a)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Konverzije:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Uobičajeni ofanzivni pristupi

- Verovanje root sertifikatima koje obezbeđuje korisnik / nedostajuća validacija lanca
- Slabi algoritmi potpisivanja (legacy)
- Ograničenja imena / greške pri parsiranju SAN-a (specifične za implementaciju)
- Problemi sa confused deputy usled pogrešnog povezivanja autentikacije pomoću client sertifikata

### CT logovi

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
