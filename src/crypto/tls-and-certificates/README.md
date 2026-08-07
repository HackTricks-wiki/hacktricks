# TLS & Sertifikate

{{#include ../../banners/hacktricks-training.md}}


Hierdie afdeling handel oor **X.509-ontleding, formate, omskakelings en algemene foute**.

## X.509: ontleding, formate en algemene foute

### Vinnige ontleding
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Nuttige velde om te inspekteer:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (is dit ’n CA?)
- Geldigheidsperiode (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Formate en omskakeling

- PEM (Base64 met BEGIN/END headers)
- DER (binêr)
- PKCS#7 (`.p7b`) (cert chain, geen private key nie)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Omskakelings:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Algemene offensiewe benaderings

- Vertroue op user-provided roots / ontbrekende chain validation
- Swak signature algorithms (legacy)
- Name constraints / SAN parsing bugs (implementation-specific)
- Confused deputy-kwessies met client-certificate authentication misbinding

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
