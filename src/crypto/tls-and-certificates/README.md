# TLS i sertifikati

{{#include ../../banners/hacktricks-training.md}}

Ovaj odeljak pokriva **X.509 parsiranje, formate, konverzije i uobičajene greške**.

## X.509: parsiranje, formati & uobičajene greške

### Brzo parsiranje
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Korisna polja za pregled:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (is it a CA?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Formati i konverzija

- PEM (Base64 with BEGIN/END headers)
- DER (binary)
- PKCS#7 (`.p7b`) (lanac sertifikata, bez privatnog ključa)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Konverzije:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Uobičajeni ofanzivni pravci

- Poveravanje root sertifikatima koje korisnik obezbedi / nedostatak validacije lanca
- Slabi algoritmi potpisa (zastareli)
- Ograničenja imena / greške pri parsiranju SAN-a (specifično za implementaciju)
- Confused deputy problemi zbog pogrešnog vezivanja client-certificate autentifikacije

### CT logovi

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
