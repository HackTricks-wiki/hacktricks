# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}

Ovo područje se bavi **X.509 parsiranjem, formatima, konverzijama i uobičajenim greškama**.

## X.509: parsiranje, formati & uobičajene greške

### Brzo parsiranje
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Korisna polja za proveru:

- Subjekat / Izdavač / SAN
- Namena ključa / EKU
- Osnovna ograničenja (da li je CA?)
- Period važenja (NotBefore/NotAfter)
- Algoritam potpisa (MD5? SHA1?)

### Formati i konverzija

- PEM (Base64 sa BEGIN/END headerima)
- DER (binarni)
- PKCS#7 (`.p7b`) (lanac sertifikata, bez privatnog ključa)
- PKCS#12 (`.pfx/.p12`) (sertifikat + privatni ključ + lanac)

Konverzije:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Uobičajeni ofanzivni pristupi

- Pouzdavanje u root sertifikate koje je obezbedio korisnik / nedostajuća validacija lanca
- Slabi algoritmi potpisa (legacy)
- Ograničenja imena / bagovi u parsiranju SAN (specifično za implementaciju)
- Confused deputy issues pri client-certificate authentication misbinding-u

### CT logovi

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
