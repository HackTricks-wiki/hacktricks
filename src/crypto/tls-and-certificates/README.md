# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}

Hierdie afdeling handel oor **X.509-ontleding, formate, omskakelings en algemene foute**.

## X.509: ontleding, formate & algemene foute

### Vinnige ontleding
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Nuttige velde om te ondersoek:

- Onderwerp / Uitreiker / SAN
- Sleutelgebruik / EKU
- Basiese beperkings (is dit 'n CA?)
- Geldigheidsvenster (NotBefore/NotAfter)
- Handtekeningalgoritme (MD5? SHA1?)

### Formate & omskakeling

- PEM (Base64 met BEGIN/END headers)
- DER (binêr)
- PKCS#7 (`.p7b`) (sertifikaatsketting, geen private sleutel)
- PKCS#12 (`.pfx/.p12`) (sertifikaat + private sleutel + sertifikaatsketting)

Omskakelings:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Gereelde offensiewe hoeke

- Vertroue in deur gebruiker verskafde root-sertifikate / ontbrekende kettingvalidasie
- Swak handtekeningsalgoritmes (verouderd)
- Naambeperkings / SAN parsing bugs (implementeringspesifiek)
- Confused deputy issues met client-certificate authentication misbinding

### CT logs

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
