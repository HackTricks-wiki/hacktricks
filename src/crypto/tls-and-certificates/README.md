# TLS & Sertifikate

{{#include ../../banners/hacktricks-training.md}}

Hierdie area gaan oor **X.509 ontleding, formate, omskakelings, en algemene foute**.

## X.509: ontleding, formate & algemene foute

### Vinnige ontleding
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Nuttige velde om te ondersoek:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (is dit 'n CA?)
- Geldigheidsvenster (NotBefore/NotAfter)
- Handtekeningalgoritme (MD5? SHA1?)

### Formate & omskakeling

- PEM (Base64 met BEGIN/END headers)
- DER (binêr)
- PKCS#7 (`.p7b`) (sertifikaatketting, geen privaat sleutel)
- PKCS#12 (`.pfx/.p12`) (cert + privaat sleutel + sertifikaatketting)

Omskakelings:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Algemene offensiewe hoeke

- Vertroue in deur gebruiker verskafde root-sertifikate / ontbrekende kettingvalidasie
- Swak handtekeningalgoritmes (verouderd)
- Naambeperkings / SAN-ontledingsfoute (implementasiespesifiek)
- Confused deputy-kwessies met verkeerde binding van kliënt-sertifikaatverifikasie

### CT-logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
