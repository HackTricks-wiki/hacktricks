# TLS & Zertifikate

{{#include ../../banners/hacktricks-training.md}}


In diesem Bereich geht es um **X.509-Parsing, Formate, Konvertierungen und häufige Fehler**.

## X.509: Parsing, Formate und häufige Fehler

### Schnelles Parsen
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Nützliche Felder zur Überprüfung:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (ist es eine CA?)
- Gültigkeitszeitraum (NotBefore/NotAfter)
- Signaturalgorithmus (MD5? SHA1?)

### Formate und Konvertierung

- PEM (Base64 mit BEGIN/END-Headern)
- DER (binär)
- PKCS#7 (`.p7b`) (Zertifikatskette, kein privater Schlüssel)
- PKCS#12 (`.pfx/.p12`) (Zertifikat + privater Schlüssel + Kette)

Konvertierungen:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Häufige offensive Ansatzpunkte

- Vertrauen in vom Benutzer bereitgestellte Roots / fehlende Kettenvalidierung
- Schwache Signaturalgorithmen (veraltet)
- Fehler beim Parsen von Name Constraints / SAN (implementierungsspezifisch)
- Confused-Deputy-Probleme durch fehlerhafte Zuordnung bei der Authentifizierung mit Client-Zertifikaten

### CT-Logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
