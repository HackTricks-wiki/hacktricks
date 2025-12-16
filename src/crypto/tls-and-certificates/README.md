# TLS & Zertifikate

{{#include ../../banners/hacktricks-training.md}}

Dieser Bereich behandelt **X.509-Parsing, Formate, Konvertierungen und häufige Fehler**.

## X.509: Parsing, Formate & häufige Fehler

### Schnelles Parsing
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Nützliche Felder zur Überprüfung:

- Subject / Issuer / SAN
- Schlüsselverwendung / EKU
- Basic Constraints (ist es eine CA?)
- Gültigkeitszeitraum (NotBefore/NotAfter)
- Signaturalgorithmus (MD5? SHA1?)

### Formate & Konvertierung

- PEM (Base64 mit BEGIN/END-Headern)
- DER (binär)
- PKCS#7 (`.p7b`) (Zertifikatskette, kein privater Schlüssel)
- PKCS#12 (`.pfx/.p12`) (Zertifikat + privater Schlüssel + Zertifikatskette)

Konvertierungen:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Häufige offensive Angriffsvektoren

- Vertrauen auf vom Benutzer bereitgestellte Root-Zertifikate / fehlende Kettenvalidierung
- Schwache Signaturalgorithmen (veraltet)
- Name-Constraints / SAN-Parsing-Fehler (implementierungsspezifisch)
- Confused-deputy-Probleme durch Fehlbindung der Client-Zertifikat-Authentifizierung

### CT-Logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
