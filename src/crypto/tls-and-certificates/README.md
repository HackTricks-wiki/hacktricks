# TLS & Certificats

{{#include ../../banners/hacktricks-training.md}}


Cette section concerne le **parsing X.509, les formats, les conversions et les erreurs courantes**.

## X.509 : parsing, formats et erreurs courantes

### Parsing rapide
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Useful fields to inspect:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (is it a CA?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Formats & conversion

- PEM (Base64 with BEGIN/END headers)
- DER (binary)
- PKCS#7 (`.p7b`) (certificate chain, no private key)
- PKCS#12 (`.pfx/.p12`) (certificate + private key + chain)

Conversions:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Angles d’attaque offensifs courants

- Confiance accordée aux autorités racines fournies par l’utilisateur / absence de validation de la chaîne
- Algorithmes de signature faibles (legacy)
- Contraintes de nommage / bugs d’analyse des SAN (spécifiques à l’implémentation)
- Problèmes de confused deputy liés à un mauvais rattachement de l’authentification par certificat client

### Journaux CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
