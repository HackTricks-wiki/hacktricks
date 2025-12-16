# TLS & Certificats

{{#include ../../banners/hacktricks-training.md}}

Cette section traite de **l'analyse X.509, des formats, des conversions et des erreurs courantes**.

## X.509 : analyse, formats & erreurs courantes

### Analyse rapide
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Champs utiles à inspecter :

- Sujet / Émetteur / SAN
- Utilisation de la clé / EKU
- Basic Constraints (est-ce une CA ?)
- Fenêtre de validité (NotBefore/NotAfter)
- Algorithme de signature (MD5 ? SHA1 ?)

### Formats & conversion

- PEM (Base64 avec en-têtes BEGIN/END)
- DER (binaire)
- PKCS#7 (`.p7b`) (chaîne de certificats, pas de clé privée)
- PKCS#12 (`.pfx/.p12`) (certificat + clé privée + chaîne)

Conversions:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Angles d'attaque courants

- Faire confiance aux racines fournies par l'utilisateur / validation de chaîne manquante
- Algorithmes de signature faibles (legacy)
- Contraintes de nom / bugs d'analyse SAN (spécifiques à l'implémentation)
- Problèmes de Confused deputy avec misbinding de l'authentification par client-certificate

### Journaux CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
