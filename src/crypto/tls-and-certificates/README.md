# TLS & Certificati

{{#include ../../banners/hacktricks-training.md}}

Questa sezione riguarda **l'analisi di X.509, i formati, le conversioni e gli errori comuni**.

## X.509: analisi, formati e errori comuni

### Analisi rapida
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Campi utili da ispezionare:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (è una CA?)
- Finestra di validità (NotBefore/NotAfter)
- Algoritmo di firma (MD5? SHA1?)

### Formati & conversione

- PEM (Base64 con header BEGIN/END)
- DER (binario)
- PKCS#7 (`.p7b`) (catena di certificati, senza chiave privata)
- PKCS#12 (`.pfx/.p12`) (certificato + chiave privata + catena)

Conversioni:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Approcci offensivi comuni

- Affidarsi a root fornite dall'utente / mancata validazione della catena
- Algoritmi di firma deboli (obsoleti)
- Vincoli di nome / bug di parsing SAN (dipende dall'implementazione)
- Problemi di Confused deputy con client-certificate authentication misbinding

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
