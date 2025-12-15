# TLS e Certificati

{{#include ../../banners/hacktricks-training.md}}

Questa area riguarda **l'analisi di X.509, i formati, le conversioni e gli errori comuni**.

## X.509: analisi, formati & errori comuni

### Analisi rapida
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Campi utili da ispezionare:

- Subject / Issuer / SAN
- Uso della chiave / EKU
- Basic Constraints (è una CA?)
- Finestra di validità (NotBefore/NotAfter)
- Algoritmo di firma (MD5? SHA1?)

### Formati & conversione

- PEM (Base64 con intestazioni BEGIN/END)
- DER (binario)
- PKCS#7 (`.p7b`) (catena di certificati, senza chiave privata)
- PKCS#12 (`.pfx/.p12`) (certificato + chiave privata + catena)

Conversioni:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Angoli offensivi comuni

- Affidarsi a root fornite dall'utente / mancata validazione della catena
- Algoritmi di firma deboli (obsoleti)
- Vincoli di nome / bug nel parsing dei SAN (specifici dell'implementazione)
- Problemi di Confused deputy con il misbinding dell'autenticazione client-certificate

### CT logs

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
