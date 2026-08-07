# TLS e certificati

{{#include ../../banners/hacktricks-training.md}}


Questa sezione riguarda il **parsing di X.509, i formati, le conversioni e gli errori comuni**.

## X.509: parsing, formati ed errori comuni

### Parsing rapido
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Campi utili da esaminare:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (è una CA?)
- Finestra di validità (NotBefore/NotAfter)
- Algoritmo di firma (MD5? SHA1?)

### Formati e conversione

- PEM (Base64 con header BEGIN/END)
- DER (binario)
- PKCS#7 (`.p7b`) (catena di certificati, senza private key)
- PKCS#12 (`.pfx/.p12`) (certificato + private key + catena)

Conversioni:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Approcci offensivi comuni

- Fidarsi delle root fornite dall'utente / mancata convalida della catena
- Algoritmi di firma deboli (legacy)
- Bug nei name constraints / nel parsing dei SAN (specifici dell'implementazione)
- Problemi di confused deputy dovuti a un'associazione errata nell'autenticazione tramite certificato client

### Log CT

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
