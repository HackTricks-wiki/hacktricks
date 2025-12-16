# TLS & Πιστοποιητικά

{{#include ../../banners/hacktricks-training.md}}

Αυτή η ενότητα αφορά **την ανάλυση X.509, τις μορφές, τις μετατροπές και τα κοινά λάθη**.

## X.509: ανάλυση, μορφές & κοινά λάθη

### Γρήγορη ανάλυση
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Χρήσιμα πεδία για έλεγχο:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (είναι CA?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Μορφές & μετατροπή

- PEM (Base64 με κεφαλίδες BEGIN/END)
- DER (δυαδικό)
- PKCS#7 (`.p7b`) (αλυσίδα πιστοποιητικών, χωρίς ιδιωτικό κλειδί)
- PKCS#12 (`.pfx/.p12`) (πιστοποιητικό + ιδιωτικό κλειδί + αλυσίδα)

Μετατροπές:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Κοινές επιθετικές προσεγγίσεις

- Εμπιστοσύνη σε root πιστοποιητικά που παρέχονται από χρήστες / έλλειψη επαλήθευσης της αλυσίδας
- Αδύναμοι αλγόριθμοι υπογραφής (παλαιοί)
- Περιορισμοί ονομάτων / σφάλματα στην ανάλυση SAN (εξαρτώμενα από την υλοποίηση)
- Προβλήματα τύπου Confused deputy με misbinding στην πιστοποίηση client-certificate

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
