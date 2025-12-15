# TLS & Πιστοποιητικά

{{#include ../../banners/hacktricks-training.md}}

Αυτό το τμήμα αφορά **ανάλυση X.509, μορφές, μετατροπές και συνηθισμένα λάθη**.

## X.509: ανάλυση, μορφές & συνηθισμένα λάθη

### Γρήγορη ανάλυση
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Χρήσιμα πεδία προς εξέταση:

- Θέμα / Εκδότης / SAN
- Χρήση κλειδιού / EKU
- Βασικοί περιορισμοί (είναι CA;)
- Περίοδος ισχύος (NotBefore/NotAfter)
- Αλγόριθμος υπογραφής (MD5? SHA1?)

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

- Εμπιστοσύνη σε ρίζες που παρέχονται από τον χρήστη / ελλιπής επικύρωση αλυσίδας
- Αδύναμοι αλγόριθμοι υπογραφής (παρωχημένα)
- Περιορισμοί ονομάτων / σφάλματα ανάλυσης SAN (εξαρτάται από την υλοποίηση)
- Confused deputy issues with client-certificate authentication misbinding

### CT logs

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
