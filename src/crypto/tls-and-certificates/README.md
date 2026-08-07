# TLS & Πιστοποιητικά

{{#include ../../banners/hacktricks-training.md}}


Αυτή η ενότητα αφορά την **ανάλυση X.509, τις μορφές, τις μετατροπές και τα συνηθισμένα λάθη**.

## X.509: ανάλυση, μορφές και συνηθισμένα λάθη

### Γρήγορη ανάλυση
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Χρήσιμα πεδία προς έλεγχο:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (είναι CA;)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5; SHA1;)

### Formats & conversion

- PEM (Base64 με κεφαλίδες BEGIN/END)
- DER (binary)
- PKCS#7 (`.p7b`) (cert chain, χωρίς private key)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Μετατροπές:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### Συνήθεις offensive angles

- Εμπιστοσύνη σε roots που παρέχονται από τον χρήστη / απουσία επικύρωσης της αλυσίδας
- Αδύναμοι αλγόριθμοι υπογραφής (legacy)
- Περιορισμοί ονομάτων / bugs στο parsing του SAN (συγκεκριμένα για την υλοποίηση)
- Ζητήματα confused deputy λόγω λανθασμένης αντιστοίχισης στο authentication μέσω client-certificate

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
