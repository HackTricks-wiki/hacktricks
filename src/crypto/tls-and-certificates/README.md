# TLS και Πιστοποιητικά

{{#include ../../banners/hacktricks-training.md}}

Αυτή η ενότητα καλύπτει την επιθεώρηση X.509, τις κωδικοποιήσεις, τις μετατροπές και τα σφάλματα επικύρωσης που σχετίζονται με την ασφάλεια.

## Ανάλυση X.509

Το OpenSSL μπορεί να εμφανίσει τα αποκωδικοποιημένα πεδία ενός πιστοποιητικού, ενώ το `asn1parse` εμφανίζει την υποκείμενη δομή ASN.1.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
Ελέγξτε τουλάχιστον:

- το subject, τον issuer και το Subject Alternative Name (SAN)·
- το key usage και το extended key usage·
- τα basic constraints και τα path-length constraints·
- τους χρόνους ισχύος `notBefore` και `notAfter`·
- τις παραμέτρους του public key και τον signature algorithm.

Οι legacy signatures, όπως οι certificate signatures που βασίζονται σε MD5 ή SHA-1, αποτελούν ιδιαίτερα σημαντικά ευρήματα, αν και η ακριβής αποδοχή και επίδρασή τους εξαρτώνται από τον validator και το trust context.<sup>[[3]](#references)</sup>

Το RFC 5280 ορίζει το Internet X.509 profile και τους κανόνες επεξεργασίας για extensions όπως τα SAN, key usage, name constraints και basic constraints.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** Δεδομένα Base64 μεταξύ των ορίων `BEGIN` και `END`.
- **DER:** η δυαδική αναπαράσταση Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** συνήθως περιέχει certificates και certificate chain, αλλά όχι private keys.
- **PKCS#12 (`.p12` ή `.pfx`):** μπορεί να περιέχει private keys, certificates και supporting certificates.

Το RFC 7468 καθορίζει τα textual encodings που χρησιμοποιούνται για δομές PKIX, PKCS και CMS· η εντολή `pkcs12` του OpenSSL δημιουργεί και αναλύει αρχεία PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
Αντιμετωπίστε το `out.pem` ως ευαίσθητο: εκτός αν χρησιμοποιούνται επιλογές όπως `-nokeys`, η έξοδος ενδέχεται να περιέχει υλικό ιδιωτικού κλειδιού.<sup>[[5]](#references)</sup>

## Λίστα ελέγχου αναθεώρησης ασφάλειας

Εφαρμόστε τις απαιτήσεις επεξεργασίας πιστοποιητικών του RFC 5280 κατά την αναθεώρηση ενός validator ή μιας απόφασης εμπιστοσύνης.<sup>[[3]](#references)</sup>

- Επαληθεύστε την πλήρη αλυσίδα έως ένα ρητά έμπιστο anchor· μην εμπιστεύεστε έμμεσα roots που παρέχονται από τον χρήστη.
- Επιβεβαιώστε το hostname ή την ταυτότητα της υπηρεσίας έναντι των τιμών SAN.<sup>[[8]](#references)</sup>
- Επιβάλετε basic constraints, name constraints, key usage και extended key usage.
- Απορρίπτετε ληγμένα ή μη ακόμη έγκυρα πιστοποιητικά, καθώς και μη επιτρεπόμενους αλγόριθμους κλειδιών ή υπογραφής.
- Συνδέστε τις ταυτότητες των client-certificate με τον σωστό λογαριασμό εφαρμογής και το κατάλληλο authorization context.

## Certificate Transparency Logs

Το Certificate Transparency παρέχει δημόσια ελέγξιμα logs εκδοθέντων πιστοποιητικών.<sup>[[6]](#references)</sup> Αναζητήστε ένα domain με το crt.sh κατά την εξουσιοδοτημένη ανακάλυψη assets.<sup>[[7]](#references)</sup>

## References

- [1] [Τεκμηρίωση OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Τεκμηρίωση OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Προφίλ Υποδομής Δημοσίου Κλειδιού Internet X.509 για Πιστοποιητικά και CRL](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Κειμενικές κωδικοποιήσεις δομών PKIX, PKCS και CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Τεκμηρίωση OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Έκδοση 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Αναζήτηση πιστοποιητικών](https://crt.sh/)
- [8] [RFC 9525 - Ταυτότητα υπηρεσίας στο TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
