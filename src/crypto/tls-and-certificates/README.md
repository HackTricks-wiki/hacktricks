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
- τους basic constraints και τους περιορισμούς μήκους διαδρομής·
- τους χρόνους ισχύος `notBefore` και `notAfter`·
- τις παραμέτρους του δημόσιου κλειδιού και τον αλγόριθμο υπογραφής.

Οι παλαιού τύπου υπογραφές, όπως οι υπογραφές πιστοποιητικών που βασίζονται σε MD5 ή SHA-1, είναι ιδιαίτερα σημαντικά ευρήματα, αν και η ακριβής αποδοχή και ο αντίκτυπος εξαρτώνται από τον validator και το πλαίσιο εμπιστοσύνης.<sup>[[3]](#references)</sup>

Το RFC 5280 ορίζει το προφίλ Internet X.509 και τους κανόνες επεξεργασίας για επεκτάσεις όπως SAN, key usage, name constraints και basic constraints.<sup>[[3]](#references)</sup>

## Κωδικοποιήσεις και Containers

- **Κειμενική κωδικοποίηση τύπου PEM:** δεδομένα Base64 ανάμεσα σε οριοθέτες `BEGIN` και `END`.
- **DER:** η δυαδική αναπαράσταση Distinguished Encoding Rules.
- **PKCS#7/CMS (`.p7b`):** περιέχει συνήθως πιστοποιητικά και αλυσίδα πιστοποιητικών, αλλά όχι ιδιωτικά κλειδιά.
- **PKCS#12 (`.p12` ή `.pfx`):** μπορεί να περιέχει ιδιωτικά κλειδιά, πιστοποιητικά και υποστηρικτικά πιστοποιητικά.

Το RFC 7468 καθορίζει τις κειμενικές κωδικοποιήσεις που χρησιμοποιούνται για δομές PKIX, PKCS και CMS· η εντολή `pkcs12` του OpenSSL δημιουργεί και αναλύει αρχεία PKCS#12.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

Να χειρίζεστε το `out.pem` ως ευαίσθητο αρχείο: εκτός αν χρησιμοποιούνται επιλογές όπως η `-nokeys`, η έξοδος μπορεί να περιέχει υλικό ιδιωτικού κλειδιού.<sup>[[5]](#references)</sup>

## Λίστα ελέγχου αναθεώρησης ασφάλειας

Κατά την αναθεώρηση ενός validator ή μιας απόφασης εμπιστοσύνης, εφαρμόστε τις απαιτήσεις επεξεργασίας πιστοποιητικών του RFC 5280.<sup>[[3]](#references)</sup>

- Επαληθεύστε ολόκληρη την αλυσίδα έως μια ρητά έμπιστη αρχή· μην εμπιστεύεστε σιωπηρά ρίζες που παρέχονται από τον χρήστη.
- Επιβεβαιώστε το hostname ή την ταυτότητα υπηρεσίας με βάση τις τιμές SAN.<sup>[[8]](#references)</sup>
- Επιβάλετε τους βασικούς περιορισμούς, τους περιορισμούς ονομάτων, τη χρήση κλειδιού και την εκτεταμένη χρήση κλειδιού.
- Απορρίψτε πιστοποιητικά που έχουν λήξει ή δεν έχουν ακόμη ισχύ, καθώς και μη επιτρεπόμενους αλγορίθμους κλειδιών ή υπογραφής.
- Αντιστοιχίστε τις ταυτότητες πιστοποιητικών πελάτη στον σωστό λογαριασμό εφαρμογής και στο κατάλληλο πλαίσιο εξουσιοδότησης.

## Αρχεία καταγραφής Certificate Transparency

Το Certificate Transparency παρέχει δημόσια ελέγξιμα αρχεία καταγραφής εκδοθέντων πιστοποιητικών.<sup>[[6]](#references)</sup> Αναζητήστε ένα domain στο crt.sh κατά την εξουσιοδοτημένη ανακάλυψη στοιχείων ενεργητικού.<sup>[[7]](#references)</sup>

## References

- [1] [Τεκμηρίωση OpenSSL - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [Τεκμηρίωση OpenSSL - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Προφίλ υποδομής δημόσιου κλειδιού Internet X.509 για πιστοποιητικά και CRL](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Κειμενικές κωδικοποιήσεις δομών PKIX, PKCS και CMS](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [Τεκμηρίωση OpenSSL - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency έκδοση 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Αναζήτηση πιστοποιητικών](https://crt.sh/)
- [8] [RFC 9525 - Ταυτότητα υπηρεσίας στο TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
