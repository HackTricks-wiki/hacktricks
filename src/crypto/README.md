# Κρυπτογραφία

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα εστιάζει στην πρακτική κρυπτογραφία για ελέγχους ασφάλειας και CTF: στην αναγνώριση συνηθισμένων μοτίβων, στην επιλογή κατάλληλων εργαλείων και στην εφαρμογή γνωστών επιθέσεων.

Για τεχνικές απόκρυψης δεδομένων μέσα σε αρχεία, δείτε την ενότητα **Stego**.

## Πώς να χρησιμοποιήσετε αυτή την ενότητα

Ξεκινήστε εντοπίζοντας το primitive και τις παραμέτρους του. Στη συνέχεια, προσδιορίστε τι ελέγχει ή παρατηρεί ο επιτιθέμενος, όπως ένα oracle, μια leaked τιμή ή την επαναχρησιμοποίηση nonce, πριν επιλέξετε επίθεση.

### Ροή εργασίας CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Συμμετρική κρυπτογραφία

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs και KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Κρυπτογραφία δημόσιου κλειδιού

{{#ref}}
public-key/README.md
{{#endref}}

### TLS και πιστοποιητικά

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Κρυπτογραφία σε malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Διάφορα

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Γρήγορη εγκατάσταση

Δημιουργήστε ένα απομονωμένο περιβάλλον Python και εγκαταστήστε πακέτα που χρησιμοποιούνται συχνά. Η τεκμηρίωση του PyCryptodome προτείνει την εγκατάσταση του `pycryptodome` με `pip`. Το SageMath παρέχει ξεχωριστές οδηγίες εγκατάστασης για κάθε υποστηριζόμενη πλατφόρμα.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

Το SageMath είναι συχνά χρήσιμο για αλγεβρικούς υπολογισμούς, υπολογισμούς lattice, RSA και ελλειπτικών καμπυλών.<sup>[[2]](#references)</sup>

## References

- [1] [Τεκμηρίωση PyCryptodome - Εγκατάσταση](https://www.pycryptodome.org/src/installation)
- [2] [Τεκμηρίωση SageMath - Οδηγός εγκατάστασης](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
