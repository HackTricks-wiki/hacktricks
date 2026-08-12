# Κρυπτογραφία

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα εστιάζει στην πρακτική κρυπτογραφία για security testing και CTFs: αναγνώριση κοινών μοτίβων, επιλογή κατάλληλων εργαλείων και εφαρμογή γνωστών επιθέσεων.

Για τεχνικές που κρύβουν δεδομένα μέσα σε αρχεία, δείτε την ενότητα **Stego**.

## Πώς να χρησιμοποιήσετε αυτή την ενότητα

Ξεκινήστε αναγνωρίζοντας το primitive και τις παραμέτρους του. Στη συνέχεια προσδιορίστε τι ελέγχει ή παρατηρεί ο attacker, όπως ένα oracle, μια leaked τιμή ή επαναχρησιμοποίηση nonce, πριν επιλέξετε μια επίθεση.

### CTF workflow

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

### TLS και certificates

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

Δημιουργήστε ένα απομονωμένο Python environment και εγκαταστήστε πακέτα που χρησιμοποιούνται συχνά. Η τεκμηρίωση του PyCryptodome συνιστά την εγκατάσταση του `pycryptodome` με `pip`· το SageMath παρέχει ξεχωριστές οδηγίες εγκατάστασης για κάθε υποστηριζόμενη πλατφόρμα.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
Το SageMath είναι συχνά χρήσιμο για αλγεβρικούς υπολογισμούς, υπολογισμούς σε lattices, RSA και elliptic curves.<sup>[[2]](#references)</sup>

## References

- [1] [Τεκμηρίωση PyCryptodome - Εγκατάσταση](https://www.pycryptodome.org/src/installation)
- [2] [Τεκμηρίωση SageMath - Οδηγός εγκατάστασης](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
