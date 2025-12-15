# Crypto

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα επικεντρώνεται στην **πρακτική κρυπτογραφία για hacking/CTFs**: πώς να αναγνωρίζετε γρήγορα κοινά πρότυπα, να επιλέγετε τα κατάλληλα εργαλεία και να εφαρμόζετε γνωστές επιθέσεις.

Αν βρίσκεστε εδώ για απόκρυψη δεδομένων μέσα σε αρχεία, πηγαίνετε στην ενότητα **Stego**.

## Πώς να χρησιμοποιήσετε αυτή την ενότητα

Τα Crypto challenges επιβραβεύουν την ταχύτητα: ταξινομήστε το primitive, εντοπίστε τι ελέγχετε (oracle/leak/nonce reuse), και στη συνέχεια εφαρμόστε ένα γνωστό attack template.

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

### Crypto σε malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Διάφορα
{{#ref}}
ctf-misc/README.md
{{#endref}}

## Γρήγορη εγκατάσταση

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Βιβλιοθήκες: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (συχνά απαραίτητο για lattice/RSA/ECC): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
