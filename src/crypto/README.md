# Κρυπτογραφία

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα εστιάζει στην **πρακτική κρυπτογραφία για hacking/CTFs**: πώς να αναγνωρίζεις γρήγορα κοινά μοτίβα, να επιλέγεις τα σωστά εργαλεία και να εφαρμόζεις γνωστά attacks.

Αν βρίσκεσαι εδώ για να κρύψεις δεδομένα μέσα σε αρχεία, πήγαινε στην ενότητα **Stego**.

## Πώς να χρησιμοποιήσεις αυτή την ενότητα

Τα Crypto challenges ανταμείβουν την ταχύτητα: ταξινόμησε το primitive, εντόπισε τι ελέγχεις (oracle/leak/nonce reuse) και, στη συνέχεια, εφάρμοσε ένα γνωστό attack template.

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

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Βιβλιοθήκες: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (συχνά απαραίτητο για lattice/RSA/ECC): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
