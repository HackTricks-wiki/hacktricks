{{#include ../../banners/hacktricks-training.md}}

Για μια αξιολόγηση phishing, μερικές φορές μπορεί να είναι χρήσιμο να **κλωνοποιήσετε μια ιστοσελίδα**.

Σημειώστε ότι μπορείτε επίσης να προσθέσετε μερικά payloads στην κλωνοποιημένη ιστοσελίδα, όπως ένα BeEF hook για να "ελέγξετε" την καρτέλα του χρήστη.

Υπάρχουν διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτόν τον σκοπό:

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Εργαλειοθήκη Κοινωνικής Μηχανικής
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
