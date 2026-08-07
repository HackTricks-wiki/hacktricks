# Κλωνοποίηση ενός Website

{{#include ../../banners/hacktricks-training.md}}


Σε μια αξιολόγηση phishing, μερικές φορές μπορεί να είναι χρήσιμο να **κλωνοποιήσετε/κάνετε dump ενός website** πλήρως.

Σημειώστε ότι μπορείτε επίσης να προσθέσετε payloads στο cloned website, όπως ένα BeEF hook, για να "ελέγχετε" το tab του χρήστη.

Υπάρχουν διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτόν τον σκοπό:

## wget
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Εργαλειοθήκη Social Engineering
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
