# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Τι είναι το Distroless

Ένα distroless container είναι ένας τύπος container που **περιέχει μόνο τις απαραίτητες εξαρτήσεις για να εκτελέσει μια συγκεκριμένη εφαρμογή**, χωρίς επιπλέον λογισμικό ή εργαλεία που δεν απαιτούνται. Αυτά τα containers έχουν σχεδιαστεί για να είναι όσο το δυνατόν **ελαφρύτερα** και **ασφαλέστερα**, και στοχεύουν να **ελαχιστοποιήσουν την επιφάνεια επίθεσης** αφαιρώντας οποιαδήποτε περιττά στοιχεία.

Τα distroless containers χρησιμοποιούνται συχνά σε **παραγωγικά περιβάλλοντα όπου η ασφάλεια και η αξιοπιστία είναι πρωταρχικής σημασίας**.

Ορισμένα **παραδείγματα** **distroless containers** είναι:

- Παρέχονται από **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Παρέχονται από **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Ο στόχος της οπλοποίησης ενός distroless container είναι να είναι δυνατή η **εκτέλεση αυθαίρετων δυαδικών και payloads ακόμη και με τους περιορισμούς** που υπονοούνται από το **distroless** (έλλειψη κοινών δυαδικών στο σύστημα) και επίσης προστασίες που συχνά βρίσκονται σε containers όπως **read-only** ή **no-execute** στο `/dev/shm`.

### Μέσω μνήμης

Έρχεται κάποια στιγμή το 2023...

### Μέσω Υπαρχόντων δυαδικών

#### openssl

\***\*[**Σε αυτή την ανάρτηση,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) εξηγείται ότι το δυαδικό **`openssl`** συχνά βρίσκεται σε αυτά τα containers, πιθανώς επειδή είναι **απαραίτητο\*\* από το λογισμικό που πρόκειται να εκτελείται μέσα στο container.

{{#include ../../../banners/hacktricks-training.md}}
