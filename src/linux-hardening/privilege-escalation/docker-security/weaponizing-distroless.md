# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

Ένα distroless container είναι ένας τύπος container που **περιέχει μόνο τις απαραίτητες εξαρτήσεις για να τρέξει μια συγκεκριμένη εφαρμογή**, χωρίς επιπλέον λογισμικό ή εργαλεία που δεν απαιτούνται. Αυτά τα containers έχουν σχεδιαστεί για να είναι όσο το δυνατόν **ελαφρύτερα** και **ασφαλέστερα**, και στοχεύουν να **μειώσουν την επιφάνεια επίθεσης** αφαιρώντας οποιαδήποτε περιττά στοιχεία.

Τα distroless containers χρησιμοποιούνται συχνά σε **παραγωγικά περιβάλλοντα όπου η ασφάλεια και η αξιοπιστία είναι πρωταρχικής σημασίας**.

Ορισμένα **παραδείγματα** **distroless containers** είναι:

- Παρέχονται από **Google**: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- Παρέχονται από **Chainguard**: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Ο στόχος της οπλοποίησης ενός distroless container είναι να μπορεί να **εκτελεί αυθαίρετους δυαδικούς κώδικες και payloads ακόμη και με τους περιορισμούς** που υπονοούνται από το **distroless** (έλλειψη κοινών δυαδικών κωδίκων στο σύστημα) και επίσης προστασίες που συχνά βρίσκονται σε containers όπως **read-only** ή **no-execute** στο `/dev/shm`.

### Through memory

Coming at some point of 2023...

### Via Existing binaries

#### openssl

\***\*[**In this post,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) εξηγείται ότι ο δυαδικός κώδικας **`openssl`** βρίσκεται συχνά σε αυτά τα containers, πιθανώς επειδή είναι **απαραίτητος** από το λογισμικό που πρόκειται να τρέξει μέσα στο container.

{{#include ../../../banners/hacktricks-training.md}}
