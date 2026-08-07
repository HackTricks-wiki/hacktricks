# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Τα **Apple Events** είναι μια δυνατότητα του macOS της Apple που επιτρέπει στις εφαρμογές να επικοινωνούν μεταξύ τους. Αποτελούν μέρος του **Apple Event Manager**, ενός στοιχείου του λειτουργικού συστήματος macOS που είναι υπεύθυνο για τη διαχείριση της interprocess communication. Αυτό το σύστημα επιτρέπει σε μια εφαρμογή να στείλει ένα μήνυμα σε μια άλλη εφαρμογή, ζητώντας της να εκτελέσει μια συγκεκριμένη λειτουργία, όπως το άνοιγμα ενός αρχείου, την ανάκτηση δεδομένων ή την εκτέλεση μιας εντολής.

Ο κύριος daemon είναι το `/System/Library/CoreServices/appleeventsd`, ο οποίος καταχωρίζει την υπηρεσία `com.apple.coreservices.appleevents`.

Κάθε εφαρμογή που μπορεί να λαμβάνει events επικοινωνεί με αυτόν τον daemon, παρέχοντας το Apple Event Mach Port της. Όταν μια εφαρμογή θέλει να στείλει ένα event σε αυτήν, ζητά αυτή τη θύρα από τον daemon.

Οι Sandboxed εφαρμογές απαιτούν privileges όπως `allow appleevent-send` και `(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))`, ώστε να μπορούν να στέλνουν events. Ωστόσο, entitlements όπως το `com.apple.security.temporary-exception.apple-events` μπορούν να περιορίσουν ποιοι έχουν πρόσβαση στην αποστολή events, κάτι που μπορεί να απαιτεί entitlements όπως το `com.apple.private.appleevents`.

> [!TIP]
> Είναι δυνατή η χρήση της env variable **`AEDebugSends`** για την καταγραφή πληροφοριών σχετικά με το μήνυμα που αποστέλλεται:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
