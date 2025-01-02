# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

**Apple Events** είναι μια δυνατότητα στο macOS της Apple που επιτρέπει στις εφαρμογές να επικοινωνούν μεταξύ τους. Είναι μέρος του **Apple Event Manager**, ο οποίος είναι ένα συστατικό του λειτουργικού συστήματος macOS υπεύθυνο για την διαχείριση της δια-διεργασίας επικοινωνίας. Αυτό το σύστημα επιτρέπει σε μια εφαρμογή να στείλει ένα μήνυμα σε μια άλλη εφαρμογή για να ζητήσει να εκτελέσει μια συγκεκριμένη λειτουργία, όπως το άνοιγμα ενός αρχείου, την ανάκτηση δεδομένων ή την εκτέλεση μιας εντολής.

Ο daemon mina είναι `/System/Library/CoreServices/appleeventsd` που καταχωρεί την υπηρεσία `com.apple.coreservices.appleevents`.

Κάθε εφαρμογή που μπορεί να λάβει γεγονότα θα ελέγχει με αυτόν τον daemon παρέχοντας το Apple Event Mach Port της. Και όταν μια εφαρμογή θέλει να στείλει ένα γεγονός σε αυτόν, η εφαρμογή θα ζητήσει αυτό το port από τον daemon.

Οι εφαρμογές που είναι σε sandbox απαιτούν δικαιώματα όπως `allow appleevent-send` και `(allow mach-lookup (global-name "com.apple.coreservices.appleevents))` προκειμένου να μπορούν να στέλνουν γεγονότα. Σημειώστε ότι τα δικαιώματα όπως `com.apple.security.temporary-exception.apple-events` θα μπορούσαν να περιορίσουν ποιος έχει πρόσβαση για να στείλει γεγονότα, τα οποία θα χρειαστούν δικαιώματα όπως `com.apple.private.appleevents`.

> [!TIP]
> Είναι δυνατόν να χρησιμοποιήσετε τη μεταβλητή env **`AEDebugSends`** προκειμένου να καταγράψετε πληροφορίες σχετικά με το μήνυμα που στάλθηκε:
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

{{#include ../../../../banners/hacktricks-training.md}}
