# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Τα **Apple events** είναι δομημένα μηνύματα interprocess που χρησιμοποιούν οι εφαρμογές για να ζητούν λειτουργίες ή δεδομένα από άλλες εφαρμογές. Ο **Apple Event Manager** παρέχει τα APIs για τη δημιουργία, την αποστολή, τη λήψη και την απόκριση σε αυτά τα μηνύματα.<sup>[[1]](#references)</sup>

Στο macOS, ο κύριος broker είναι το `/System/Library/CoreServices/appleeventsd`, ο οποίος καταχωρίζει το Mach service `com.apple.coreservices.appleevents`. Οι εφαρμογές που λαμβάνουν events καταχωρίζουν ένα Apple-event Mach port σε αυτή την υπηρεσία· οι αποστολείς λαμβάνουν μέσω αυτής το port προορισμού.<sup>[[3]](#references)</sup>

Οι κανόνες του Sandbox και τα entitlements περιορίζουν αυτή την επικοινωνία. Ένα sandbox profile συνήθως εκφράζει τις απαιτούμενες λειτουργίες ως `allow appleevent-send` και ως Mach lookup για το `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>
```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```
Το δημόσιο entitlement `com.apple.security.temporary-exception.apple-events` μπορεί να περιορίσει μια εφαρμογή σε sandbox σε named destination bundle identifiers. Κατά την ανάλυση στοιχείων υπογεγραμμένων από την Apple, ελέγξτε επίσης το private entitlement `com.apple.private.appleevents`. Τα private Apple entitlements συνήθως δεν είναι διαθέσιμα σε εφαρμογές τρίτων.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Ορίστε τη μεταβλητή περιβάλλοντος **`AEDebugSends`** για να καταγράφετε πληροφορίες σχετικά με τα Apple events που αποστέλλονται από μια διεργασία:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Τεκμηρίωση Apple για developers - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Τεκμηρίωση Apple για developers - App Sandbox Temporary Exception Entitlements](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Mac OS X and iOS Internals - Μεταβλητές περιβάλλοντος για debugging Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
