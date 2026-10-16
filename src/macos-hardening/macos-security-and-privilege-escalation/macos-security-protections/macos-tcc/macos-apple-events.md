# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Τα **Apple events** είναι δομημένα μηνύματα μεταξύ διεργασιών, τα οποία χρησιμοποιούν οι εφαρμογές για να ζητούν λειτουργίες ή δεδομένα από άλλες εφαρμογές. Το **Apple Event Manager** παρέχει τα API για τη δημιουργία, την αποστολή, τη λήψη και την απόκριση σε αυτά τα μηνύματα.<sup>[[1]](#references)</sup>

Στο macOS, ο κύριος broker είναι το `/System/Library/CoreServices/appleeventsd`, ο οποίος καταχωρίζει την υπηρεσία Mach `com.apple.coreservices.appleevents`. Οι εφαρμογές που λαμβάνουν events καταχωρίζουν μια θύρα Mach για Apple events σε αυτή την υπηρεσία· οι αποστολείς λαμβάνουν μέσω αυτής τη θύρα προορισμού.<sup>[[3]](#references)</sup>

Οι κανόνες sandbox και τα entitlements περιορίζουν αυτή την επικοινωνία. Ένα προφίλ sandbox συνήθως ορίζει τις απαιτούμενες λειτουργίες ως `allow appleevent-send` και αναζήτηση Mach για το `com.apple.coreservices.appleevents`:<sup>[[3]](#references)</sup>

```scheme
(allow appleevent-send)
(allow mach-lookup (global-name "com.apple.coreservices.appleevents"))
```

Το δημόσιο entitlement `com.apple.security.temporary-exception.apple-events` μπορεί να περιορίσει μια εφαρμογή σε sandbox ώστε να επικοινωνεί μόνο με καθορισμένα αναγνωριστικά bundle προορισμού. Κατά την ανάλυση στοιχείων υπογεγραμμένων από την Apple, ελέγξτε επίσης για το ιδιωτικό entitlement `com.apple.private.appleevents`· τα ιδιωτικά Apple entitlements δεν είναι συνήθως διαθέσιμα σε εφαρμογές τρίτων.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

> [!TIP]
> Ορίστε τη μεταβλητή περιβάλλοντος **`AEDebugSends`** για να καταγράφετε πληροφορίες σχετικά με τα Apple events που αποστέλλονται από μια διεργασία:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

Για να αντιστοιχίσετε μια άδεια Automation στον αποστολέα και τον παραλήπτη της, δείτε [TCC Apple Events grants](index.html#identify-apple-events-sender-and-target-grants).



## References

- [1] [Τεκμηρίωση Apple Developer - Διαχειριστής Apple Event](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Τεκμηρίωση Apple Developer - Δικαιώματα προσωρινών εξαιρέσεων App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Εσωτερικά των Mac OS X και iOS - Μεταβλητές περιβάλλοντος αποσφαλμάτωσης Apple-event](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
