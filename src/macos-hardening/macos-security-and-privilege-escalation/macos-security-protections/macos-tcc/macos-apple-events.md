# macOS Apple Events

{{#include ../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Τα **Apple events** είναι δομημένα μηνύματα μεταξύ διεργασιών, τα οποία οι εφαρμογές χρησιμοποιούν για να ζητούν λειτουργίες ή δεδομένα από άλλες εφαρμογές. Το **Apple Event Manager** παρέχει τα APIs για τη δημιουργία, την αποστολή, τη λήψη και την απόκριση σε αυτά τα μηνύματα.<sup>[[1]](#references)</sup>

Στο macOS, ο κύριος broker είναι το `/System/Library/CoreServices/appleeventsd`, ο οποίος καταχωρίζει την υπηρεσία Mach `com.apple.coreservices.appleevents`. Οι εφαρμογές που λαμβάνουν events καταχωρίζουν μια θύρα Mach για Apple events σε αυτή την υπηρεσία· οι αποστολείς λαμβάνουν μέσω αυτής τη θύρα προορισμού.<sup>[[3]](#references)</sup>

Οι κανόνες sandbox και τα entitlements περιορίζουν αυτή την επικοινωνία. Ένα sandbox profile χρειάζεται άδεια για την αποστολή Apple events και την αναζήτηση της υπηρεσίας Mach του broker. Το entitlement `com.apple.security.temporary-exception.apple-events` μπορεί να περιορίσει περαιτέρω μια εφαρμογή σε sandbox, ώστε να επικοινωνεί μόνο με προορισμούς που αντιστοιχούν σε συγκεκριμένα bundle identifiers.<sup>[[2]](#references)</sup>

> [!TIP]
> Ορίστε τη μεταβλητή περιβάλλοντος **`AEDebugSends`** για να καταγράφετε πληροφορίες σχετικά με τα Apple events που αποστέλλονται από μια διεργασία:<sup>[[3]](#references)</sup>
>
> ```bash
> AEDebugSends=1 osascript -e 'tell application "iTerm" to activate'
> ```

## References

- [1] [Τεκμηρίωση Apple για developers - Apple Event Manager](https://developer.apple.com/documentation/applicationservices/apple_event_manager)
- [2] [Τεκμηρίωση Apple για developers - Προσωρινά Exception Entitlements του App Sandbox](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/AppSandboxTemporaryExceptionEntitlements.html)
- [3] [Εσωτερική λειτουργία των Mac OS X και iOS - Μεταβλητές περιβάλλοντος για debugging Apple events](https://www.newosxbook.com/MOXiI.pdf)
{{#include ../../../../banners/hacktricks-training.md}}
