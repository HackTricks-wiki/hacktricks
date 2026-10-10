# Διεργασίες, Crontab, Systemd και D-Bus

{{#include ../../banners/hacktricks-training.md}}

Οι προγραμματισμένες εργασίες και η επικοινωνία μεταξύ διεργασιών μπορούν να εκτελέσουν κώδικα με διαφορετικά προνόμια από αυτά του καλούντος. Ελέγξτε τον κάτοχο, την εντολή και τα εγγράψιμα δεδομένα εισόδου μιας υπηρεσίας ή εργασίας πριν τη δοκιμάσετε.

- [Απαρίθμηση διεργασιών και διαδρομές υπηρεσιών](process-enumeration-and-service-paths.md) καλύπτει δέντρα διεργασιών, αρχεία χρόνου εκτέλεσης και αλυσίδες εκτέλεσης systemd.
- [Cron jobs και χρονοδιακόπτες systemd](cron-and-systemd-timers.md) καλύπτει την ανακάλυψη προγραμματισμένων εργασιών και τα εγγράψιμα δεδομένα εισόδου.
- [Απαρίθμηση D-Bus και privilege escalation μέσω command injection](d-bus-enumeration-and-command-injection-privilege-escalation.md) καλύπτει το message bus και τις μεθόδους προνομιούχων υπηρεσιών.
- [Payloads προς εκτέλεση](payloads-to-execute.md) συγκεντρώνει payloads που μπορούν να χρησιμοποιηθούν όταν εντοπιστεί μια διαδρομή εκτέλεσης.

Για μια ευρύτερη επισκόπηση των cron jobs και των υπηρεσιών systemd, χρησιμοποιήστε τη [λίστα ελέγχου Linux privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
