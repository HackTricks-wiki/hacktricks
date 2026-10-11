# Διεργασίες, Crontab, Systemd και D-Bus

{{#include ../../banners/hacktricks-training.md}}

Οι προγραμματισμένες εργασίες και η επικοινωνία μεταξύ διεργασιών μπορούν να εκτελέσουν κώδικα με διαφορετικά προνόμια από αυτά του καλούντος. Ελέγξτε τον κάτοχο, την εντολή και τις εγγράψιμες εισόδους μιας υπηρεσίας ή εργασίας πριν τη δοκιμάσετε.

- [Απαρίθμηση διεργασιών και διαδρομές υπηρεσιών](process-enumeration-and-service-paths.md) καλύπτει τα δέντρα διεργασιών, τα αρχεία χρόνου εκτέλεσης και τις αλυσίδες εκτέλεσης του systemd.
- [Cron jobs και systemd timers](cron-and-systemd-timers.md) καλύπτει τον εντοπισμό προγραμματισμένων εργασιών και τις εγγράψιμες εισόδους.
- [Απαρίθμηση D-Bus και command injection privilege escalation](d-bus-enumeration-and-command-injection-privilege-escalation.md) καλύπτει το bus μηνυμάτων και τις μεθόδους προνομιούχων υπηρεσιών.
- [Payloads προς εκτέλεση](payloads-to-execute.md) συγκεντρώνει payloads που μπορούν να χρησιμοποιηθούν όταν έχει εντοπιστεί μια διαδρομή εκτέλεσης.

Για μια ευρύτερη ανασκόπηση των Cron jobs και των υπηρεσιών systemd, χρησιμοποιήστε τη [λίστα ελέγχου Linux privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
{{#include ../../banners/hacktricks-training.md}}
