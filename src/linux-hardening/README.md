# Σκλήρυνση Linux

{{#include ../banners/hacktricks-training.md}}

Χρησιμοποιήστε αυτή την ενότητα για να εξετάσετε hosts Linux, να κατανοήσετε τα όρια προνομίων και να ελέγξετε τους μηχανισμούς που περιορίζουν την τοπική πρόσβαση. Ξεκινήστε από τα [βασικά του Linux](linux-basics/README.md) και τη [λίστα ελέγχου κλιμάκωσης προνομίων](main-system-information/linux-privilege-escalation-checklist.md) για μια γενική αξιολόγηση και, στη συνέχεια, εξετάστε τα σχετικά θέματα παρακάτω.

- [Βασικά του Linux](linux-basics/README.md): μεθοδολογία κλιμάκωσης προνομίων, χρήσιμες εντολές, μεταβλητές περιβάλλοντος και παρακάμψεις περιορισμών.
- [Κύριες πληροφορίες συστήματος](main-system-information/README.md): kernel, modules, sudo, συμπεριφορά συστήματος αρχείων, jails και λίστα ελέγχου κλιμάκωσης προνομίων.
- [Πληροφορίες χρηστών](user-information/README.md): ταυτότητες και ομάδες Linux, προώθηση SSH agent και ενσωμάτωση με το Active Directory.
- [Ενδιαφέροντα αρχεία και δικαιώματα](interesting-files-permissions/README.md): εγγράψιμες διαδρομές, capabilities, συμπεριφορά SUID, NFS, επέκταση wildcard και SELinux.
- [Πληροφορίες δικτύου](network-information/README.md): τοπικές υπηρεσίες, sockets και παραδείγματα εκμετάλλευσης σχετιζόμενα με το δίκτυο.
- [Πληροφορίες λογισμικού](software-information/README.md): modules πιστοποίησης και επιφάνειες επίθεσης ειδικές για εφαρμογές.
- [Διεργασίες, crontab, systemd και D-Bus](processes-crontab-systemd-dbus/README.md): προγραμματισμένη εκτέλεση και επικοινωνία μεταξύ διεργασιών.
- [Containers και namespaces](containers-namespaces/README.md): runtimes, όρια απομόνωσης και σκλήρυνση containers.
- [Post-exploitation](post-exploitation/README.md): αναζήτηση διαπιστευτηρίων, persistence και επόμενες τεχνικές σε επίπεδο host.
{{#include ../banners/hacktricks-training.md}}
