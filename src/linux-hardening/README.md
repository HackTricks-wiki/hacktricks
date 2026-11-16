# Ενίσχυση της ασφάλειας Linux

{{#include ../banners/hacktricks-training.md}}

Χρησιμοποιήστε αυτή την ενότητα για να εξετάσετε συστήματα Linux, να κατανοήσετε τα όρια προνομίων και να ελέγξετε τους μηχανισμούς ελέγχου που περιορίζουν την τοπική πρόσβαση. Ξεκινήστε από τα [βασικά του Linux](linux-basics/README.md) και τη [λίστα ελέγχου κλιμάκωσης προνομίων](main-system-information/linux-privilege-escalation-checklist.md) για μια γενική αξιολόγηση και, στη συνέχεια, ακολουθήστε το σχετικό θέμα παρακάτω.

- [Βασικά του Linux](linux-basics/README.md): μεθοδολογία κλιμάκωσης προνομίων, χρήσιμες εντολές, μεταβλητές περιβάλλοντος και παρακάμψεις περιορισμών.
- [Κύριες πληροφορίες συστήματος](main-system-information/README.md): kernel, modules, sudo, συμπεριφορά συστήματος αρχείων, jails και λίστα ελέγχου κλιμάκωσης προνομίων.
- [Πληροφορίες χρηστών](user-information/README.md): ταυτότητες Linux, ομάδες, SSH agent forwarding και ενσωμάτωση με το Active Directory.
- [Ενδιαφέροντα αρχεία και δικαιώματα](interesting-files-permissions/README.md): διαδρομές με δικαίωμα εγγραφής, capabilities, συμπεριφορά SUID, NFS, επέκταση wildcard και SELinux.
- [Πληροφορίες δικτύου](network-information/README.md): τοπικές υπηρεσίες, sockets και παραδείγματα εκμετάλλευσης που σχετίζονται με το δίκτυο.
- [Πληροφορίες λογισμικού](software-information/README.md): modules ελέγχου ταυτότητας και επιφάνειες επίθεσης ειδικές για εφαρμογές.
- [Διεργασίες, crontab, systemd και D-Bus](processes-crontab-systemd-dbus/README.md): προγραμματισμένη εκτέλεση και επικοινωνία μεταξύ διεργασιών.
- [Containers και namespaces](containers-namespaces/README.md): runtimes, όρια απομόνωσης και ενίσχυση της ασφάλειας των containers.
- [Κατάχρηση αρχείων ελέγχου πολιτικής του AppArmor](containers-namespaces/container-security/protections/apparmor.md#policy-control-files-as-a-privileged-write-primitive): εξετάστε αν ένα προνομιούχο βοηθητικό πρόγραμμα μπορεί να γράψει σε αρχείο ελέγχου του AppArmor που έχει ανοιχτεί από τοπικό χρήστη.
- [Post-exploitation](post-exploitation/README.md): εντοπισμός διαπιστευτηρίων, persistence και τεχνικές περαιτέρω ενεργειών σε επίπεδο συστήματος.

Σε επηρεαζόμενους kernels, το άνοιγμα ενός αρχείου ελέγχου πολιτικής του AppArmor στο securityfs από μη προνομιούχο χρήστη μπορεί να επιτύχει, παρότι η απευθείας εγγραφή απορρίπτεται. Αν ένα προνομιούχο βοηθητικό πρόγραμμα κληρονομήσει αυτό το αρχείο ως stdout, η εγγραφή του μπορεί να τροποποιήσει την ενεργή πολιτική· πρόκειται για ξεχωριστή τοπική διαδρομή επίθεσης και όχι απλώς για τον εντοπισμό ενός αδύναμου προφίλ container. Ελέγξτε τις διορθώσεις του κατασκευαστή του kernel και του βοηθητικού προγράμματος πριν από τη δοκιμή.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Τεχνική γνωμοδότηση της Qualys για το CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [2] [Βάση γνώσεων ευπαθειών CrackArmor του Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../banners/hacktricks-training.md}}
