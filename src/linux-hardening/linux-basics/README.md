# Βασικές αρχές Linux

{{#include ../../banners/hacktricks-training.md}}

Αυτό είναι το σημείο εκκίνησης για την αξιολόγηση host σε Linux. Οι σελίδες καλύπτουν μια ευρεία διαδικασία privilege escalation, πρακτικές εντολές, μεταβλητές περιβάλλοντος και συνήθεις περιορισμούς που επηρεάζουν το τι μπορεί να εκτελεστεί σε έναν host.

- Η σελίδα [Linux privilege escalation](linux-privilege-escalation/README.md) περιγράφει την απαρίθμηση και πιθανές διαδρομές τοπικού escalation. Για μια συντομότερη λίστα εργασιών, χρησιμοποιήστε τη [λίστα ελέγχου privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- Η σελίδα [Εκκίνηση shell, aliases και ιστορικό](shell-startup-aliases-and-history.md) εξηγεί την επίλυση εντολών, την εκτέλεση αρχείων εκκίνησης και τα στοιχεία που αποκαλύπτει το ιστορικό.
- Η σελίδα [Χρήσιμες εντολές Linux](useful-linux-commands.md) συγκεντρώνει εντολές για την εξέταση αρχείων, διεργασιών, υπηρεσιών και του περιβάλλοντος.
- Η σελίδα [Μεταβλητές περιβάλλοντος Linux](linux-environment-variables.md) εξηγεί πώς οι τιμές περιβάλλοντος επηρεάζουν την εκτέλεση και πού μπορεί να εμφανιστούν ευαίσθητες τιμές.
- Η σελίδα [Παράκαμψη περιορισμών Linux](bypass-linux-restrictions/README.md) καλύπτει περιορισμένα shells και περιβάλλοντα εκτέλεσης, συμπεριλαμβανομένων των προστασιών του συστήματος αρχείων, του `noexec` και των distroless συστημάτων.

## Εκμετάλλευση εγγενών δυαδικών αρχείων

Όταν μια αξιολόγηση οδηγεί σε ένα ευάλωτο εκτελέσιμο Linux, χρησιμοποιήστε το σχετικό υλικό στο Binary Exploitation:

- Οι σελίδες [Μορφή ELF και συμπεριφορά του loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) και [Προστασίες δυαδικών αρχείων και παρακάμψεις](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) εξηγούν τη διάταξη του εκτελέσιμου και τους μηχανισμούς μετριασμού.
- Οι σελίδες [Εκμετάλλευση stack](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) και [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) καλύπτουν επιθέσεις στη ροή ελέγχου.
- Οι σελίδες [Εκμετάλλευση heap της Libc](../../binary-exploitation/libc-heap/README.md) και [Συμβολοσειρές μορφοποίησης](../../binary-exploitation/format-strings/README.md) καλύπτουν άλλες συνήθεις διαδρομές αλλοίωσης μνήμης.

Μελέτες περιπτώσεων ειδικά για τον kernel παρατίθενται στο [Υλικό Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
