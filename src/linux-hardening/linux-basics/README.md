# Βασικά στοιχεία του Linux

{{#include ../../banners/hacktricks-training.md}}

Αυτό είναι το σημείο εκκίνησης για την αξιολόγηση ενός host Linux. Οι σελίδες καλύπτουν μια ευρεία ροή εργασίας για privilege escalation, πρακτικές εντολές, μεταβλητές περιβάλλοντος και συνήθεις περιορισμούς που επηρεάζουν το τι μπορεί να εκτελεστεί σε έναν host.

- Το [Linux privilege escalation](linux-privilege-escalation/README.md) περιγράφει την απαρίθμηση και πιθανές διαδρομές τοπικής κλιμάκωσης προνομίων. Για μια συντομότερη λίστα εργασιών, χρησιμοποιήστε το [checklist για privilege escalation](../main-system-information/linux-privilege-escalation-checklist.md).
- Το [εκκίνηση του Shell, ψευδώνυμα και ιστορικό](shell-startup-aliases-and-history.md) εξηγεί την επίλυση εντολών, την εκτέλεση αρχείων εκκίνησης και τα στοιχεία που προκύπτουν από το ιστορικό.
- Το [Χρήσιμες εντολές Linux](useful-linux-commands.md) συγκεντρώνει εντολές για την επιθεώρηση αρχείων, διεργασιών, υπηρεσιών και του περιβάλλοντος.
- Οι [μεταβλητές περιβάλλοντος Linux](linux-environment-variables.md) εξηγούν πώς οι τιμές περιβάλλοντος επηρεάζουν την εκτέλεση και πού μπορεί να εμφανιστούν ευαίσθητες τιμές.
- Η [παράκαμψη περιορισμών Linux](bypass-linux-restrictions/README.md) καλύπτει περιορισμένα shells και περιβάλλοντα εκτέλεσης, συμπεριλαμβανομένων των προστασιών συστήματος αρχείων, του `noexec` και των distroless συστημάτων.

## Εγγενής εκμετάλλευση δυαδικών αρχείων

Όταν μια αξιολόγηση οδηγεί σε ένα ευάλωτο εκτελέσιμο Linux, χρησιμοποιήστε το σχετικό υλικό στην ενότητα Binary Exploitation:

- Τα [μορφή ELF και συμπεριφορά του loader](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md) και [προστασίες δυαδικών αρχείων και παρακάμψεις](../../binary-exploitation/common-binary-protections-and-bypasses/README.md) εξηγούν τη διάταξη του εκτελέσιμου αρχείου και τους μηχανισμούς μετριασμού.
- Η [εκμετάλλευση στοίβας](../../binary-exploitation/basic-stack-binary-exploitation-methodology/README.md) και το [ROP](../../binary-exploitation/rop-return-oriented-programing/README.md) καλύπτουν επιθέσεις στη ροή ελέγχου.
- Η [εκμετάλλευση heap της Libc](../../binary-exploitation/libc-heap/README.md) και τα [format strings](../../binary-exploitation/format-strings/README.md) καλύπτουν άλλες συνήθεις διαδρομές αλλοίωσης μνήμης.

Μελέτες περιπτώσεων ειδικά για τον kernel παρατίθενται στο [υλικό για Kernel/LPE/CVE](../main-system-information/kernel-lpe-cves/README.md).
{{#include ../../banners/hacktricks-training.md}}
