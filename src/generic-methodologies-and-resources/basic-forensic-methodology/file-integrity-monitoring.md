{{#include ../../banners/hacktricks-training.md}}

# Βασική Γραμμή

Μια βασική γραμμή αποτελείται από τη λήψη μιας στιγμιότυπης εικόνας ορισμένων τμημάτων ενός συστήματος για **να τη συγκρίνουμε με μια μελλοντική κατάσταση ώστε να επισημάνουμε τις αλλαγές**.

Για παράδειγμα, μπορείτε να υπολογίσετε και να αποθηκεύσετε το hash κάθε αρχείου του συστήματος αρχείων για να μπορέσετε να διαπιστώσετε ποια αρχεία έχουν τροποποιηθεί.\
Αυτό μπορεί επίσης να γίνει με τους λογαριασμούς χρηστών που έχουν δημιουργηθεί, τις διαδικασίες που εκτελούνται, τις υπηρεσίες που εκτελούνται και οτιδήποτε άλλο δεν θα έπρεπε να αλλάξει πολύ ή καθόλου.

## Παρακολούθηση Ακεραιότητας Αρχείων

Η Παρακολούθηση Ακεραιότητας Αρχείων (FIM) είναι μια κρίσιμη τεχνική ασφάλειας που προστατεύει τα IT περιβάλλοντα και τα δεδομένα παρακολουθώντας τις αλλαγές στα αρχεία. Περιλαμβάνει δύο βασικά βήματα:

1. **Σύγκριση Βασικής Γραμμής:** Καθιερώστε μια βασική γραμμή χρησιμοποιώντας χαρακτηριστικά αρχείων ή κρυπτογραφικούς ελέγχους (όπως MD5 ή SHA-2) για μελλοντικές συγκρίσεις ώστε να ανιχνεύσετε τροποποιήσεις.
2. **Ειδοποίηση Αλλαγών σε Πραγματικό Χρόνο:** Λάβετε άμεσες ειδοποιήσεις όταν τα αρχεία προσπελάζονται ή τροποποιούνται, συνήθως μέσω επεκτάσεων πυρήνα OS.

## Εργαλεία

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Αναφορές

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
