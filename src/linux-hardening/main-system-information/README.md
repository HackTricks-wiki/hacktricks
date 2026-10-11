# Κύριες πληροφορίες συστήματος

{{#include ../../banners/hacktricks-training.md}}

Εξετάστε τον kernel, το filesystem, τα προνομιούχα βοηθητικά προγράμματα και τις διαθέσιμες διαδρομές διαφυγής του host πριν επιλέξετε τεχνική τοπικής κλιμάκωσης προνομίων. Η [λίστα ελέγχου κλιμάκωσης προνομίων](linux-privilege-escalation-checklist.md) παρέχει μια συνοπτική σειρά ενεργειών.

- Η [αξιολόγηση ευπαθειών του kernel και η έκθεση κατά τον χρόνο εκτέλεσης](kernel-vulnerability-assessment.md) ελέγχει τη δυνατότητα εφαρμογής του build, την προσβασιμότητα και τα ενεργά μέτρα μετριασμού.
- Οι [μονάδες kernel και η κατάχρηση του modprobe](kernel-modules-and-modprobe.md) καλύπτουν τη φόρτωση μονάδων και την έκθεση της διαδρομής βοηθητικού προγράμματος.
- Η [κατάχρηση εντολών sudo](sudo-command-abuse.md) εξετάζει τρόπους με τους οποίους οι εκχωρημένες εντολές μπορούν να παραβιάσουν τα όρια προνομίων.
- Οι [symlinks, hardlinks και file descriptors](filesystem-links-and-file-descriptors.md) καλύπτουν την ανακατεύθυνση διαδρομών και τα κληρονομημένα ή διαγραμμένα αλλά ανοιχτά αρχεία.
- Τα [filesystem, inodes και ανάκτηση](filesystem-inodes-and-recovery.md) εξηγούν συμπεριφορές του filesystem που είναι χρήσιμες κατά την έρευνα.
- Η [λίστα ελέγχου: κλιμάκωση προνομίων Linux](linux-privilege-escalation-checklist.md) παραθέτει ελέγχους του host και συνδέσμους προς πιο αναλυτικό υλικό.
- Η [διαφυγή από jails](escaping-from-limited-bash.md) καλύπτει περιορισμένα shells και περιβάλλοντα.
- Το [υλικό για Kernel/LPE/CVE](kernel-lpe-cves/README.md) συγκεντρώνει εξειδικευμένα άρθρα για τοπική κλιμάκωση προνομίων και ευπάθειες.
{{#include ../../banners/hacktricks-training.md}}
