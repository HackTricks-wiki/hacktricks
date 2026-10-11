# Εκκίνηση Shell, Aliases και Ιστορικό

{{#include ../../banners/hacktricks-training.md}}

Μια εντολή shell μπορεί να συμπεριφέρεται διαφορετικά από το εκτελέσιμο αρχείο με το ίδιο όνομα, αν ένα alias, μια συνάρτηση, ένα αρχείο εκκίνησης ή μια μεταβλητή περιβάλλοντος αλλάζει τον τρόπο εκτέλεσής της. Ελέγξτε τα παραπάνω πριν εμπιστευτείτε την έξοδο μιας εντολής ή υποθέσετε ότι ένα script χρησιμοποιεί το ίδιο PATH με μια διαδραστική συνεδρία.

## Επιθεώρηση του τρέχοντος shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

Τα `type` και `command -V` δείχνουν αν ένα όνομα αντιστοιχεί σε alias, function, builtin ή αρχείο. Τα `command -v` και `which` μπορεί να δώσουν διαφορετικά αποτελέσματα για aliases και functions. Το ιστορικό του shell μπορεί να αποκαλύψει εντολές ή διαπιστευτήρια, αλλά μπορεί να είναι ελλιπές, απενεργοποιημένο ή να παραμένει στη μνήμη μέχρι να τερματιστεί η συνεδρία.

## Ελέγξτε τα αρχεία εκκίνησης και ιστορικού

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Ένα startup file με δυνατότητα εγγραφής από χρήστη μπορεί να εκτελεί εντολές κατά την επόμενη εκκίνηση του shell. Ένα startup file σε επίπεδο συστήματος ή startup file προνομιούχου χρήστη είναι πιο ευαίσθητο, αν μπορεί να το τροποποιήσει ένας λογαριασμός με λιγότερα προνόμια. Το μη διαδραστικό Bash μπορεί επίσης να διαβάσει το αρχείο που ορίζεται από το `BASH_ENV`· η σελίδα [μεταβλητές περιβάλλοντος](linux-environment-variables.md#bash_env--env) εξηγεί αυτή τη συμπεριφορά και άλλα hooks διερμηνευτών. Επαληθεύστε ποια αρχεία διαβάζει πράγματι το shell για συνεδρίες login, interactive και non-interactive, πριν ισχυριστείτε ότι υπάρχει διαδρομή persistence.

Ελέγξτε επίσης τα αρχεία που φορτώνονται από ένα global startup file. Για παράδειγμα, ένα κυριολεκτικό `source /opt/app/venv/bin/activate` στο `/etc/bash.bashrc` εκτελεί το αρχείο ενεργοποίησης ως κώδικα shell όταν το shell διαβάζει πράγματι αυτό το startup file. Ελέγξτε το αρχείο ενεργοποίησης, τα δικαιώματα του symlink και των γονικών καταλόγων, καθώς και τα ACL· ένας χρήστης με λιγότερα προνόμια μπορεί να επηρεάσει ένα προνομιούχο shell μόνο αν αυτό το shell ή μια προνομιούχα εργασία φορτώσει αργότερα το αρχείο. Αν η πρόσβαση εγγραφής εξαρτάται από το `sudoedit`, επαληθεύστε πρώτα τον ακριβή κανόνα sudoers και το εγκατεστημένο πακέτο sudo με τις τροποποιήσεις του προμηθευτή· μια συμβολοσειρά έκδοσης upstream από μόνη της δεν τεκμηριώνει [έκθεση σε εισαγωγή ορισμάτων sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Ελέγξτε το ιστορικό, τα dotfiles και τα αντίγραφα ασφαλείας για μυστικά, όπως περιγράφεται στην ενότητα [χρήστες και συνεδρίες](../user-information/user-and-session-triage.md). Αν ένα προνομιούχο script εντοπίζει εντολές με βάση το όνομά τους, συνδυάστε αυτόν τον έλεγχο με τις [οδηγίες για το PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
