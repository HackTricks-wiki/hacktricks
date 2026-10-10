# Εκκίνηση του Shell, Aliases και Ιστορικό

{{#include ../../banners/hacktricks-training.md}}

Μια εντολή του shell μπορεί να συμπεριφέρεται διαφορετικά από το εκτελέσιμο με το ίδιο όνομα, αν ένα alias, μια συνάρτηση, ένα αρχείο εκκίνησης ή μια μεταβλητή περιβάλλοντος αλλάζει τον τρόπο εκτέλεσής της. Ελέγξτε τα παραπάνω πριν εμπιστευτείτε την έξοδο μιας εντολής ή υποθέσετε ότι ένα script χρησιμοποιεί το ίδιο PATH με μια διαδραστική συνεδρία.

## Επιθεώρηση του τρέχοντος shell

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

Τα `type` και `command -V` αποκαλύπτουν αν ένα όνομα αντιστοιχεί σε alias, function, builtin ή αρχείο. Τα `command -v` και `which` ενδέχεται να μην εμφανίζουν την ίδια εικόνα για alias και function. Το ιστορικό του shell μπορεί να αποκαλύψει εντολές ή διαπιστευτήρια, αλλά ενδέχεται να είναι ελλιπές, απενεργοποιημένο ή να παραμένει στη μνήμη μέχρι να τερματιστεί η συνεδρία.

## Ελέγξτε τα αρχεία εκκίνησης και ιστορικού

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Ένα startup file εγγράψιμο από τον χρήστη μπορεί να εκτελέσει εντολές κατά την επόμενη εκκίνηση του shell. Ένα startup file σε επίπεδο συστήματος ή το startup file ενός προνομιούχου χρήστη είναι πιο ευαίσθητο, αν μπορεί να το τροποποιήσει ένας λογαριασμός με χαμηλότερα προνόμια. Το μη διαδραστικό Bash μπορεί επίσης να διαβάσει το αρχείο που ορίζεται από το `BASH_ENV`· η σελίδα [μεταβλητές περιβάλλοντος](linux-environment-variables.md#bash_env--env) εξηγεί αυτή τη συμπεριφορά και άλλα hooks διερμηνευτών. Επαληθεύστε ποια αρχεία διαβάζει το πραγματικό shell σε login, interactive και non-interactive sessions, πριν ισχυριστείτε ότι υπάρχει διαδρομή persistence.

Ελέγξτε επίσης τα αρχεία που γίνονται source από ένα global startup file. Για παράδειγμα, ένα κυριολεκτικό `source /opt/app/venv/bin/activate` στο `/etc/bash.bashrc` εκτελεί το αρχείο ενεργοποίησης ως κώδικα shell, όταν ένα shell διαβάζει πράγματι αυτό το startup file. Ελέγξτε το αρχείο ενεργοποίησης, τα δικαιώματα των symlink και των γονικών καταλόγων, καθώς και τα ACL· ένας χρήστης με χαμηλότερα προνόμια μπορεί να επηρεάσει ένα προνομιούχο shell μόνο αν το shell ή μια προνομιούχα εργασία κάνει αργότερα source το αρχείο. Αν η πρόσβαση εγγραφής εξαρτάται από το `sudoedit`, επαληθεύστε πρώτα τον ακριβή κανόνα sudoers και το εγκατεστημένο πακέτο sudo με τις τροποποιήσεις του vendor· μια upstream συμβολοσειρά έκδοσης από μόνη της δεν αποδεικνύει [έκθεση σε argument injection μέσω sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Ελέγξτε το ιστορικό, τα dotfiles και τα αντίγραφα ασφαλείας για secrets, όπως περιγράφεται στην ενότητα [χρήστες και sessions](../user-information/user-and-session-triage.md). Αν ένα προνομιούχο script εντοπίζει εντολές βάσει ονόματος, συνδυάστε αυτόν τον έλεγχο με τις [οδηγίες για PATH hijacking](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
