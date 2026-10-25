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

`type` και `command -V` αποκαλύπτουν αν ένα όνομα αντιστοιχεί σε alias, function, builtin ή αρχείο. Τα `command -v` και `which` μπορεί να μη δίνουν την ίδια πληροφορία για alias και function. Το ιστορικό του shell μπορεί να αποκαλύψει εντολές ή διαπιστευτήρια, αλλά ενδέχεται να είναι ελλιπές, απενεργοποιημένο ή να παραμένει στη μνήμη μέχρι να τερματιστεί η συνεδρία.

Ένα τροποποιημένο `.bashrc` μπορεί να ορίσει ένα alias `sudo` που μιμείται μια προτροπή κωδικού πρόσβασης, καταγράφει την απάντηση και τη μεταβιβάζει στην πραγματική εντολή. Έτσι μπορεί να υποκρύψει την υποκλοπή διαπιστευτηρίων χωρίς να αλλάξει το εκτελέσιμο `sudo` ή το `PATH`.<sup>[[5]](#references)</sup> Το shell πρέπει να διαβάσει το τροποποιημένο αρχείο εκκίνησης και να αναπτύξει το alias.<sup>[[7]](#references)</sup> Από προεπιλογή, το μη διαδραστικό Bash δεν αναπτύσσει alias, εκτός αν είναι ενεργοποιημένο το `expand_aliases`.<sup>[[6]](#references)</sup>

## Έλεγχος αρχείων εκκίνησης και ιστορικού

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Ένα αρχείο εκκίνησης στο οποίο μπορεί να γράψει ένας χρήστης μπορεί να εκτελέσει εντολές την επόμενη φορά που θα ξεκινήσει ένα shell. Ένα καθολικό αρχείο εκκίνησης ή ένα αρχείο εκκίνησης προνομιούχου χρήστη είναι πιο ευαίσθητο, αν μπορεί να το τροποποιήσει ένας λογαριασμός με χαμηλότερα προνόμια. Το μη διαδραστικό Bash μπορεί επίσης να διαβάσει το αρχείο που ορίζεται από το `BASH_ENV`· η σελίδα [μεταβλητές περιβάλλοντος](linux-environment-variables.md#bash_env--env) εξηγεί αυτή τη συμπεριφορά και άλλα hooks διερμηνευτών. Επαληθεύστε ποια αρχεία διαβάζει το πραγματικό shell σε συνδέσεις login, διαδραστικές και μη διαδραστικές, προτού ισχυριστείτε ότι υπάρχει διαδρομή persistence.

Ελέγξτε επίσης τα αρχεία που γίνονται source από ένα καθολικό αρχείο εκκίνησης. Για παράδειγμα, ένα κυριολεκτικό `source /opt/app/venv/bin/activate` στο `/etc/bash.bashrc` εκτελεί το αρχείο ενεργοποίησης ως κώδικα shell, όταν ένα shell διαβάζει πράγματι αυτό το αρχείο εκκίνησης. Εξετάστε το αρχείο ενεργοποίησης, τα δικαιώματα του symlink και των γονικών καταλόγων, καθώς και τα ACL· ένας χρήστης με χαμηλότερα προνόμια μπορεί να επηρεάσει ένα προνομιούχο shell μόνο αν το shell ή μια προνομιούχα εργασία κάνει αργότερα source το αρχείο. Αν η πρόσβαση εγγραφής εξαρτάται από το `sudoedit`, επαληθεύστε πρώτα τον ακριβή κανόνα sudoers και το εγκατεστημένο πακέτο sudo με patches του προμηθευτή· μια συμβολοσειρά έκδοσης upstream από μόνη της δεν τεκμηριώνει έκθεση σε [injection ορισμάτων sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Ελέγξτε το ιστορικό, τα dotfiles και τα αντίγραφα ασφαλείας για μυστικά, όπως περιγράφεται στην ενότητα [χρήστες και συνεδρίες](../user-information/user-and-session-triage.md). Αν ένα προνομιούχο script αναζητά εντολές με βάση το όνομά τους, συνδυάστε αυτόν τον έλεγχο με τις [οδηγίες για το PATH hijacking](linux-environment-variables.md#path).

## Ανακατεύθυνση εκκίνησης του Zsh και μεταγλωττισμένα αρχεία

Με τις προεπιλεγμένες ρυθμίσεις `RCS`, το zsh διαβάζει το `$ZDOTDIR/.zshenv` πριν από τις συνήθεις εκτελέσεις, συμπεριλαμβανομένων των `zsh -c` και των scripts· αν δεν έχει οριστεί το `ZDOTDIR`, χρησιμοποιεί το `$HOME`. Όταν ένας command runner δέχεται χάρτη περιβάλλοντος, ελέγξτε αν προωθεί κάποια από αυτές τις μεταβλητές σε μια προνομιούχα διεργασία zsh. Ένα εγγράψιμο `.zshenv` μπορεί τότε να εκτελεστεί **πριν** από το σώμα της εντολής που ελέγχει ή επιτρέπει ο runner. Αυτό προϋποθέτει ότι η προνομιούχα διεργασία κληρονομεί τον ανακατευθυνόμενο κατάλογο· το `zsh -f` παραλείπει τα αρχεία εκκίνησης χρήστη, αλλά όχι το καθολικό `zshenv` (συχνά `/etc/zshenv`, αν και οι διαδρομές διαφέρουν ανά διανομή). Η [σελίδα για injection zsh στο macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) περιέχει ένα ελάχιστο παράδειγμα `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Ένα νεότερο, έγκυρο `.zshenv.zwc` ή `.zshrc.zwc` εκτελείται αντί για το αντίστοιχο αρχείο εκκίνησης απλού κειμένου. Αν μπορείτε να γράψετε στον κατάλογο εκκίνησης, η μεταγλώττιση ενός τροποποιημένου αρχείου και, στη συνέχεια, η επαναφορά ενός ακίνδυνου φαινομενικά αρχείου απλού κειμένου μπορεί να αφήσει εκτελέσιμο κώδικα στο μεταγλωττισμένο αντίγραφο. Αυτό είναι απόκρυψη, όχι κρυπτογράφηση. Η παρακάτω δοκιμή σε προσωρινό περιβάλλον δείχνει γιατί δεν αρκεί να εξετάζετε μόνο το αρχείο κειμένου· δεν αγγίζει πραγματικό home directory.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

Για έναν πραγματικό στόχο, προσδιορίστε το ενεργό `ZDOTDIR`/`HOME`, ελέγξτε τόσο τα αρχεία κειμένου όσο και τα αρχεία `.zwc` και ελέγξτε τις χρονικές σημάνσεις, την ιδιοκτησία και αν οι γονικοί κατάλογοι είναι εγγράψιμοι. Ένα αρχείο `.zwc` πρέπει να αντιστοιχεί στο αρχείο πηγαίου κώδικα και να είναι νεότερο για να έχει προτεραιότητα.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Αρχεία εκκίνησης και τερματισμού του Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Συμβουλευτική ειδοποίηση για έγχυση στο περιβάλλον εκκίνησης του shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Ενσωματωμένες εντολές του Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [Το .zshrc.zwc που ξεχάσατε να ελέγξετε](https://dfir.ch/posts/compiled_zsh/)
- [5] [Εκστρατεία κατασκοπείας με υποστήριξη AI στοχεύει κυβερνητικές υποδομές Linux](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Εγχειρίδιο Bash: Ψευδώνυμα](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Εγχειρίδιο Bash: Αρχεία εκκίνησης του Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}
