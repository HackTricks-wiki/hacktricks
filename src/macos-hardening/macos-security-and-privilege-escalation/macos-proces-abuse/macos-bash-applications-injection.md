# Injection σε Shell Applications του macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Όταν το Bash ξεκινά non-interactively για να εκτελέσει ένα script ή μια εντολή `-c`, επεκτείνει την τιμή του `BASH_ENV` και κάνει source το αρχείο που προκύπτει πριν εκτελέσει την ζητούμενη εντολή. Το Bash δεν χρησιμοποιεί το `PATH` για να εντοπίσει αυτό το αρχείο. Επομένως, μια διεργασία που εκκινεί non-interactive Bash με environment variables ελεγχόμενες από τον attacker μπορεί να εξαναγκαστεί να εκτελέσει πρώτα ένα αναγνώσιμο shell payload.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Το hook εκτελείται μόνο όταν ο στόχος εκκινεί πραγματικά το Bash· το `/bin/sh` σε άλλη πλατφόρμα ή ένα πρόγραμμα που εκτελεί μια εντολή χωρίς shell δεν θα το τηρεί απαραίτητα. Το Bash σε privileged mode αγνοεί το `BASH_ENV`. Όταν τα effective και real user/group IDs διαφέρουν, το Bash παραλείπει επίσης τα startup files και επαναφέρει τα effective IDs, εκτός αν παρέχεται το `-p`· με το `-p`, το privileged mode παραμένει ενεργοποιημένο και το `BASH_ENV` εξακολουθεί να αγνοείται.<sup>[[1]](#references)[[2]](#references)</sup>

Στο macOS, τα jobs του `launchd` μπορούν να ορίζουν inherited ή per-job environment variables, επομένως ελέγξτε τα plists και τα launch contexts που τροφοδοτούν privileged scripts. Μην βασίζεστε αποκλειστικά στο SIP για τον καθαρισμό των interpreter variables: χρησιμοποιήστε ένα minimal environment (`env -i`), κάντε explicit unset το `BASH_ENV`, καλέστε τον intended interpreter μέσω absolute path και αποφύγετε writable startup files.

## zsh `ZDOTDIR`

Το zsh διαβάζει το `$ZDOTDIR/.zshenv` για κάθε normal shell, συμπεριλαμβανομένων των non-interactive shells· αν το `ZDOTDIR` δεν έχει οριστεί, χρησιμοποιεί το `HOME`. Επομένως, η ανακατεύθυνση του `ZDOTDIR` σε έναν writable directory εκτελεί το `.zshenv` πριν από μια εντολή ή ένα script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` καταργεί την επιλογή `RCS` και παραλείπει αυτό το αρχείο εκκίνησης του χρήστη. Το καθολικό `/etc/zshenv` εξακολουθεί να διαβάζεται, επομένως πρέπει να παραμένει αξιόπιστο και ελάχιστο.

## fish `XDG_CONFIG_HOME`

Το fish διαβάζει τα `$XDG_CONFIG_HOME/fish/conf.d/*.fish` και `$XDG_CONFIG_HOME/fish/config.fish` κατά την εκκίνηση κάθε shell, όχι μόνο των interactive ή login shells. Εκτελεί επίσης τα `fish/vendor_conf.d/*.fish` κάτω από τις καταχωρίσεις του `XDG_DATA_DIRS`. Ένας attacker που ελέγχει μία από αυτές τις μεταβλητές και έναν αναγνώσιμο κατάλογο μπορεί επομένως να εκτελέσει κώδικα πριν από ένα fish script ή μια εντολή `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Χρησιμοποιήστε το `fish --no-config` για μια αξιόπιστη κλήση και διαγράψτε τις μη αξιόπιστες μεταβλητές διαδρομής XDG.

## References

- [1] [Αρχεία εκκίνησης Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Κλήση του Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Αρχεία εκκίνησης/τερματισμού zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Αρχεία ρυθμίσεων fish](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
