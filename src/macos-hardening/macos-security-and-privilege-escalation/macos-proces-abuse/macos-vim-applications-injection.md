# Injection σε εφαρμογές Vim/Neovim του macOS

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Η ενσωματωμένη γλώσσα scripting του Vim (Vimscript) μπορεί να εκτελεί **αυθαίρετες εντολές Ex και εντολές shell κατά την εκκίνηση** από μεταβλητές περιβάλλοντος. Αν μια διεργασία με περισσότερα προνόμια (μια ροή εργασίας συντήρησης/root, ένα `sudo vim …`, ένας editor που εκκινείται από άλλο εργαλείο, το `crontab -e`, το `visudo`, το `git`/`less` που καλεί έναν editor, …) εκκινήσει το Vim/Neovim με περιβάλλον που επηρεάζεται από τον attacker, ο attacker αποκτά εκτέλεση κώδικα σε αυτό το context.

## `VIMINIT`

Κατά την αρχικοποίηση, το Vim διαβάζει και εκτελεί τις εντολές Ex στο **`VIMINIT`**. Οι εντολές Ex περιλαμβάνουν τις `:!cmd` (εκτέλεση εντολής shell) και `:call system(...)`, επομένως μία μόνο μεταβλητή παρέχει αυθαίρετη εκτέλεση πριν από την επεξεργασία οποιουδήποτε αρχείου.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
Το `:qa!` που τροφοδοτείται μέσω stdin απλώς κλείνει τον editor αφού το payload έχει ήδη εκτελεστεί· σε ένα πραγματικό σενάριο το θύμα απλώς ανοίγει κανονικά το Vim.

## `EXINIT`

Αν το `VIMINIT` δεν έχει οριστεί, το Vim (και τα binaries συμβατότητας `vi`/`ex`) χρησιμοποιεί ως εναλλακτική το **`EXINIT`**, το οποίο εκτελείται με τον ίδιο τρόπο. Είναι η κλασική παραλλαγή της ίδιας primitive από την εποχή του vi.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Σημειώσεις και επισημάνσεις

- Το **Neovim** υποστηρίζει επίσης το `VIMINIT` (ελέγχεται πριν από το `init.vim`/`init.lua` του χρήστη).
- Το Batch/Ex mode (`vim -es` / `vim -Es`) **δεν** κάνει source το `VIMINIT`/`EXINIT`. Οι μεταβλητές εκτελούνται σε ένα κανονικό (interactive) startup, το οποίο είναι το συνηθισμένο σενάριο θύματος.
- Σχετικά file-based vectors είναι οι per-directory δυνατότητες `exrc`/`.nvimrc` "modeline"/local-rc και το `-u <vimrc>`. Η διαδρομή μέσω environment variable παραπάνω δεν απαιτεί καθόλου writable file.

## Hardening

- Κάντε sanitize το environment (αφαιρέστε τα `VIMINIT`/`EXINIT`) πριν από την εκκίνηση editors από privileged ή automated contexts και προτιμήστε wrappers `sudo -i`/`env -i` που κάνουν reset το environment.
- Ορίστε τα `EDITOR`/`VISUAL` σε trusted absolute paths και αποφύγετε την εκτέλεση editors ως root με inherited user environment.
- Αντιμετωπίστε τον έλεγχο του environment ενός target ως ισοδύναμο με code execution για οποιοδήποτε Vim/Neovim εκκινεί.

## References

- [1] [Τεκμηρίωση του Vim — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}
