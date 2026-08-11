# euid, ruid, suid

### Μεταβλητές αναγνώρισης χρήστη

- **`ruid`**: Το **πραγματικό ID χρήστη** υποδηλώνει τον χρήστη που ξεκίνησε τη διεργασία.<sup>[[1]](#references)</sup>
- **`euid`**: Γνωστό ως **effective user ID**, αντιπροσωπεύει την ταυτότητα χρήστη που χρησιμοποιεί το σύστημα για να προσδιορίσει τα δικαιώματα της διεργασίας. Γενικά, το `euid` ταυτίζεται με το `ruid`, εκτός από περιπτώσεις όπως η εκτέλεση ενός SetUID binary (όταν εφαρμόζεται η μετάβαση set-user-ID), όπου το `euid` αποκτά την ταυτότητα του κατόχου του αρχείου, παρέχοντας έτσι συγκεκριμένα operational permissions.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Αυτό το **saved user ID** είναι σημαντικό όταν μια διεργασία με υψηλά δικαιώματα (συνήθως εκτελούμενη ως root) χρειάζεται να αποποιηθεί προσωρινά τα δικαιώματά της για να εκτελέσει ορισμένες εργασίες και στη συνέχεια να ανακτήσει την αρχική elevated κατάστασή της.<sup>[[1]](#references)</sup>

#### Σημαντική σημείωση

Μια διεργασία χωρίς δικαιώματα μπορεί να τροποποιήσει το `euid` μόνο ώστε να ταιριάζει με το τρέχον `ruid`, `euid` ή `suid`.<sup>[[3]](#references)</sup>

### Κατανόηση των συναρτήσεων set\*uid

- **`setuid`**: Σε αντίθεση με τις αρχικές υποθέσεις, η `setuid` ορίζει το `euid` της διεργασίας που την καλεί. Για μια privileged διεργασία, ορίζει επίσης τα `ruid` και `suid` στον καθορισμένο χρήστη. Αφού όλα τα IDs οριστούν σε root, η διεργασία δεν μπορεί να ανακτήσει μια προηγούμενη ταυτότητα χρησιμοποιώντας τη `setuid`. Λεπτομερείς πληροφορίες παρέχονται στη [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** και **`setresuid`**: Η `setreuid` αλλάζει τα `ruid` και `euid`, ενώ η `setresuid` αλλάζει και τα τρία IDs. Για μια unprivileged διεργασία, η `setresuid` περιορίζει κάθε target στο τρέχον `ruid`, `euid` ή `suid`. Η `setreuid` περιορίζει το `euid` σε αυτές τις τιμές και το `ruid` στο τρέχον `ruid` ή `euid`. Μια διεργασία με `CAP_SETUID` μπορεί να αντιστοιχίσει αυθαίρετες τιμές στα IDs που υποστηρίζει κάθε call. Περισσότερες πληροφορίες παρέχονται στη [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) και στη [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Αυτές οι λειτουργίες δεν σχεδιάστηκαν ως security mechanism, αλλά για να διευκολύνουν την προβλεπόμενη operational ροή, όπως όταν ένα πρόγραμμα υιοθετεί την ταυτότητα ενός άλλου χρήστη αλλάζοντας το effective user ID του.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Σημαντικό είναι ότι ένα privileged call στη `setuid` μπορεί να ορίσει και τα τρία IDs, ενώ οι `setreuid` και `setresuid` παρέχουν διαφορετικούς ελέγχους. Η διάκριση μεταξύ αυτών των συναρτήσεων είναι κρίσιμη για την κατανόηση των μεταβάσεων user-ID.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Μηχανισμοί εκτέλεσης προγραμμάτων στο Linux

#### **System Call `execve`**

- **Λειτουργικότητα**: Η `execve` ξεκινά ένα πρόγραμμα, το οποίο καθορίζεται από το πρώτο argument. Δέχεται δύο array arguments, το `argv` για τα arguments και το `envp` για το environment.<sup>[[5]](#references)</sup>
- **Συμπεριφορά**: Διατηρεί τον memory space του caller, αλλά ανανεώνει τα stack, heap και data segments. Ο κώδικας του προγράμματος αντικαθίσταται από το νέο πρόγραμμα.<sup>[[5]](#references)</sup>
- **Διατήρηση User ID**:
- Τα `ruid` και supplementary group IDs παραμένουν αμετάβλητα.<sup>[[5]](#references)</sup>
- Το `euid` κανονικά παραμένει αμετάβλητο, αλλά μπορεί να αλλάξει αν το νέο πρόγραμμα έχει ενεργοποιημένο το SetUID bit.<sup>[[5]](#references)</sup>
- Το `suid` ενημερώνεται από το `euid` μετά την εκτέλεση.<sup>[[5]](#references)</sup>
- **Τεκμηρίωση**: Λεπτομερείς πληροφορίες παρέχονται στη [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Συνάρτηση `system`**

- **Λειτουργικότητα**: Σε αντίθεση με την `execve`, η `system` λειτουργεί σαν να δημιουργεί μια child process χρησιμοποιώντας `fork` και να εκτελεί την εντολή μέσα σε αυτή τη child process χρησιμοποιώντας `execl`.<sup>[[6]](#references)</sup>
- **Εκτέλεση εντολής**: Εκτελεί την εντολή μέσω του `sh` με `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Συμπεριφορά**: Επειδή η `execl` είναι call της οικογένειας `exec`, λειτουργεί παρόμοια με την `execve`, αλλά στο πλαίσιο μιας νέας child process.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Τεκμηρίωση**: Περισσότερες πληροφορίες παρέχονται στη [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Συμπεριφορά των `bash` και `sh` με SUID**

- **`bash`**:
- Διαθέτει την επιλογή `-p`, η οποία επηρεάζει τον τρόπο αντιμετώπισης των `euid` και `ruid`.<sup>[[7]](#references)</sup>
- Χωρίς την `-p`, η `bash` ορίζει το `euid` ίσο με το `ruid` αν αρχικά διαφέρουν.<sup>[[7]](#references)</sup>
- Με την `-p`, διατηρείται το αρχικό `euid`.<sup>[[7]](#references)</sup>
- Περισσότερες λεπτομέρειες παρέχονται στη [`bash` man page](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- Η POSIX `sh` δεν ορίζει privilege-preservation option τύπου Bash `-p`.<sup>[[8]](#references)</sup>
- Η λίστα POSIX options περιλαμβάνει την `-i`, η οποία επιλέγει interactive mode και μπορεί να απορριφθεί όταν τα real και effective IDs διαφέρουν.<sup>[[8]](#references)</sup>
- Πρόσθετες πληροφορίες παρέχονται στη [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Αυτοί οι μηχανισμοί, οι οποίοι διαφέρουν ως προς τη λειτουργία τους, προσφέρουν ένα ευέλικτο σύνολο επιλογών για την εκτέλεση και τη μετάβαση μεταξύ προγραμμάτων, με συγκεκριμένες ιδιαιτερότητες στον τρόπο διαχείρισης και διατήρησης των user IDs.

### Έλεγχος συμπεριφορών User ID κατά τις εκτελέσεις

Παραδείγματα από το https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail. Ελέγξτε το για περισσότερες πληροφορίες.<sup>[[1]](#references)</sup>

#### Περίπτωση 1: Χρήση της `setuid` με τη `system`

**Στόχος**: Κατανόηση της επίδρασης της `setuid` σε συνδυασμό με τις `system` και `bash` ως `sh`.

**Κώδικας C**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Μεταγλώττιση και Δικαιώματα:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

- Τα `ruid` και `euid` ξεκινούν ως 99 (nobody) και 1000 (frank), αντίστοιχα.
- Σε αυτό το unprivileged context, η `setuid(1000)` αφήνει το `ruid` στο 99 και το `euid` στο 1000.<sup>[[1]](#references)</sup>
- Η `system` εκτελεί το `/bin/bash -c id` λόγω του symlink από το sh στο bash.
- Το `bash`, χωρίς `-p`, προσαρμόζει το `euid` ώστε να αντιστοιχεί στο `ruid`, με αποτέλεσμα και τα δύο να γίνονται 99 (nobody).<sup>[[1]](#references)</sup>

#### Περίπτωση 2: Χρήση του setreuid με system

**Κώδικας C:**
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Μεταγλώττιση και Δικαιώματα:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Εκτέλεση και Αποτέλεσμα:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

- Το `setreuid` ορίζει τόσο το ruid όσο και το euid σε 1000.
- Το `system` καλεί το bash, το οποίο διατηρεί τα user IDs λόγω της ισότητάς τους, λειτουργώντας ουσιαστικά ως frank.<sup>[[1]](#references)</sup>

#### Περίπτωση 3: Χρήση του setuid με execve

Στόχος: Διερεύνηση της αλληλεπίδρασης μεταξύ setuid και execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

- Το `ruid` παραμένει 99, αλλά το euid ορίζεται σε 1000, σύμφωνα με την επίδραση του setuid.<sup>[[1]](#references)</sup>

**Παράδειγμα κώδικα C 2 (Κλήση του Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Ανάλυση:**

- Παρόλο που το `euid` ορίζεται σε 1000 από το `setuid`, το `bash` επαναφέρει το `euid` στο `ruid` (99), λόγω της απουσίας του `-p`.<sup>[[1]](#references)</sup>

**Παράδειγμα κώδικα C 3 (Χρήση του bash -p):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**Εκτέλεση και Αποτέλεσμα:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - σελίδα man του setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - σελίδα man του setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - σελίδα man του setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - σελίδα man του execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - σελίδα man του system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - σελίδα man του bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - σελίδα man του POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
