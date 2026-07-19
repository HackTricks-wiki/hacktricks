# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### Μεταβλητές Αναγνώρισης Χρήστη

- **`ruid`**: Το **πραγματικό user ID** δηλώνει τον χρήστη που ξεκίνησε τη διεργασία.
- **`euid`**: Γνωστό ως **effective user ID**, αντιπροσωπεύει την ταυτότητα χρήστη που χρησιμοποιεί το σύστημα για να προσδιορίσει τα δικαιώματα της διεργασίας. Γενικά, το `euid` είναι ίδιο με το `ruid`, εκτός από περιπτώσεις όπως η εκτέλεση ενός SetUID binary, όπου το `euid` αποκτά την ταυτότητα του ιδιοκτήτη του αρχείου, παρέχοντας έτσι συγκεκριμένα operational permissions.
- **`suid`**: Αυτό το **saved user ID** είναι κρίσιμο όταν μια διεργασία με υψηλά privileges (συνήθως εκτελείται ως root) χρειάζεται να αποποιηθεί προσωρινά τα privileges της για να εκτελέσει ορισμένες εργασίες και στη συνέχεια να ανακτήσει την αρχική elevated κατάστασή της.

#### Σημαντική σημείωση

Μια διεργασία που δεν εκτελείται ως root μπορεί να τροποποιήσει το `euid` της μόνο ώστε να ταιριάζει με το τρέχον `ruid`, `euid` ή `suid`.

### Κατανόηση των set\*uid Functions

- **`setuid`**: Σε αντίθεση με την αρχική υπόθεση, το `setuid` τροποποιεί κυρίως το `euid` και όχι το `ruid`. Συγκεκριμένα, για privileged διεργασίες, ευθυγραμμίζει τα `ruid`, `euid` και `suid` με τον καθορισμένο χρήστη, συχνά τον root, σταθεροποιώντας ουσιαστικά αυτά τα IDs λόγω του overriding `suid`. Αναλυτικές πληροφορίες υπάρχουν στη [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).
- **`setreuid`** και **`setresuid`**: Αυτές οι functions επιτρέπουν τη λεπτομερή προσαρμογή των `ruid`, `euid` και `suid`. Ωστόσο, οι δυνατότητές τους εξαρτώνται από το επίπεδο privileges της διεργασίας. Για non-root διεργασίες, οι τροποποιήσεις περιορίζονται στις τρέχουσες τιμές των `ruid`, `euid` και `suid`. Αντίθετα, οι root διεργασίες ή όσες διαθέτουν το `CAP_SETUID` capability μπορούν να εκχωρήσουν αυθαίρετες τιμές σε αυτά τα IDs. Περισσότερες πληροφορίες υπάρχουν στη [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) και στη [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).

Αυτές οι λειτουργίες δεν σχεδιάστηκαν ως security mechanism, αλλά για να διευκολύνουν την προβλεπόμενη operational flow, όπως όταν ένα πρόγραμμα υιοθετεί την ταυτότητα ενός άλλου χρήστη αλλάζοντας το effective user ID του.

Αξίζει να σημειωθεί ότι, ενώ το `setuid` μπορεί να αποτελεί συνηθισμένη επιλογή για privilege elevation σε root (επειδή ευθυγραμμίζει όλα τα IDs με το root), η διάκριση μεταξύ αυτών των functions είναι κρίσιμη για την κατανόηση και τον χειρισμό της συμπεριφοράς των user IDs σε διαφορετικά σενάρια.

### Mechanisms Εκτέλεσης Προγραμμάτων στο Linux

#### **System Call `execve`**

- **Functionality**: Το `execve` ξεκινά ένα πρόγραμμα, το οποίο καθορίζεται από το πρώτο argument. Δέχεται δύο array arguments, το `argv` για τα arguments και το `envp` για το environment.
- **Behavior**: Διατηρεί τον memory space του caller, αλλά ανανεώνει τα stack, heap και data segments. Ο κώδικας του προγράμματος αντικαθίσταται από το νέο πρόγραμμα.
- **User ID Preservation**:
- Τα `ruid`, `euid` και supplementary group IDs παραμένουν αμετάβλητα.
- Το `euid` ενδέχεται να υποστεί nuanced αλλαγές αν το νέο πρόγραμμα έχει ενεργοποιημένο το SetUID bit.
- Το `suid` ενημερώνεται από το `euid` μετά την εκτέλεση.
- **Documentation**: Αναλυτικές πληροφορίες υπάρχουν στη [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).

#### **Function `system`**

- **Functionality**: Σε αντίθεση με το `execve`, το `system` δημιουργεί ένα child process χρησιμοποιώντας `fork` και εκτελεί μια εντολή μέσα σε αυτό το child process χρησιμοποιώντας `execl`.
- **Command Execution**: Εκτελεί την εντολή μέσω του `sh` με `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: Καθώς το `execl` είναι μια μορφή του `execve`, λειτουργεί με παρόμοιο τρόπο, αλλά στο πλαίσιο ενός νέου child process.
- **Documentation**: Περισσότερες πληροφορίες υπάρχουν στη [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior των `bash` και `sh` με SUID**

- **`bash`**:
- Διαθέτει την επιλογή `-p`, η οποία επηρεάζει τον τρόπο με τον οποίο αντιμετωπίζονται τα `euid` και `ruid`.
- Χωρίς το `-p`, το `bash` θέτει το `euid` ίσο με το `ruid` αν αρχικά διαφέρουν.
- Με το `-p`, διατηρείται το αρχικό `euid`.
- Περισσότερες λεπτομέρειες υπάρχουν στη [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Δεν διαθέτει mechanism παρόμοιο με το `-p` του `bash`.
- Η συμπεριφορά σχετικά με τα user IDs δεν αναφέρεται ρητά, εκτός από την επιλογή `-i`, η οποία δίνει έμφαση στη διατήρηση της ισότητας των `euid` και `ruid`.
- Πρόσθετες πληροφορίες υπάρχουν στη [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Αυτοί οι mechanisms, που διαφέρουν ως προς τη λειτουργία τους, προσφέρουν ένα ευέλικτο εύρος επιλογών για την εκτέλεση και τη μετάβαση μεταξύ προγραμμάτων, με συγκεκριμένες ιδιαιτερότητες στον τρόπο διαχείρισης και διατήρησης των user IDs.

### Testing της Συμπεριφοράς των User IDs κατά τις Εκτελέσεις

Παραδείγματα από το https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, δείτε το για περισσότερες πληροφορίες

#### Case 1: Χρήση του `setuid` με `system`

**Objective**: Κατανόηση της επίδρασης του `setuid` σε συνδυασμό με τα `system` και `bash` ως `sh`.

**C Code**:
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

- Τα `ruid` και `euid` ξεκινούν ως 99 (nobody) και 1000 (frank) αντίστοιχα.
- Το `setuid` ευθυγραμμίζει και τα δύο με το 1000.
- Το `system` εκτελεί το `/bin/bash -c id` λόγω του symlink από το sh στο bash.
- Το `bash`, χωρίς `-p`, προσαρμόζει το `euid` ώστε να αντιστοιχεί στο `ruid`, με αποτέλεσμα και τα δύο να γίνονται 99 (nobody).

#### Περίπτωση 2: Χρήση του setreuid με το system

**Κώδικας C**:
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
- Το `system` καλεί το bash, το οποίο διατηρεί τα user IDs λόγω της ισότητάς τους, λειτουργώντας ουσιαστικά ως ο frank.

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

- Το `ruid` παραμένει 99, αλλά το euid ορίζεται σε 1000, σύμφωνα με την επίδραση του setuid.

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

- Παρόλο που το `euid` ορίζεται σε 1000 από το `setuid`, το `bash` επαναφέρει το euid στο `ruid` (99), λόγω της απουσίας του `-p`.

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
uid=99(nobody) gid=99(nobody) euid=100
```
## Αναφορές

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
