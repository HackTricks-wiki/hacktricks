# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Μεταβλητές Αναγνώρισης Χρήστη

- **`ruid`**: Το **real user ID** υποδεικνύει τον χρήστη που ξεκίνησε τη διεργασία.
- **`euid`**: Γνωστό ως **effective user ID**, αντιπροσωπεύει την ταυτότητα χρήστη που χρησιμοποιεί το σύστημα για να καθορίσει τα δικαιώματα της διεργασίας. Γενικά, το `euid` είναι ίδιο με το `ruid`, εκτός από περιπτώσεις όπως η εκτέλεση ενός SetUID binary, όπου το `euid` λαμβάνει την ταυτότητα του owner του αρχείου, παρέχοντας έτσι συγκεκριμένα operational permissions.
- **`suid`**: Αυτό το **saved user ID** είναι καθοριστικό όταν μια διεργασία με υψηλά privileges (συνήθως εκτελούμενη ως root) χρειάζεται να relinquish προσωρινά τα privileges της για να εκτελέσει συγκεκριμένες εργασίες και στη συνέχεια να ανακτήσει την αρχική elevated κατάστασή της.

#### Σημαντική σημείωση

Μια διεργασία που δεν εκτελείται ως root μπορεί να τροποποιήσει το `euid` της μόνο ώστε να ταιριάζει με το τρέχον `ruid`, `euid` ή `suid`.

### Κατανόηση των set\*uid Functions

- **`setuid`**: Σε αντίθεση με τις αρχικές υποθέσεις, το `setuid` τροποποιεί κυρίως το `euid` και όχι το `ruid`. Συγκεκριμένα, για privileged διεργασίες, ευθυγραμμίζει τα `ruid`, `euid` και `suid` με τον καθορισμένο χρήστη, συχνά τον root, ουσιαστικά παγιώνοντας αυτά τα IDs λόγω του overriding `suid`. Λεπτομερείς πληροφορίες υπάρχουν στη [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** και **`setresuid`**: Αυτές οι functions επιτρέπουν τη λεπτομερή προσαρμογή των `ruid`, `euid` και `suid`. Ωστόσο, οι δυνατότητές τους εξαρτώνται από το επίπεδο privilege της διεργασίας. Για non-root διεργασίες, οι τροποποιήσεις περιορίζονται στις τρέχουσες τιμές των `ruid`, `euid` και `suid`. Αντίθετα, root διεργασίες ή διεργασίες με capability `CAP_SETUID` μπορούν να εκχωρήσουν αυθαίρετες τιμές σε αυτά τα IDs. Περισσότερες πληροφορίες υπάρχουν στη [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) και στη [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Αυτές οι λειτουργίες δεν έχουν σχεδιαστεί ως security mechanism, αλλά για να διευκολύνουν την προβλεπόμενη operational ροή, όπως όταν ένα πρόγραμμα υιοθετεί την ταυτότητα άλλου χρήστη αλλάζοντας το effective user ID του.

Αξίζει να σημειωθεί ότι, ενώ το `setuid` μπορεί να αποτελεί συνηθισμένη επιλογή για privilege elevation σε root (καθώς ευθυγραμμίζει όλα τα IDs με το root), η διάκριση μεταξύ αυτών των functions είναι κρίσιμη για την κατανόηση και τον χειρισμό της συμπεριφοράς των user IDs σε διαφορετικά σενάρια.

### Μηχανισμοί Εκτέλεσης Προγραμμάτων στο Linux

#### **System Call `execve`**

- **Functionality**: Το `execve` ξεκινά ένα πρόγραμμα, το οποίο καθορίζεται από το πρώτο argument. Δέχεται δύο array arguments, το `argv` για τα arguments και το `envp` για το environment.
- **Behavior**: Διατηρεί τον memory space του caller, αλλά ανανεώνει τα stack, heap και data segments. Ο κώδικας του προγράμματος αντικαθίσταται από το νέο πρόγραμμα.
- **User ID Preservation**:
- Τα `ruid`, `euid` και supplementary group IDs παραμένουν αμετάβλητα.
- Το `euid` ενδέχεται να υποστεί nuanced αλλαγές αν το νέο πρόγραμμα έχει ενεργοποιημένο το SetUID bit.
- Το `suid` ενημερώνεται από το `euid` μετά την εκτέλεση.
- **Documentation**: Λεπτομερείς πληροφορίες υπάρχουν στη [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Function `system`**

- **Functionality**: Σε αντίθεση με το `execve`, το `system` δημιουργεί μια child process χρησιμοποιώντας `fork` και εκτελεί μια command μέσα σε αυτή τη child process χρησιμοποιώντας `execl`.
- **Command Execution**: Εκτελεί την command μέσω του `sh` με `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Behavior**: Καθώς το `execl` αποτελεί μορφή του `execve`, λειτουργεί με παρόμοιο τρόπο, αλλά στο πλαίσιο μιας νέας child process.
- **Documentation**: Περισσότερες πληροφορίες υπάρχουν στη [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Behavior των `bash` και `sh` με SUID**

- **`bash`**:
- Διαθέτει option `-p` που επηρεάζει τον τρόπο με τον οποίο αντιμετωπίζονται τα `euid` και `ruid`.
- Χωρίς το `-p`, το `bash` ορίζει το `euid` ίσο με το `ruid` αν αρχικά διαφέρουν.
- Με το `-p`, διατηρείται το αρχικό `euid`.
- Περισσότερες λεπτομέρειες υπάρχουν στη [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Δεν διαθέτει mechanism παρόμοιο με το `-p` του `bash`.
- Η συμπεριφορά σχετικά με τα user IDs δεν αναφέρεται ρητά, εκτός από την option `-i`, η οποία δίνει έμφαση στη διατήρηση της ισότητας των `euid` και `ruid`.
- Πρόσθετες πληροφορίες υπάρχουν στη [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Αυτοί οι mechanisms, παρότι διαφέρουν στη λειτουργία τους, προσφέρουν ένα ευέλικτο σύνολο options για την εκτέλεση και τη μετάβαση μεταξύ προγραμμάτων, με συγκεκριμένες ιδιαιτερότητες στον τρόπο διαχείρισης και διατήρησης των user IDs.

### Testing της Συμπεριφοράς των User IDs κατά τις Εκτελέσεις

Examples taken from https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, ελέγξτε το για περισσότερες πληροφορίες<sup>[[1]](#references)</sup>

#### Case 1: Χρήση του `setuid` με το `system`

**Objective**: Κατανόηση της επίδρασης του `setuid` σε συνδυασμό με το `system` και το `bash` ως `sh`.

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

- Τα `ruid` και `euid` ξεκινούν ως 99 (nobody) και 1000 (frank), αντίστοιχα.
- Το `setuid` ευθυγραμμίζει και τα δύο στο 1000.
- Το `system` εκτελεί το `/bin/bash -c id` λόγω του symlink από το sh στο bash.
- Το `bash`, χωρίς το `-p`, προσαρμόζει το `euid` ώστε να ταιριάζει με το `ruid`, με αποτέλεσμα και τα δύο να είναι 99 (nobody).

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

- Το `setreuid` ορίζει τα ruid και euid σε 1000.
- Το `system` καλεί το bash, το οποίο διατηρεί τα user IDs λόγω της ισότητάς τους, λειτουργώντας ουσιαστικά ως ο frank.

#### Περίπτωση 3: Χρήση του setuid με το execve

Στόχος: Διερεύνηση της αλληλεπίδρασης μεταξύ του setuid και του execve.
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

- Παρότι το `euid` ορίζεται σε 1000 από το `setuid`, το `bash` επαναφέρει το euid στο `ruid` (99), επειδή απουσιάζει το `-p`.

**Παράδειγμα κώδικα C 3 (Χρήση bash -p):**
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

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - σελίδα man του setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - σελίδα man του setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - σελίδα man του setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - σελίδα man του execve](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
