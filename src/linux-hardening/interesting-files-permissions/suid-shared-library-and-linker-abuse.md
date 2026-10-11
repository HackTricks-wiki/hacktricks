# Κατάχρηση SUID Shared Library και Linker

{{#include ../../banners/hacktricks-training.md}}

Τα SUID binaries συνήθως ελέγχονται για άμεση εκτέλεση εντολών, αλλά τα προσαρμοσμένα SUID προγράμματα μπορεί επίσης να είναι ευάλωτα μέσω του dynamic linker. Το κοινό μοτίβο είναι απλό: ένα προνομιούχο εκτελέσιμο φορτώνει κώδικα από μια διαδρομή ή διαμόρφωση που μπορεί να επηρεάσει ένας χρήστης με χαμηλότερα προνόμια.<sup>[[1]](#references)</sup>

Αυτή η σελίδα εστιάζει σε γενικά μοτίβα τεχνικών: βιβλιοθήκες που λείπουν, κατάλογοι βιβλιοθηκών με δικαίωμα εγγραφής, `RPATH`/`RUNPATH`, `LD_PRELOAD` μέσω sudo, διαμόρφωση του linker και σύγχυση με SUID hardlinks.

Για τις κεφαλίδες προγράμματος ELF, το dynamic section και τη συμπεριφορά του loader που βρίσκονται πίσω από αυτούς τους ελέγχους, δείτε τις [Βασικές πληροφορίες ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Γρήγορη απαρίθμηση

Ξεκινήστε εντοπίζοντας ασυνήθιστα SUID αρχεία και ελέγχοντας αν είναι δυναμικά συνδεδεμένα:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Χρησιμοποιήστε το `readelf` για ένα άγνωστο εκτελέσιμο: [`ldd` μπορεί να εκτελέσει έναν μη έμπιστο ELF interpreter](https://man7.org/linux/man-pages/man1/ldd.1.html). Το `readelf` εμφανίζει τις άμεσες εξαρτήσεις, επομένως επιβεβαιώστε ξεχωριστά τη διαδρομή που επιλέγει πράγματι ο loader.<sup>[[1]](#references)[[3]](#references)</sup>

Εστιάστε σε μη τυπικές τοποθεσίες, προσαρμοσμένες διαδρομές εφαρμογών, binaries που ανήκουν στον root αλλά βρίσκονται εκτός καταλόγων που διαχειρίζονται πακέτα και εξαρτήσεις που φορτώνονται από εγγράψιμους καταλόγους.<sup>[[1]](#references)</sup>

Χρήσιμοι έλεγχοι δυνατότητας εγγραφής:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Ορισμένα προσαρμοσμένα SUID binaries προσπαθούν να φορτώσουν ένα shared object που δεν υπάρχει. Αν η διαδρομή που λείπει βρίσκεται κάτω από έναν κατάλογο που ελέγχει ο επιτιθέμενος, το binary μπορεί να φορτώσει κώδικα που έχει παράσχει ο επιτιθέμενος, με effective user.<sup>[[1]](#references)</sup>

Το ίδιο όριο ισχύει για ένα **προσαρμοσμένο binary που επιτρέπεται μέσω sudo**, όταν καλεί `dlopen()` σε μια απόλυτη διαδρομή `.so` κάτω από έναν κατάλογο home ή ρυθμίσεων στον οποίο μπορεί να γράψει ο καλών. Αυτό το καθυστερημένο library load μπορεί να απουσιάζει από τα `ldd` και τις εγγραφές ELF `NEEDED`. Μια περιορισμένη ανασκόπηση με `strings` ή ένα trace μιας **μη προνομιούχας** εκτέλεσης μπορεί να αποκαλύψει τη διαδρομή που επιχειρείται· ένας κωδικός πρόσβασης εφαρμογής ή μια επιλογή μενού μπορεί να ελέγχει την αναζήτηση. Επιβεβαιώστε τον ακριβή κανόνα sudo, τη διαδρομή και τα δικαιώματα του γονικού καταλόγου, καθώς και ότι η προνομιούχα εκτέλεση φτάνει σε εκείνη την αναζήτηση, προτού τη θεωρήσετε κλιμάκωση δικαιωμάτων. Μην εκτελείτε τον στόχο sudo μόνο και μόνο για να τον απαριθμήσετε.

Εντοπίστε αποτυχημένες αναζητήσεις βιβλιοθηκών με το syscall filter του `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Αν το binary αναζητά το `libexample.so` σε μια διαδρομή με δικαιώματα εγγραφής, μια ελάχιστη proof library μπορεί να χρησιμοποιήσει έναν constructor. Διατηρήστε την απόδειξη επίδρασης ακίνδυνη κατά την επικύρωση:<sup>[[6]](#references)</sup>

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

Κατασκευάστε το με ακριβώς το όνομα αρχείου που προσπαθεί να φορτώσει το binary:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Η εκμεταλλεύσιμη συνθήκη δεν είναι απλώς η απουσία της βιβλιοθήκης. Ο επιτιθέμενος πρέπει να μπορεί να τοποθετήσει ένα συμβατό shared object σε μια διαδρομή που θα αποδεχτεί ο προνομιούχος loader.<sup>[[1]](#references)</sup>

## Εγγράψιμος κατάλογος βιβλιοθηκών

Μερικές φορές υπάρχουν όλες οι εξαρτήσεις, αλλά ένας από τους καταλόγους που χρησιμοποιούνται για την επίλυσή τους είναι εγγράψιμος. Αυτό μπορεί να επιτρέψει την αντικατάσταση μιας φορτωμένης βιβλιοθήκης ή την τοποθέτηση μιας βιβλιοθήκης με το ίδιο όνομα και υψηλότερη προτεραιότητα.<sup>[[1]](#references)</sup>

Ο ίδιος έλεγχος ισχύει για ένα custom ELF που **επιτρέπεται μέσω sudo**, ακόμη κι όταν το ELF δεν έχει SUID bit και ο επιτρεπόμενος λογαριασμός RunAs δεν είναι root. Συγκρίνετε τις καταχωρίσεις `DT_NEEDED` με τη διαδρομή της βιβλιοθήκης που θα επιλύσει ο loader και, στη συνέχεια, ελέγξτε αν ο καλών μπορεί να γράψει σε αυτό το αρχείο ή να το αντικαταστήσει μέσω ενός εγγράψιμου γονικού καταλόγου στον οποίο έχει δικαίωμα αναζήτησης. Επιβεβαιώστε τον ακριβή κανόνα sudo RunAs, τα symlinks και τα ACL, την πολιτική του loader και ότι η διεργασία-στόχος φορτώνει τη βιβλιοθήκη ως ο λογαριασμός με τα υψηλότερα προνόμια. Ένα εγγράψιμο `.so` ή ένα όνομα εξάρτησης από μόνο του αποτελεί απλώς ένδειξη· εξετάστε τα μεταδεδομένα χωρίς να εκτελέσετε την εντολή sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Ελέγξτε τις διαδρομές εξαρτήσεων:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Αν ο κατάλογος είναι εγγράψιμος, επαληθεύστε το σε εργαστηριακό περιβάλλον με ασφαλή προσέγγιση που χρησιμοποιεί αντίγραφο. Η αντικατάσταση system libraries σε ενεργό host μπορεί να αφήσει διεργασίες που ξεκινούν ταυτόχρονα με ασύμβατες εκδόσεις βιβλιοθηκών.<sup>[[8]](#references)</sup>

### Εγγράψιμες βιβλιοθήκες μέσα σε chroot

Ένα chroot από μόνο του δεν κλείνει τα κληρονομημένα file descriptors ούτε περιορίζει κάθε πρόσβαση στο filesystem. Αν ένα sandbox αφήσει ένα directory descriptor που δείχνει έξω από το νέο root του και η περιορισμένη διεργασία μπορεί να κάνει dereference αυτό το descriptor (για παράδειγμα μέσω μιας προσβάσιμης καταχώρισης `/proc/<pid>/fd/`), οι διαδρομές του host ενδέχεται να παραμένουν προσβάσιμες. Πρόκειται για ζήτημα ορίων του filesystem· από μόνο του δεν παρέχει root privileges.<sup>[[11]](#references)[[12]](#references)</sup>

Ελέγξτε ξεχωριστά αν ο περιορισμένος χρήστης μπορεί να γράψει σε κατάλογο βιβλιοθηκών που θα χρησιμοποιήσει ένα **host root-SUID executable** όταν εκκινηθεί από το jail. Ο loader επιλύει τις εξαρτήσεις σύμφωνα με το filesystem view της διεργασίας, επομένως μια βιβλιοθήκη που ελέγχεται από τον attacker εκεί μπορεί να εκτελεστεί με την effective identity του SUID προγράμματος. Επιβεβαιώστε το ακριβές executable, το SUID bit και την πολιτική του mount, τον στόχο και τα δικαιώματα πρόσβασης του descriptor, τη διαδρομή αναζήτησης βιβλιοθηκών του jail και ότι το πρόγραμμα μπορεί πράγματι να έχει πρόσβαση στο host executable. Ένα file capability στον launcher του sandbox, ένα εγγράψιμο jail ή ένα host SUID binary από μόνο του είναι απλώς μια ένδειξη· η πλήρης αλυσίδα εξαρτάται από την υλοποίηση του sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

Τα `RPATH` και `RUNPATH` είναι καταχωρίσεις στο dynamic section που υποδεικνύουν στον loader πού να αναζητήσει βιβλιοθήκες. Είναι επικίνδυνα σε SUID προγράμματα όταν δείχνουν σε καταλόγους εγγράψιμους από attacker.<sup>[[1]](#references)</sup>

Εντοπίστε τα:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Παράδειγμα επικίνδυνης εξόδου:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Αν ο κατάλογος `/opt/app/lib` είναι εγγράψιμος και το binary χρειάζεται το `libcustom.so`, ο επιτιθέμενος μπορεί να τοποθετήσει εκεί ένα κακόβουλο `libcustom.so`:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` και `RUNPATH` δεν είναι πανομοιότυπα σε όλες τις λεπτομέρειες επίλυσης, αλλά για τον έλεγχο κλιμάκωσης προνομίων το πρακτικό ερώτημα είναι το ίδιο: αναζητά το SUID binary μια βιβλιοθήκη σε κατάλογο όπου μπορεί να γράψει ένας attacker;<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH και SUID

Για κανονικά προγράμματα, τα `LD_PRELOAD` και `LD_LIBRARY_PATH` μπορούν να επιβάλουν ή να επηρεάσουν τη φόρτωση shared object. Για προγράμματα SUID, ο dynamic loader περνά συνήθως σε secure-execution mode και αγνοεί επικίνδυνες μεταβλητές περιβάλλοντος.<sup>[[1]](#references)</sup>

Αυτό σημαίνει ότι ένα απλό SUID binary συνήθως δεν είναι ευάλωτο μόνο και μόνο επειδή ο χρήστης μπορεί να ορίσει το `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Η συνήθης εξαίρεση είναι μια πολιτική sudo που επιτρέπει την εκχώρηση μεταβλητής περιβάλλοντος στη γραμμή εντολών για τον στόχο, όπως ένα tag `SETENV` ή μια σχετική επιλογή `setenv`. Αν ο στόχος είναι δυναμικά συνδεδεμένος και το sudo δέχεται `LD_PRELOAD=/path/to/library`, ο στόχος μπορεί να φορτώσει κώδικα που ελέγχει ο χρήστης που τον καλεί. Ελέγξτε τον ενεργό κανόνα και την ταυτότητα του στόχου. Η απλή προσθήκη του `LD_PRELOAD` στο `env_keep` δεν αρκεί σε συστήματα όπου ο dynamic loader αφαιρεί το κληρονομημένο `LD_PRELOAD` πριν ξεκινήσει η διεργασία SUID `sudo`· η εκχώρηση στη γραμμή εντολών αξιολογείται από το sudo μετά τη δική του εκκίνηση.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Μην συγχέετε αυτές τις περιπτώσεις· οι κανόνες του loader και της πολιτικής sudo παραπάνω τις διακρίνουν:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` απέναντι σε ένα κανονικό SUID binary: συνήθως αποκλείεται από την ασφαλή εκτέλεση.
- `LD_PRELOAD` αποδεκτό ως εκχώρηση στη γραμμή εντολών sudo για έναν προνομιούχο, δυναμικά συνδεδεμένο στόχο: δυνητικά εκμεταλλεύσιμο.
- Απουσία `.so` σε εγγράψιμη διαδρομή: εκμεταλλεύσιμη όταν το SUID binary φορτώνει φυσιολογικά αυτήν τη διαδρομή.
- `RPATH`/`RUNPATH` προς εγγράψιμο κατάλογο: εκμεταλλεύσιμο όταν μπορεί να ελεγχθεί μια απαιτούμενη βιβλιοθήκη.
- Πρόσβαση εγγραφής στο `/etc/ld.so.preload` ή στη ρύθμιση παραμέτρων του linker: αφορά όλο το σύστημα και έχει μεγάλο αντίκτυπο.

## Ρύθμιση παραμέτρων του Linker

Το `ld.so` χρησιμοποιεί την cache του linker και το `/etc/ld.so.preload`· το `ldconfig` δημιουργεί αυτήν την cache από το `/etc/ld.so.conf` και τα αρχεία που περιλαμβάνονται από αυτό, συνήθως από το `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Έλεγχοι υψηλής αξίας:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Οι εγγράψιμες ρυθμίσεις του linker είναι συνήθως πιο επικίνδυνες από ένα μεμονωμένο ευάλωτο SUID binary, επειδή μπορούν να επηρεάσουν πολλές διεργασίες που συνδέονται δυναμικά. Το `/etc/ld.so.preload` είναι ιδιαίτερα επικίνδυνο, επειδή μπορεί να αναγκάσει τη φόρτωση ενός shared object σε προνομιούχες διεργασίες.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Σύγχυση με SUID Hardlink

Τα hardlinks μπορούν να κάνουν το ίδιο SUID inode να εμφανίζεται με πολλά ονόματα.<sup>[[9]](#references)</sup> Αυτό είναι χρήσιμο για την απόκρυψη ενός προνομιούχου helper, την πρόκληση σύγχυσης κατά τον καθαρισμό ή την παράκαμψη αφελών ελέγχων βάσει διαδρομής.

Βρείτε αρχεία SUID με περισσότερους από έναν συνδέσμους:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Εξετάστε όλες τις διαδρομές προς το ίδιο inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Η κατάχρηση δεν συνίσταται στο ότι ένα hardlink αλλάζει δικαιώματα. Η κατάχρηση είναι η σύγχυση διαδρομών: ένα προνομιούχο inode μπορεί να είναι προσβάσιμο μέσω ενός ονόματος που οι αμυνόμενοι ή τα scripts δεν περιμένουν.<sup>[[9]](#references)</sup> Για περισσότερες πληροφορίες σχετικά με τα inode και τη ροή εργασιών των hardlink, δείτε το [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Διατηρείτε τα SUID binaries ελάχιστα, ελεγμένα και, όπου είναι δυνατόν, υπό διαχείριση πακέτων.
- Αποφύγετε καταχωρίσεις `RPATH`/`RUNPATH` που δείχνουν σε εγγράψιμους καταλόγους ή καταλόγους υπό διαχείριση εφαρμογών.<sup>[[1]](#references)[[8]](#references)</sup>
- Διατηρείτε τους καταλόγους βιβλιοθηκών υπό την ιδιοκτησία του root και μη εγγράψιμους από απλούς χρήστες.<sup>[[8]](#references)</sup>
- Μην διατηρείτε τις μεταβλητές loader `LD_PRELOAD`, `LD_LIBRARY_PATH` ή παρόμοιες μέσω του sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Παρακολουθείτε τα `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` και απρόσμενα αρχεία SUID.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Ελέγχετε αρχεία SUID με hardlink και διερευνάτε προσαρμοσμένα SUID wrappers εκτός των τυπικών διαδρομών συστήματος.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (Βοηθητικά προγράμματα δυαδικών αρχείων GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Σελίδα εγχειριδίου Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Κοινά χαρακτηριστικά (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Ενίσχυση ασφάλειας του δυναμικού linker (Η βιβλιοθήκη GNU C)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (Βοηθητικά προγράμματα δυαδικών αρχείων GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
