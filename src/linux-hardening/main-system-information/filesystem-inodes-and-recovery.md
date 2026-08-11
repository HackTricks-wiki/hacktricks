# Filesystem, Inodes και Ανάκτηση

{{#include ../../banners/hacktricks-training.md}}

Η κατάχρηση του Filesystem συχνά αφορά τη σύγχυση της σχέσης μεταξύ μιας ορατής διαδρομής και του αντικειμένου που βρίσκεται πίσω από αυτήν.

Τα disk images ενδέχεται να κρύβουν ένα άλλο filesystem.<sup>[[1]](#references)</sup> Τα writable mounts ενδέχεται να χρησιμοποιούνται από privileged jobs.

Τα hardlinks ενδέχεται να εκθέτουν το ίδιο inode μέσω διαφορετικού ονόματος.<sup>[[3]](#references)</sup> Τα διαγραμμένα αρχεία ενδέχεται να παραμένουν αναγνώσιμα μέσω ενός ανοιχτού file descriptor.<sup>[[5]](#references)[[6]](#references)</sup>

Αυτή η σελίδα εστιάζει στην τεχνική και όχι σε ένα συγκεκριμένο lab ή target.

## Disk Images και Loop Mounts

Ένα regular file μπορεί να περιέχει ένα πλήρες filesystem, επομένως ένα disk image μπορεί να εκθέσει ένα δεύτερο filesystem tree όταν γίνει mount.<sup>[[1]](#references)</sup>

Τα backup images, τα copied block devices, τα VM artifacts ή τα renamed blobs μπορούν επομένως να περιέχουν credentials, scripts, SSH keys, configuration files ή flags, ακόμη και όταν εξωτερικά δεν φαίνονται χρήσιμα.

Εντοπίστε πιθανά images με το `file` για να ταξινομήσετε έναν υποψήφιο, με το `blkid` για να εξετάσετε αναγνωρισμένα filesystem metadata και με το `strings -a` για να σαρώσετε ολόκληρο το αρχείο για εκτυπώσιμες ακολουθίες.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Όταν επιτρέπεται η προσάρτηση, χρησιμοποιήστε loop mount με `ro`, ώστε το image να προσαρτηθεί μόνο για ανάγνωση· η παρακάτω εντολή `find` περιορίζει το βάθος επιθεώρησης και τον τύπο αρχείου.<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Εάν το mounting δεν είναι διαθέσιμο και το image είναι ext2/ext3/ext4, επιθεωρήστε απευθείας τα metadata του με το `debugfs`.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Η τεχνική είναι χρήσιμη επειδή μετατρέπει ένα αρχείο που φαίνεται φυσιολογικό σε ένα δεύτερο δέντρο filesystem.<sup>[[1]](#references)</sup> Αντιμετωπίστε την ως τρόπο ανάκτησης κρυφών δεδομένων και όχι ως privilege escalation από μόνη της.

## Κατάχρηση Writable Mounts

Ένα writable mount γίνεται επικίνδυνο όταν ένα πιο privileged context εμπιστεύεται αργότερα κάτι που βρίσκεται μέσα σε αυτό. Το σημαντικό ερώτημα δεν είναι μόνο «μπορώ να γράψω εδώ;», αλλά «ποιος διαβάζει, εκτελεί, κάνει import ή φορτώνει αργότερα από εδώ;».

Χρησιμοποιήστε το `findmnt` για να ελέγξετε τα mounted filesystems και τις επιλογές τους.<sup>[[9]](#references)</sup>

Βρείτε writable mounts και ύποπτους consumers με τα τεκμηριωμένα predicates δικαιωμάτων, τύπου και ορίων filesystem του `find`, και στη συνέχεια χρησιμοποιήστε recursive `grep` για να αναζητήσετε πιθανές ρυθμίσεις των consumers.<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Συνήθη μοτίβα κατάχρησης:

- Μια cron job ή υπηρεσία systemd εκτελεί ένα script με δικαίωμα εγγραφής από το mount.<sup>[[13]](#references)[[14]](#references)</sup>
- Μια προνομιούχα υπηρεσία φορτώνει plugins, config, templates ή βοηθητικά binaries από το mount.
- Ένα mount περιέχει αρχεία SUID και επιτρέπει την τροποποίηση, αντικατάσταση ή χειραγώγηση διαδρομών.
- Ένα container ή chroot εκθέτει μια διαδρομή που υποστηρίζεται από το host και είναι εγγράψιμη από το περιορισμένο περιβάλλον. Τα mount namespaces παρέχουν ξεχωριστές ιεραρχίες mount, ενώ το `chroot()` αλλάζει μόνο την επίλυση ονομάτων διαδρομών και δεν αποτελεί πλήρες sandbox.<sup>[[15]](#references)[[16]](#references)</sup>

Γενικό μοτίβο επικύρωσης με χρήση των ίδιων predicates του `find`.<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Κατά την απόδειξη του impact σε ένα εξουσιοδοτημένο lab, διατηρείτε το payload παρατηρήσιμο και ελάχιστο, για παράδειγμα γράφοντας την έξοδο του `id` σε ένα προσωρινό αρχείο.<sup>[[23]](#references)</sup> Η βασική τεχνική είναι η delayed execution μέσω μιας αξιόπιστης τοποθεσίας με δυνατότητα εγγραφής.

## Inodes και Path Confusion

Ένα inode είναι το αντικείμενο του filesystem· ένα path είναι απλώς ένα όνομα που δείχνει σε αυτό. Τα metadata της συσκευής και του inode σάς επιτρέπουν να διακρίνετε αντικείμενα μεταξύ διαφορετικών filesystems, ενώ οι μετρητές συνδέσμων αποκαλύπτουν πολλαπλά hard links.<sup>[[3]](#references)</sup> Η διαγραμμένη pathname δεν σημαίνει πάντα ότι τα δεδομένα έχουν εξαφανιστεί, όσο μια διεργασία εξακολουθεί να έχει το αρχείο ανοιχτό.<sup>[[5]](#references)</sup>

Τα παρακάτω predicates του `find` συγκρίνουν την ταυτότητα του inode, τους μετρητές συνδέσμων, τα όρια των συσκευών και τα timestamps.<sup>[[4]](#references)</sup>

Συγκρίνετε αρχεία βάσει inode και συσκευής με τα `ls -i` και τις μορφές metadata του `stat`.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Βρείτε κάθε ορατή διαδρομή για το ίδιο inode με το `find -samefile`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Αναζητήστε απευθείας με βάση τον αριθμό inode με το `find -inum` όταν έχετε μόνο metadata.<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Αυτή η τεχνική είναι χρήσιμη όταν ένα αρχείο εμφανίζεται με μη αναμενόμενο όνομα, όταν μια εφαρμογή επικυρώνει μία διαδρομή αλλά χρησιμοποιεί μια άλλη ή όταν ένα προνομιούχο wrapper αλληλεπιδρά με ένα inode που είναι επίσης προσβάσιμο από κάπου αλλού.

## Κατάχρηση Hardlink

Τα Hardlinks δημιουργούν πολλά ονόματα για το ίδιο inode. Δεν δείχνουν σε μια διαδρομή-στόχο όπως τα symlinks· είναι ισότιμα ονόματα για το ίδιο αντικείμενο αρχείου.<sup>[[3]](#references)</sup>

Βρείτε αρχεία SUID με πολλά hardlinks χρησιμοποιώντας τα predicates δικαιωμάτων και αριθμού συνδέσεων του `find`.<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Επιθεωρήστε ένα ύποπτο αρχείο με `stat` και `find -samefile`.<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Γιατί έχει σημασία:

- Ένα ευαίσθητο αρχείο μπορεί να είναι προσβάσιμο μέσω μιας λιγότερο προφανούς διαδρομής.
- Ένα SUID wrapper μπορεί να είναι κρυμμένο πίσω από ένα όνομα που δεν φαίνεται privileged.
- Ο καθαρισμός που αφαιρεί ένα pathname μπορεί να αφήσει ενεργό ένα άλλο hardlink.

Το sysctl `fs.protected_hardlinks` του Linux μπορεί να περιορίσει τη δημιουργία hardlink μεταξύ διαφορετικών ορίων προνομίων.<sup>[[7]](#references)</sup> Τα υπάρχοντα hardlink εξακολουθούν να χρήζουν ελέγχου.

## Ανάκτηση διαγραμμένων αρχείων μέσω ανοιχτών FD

Όταν μια διεργασία διατηρεί ένα αρχείο ανοιχτό, η κατάργηση του τελευταίου pathname του αφήνει το αρχείο ενεργό μέχρι να κλείσει ο τελευταίος descriptor· το Linux εκθέτει αυτούς τους descriptor κάτω από το `/proc/<pid>/fd/`.<sup>[[5]](#references)[[6]](#references)</sup>

Βρείτε διαγραμμένα ανοιχτά αρχεία παραθέτοντας τους descriptor του `/proc` και φιλτράροντας την έξοδο των ανοιχτών αρχείων.<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Η ανάκτηση μέσω αυτών των συνδέσμων εξαρτάται από τα δικαιώματα, επειδή η αποαναφορά του `/proc/<pid>/fd` υπόκειται σε ελέγχους πρόσβασης `ptrace` και στα δικαιώματα αρχείων.<sup>[[6]](#references)</sup>

Όταν επιτρέπεται, το `readlink` εμφανίζει το target του descriptor και το `cp` αντιγράφει τα περιεχόμενά του.<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Πρόκειται για μια πρακτική τεχνική για την ανάκτηση διαγραμμένων logs, προσωρινών secrets, binaries που απορρίφθηκαν, rotated files ή scripts που αφαιρέθηκαν μετά την εκτέλεσή τους.

## Ανάκτηση ext με debugfs

Σε filesystems ext2/ext3/ext4, το `debugfs` μπορεί να επιθεωρήσει metadata των inodes και να κάνει dump των περιεχομένων των inodes από μια block device ή image· χωρίς το `-w`, ανοίγει το filesystem σε read-only mode.<sup>[[2]](#references)</sup> Όποτε είναι δυνατόν, εργαστείτε σε αντίγραφο ή σε read-only image.

Καταχωρίστε τα entries και επιθεωρήστε τα inodes με requests του `debugfs` για listings καταλόγων, κατάσταση inode και ελέγχους inode-to-path.<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Αποσπάστε ένα γνωστό inode με την εντολή `debugfs dump` και, στη συνέχεια, ταξινομήστε την ανακτημένη έξοδο με το `file`.<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Αυτό δεν εγγυάται την ανάκτηση. Εξαρτάται από την κατάσταση του filesystem, από το αν τα blocks επαναχρησιμοποιήθηκαν και από το αν εξακολουθούν να υπάρχουν τα metadata. Για ext3/ext4, το manual του `debugfs` σημειώνει ότι η ανάκτηση διαγραμμένων inodes μπορεί να αποτύχει, επειδή τα blocks δεδομένων των αποδεσμευμένων inodes δεν είναι πλέον διαθέσιμα.<sup>[[2]](#references)</sup> Η τεχνική παραμένει χρήσιμη, επειδή σας επιτρέπει να εξετάσετε την κατάσταση σε επίπεδο inode χωρίς να βασίζεστε στη συνήθη traversal μέσω paths.

## Εξάντληση και Σειρά των Inodes

Η εξάντληση των inodes συμβαίνει όταν ένα filesystem ξεμένει από nodes αρχείων, ακόμη και αν παραμένει ελεύθερος χώρος στον δίσκο.<sup>[[8]](#references)[[17]](#references)</sup> Συνήθως προκαλεί failures αξιοπιστίας, αλλά μπορεί επίσης να εξηγήσει παράξενη συμπεριφορά κατά τη διάρκεια incident response ή lab triage.

Χρησιμοποιήστε το `df -i` για να εμφανίσετε πληροφορίες inode αντί για τη χρήση blocks.<sup>[[8]](#references)</sup>

Ελέγξτε την πίεση στα inodes με τα `df` και μια καταμέτρηση `find` των parent directories.<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Οι αριθμοί inode και οι χρονικές σημάνσεις μπορούν επίσης να βοηθήσουν στην ανακατασκευή δραστηριότητας σε απλά εργαστηριακά περιβάλλοντα.

Οι παρακάτω οδηγίες μορφοποίησης του `find` εμφανίζουν αυτά τα πεδία.<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Αντιμετωπίστε τη σειρά ως ένδειξη, όχι ως απόδειξη. Οι λειτουργίες αντιγραφής, η εξαγωγή archive, ο τύπος filesystem, οι επαναφορές και οι ταυτόχρονες εγγραφές μπορούν να αλλάξουν τα μοτίβα allocation.

## Defensive Notes

- Κάντε mount άγνωστα images ως read-only κατά την ανάλυση.<sup>[[1]](#references)</sup>
- Διατηρείτε privileged scripts, service units, plugins και helper paths εκτός mounts με δυνατότητα εγγραφής από χρήστες.
- Χρησιμοποιήστε `nosuid`, `nodev` και `noexec` όπου είναι λειτουργικά κατάλληλο· αυτές οι επιλογές απενεργοποιούν την εκτέλεση set-ID/capability, την ερμηνεία συσκευών ή την άμεση εκτέλεση binary στο mount.<sup>[[1]](#references)</sup> Μην τα αντιμετωπίζετε ως πλήρες boundary.
- Περιορίστε την πρόσβαση στο `/proc/<pid>/fd`· το dereferencing αυτών των links ελέγχεται από ptrace access checks και file permissions.<sup>[[6]](#references)</sup> Περιορίστε, όπου είναι δυνατό, τα ευρύτερα process metadata και το cross-user inspection.
- Παρακολουθείτε writable mount points, απρόσμενα hardlinks προς privileged files και ευαίσθητα αρχεία που έχουν διαγραφεί αλλά παραμένουν ανοιχτά.

## References

- [1] [mount(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Τεκμηρίωση για το /proc/sys/fs/ — Τεκμηρίωση Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
