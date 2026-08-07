# Σύστημα αρχείων, Inodes και Recovery

{{#include ../../banners/hacktricks-training.md}}

Η κατάχρηση συστημάτων αρχείων αφορά συχνά τη σύγχυση μεταξύ μιας ορατής διαδρομής και του αντικειμένου που βρίσκεται πίσω από αυτήν. Οι εικόνες δίσκου μπορεί να κρύβουν ένα άλλο σύστημα αρχείων, τα εγγράψιμα mounts μπορεί να χρησιμοποιηθούν από προνομιούχες εργασίες, τα hardlinks μπορεί να εκθέσουν το ίδιο inode μέσω διαφορετικού ονόματος και τα διαγραμμένα αρχεία μπορεί να παραμένουν αναγνώσιμα μέσω ενός ανοιχτού file descriptor.

Αυτή η σελίδα εστιάζει στην τεχνική και όχι σε ένα συγκεκριμένο lab ή target.

## Εικόνες δίσκου και Loop Mounts

Ένα κανονικό αρχείο μπορεί να περιέχει ένα πλήρες σύστημα αρχείων. Επομένως, images αντιγράφων ασφαλείας, αντιγραμμένες block devices, VM artifacts ή blobs που έχουν μετονομαστεί μπορεί να περιέχουν credentials, scripts, SSH keys, αρχεία ρυθμίσεων ή flags, ακόμη και όταν εξωτερικά δεν φαίνονται χρήσιμα.

Εντοπίστε πιθανές images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Αν επιτρέπεται η προσάρτηση, προσαρτήστε πρώτα τις άγνωστες εικόνες μόνο για ανάγνωση:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Εάν το mounting δεν είναι διαθέσιμο, εξετάστε απευθείας τα μεταδεδομένα του filesystem:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Η τεχνική είναι χρήσιμη επειδή μετατρέπει ένα αρχείο που φαίνεται φυσιολογικό σε ένα δεύτερο δέντρο filesystem. Αντιμετωπίστε την ως τρόπο ανάκτησης κρυφών δεδομένων και όχι ως privilege escalation από μόνη της.

## Κατάχρηση εγγράψιμου mount

Ένα εγγράψιμο mount γίνεται επικίνδυνο όταν ένα πιο privileged context εμπιστεύεται αργότερα κάτι που βρίσκεται μέσα σε αυτό. Το σημαντικό ερώτημα δεν είναι μόνο «μπορώ να γράψω εδώ;», αλλά «ποιος θα διαβάσει, θα εκτελέσει, θα κάνει import ή θα φορτώσει αργότερα κάτι από εδώ;».

Εντοπίστε εγγράψιμα mounts και ύποπτους consumers:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Συνήθη μοτίβα κατάχρησης:

- Ένα privileged cron ή systemd unit εκτελεί ένα writable script από το mount.
- Ένα privileged service φορτώνει plugins, config, templates ή helper binaries από το mount.
- Ένα mount περιέχει αρχεία SUID και επιτρέπει τροποποίηση, αντικατάσταση ή χειραγώγηση path.
- Ένα container ή chroot εκθέτει ένα host-backed path που είναι writable από το restricted environment.

Γενικό μοτίβο επικύρωσης:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Όταν αποδεικνύετε τον αντίκτυπο σε ένα εξουσιοδοτημένο lab, διατηρείτε το payload παρατηρήσιμο και ελάχιστο, για παράδειγμα γράφοντας την έξοδο του `id` σε ένα προσωρινό αρχείο. Η βασική τεχνική είναι η καθυστερημένη εκτέλεση μέσω μιας αξιόπιστης τοποθεσίας με δυνατότητα εγγραφής.

## Inodes και σύγχυση διαδρομών

Ένα inode είναι το αντικείμενο του filesystem· μια διαδρομή είναι απλώς ένα όνομα που δείχνει σε αυτό. Αυτό έχει σημασία επειδή δύο διαφορετικές διαδρομές μπορούν να δείχνουν στο ίδιο inode, ενώ η διαγραφή ενός ονόματος διαδρομής δεν σημαίνει πάντα ότι τα δεδομένα έχουν χαθεί.

Συγκρίνετε αρχεία με βάση το inode και τη συσκευή:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Βρείτε κάθε ορατό pathname για το ίδιο inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Αναζητήστε απευθείας με βάση τον αριθμό inode όταν έχετε μόνο μεταδεδομένα:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Αυτή η τεχνική είναι χρήσιμη όταν ένα αρχείο εμφανίζεται με μη αναμενόμενο όνομα, όταν μια εφαρμογή επικυρώνει μία διαδρομή αλλά χρησιμοποιεί μια άλλη ή όταν ένα privileged wrapper αλληλεπιδρά με ένα inode που είναι επίσης προσβάσιμο από κάπου αλλού.

## Κατάχρηση Hardlinks

Τα hardlinks δημιουργούν πολλαπλά ονόματα για το ίδιο inode. Δεν δείχνουν σε μια διαδρομή-στόχο όπως κάνουν τα symlinks· είναι ισοδύναμα ονόματα για το ίδιο αντικείμενο αρχείου.

Βρείτε αρχεία SUID με πολλαπλά hardlinks:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Επιθεωρήστε ένα ύποπτο αρχείο:
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
Γιατί έχει σημασία:

- Ένα ευαίσθητο αρχείο μπορεί να είναι προσβάσιμο μέσω μιας λιγότερο προφανούς διαδρομής.
- Ένα SUID wrapper μπορεί να είναι κρυμμένο πίσω από ένα όνομα που δεν φαίνεται να έχει προνόμια.
- Ο καθαρισμός που αφαιρεί ένα pathname μπορεί να αφήσει ενεργό ένα άλλο hardlink.

Οι σύγχρονοι kernels και οι mount options μπορούν να περιορίσουν τη δημιουργία hardlink για να μειώσουν αυτόν τον τύπο κατάχρησης, αλλά τα υπάρχοντα hardlink εξακολουθούν να αξίζει να ελεγχθούν.

## Ανάκτηση διαγραμμένων αρχείων μέσω ανοιχτών FD

Όταν μια διεργασία διατηρεί ένα αρχείο ανοιχτό, τα δεδομένα του αρχείου μπορεί να παραμείνουν διαθέσιμα ακόμη και μετά τη διαγραφή του pathname. Το Linux εκθέτει αυτούς τους ανοιχτούς descriptors κάτω από το `/proc/<pid>/fd/`.

Εντοπισμός διαγραμμένων ανοιχτών αρχείων:
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
Ανακτήστε τα δεδομένα όταν τα δικαιώματα το επιτρέπουν:
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
Αυτή είναι μια πρακτική τεχνική για την ανάκτηση διαγραμμένων logs, προσωρινών secrets, dropped binaries, rotated files ή scripts που αφαιρέθηκαν μετά την εκτέλεσή τους.

## Ανάκτηση ext με debugfs

Σε filesystems ext, το `debugfs` μπορεί να επιθεωρήσει τα metadata των inodes και, μερικές φορές, να κάνει dump των περιεχομένων αρχείων από ένα filesystem image. Όποτε είναι δυνατόν, εργαστείτε σε αντίγραφο ή σε read-only image.

Παραθέστε τις καταχωρίσεις και επιθεωρήστε τα inodes:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Dump ενός γνωστού inode:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Αυτό δεν εγγυάται την ανάκτηση. Εξαρτάται από την κατάσταση του συστήματος αρχείων, από το αν τα blocks έχουν επαναχρησιμοποιηθεί και από το αν εξακολουθούν να υπάρχουν τα metadata. Η τεχνική παραμένει χρήσιμη, επειδή σας επιτρέπει να επιθεωρείτε την κατάσταση σε επίπεδο inode χωρίς να βασίζεστε σε κανονικό path traversal.

## Εξάντληση και Διάταξη Inode

Η εξάντληση inode συμβαίνει όταν ένα σύστημα αρχείων ξεμένει από αντικείμενα αρχείων, ακόμη και αν παραμένει ελεύθερος χώρος στον δίσκο. Συνήθως προκαλεί αστοχίες αξιοπιστίας, αλλά μπορεί επίσης να εξηγήσει παράξενη συμπεριφορά κατά την απόκριση σε περιστατικά ή το lab triage.

Ελέγξτε την πίεση των inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Οι αριθμοί inode και οι χρονικές σημάνσεις μπορούν επίσης να βοηθήσουν στην ανακατασκευή της δραστηριότητας σε απλά εργαστηριακά περιβάλλοντα:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Αντιμετωπίζετε τη σειρά ως ένδειξη, όχι ως απόδειξη. Οι λειτουργίες αντιγραφής, η εξαγωγή αρχείων αρχειοθέτησης, ο τύπος filesystem, οι επαναφορές και οι ταυτόχρονες εγγραφές μπορούν να αλλάξουν τα μοτίβα κατανομής.

## Αμυντικές σημειώσεις

- Κάντε mount άγνωστα images ως read-only κατά την ανάλυση.
- Διατηρείτε προνομιούχα scripts, service units, plugins και helper paths εκτός mounts με δυνατότητα εγγραφής από χρήστες.
- Χρησιμοποιείτε `nosuid`, `nodev` και `noexec` όπου είναι λειτουργικά κατάλληλο, αλλά μην τα αντιμετωπίζετε ως πλήρες boundary.
- Περιορίστε, όπου είναι δυνατό, την πρόσβαση στα `/proc/<pid>/fd`, στα process metadata και στην επιθεώρηση διεργασιών μεταξύ χρηστών.
- Παρακολουθείτε mount points με δυνατότητα εγγραφής, απρόσμενα hardlinks προς προνομιούχα αρχεία και ευαίσθητα αρχεία που έχουν διαγραφεί αλλά παραμένουν ανοιχτά.

{{#include ../../banners/hacktricks-training.md}}
