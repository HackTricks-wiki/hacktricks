# Filesystem, Inodes και Recovery

{{#include ../../banners/hacktricks-training.md}}

Η κατάχρηση του Filesystem αφορά συχνά τη σύγχυση της σχέσης μεταξύ μιας ορατής διαδρομής και του object που βρίσκεται πίσω από αυτήν. Τα disk images μπορεί να αποκρύπτουν ένα άλλο filesystem, τα writable mounts μπορεί να χρησιμοποιηθούν από privileged jobs, τα hardlinks μπορεί να εκθέτουν το ίδιο inode μέσω διαφορετικού ονόματος και τα deleted files μπορεί να παραμένουν αναγνώσιμα μέσω ενός open file descriptor.

Αυτή η σελίδα εστιάζει στην τεχνική και όχι σε ένα συγκεκριμένο lab ή target.

## Disk Images και Loop Mounts

Ένα regular file μπορεί να περιέχει ένα πλήρες filesystem. Επομένως, backup images, copied block devices, VM artifacts ή renamed blobs μπορεί να περιέχουν credentials, scripts, SSH keys, configuration files ή flags, ακόμη κι αν εξωτερικά δεν φαίνονται χρήσιμα.

Εντοπίστε πιθανά images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Αν επιτρέπεται το mounting, κάντε πρώτα mount τα άγνωστα images σε λειτουργία μόνο για ανάγνωση:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Αν η προσάρτηση δεν είναι διαθέσιμη, επιθεωρήστε απευθείας τα μεταδεδομένα του συστήματος αρχείων:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Η τεχνική είναι χρήσιμη επειδή μετατρέπει ένα αρχείο που φαίνεται φυσιολογικό σε ένα δεύτερο filesystem tree. Αντιμετωπίστε την ως τρόπο ανάκτησης κρυφών δεδομένων και όχι ως privilege escalation από μόνη της.

## Κατάχρηση Writable Mount

Ένα writable mount γίνεται επικίνδυνο όταν ένα πιο προνομιούχο context εμπιστεύεται αργότερα κάτι που βρίσκεται μέσα σε αυτό. Το σημαντικό ερώτημα δεν είναι μόνο «μπορώ να γράψω εδώ;», αλλά «ποιος θα διαβάσει, θα εκτελέσει, θα κάνει import ή θα φορτώσει αργότερα κάτι από εδώ;».

Βρείτε writable mounts και ύποπτους consumers:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Συνηθισμένα μοτίβα abuse:

- Ένα privileged cron ή systemd unit εκτελεί ένα writable script από το mount.
- Μια privileged υπηρεσία φορτώνει plugins, config, templates ή helper binaries από το mount.
- Ένα mount περιέχει αρχεία SUID και επιτρέπει τροποποίηση, αντικατάσταση ή χειραγώγηση paths.
- Ένα container ή chroot εκθέτει ένα host-backed path που είναι writable από το restricted environment.

Generic validation pattern:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Όταν αποδεικνύετε το impact σε ένα εξουσιοδοτημένο lab, διατηρείτε το payload παρατηρήσιμο και minimal, για παράδειγμα γράφοντας την έξοδο του `id` σε ένα προσωρινό αρχείο. Η βασική τεχνική είναι η delayed execution μέσω μιας αξιόπιστης writable τοποθεσίας.

## Inodes και Path Confusion

Ένα inode είναι το αντικείμενο του filesystem· ένα path είναι απλώς ένα όνομα που δείχνει σε αυτό. Αυτό έχει σημασία επειδή δύο διαφορετικά paths μπορούν να δείχνουν στο ίδιο inode και η διαγραφή ενός pathname δεν σημαίνει πάντα ότι τα δεδομένα έχουν χαθεί.

Συγκρίνετε αρχεία βάσει inode και συσκευής:
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
Βρείτε κάθε ορατό pathname για το ίδιο inode:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
Αναζητήστε απευθείας με βάση τον αριθμό inode όταν διαθέτετε μόνο μεταδεδομένα:
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
Αυτή η τεχνική είναι χρήσιμη όταν ένα αρχείο εμφανίζεται με μη αναμενόμενο όνομα, όταν μια εφαρμογή επικυρώνει μία διαδρομή αλλά χρησιμοποιεί κάποια άλλη ή όταν ένα προνομιούχο wrapper αλληλεπιδρά με ένα inode που είναι επίσης προσβάσιμο από κάπου αλλού.

## Hardlink Abuse

Τα hardlinks δημιουργούν πολλά ονόματα για το ίδιο inode. Δεν δείχνουν σε μια διαδρομή-στόχο όπως τα symlinks· είναι ισότιμα ονόματα για το ίδιο αντικείμενο αρχείου.

Εντοπίστε αρχεία SUID με πολλά hardlinks:
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
- Ένα SUID wrapper μπορεί να είναι κρυμμένο πίσω από ένα όνομα που δεν φαίνεται privileged.
- Ο καθαρισμός που καταργεί ένα pathname μπορεί να αφήσει ενεργό ένα άλλο hardlink.

Οι σύγχρονοι kernels και οι mount options μπορούν να περιορίσουν τη δημιουργία hardlinks, ώστε να μειωθεί αυτό το είδος abuse, αλλά τα υπάρχοντα hardlinks εξακολουθούν να αξίζει να ελεγχθούν.

## Ανάκτηση Διαγραμμένων Αρχείων Μέσω Ανοιχτών FDs

Όταν μια process διατηρεί ένα αρχείο ανοιχτό, τα δεδομένα του αρχείου μπορεί να παραμείνουν διαθέσιμα ακόμη και μετά τη διαγραφή του pathname. Το Linux εκθέτει αυτούς τους ανοιχτούς descriptors κάτω από το `/proc/<pid>/fd/`.

Εντοπίστε διαγραμμένα ανοιχτά αρχεία:
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
Αυτή είναι μια πρακτική τεχνική για την ανάκτηση διαγραμμένων logs, προσωρινών secrets, binaries που απορρίφθηκαν, rotated αρχείων ή scripts που αφαιρέθηκαν μετά την εκτέλεσή τους.

## Ανάκτηση ext με debugfs

Σε filesystems ext, το `debugfs` μπορεί να επιθεωρήσει τα metadata των inodes και, σε ορισμένες περιπτώσεις, να εξαγάγει τα περιεχόμενα αρχείων από ένα filesystem image. Όποτε είναι δυνατό, εργαστείτε σε αντίγραφο ή σε read-only image.

Εμφανίστε τις entries και επιθεωρήστε τα inodes:
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
Αυτό δεν εγγυάται την ανάκτηση. Εξαρτάται από την κατάσταση του filesystem, από το αν τα blocks έχουν επαναχρησιμοποιηθεί και από το αν εξακολουθούν να υπάρχουν τα metadata. Η τεχνική παραμένει χρήσιμη, επειδή σας επιτρέπει να επιθεωρείτε την κατάσταση σε επίπεδο inode χωρίς να βασίζεστε στο κανονικό path traversal.

## Εξάντληση και Ταξινόμηση Inode

Η εξάντληση inode συμβαίνει όταν ένα filesystem ξεμένει από file objects, ακόμη και αν παραμένει ελεύθερος χώρος στον δίσκο. Συνήθως προκαλεί failures αξιοπιστίας, αλλά μπορεί επίσης να εξηγήσει παράξενη συμπεριφορά κατά το incident response ή το lab triage.

Έλεγχος της πίεσης inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Οι αριθμοί inode και οι χρονικές σημάνσεις μπορούν επίσης να βοηθήσουν στην ανακατασκευή δραστηριότητας σε απλά εργαστηριακά περιβάλλοντα:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Αντιμετώπισε τη σειρά ως ένδειξη, όχι ως απόδειξη. Οι λειτουργίες αντιγραφής, η εξαγωγή αρχείων archive, ο τύπος filesystem, οι επαναφορές και οι ταυτόχρονες εγγραφές μπορούν να αλλάξουν τα μοτίβα κατανομής.

## Αμυντικές σημειώσεις

- Κάνε mount άγνωστα images ως read-only κατά την ανάλυση.
- Διατήρησε privileged scripts, service units, plugins και helper paths εκτός mounts με δυνατότητα εγγραφής από χρήστες.
- Χρησιμοποίησε `nosuid`, `nodev` και `noexec` όπου είναι λειτουργικά κατάλληλο, αλλά μην τα αντιμετωπίζεις ως πλήρες boundary.
- Περιόρισε, όπου είναι δυνατό, την πρόσβαση στα `/proc/<pid>/fd`, στα process metadata και στην επιθεώρηση processes άλλων χρηστών.
- Παρακολούθησε writable mount points, μη αναμενόμενα hardlinks προς privileged files και ευαίσθητα αρχεία που έχουν διαγραφεί αλλά παραμένουν ανοιχτά.
