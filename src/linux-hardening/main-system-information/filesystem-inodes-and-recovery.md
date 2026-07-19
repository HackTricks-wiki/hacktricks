# Σύστημα αρχείων, Inodes και Ανάκτηση

{{#include ../../banners/hacktricks-training.md}}

Η κατάχρηση του filesystem αφορά συχνά τη σύγχυση της σχέσης μεταξύ μιας ορατής διαδρομής και του αντικειμένου που βρίσκεται πίσω από αυτήν. Τα disk images μπορεί να κρύβουν ένα άλλο filesystem, τα writable mounts μπορεί να χρησιμοποιηθούν από privileged jobs, τα hardlinks μπορεί να εκθέτουν το ίδιο inode μέσω διαφορετικού ονόματος και τα διαγραμμένα αρχεία μπορεί να παραμένουν αναγνώσιμα μέσω ενός open file descriptor.

Αυτή η σελίδα εστιάζει στην τεχνική και όχι σε ένα συγκεκριμένο lab ή target.

## Disk Images και Loop Mounts

Ένα κανονικό αρχείο μπορεί να περιέχει ένα πλήρες filesystem. Επομένως, backup images, αντιγραμμένες block devices, VM artifacts ή renamed blobs μπορεί να περιέχουν credentials, scripts, SSH keys, configuration files ή flags, ακόμη και όταν εξωτερικά δεν φαίνονται χρήσιμα.

Εντοπίστε πιθανά images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
Εάν επιτρέπεται η προσάρτηση, προσαρτήστε πρώτα άγνωστα images σε λειτουργία μόνο για ανάγνωση:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
Αν η προσάρτηση δεν είναι διαθέσιμη, επιθεωρήστε απευθείας τα μεταδεδομένα του filesystem:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
Η technique είναι χρήσιμη επειδή μετατρέπει ένα αρχείο που φαίνεται φυσιολογικό σε ένα δεύτερο filesystem tree. Αντιμετώπισέ την ως τρόπο ανάκτησης κρυφών δεδομένων, όχι ως privilege escalation από μόνη της.

## Writable Mount Abuse

Ένα writable mount γίνεται επικίνδυνο όταν ένα πιο προνομιούχο context εμπιστεύεται αργότερα κάτι μέσα σε αυτό. Το σημαντικό ερώτημα δεν είναι μόνο «μπορώ να γράψω εδώ;», αλλά «ποιος θα διαβάσει, εκτελέσει, κάνει import ή φορτώσει αργότερα κάτι από εδώ;».

Βρες writable mounts και ύποπτους consumers:
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
Συνηθισμένα μοτίβα abuse:

- Ένα privileged cron ή systemd unit εκτελεί ένα writable script από το mount.
- Μια privileged service φορτώνει plugins, config, templates ή helper binaries από το mount.
- Ένα mount περιέχει αρχεία SUID και επιτρέπει την τροποποίηση, αντικατάσταση ή χειραγώγηση paths.
- Ένα container ή chroot εκθέτει ένα host-backed path που είναι writable από το restricted environment.

Generic μοτίβο validation:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
Κατά την απόδειξη του impact σε ένα εξουσιοδοτημένο lab, διατηρήστε το payload παρατηρήσιμο και minimal, για παράδειγμα γράφοντας την έξοδο της `id` σε ένα προσωρινό αρχείο. Η βασική τεχνική είναι η delayed execution μέσω μιας αξιόπιστης writable τοποθεσίας.

## Inodes και σύγχυση διαδρομών

Ένα inode είναι το αντικείμενο του filesystem· ένα path είναι απλώς ένα όνομα που δείχνει σε αυτό. Αυτό έχει σημασία επειδή δύο διαφορετικά paths μπορούν να δείχνουν στο ίδιο inode και η διαγραφή ενός pathname δεν σημαίνει πάντα ότι τα δεδομένα έχουν χαθεί.

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
Αυτή η τεχνική είναι χρήσιμη όταν ένα αρχείο εμφανίζεται με μη αναμενόμενο όνομα, όταν μια εφαρμογή επικυρώνει μία διαδρομή αλλά χρησιμοποιεί κάποια άλλη ή όταν ένα προνομιούχο wrapper αλληλεπιδρά με ένα inode που είναι επίσης προσβάσιμο από κάπου αλλού.

## Hardlink Abuse

Τα hardlinks δημιουργούν πολλά ονόματα για το ίδιο inode. Δεν δείχνουν σε μια διαδρομή-στόχο όπως κάνουν τα symlinks· είναι ισοδύναμα ονόματα για το ίδιο αντικείμενο αρχείου.

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
- Ένα SUID wrapper μπορεί να είναι κρυμμένο πίσω από ένα όνομα που δεν φαίνεται privileged.
- Ο καθαρισμός που αφαιρεί ένα pathname μπορεί να αφήσει ενεργό ένα άλλο hardlink.

Οι σύγχρονοι kernels και οι mount options μπορούν να περιορίσουν τη δημιουργία hardlink για να μειώσουν αυτό το είδος abuse, αλλά τα υπάρχοντα hardlink εξακολουθούν να αξίζει να ελεγχθούν.

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

Σε filesystems ext, το `debugfs` μπορεί να επιθεωρήσει metadata των inodes και, σε ορισμένες περιπτώσεις, να κάνει dump των περιεχομένων αρχείων από ένα filesystem image. Όποτε είναι δυνατόν, εργαστείτε σε αντίγραφο ή σε read-only image.

Παραθέστε τις εγγραφές και επιθεωρήστε τα inodes:
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
Εξαγωγή γνωστού inode:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
Αυτό δεν εγγυάται την ανάκτηση. Εξαρτάται από την κατάσταση του filesystem, από το αν τα blocks έχουν επαναχρησιμοποιηθεί και από το αν υπάρχουν ακόμη τα metadata. Η τεχνική παραμένει χρήσιμη, επειδή σας επιτρέπει να επιθεωρείτε την κατάσταση σε επίπεδο inode χωρίς να βασίζεστε στο κανονικό path traversal.

## Εξάντληση και Σειρά Inode

Η εξάντληση inode συμβαίνει όταν ένα filesystem ξεμένει από αντικείμενα αρχείων, ακόμη και αν παραμένει ελεύθερος χώρος στον δίσκο. Συνήθως προκαλεί failures αξιοπιστίας, αλλά μπορεί επίσης να εξηγήσει παράξενη συμπεριφορά κατά την απόκριση σε περιστατικά ή το lab triage.

Ελέγξτε την πίεση των inode:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Οι αριθμοί inode και οι χρονικές σημάνσεις μπορούν επίσης να βοηθήσουν στην ανασύνθεση δραστηριότητας σε απλά εργαστηριακά περιβάλλοντα:
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
Αντιμετωπίζετε τη σειρά ως ένδειξη, όχι ως απόδειξη. Οι λειτουργίες αντιγραφής, η εξαγωγή αρχείων αρχειοθέτησης, ο τύπος filesystem, οι επαναφορές και οι ταυτόχρονες εγγραφές μπορούν να αλλάξουν τα μοτίβα κατανομής.

## Αμυντικές σημειώσεις

- Κάντε mount άγνωστα images ως read-only κατά την ανάλυση.
- Διατηρείτε προνομιούχα scripts, service units, plugins και helper paths εκτός mounts με δυνατότητα εγγραφής από χρήστες.
- Χρησιμοποιείτε `nosuid`, `nodev` και `noexec` όπου είναι λειτουργικά κατάλληλο, αλλά μην τα θεωρείτε πλήρες boundary.
- Περιορίστε, όπου είναι δυνατό, την πρόσβαση στα `/proc/<pid>/fd`, στα process metadata και στην επιθεώρηση processes άλλων χρηστών.
- Παρακολουθείτε mount points με δυνατότητα εγγραφής, απρόσμενα hardlinks προς προνομιούχα αρχεία και ευαίσθητα αρχεία που έχουν διαγραφεί αλλά παραμένουν ανοιχτά.
{{#include ../../banners/hacktricks-training.md}}
