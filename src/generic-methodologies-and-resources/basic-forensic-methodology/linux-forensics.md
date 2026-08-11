# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Αρχική Συλλογή Πληροφοριών

### Βασικές Πληροφορίες

Καταρχάς, συνιστάται να έχετε κάποιο **USB** με **γνωστά και αξιόπιστα binaries και libraries** (μπορείτε απλώς να πάρετε το ubuntu και να αντιγράψετε τους φακέλους _/bin_, _/sbin_, _/lib,_ και _/lib64_), έπειτα να προσαρτήσετε το USB και να τροποποιήσετε τις μεταβλητές περιβάλλοντος ώστε να χρησιμοποιούν αυτά τα binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Αφού ρυθμίσετε το σύστημα ώστε να χρησιμοποιεί αξιόπιστα και γνωστά δυαδικά αρχεία, μπορείτε να ξεκινήσετε την **εξαγωγή ορισμένων βασικών πληροφοριών**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Ύποπτες πληροφορίες

Κατά τη συλλογή των βασικών πληροφοριών, θα πρέπει να ελέγχετε για περίεργα πράγματα, όπως:

- Οι **Root processes** συνήθως εκτελούνται με χαμηλά PIDS, επομένως, αν βρείτε ένα Root process με μεγάλο PID, μπορεί να είναι ύποπτο
- Ελέγξτε τα **registered logins** χρηστών χωρίς shell μέσα στο `/etc/passwd`
- Ελέγξτε για **password hashes** μέσα στο `/etc/shadow` για χρήστες χωρίς shell

### Memory Dump

Για να αποκτήσετε τη μνήμη του running system, συνιστάται να χρησιμοποιήσετε το [**LiME**](https://github.com/504ensicsLabs/LiME).\
Για να το **compile**, πρέπει να χρησιμοποιήσετε τον **ίδιο kernel** που χρησιμοποιεί το victim machine.

> [!TIP]
> Θυμηθείτε ότι **δεν μπορείτε να εγκαταστήσετε το LiME ή οτιδήποτε άλλο** στο victim machine, καθώς αυτό θα επιφέρει αρκετές αλλαγές σε αυτό

Επομένως, αν έχετε μια πανομοιότυπη έκδοση του Ubuntu, μπορείτε να χρησιμοποιήσετε το `apt-get install lime-forensics-dkms`\
Σε άλλες περιπτώσεις, πρέπει να κατεβάσετε το [**LiME**](https://github.com/504ensicsLabs/LiME) από το github και να το κάνετε compile με τα σωστά kernel headers. Για να **αποκτήσετε τα ακριβή kernel headers** του victim machine, μπορείτε απλώς να **αντιγράψετε τον κατάλογο** `/lib/modules/<kernel version>` στο μηχάνημά σας και, στη συνέχεια, να κάνετε **compile** το LiME χρησιμοποιώντας τα:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
Το LiME υποστηρίζει 3 **formats**:

- Raw (κάθε segment ενωμένο μαζί)
- Padded (όπως το raw, αλλά με μηδενικά στα δεξιά bits)
- Lime (recommended format με metadata

Το LiME μπορεί επίσης να χρησιμοποιηθεί για **αποστολή του dump μέσω network** αντί για αποθήκευσή του στο σύστημα, χρησιμοποιώντας κάτι όπως: `path=tcp:4444`

### Disk Imaging

#### Τερματισμός λειτουργίας

Πρώτα απ' όλα, θα χρειαστεί να **τερματίσετε τη λειτουργία του συστήματος**. Αυτό δεν αποτελεί πάντα επιλογή, καθώς μερικές φορές το σύστημα μπορεί να είναι production server που η εταιρεία δεν έχει την πολυτέλεια να τερματίσει.\
Υπάρχουν **2 τρόποι** τερματισμού της λειτουργίας του συστήματος: ο **κανονικός τερματισμός** και ο τερματισμός με **«τράβηγμα του καλωδίου»**. Ο πρώτος επιτρέπει στις **processes να τερματιστούν κανονικά** και στο **filesystem** να **συγχρονιστεί**, αλλά επιτρέπει επίσης στο πιθανό **malware** να **καταστρέψει στοιχεία**. Η προσέγγιση «τράβηγμα του καλωδίου» μπορεί να προκαλέσει **κάποια απώλεια πληροφοριών** (δεν πρόκειται να χαθούν πολλές πληροφορίες, καθώς έχουμε ήδη λάβει image της memory) και το **malware δεν θα έχει καμία δυνατότητα** να κάνει οτιδήποτε σχετικά με αυτό. Επομένως, αν **υποψιάζεστε** ότι μπορεί να υπάρχει **malware**, απλώς εκτελέστε την **εντολή** **`sync`** στο σύστημα και τραβήξτε το καλώδιο.

#### Λήψη image του disk

Είναι σημαντικό να σημειωθεί ότι **πριν συνδέσετε τον υπολογιστή σας με οτιδήποτε σχετίζεται με την υπόθεση**, πρέπει να βεβαιωθείτε ότι θα **προσαρτηθεί ως read only**, ώστε να αποφύγετε την τροποποίηση οποιωνδήποτε πληροφοριών.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Προανάλυση εικόνας δίσκου

Δημιουργία αντιγράφου μιας εικόνας δίσκου χωρίς επιπλέον δεδομένα.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## Αναζήτηση γνωστού Malware

### Τροποποιημένα αρχεία συστήματος

Το Linux προσφέρει εργαλεία για τη διασφάλιση της ακεραιότητας των στοιχείων του συστήματος, κάτι κρίσιμο για τον εντοπισμό δυνητικά προβληματικών αρχείων.<sup>[[1]](#references)</sup>

- **Συστήματα βασισμένα σε RedHat**: Χρησιμοποιήστε το `rpm -Va` για έναν ολοκληρωμένο έλεγχο.
- **Συστήματα βασισμένα σε Debian**: Χρησιμοποιήστε το `dpkg --verify` για αρχική επαλήθευση και στη συνέχεια το `debsums | grep -v "OK$"` (αφού εγκαταστήσετε το `debsums` με `apt-get install debsums`) για τον εντοπισμό τυχόν προβλημάτων.

### Ανιχνευτές Malware/Rootkit

Διαβάστε την ακόλουθη σελίδα για να μάθετε σχετικά με εργαλεία που μπορούν να φανούν χρήσιμα για την εύρεση Malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Αναζήτηση εγκατεστημένων προγραμμάτων

Για την αποτελεσματική αναζήτηση εγκατεστημένων προγραμμάτων σε συστήματα Debian και RedHat, εξετάστε το ενδεχόμενο αξιοποίησης των logs και των databases του συστήματος, σε συνδυασμό με χειροκίνητους ελέγχους σε συνηθισμένους καταλόγους.<sup>[[1]](#references)</sup>

- Για το Debian, ελέγξτε τα _**`/var/lib/dpkg/status`**_ και _**`/var/log/dpkg.log`**_ για να ανακτήσετε λεπτομέρειες σχετικά με τις εγκαταστάσεις πακέτων, χρησιμοποιώντας το `grep` για φιλτράρισμα συγκεκριμένων πληροφοριών.
- Οι χρήστες RedHat μπορούν να εκτελέσουν query στη RPM database με το `rpm -qa --root=/mntpath/var/lib/rpm` για να εμφανίσουν τα εγκατεστημένα πακέτα.

Για να εντοπίσετε software που εγκαταστάθηκε χειροκίνητα ή εκτός αυτών των package managers, εξετάστε καταλόγους όπως οι _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ και _**`/sbin`**_. Συνδυάστε τις καταχωρίσεις καταλόγων με εντολές ειδικές για το σύστημα, ώστε να εντοπίσετε executables που δεν σχετίζονται με γνωστά πακέτα, βελτιώνοντας την αναζήτησή σας για όλα τα εγκατεστημένα προγράμματα.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## Ανάκτηση Διαγραμμένων Εκτελούμενων Binaries

Φανταστείτε μια διεργασία που εκτελέστηκε από το /tmp/exec και στη συνέχεια διαγράφηκε. Είναι δυνατή η εξαγωγή της.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triage καταγραφής Syscall με SQLite και FTS5

Όταν μια διεργασία εξακολουθεί να εκτελείται ή μπορεί να επανεκτελεστεί σε lab, το **`strace`** μπορεί να παρέχει μια γρήγορη καταγραφή συμπεριφοράς χωρίς να απαιτούνται kernel modules ή πλήρες EDR telemetry. Για μεγάλες καταγραφές, αποφύγετε την απευθείας ανάγνωση του raw log ή την επικόλλησή του σε ένα **SQLite** database ή σε ένα LLM: αποθηκεύστε το σε μια βάση **SQLite** και κάντε query μόνο για το ελάχιστο υποσύνολο που χρειάζεστε.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Η σύνδεση του `strace` αλλάζει τον χρονισμό της διεργασίας και μπορεί να επηρεάσει race conditions ή άλλα ευαίσθητα bugs. Όποτε είναι δυνατόν, προτιμήστε την αναπαραγωγή σε αντίγραφο ή lab system.

### Καταγραφή

Για μια νέα διεργασία:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Για μια ενεργή διεργασία:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Χρήσιμες επιλογές:

- `-ff`: παρακολούθηση forks/threads και διατήρηση output ανά process
- `-ttt`: timestamps epoch για εύκολη συσχέτιση timeline
- `-yy`: επίλυση file descriptors στις αντίστοιχες paths/sockets, όταν είναι δυνατό
- `-s 4096`: διατήρηση μεγάλων path και buffer arguments χωρίς truncation

### Κανονικοποίηση

Ένα πρακτικό schema είναι μία γραμμή ανά syscall και μία γραμμή ανά argument:
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
Αυτό αποφεύγει την προσπάθεια ισοπέδωσης ετερογενών γραμμών syscall σε έναν ενιαίο πλατύ πίνακα και διατηρεί τα joins προβλέψιμα κατά το triage.

### Ευρετηρίαση text-heavy arguments με FTS5

Η naive αναζήτηση paths με `LIKE "%...%"` γίνεται πολύ αργή σε μεγάλα traces. Δημιουργήστε ένα FTS5 index για το κείμενο των arguments και κάντε αναζήτηση σε αυτό:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Παράδειγμα: ανάκτηση δραστηριότητας αρχείων στο `/tmp` χωρίς σάρωση κάθε γραμμής:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Έρευνες υψηλού σήματος

- **PATH hijacking / fake sudo**: αναζητήστε εγγραφές και δραστηριότητα `chmod`/`rename` κάτω από το `~/.local/bin/` και, στη συνέχεια, συσχετίστε τις με μεταγενέστερα `execve` προνομιακών ονομάτων, όπως το `sudo`.
- **TOCTOU σε προσωρινά αρχεία**: κάντε pivot στην ίδια διαδρομή `/tmp/...` μεταξύ των `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` και `execve`, για να εντοπίσετε κενά μεταξύ ελέγχου και χρήσης.
- **Αιτία crash**: συσχετίστε το `mmap` ενός αρχείου με εγγραφές ή περικοπή του ίδιου inode/μονοπατιού από άλλη διεργασία και, στη συνέχεια, εξετάστε την ακολουθία signal/exit για `SIGBUS`.
- **Ανάκτηση προορισμού δικτύου**: φιλτράρετε τα `connect`, `sendto`, `sendmsg`, `recvfrom` και τα ορίσματα που σχετίζονται με sockets, για να εξαγάγετε IPs και ports peers.

### Ανάλυση trace με τη βοήθεια LLM

Αν θέλετε ένα LLM να βοηθήσει, εκθέστε ένα **read-only** SQLite handle και δώστε του ολόκληρο το schema. Αφήστε το να εκτελεί raw SQL αντί να τυλίγετε τη βάση δεδομένων πίσω από περιορισμένες helper functions. Αυτό συνήθως λειτουργεί καλύτερα για joins, χρονική συσχέτιση και αναζητήσεις FTS.

Πρακτικοί κανόνες:

- Διατηρήστε τη βάση δεδομένων read-only, για παράδειγμα με `sqlite3 'file:trace.db?mode=ro'`.
- Δώστε στο model παραδείγματα έγκυρων queries `JOIN` και `FTS5 MATCH`.
- Μην επικολλάτε raw logs `strace` πολλών GB στο prompt.
- Κάντε στοχευμένες ερωτήσεις, όπως:
- «Παράθεσε τα persistent αρχεία που γράφτηκαν από αυτό το πρόγραμμα.»
- «Δημιούργησε ή αντικατέστησε executables σε καταλόγους του PATH που ελέγχονται από τον χρήστη;»
- «Εξήγησε γιατί αυτό το trace καταλήγει σε SIGBUS.»

## Έλεγχος τοποθεσιών Autostart

### Προγραμματισμένες εργασίες
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
#### Hunt: κατάχρηση των Cron/Anacron μέσω του 0anacron και ύποπτων stubs
Οι επιτιθέμενοι συχνά τροποποιούν το stub 0anacron που βρίσκεται σε κάθε κατάλογο /etc/cron.*/ για να διασφαλίσουν την περιοδική εκτέλεση.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: rollback του SSH hardening και backdoor shells
Οι αλλαγές στο sshd_config και στα shells των λογαριασμών συστήματος είναι συνηθισμένες μετά το post-exploitation για τη διατήρηση της πρόσβασης.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Δείκτες Cloud C2 (Dropbox/Cloudflare Tunnel)
- Τα Dropbox API beacons συνήθως χρησιμοποιούν τα api.dropboxapi.com ή content.dropboxapi.com μέσω HTTPS με Authorization: Bearer tokens.
- Αναζητήστε σε proxy/Zeek/NetFlow μη αναμενόμενη εξερχόμενη κίνηση Dropbox από servers.
- Το Cloudflare Tunnel (`cloudflared`) παρέχει εφεδρικό C2 μέσω εξερχόμενης θύρας 443.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Υπηρεσίες

Διαδρομές όπου ένα malware μπορεί να εγκατασταθεί ως υπηρεσία:

- **/etc/inittab**: Καλεί scripts αρχικοποίησης όπως το rc.sysinit, παραπέμποντας στη συνέχεια σε startup scripts.
- **/etc/rc.d/** και **/etc/rc.boot/**: Περιέχουν scripts για την εκκίνηση υπηρεσιών, με το δεύτερο να εμφανίζεται σε παλαιότερες εκδόσεις του Linux.
- **/etc/init.d/**: Χρησιμοποιείται σε ορισμένες εκδόσεις του Linux, όπως το Debian, για την αποθήκευση startup scripts.
- Οι υπηρεσίες μπορούν επίσης να ενεργοποιούνται μέσω των **/etc/inetd.conf** ή **/etc/xinetd/**, ανάλογα με το Linux variant.
- **/etc/systemd/system**: Ένας κατάλογος για scripts του system και service manager.
- **/etc/systemd/system/multi-user.target.wants/**: Περιέχει links προς υπηρεσίες που πρέπει να εκκινούν σε multi-user runlevel.
- **/usr/local/etc/rc.d/**: Για custom ή third-party υπηρεσίες.
- **\~/.config/autostart/**: Για user-specific εφαρμογές automatic startup, που μπορεί να αποτελέσει σημείο απόκρυψης για user-targeted malware.
- **/lib/systemd/system/**: System-wide default unit files που παρέχονται από εγκατεστημένα packages.

#### Αναζήτηση: systemd timers και transient units

Η persistence του Systemd δεν περιορίζεται σε αρχεία `.service`. Ερευνήστε `.timer` units, user-level units και **transient units** που δημιουργούνται κατά το runtime.
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Οι transient units είναι εύκολο να παραβλεφθούν, επειδή το `/run/systemd/transient/` είναι **μη persistent**. Αν συλλέγετε ένα live image, πάρτε το πριν από τον τερματισμό λειτουργίας.

### Kernel Modules

Τα Linux kernel modules, τα οποία συχνά χρησιμοποιούνται από malware ως components rootkit, φορτώνονται κατά την εκκίνηση του συστήματος. Οι κατάλογοι και τα αρχεία που είναι κρίσιμα για αυτά τα modules περιλαμβάνουν:

- **/lib/modules/$(uname -r)**: Περιέχει modules για την έκδοση kernel που εκτελείται.
- **/etc/modprobe.d**: Περιέχει αρχεία ρυθμίσεων για τον έλεγχο της φόρτωσης modules.
- **/etc/modprobe** και **/etc/modprobe.conf**: Αρχεία για καθολικές ρυθμίσεις modules.

### Άλλες τοποθεσίες Autostart

Το Linux χρησιμοποιεί διάφορα αρχεία για την αυτόματη εκτέλεση προγραμμάτων κατά το login του χρήστη, τα οποία ενδέχεται να φιλοξενούν malware:

- **/etc/profile.d/**\*, **/etc/profile** και **/etc/bash.bashrc**: Εκτελούνται κατά το login οποιουδήποτε χρήστη.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** και **\~/.config/autostart**: Αρχεία ειδικά για τον χρήστη, τα οποία εκτελούνται κατά το login του.
- **/etc/rc.local**: Εκτελείται αφού έχουν ξεκινήσει όλες οι system services, σηματοδοτώντας το τέλος της μετάβασης σε περιβάλλον πολλών χρηστών.

## Εξέταση Logs

Τα Linux systems καταγράφουν τις δραστηριότητες των χρηστών και τα system events μέσω διαφόρων log files. Αυτά τα logs είναι καθοριστικά για τον εντοπισμό μη εξουσιοδοτημένης πρόσβασης, μολύνσεων από malware και άλλων security incidents.<sup>[[2]](#references)</sup> Τα βασικά log files περιλαμβάνουν:

- **/var/log/syslog** (Debian) ή **/var/log/messages** (RedHat): Καταγράφουν system-wide messages και δραστηριότητες.
- **/var/log/auth.log** (Debian) ή **/var/log/secure** (RedHat): Καταγράφουν απόπειρες authentication, καθώς και επιτυχημένα και αποτυχημένα logins.
- Χρησιμοποιήστε το `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` για να φιλτράρετε σχετικά authentication events.
- **/var/log/boot.log**: Περιέχει messages κατά την εκκίνηση του συστήματος.
- **/var/log/maillog** ή **/var/log/mail.log**: Καταγράφει δραστηριότητες του email server, χρήσιμες για την παρακολούθηση services που σχετίζονται με email.
- **/var/log/kern.log**: Αποθηκεύει kernel messages, συμπεριλαμβανομένων errors και warnings.
- **/var/log/dmesg**: Περιέχει messages των device drivers.
- **/var/log/faillog**: Καταγράφει αποτυχημένες απόπειρες login, βοηθώντας στις έρευνες security breaches.
- **/var/log/cron**: Καταγράφει τις εκτελέσεις cron jobs.
- **/var/log/daemon.log**: Παρακολουθεί τις δραστηριότητες background services.
- **/var/log/btmp**: Καταγράφει αποτυχημένες απόπειρες login.
- **/var/log/httpd/**: Περιέχει error και access logs του Apache HTTPD.
- **/var/log/mysqld.log** ή **/var/log/mysql.log**: Καταγράφει τις δραστηριότητες της MySQL database.
- **/var/log/xferlog**: Καταγράφει FTP file transfers.
- **/var/log/**: Ελέγχετε πάντα για μη αναμενόμενα logs εδώ.

> [!TIP]
> Τα Linux system logs και τα audit subsystems ενδέχεται να έχουν απενεργοποιηθεί ή διαγραφεί κατά τη διάρκεια intrusion ή malware incident. Επειδή τα logs στα Linux systems περιέχουν γενικά ορισμένες από τις πιο χρήσιμες πληροφορίες σχετικά με malicious activities, οι intruders τα διαγράφουν συστηματικά. Επομένως, κατά την εξέταση των διαθέσιμων log files, είναι σημαντικό να αναζητάτε κενά ή entries εκτός σειράς, τα οποία μπορεί να αποτελούν ένδειξη διαγραφής ή tampering.

### Triage του Journald (`journalctl`)

Σε σύγχρονους Linux hosts, το **systemd journal** είναι συνήθως η πιο πολύτιμη πηγή για **service execution**, **auth events**, **package operations** και **kernel/user-space messages**. Κατά τη διάρκεια live response, προσπαθήστε να διατηρήσετε τόσο το **persistent** journal (`/var/log/journal/`) όσο και το **runtime** journal (`/run/log/journal/`), επειδή δραστηριότητα attacker μικρής διάρκειας μπορεί να υπάρχει μόνο στο δεύτερο.<sup>[[5]](#references)</sup>
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
Χρήσιμα πεδία του journal για triage περιλαμβάνουν τα `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` και `MESSAGE`. Αν το journald έχει ρυθμιστεί χωρίς persistent storage, αναμένετε μόνο πρόσφατα δεδομένα στο `/run/log/journal/`.

### Triage του Audit framework (`auditd`)

Αν το `auditd` είναι ενεργοποιημένο, προτιμήστε το όταν χρειάζεστε **απόδοση ενεργειών σε process** για αλλαγές αρχείων, εκτέλεση εντολών, δραστηριότητα login ή εγκατάσταση packages.<sup>[[6]](#references)</sup>
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
Όταν οι κανόνες αναπτύχθηκαν με κλειδιά, κάντε pivot από αυτά αντί να κάνετε grep σε ακατέργαστα logs:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Το Linux διατηρεί ένα ιστορικό εντολών για κάθε χρήστη**, αποθηκευμένο στα:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Επιπλέον, η εντολή `last -Faiwx` παρέχει μια λίστα με τις συνδέσεις χρηστών. Ελέγξτε την για άγνωστες ή μη αναμενόμενες συνδέσεις.

Ελέγξτε αρχεία που μπορούν να παραχωρήσουν επιπλέον δικαιώματα:

- Εξετάστε το `/etc/sudoers` για μη αναμενόμενα δικαιώματα χρηστών που ενδέχεται να έχουν παραχωρηθεί.
- Εξετάστε το `/etc/sudoers.d/` για μη αναμενόμενα δικαιώματα χρηστών που ενδέχεται να έχουν παραχωρηθεί.
- Εξετάστε το `/etc/groups` για ασυνήθιστες συμμετοχές σε ομάδες ή δικαιώματα.
- Εξετάστε το `/etc/passwd` για ασυνήθιστες συμμετοχές σε ομάδες ή δικαιώματα.

Ορισμένες εφαρμογές δημιουργούν επίσης τα δικά τους αρχεία καταγραφής:

- **SSH**: Εξετάστε τα _\~/.ssh/authorized_keys_ και _\~/.ssh/known_hosts_ για μη εξουσιοδοτημένες απομακρυσμένες συνδέσεις.
- **Gnome Desktop**: Ελέγξτε το _\~/.recently-used.xbel_ για αρχεία στα οποία έγινε πρόσφατη πρόσβαση μέσω εφαρμογών Gnome.
- **Firefox/Chrome**: Ελέγξτε το ιστορικό περιήγησης και τις λήψεις στο _\~/.mozilla/firefox_ ή στο _\~/.config/google-chrome_ για ύποπτη δραστηριότητα.
- **VIM**: Εξετάστε το _\~/.viminfo_ για λεπτομέρειες χρήσης, όπως διαδρομές αρχείων στα οποία έγινε πρόσβαση και ιστορικό αναζητήσεων.
- **Open Office**: Ελέγξτε για πρόσφατη πρόσβαση σε έγγραφα που μπορεί να υποδεικνύει παραβιασμένα αρχεία.
- **FTP/SFTP**: Εξετάστε τα αρχεία καταγραφής στα _\~/.ftp_history_ ή _\~/.sftp_history_ για μεταφορές αρχείων που ενδέχεται να μην ήταν εξουσιοδοτημένες.
- **MySQL**: Ερευνήστε το _\~/.mysql_history_ για εκτελεσμένα MySQL queries, τα οποία ενδέχεται να αποκαλύπτουν μη εξουσιοδοτημένη δραστηριότητα σε βάσεις δεδομένων.
- **Less**: Αναλύστε το _\~/.lesshst_ για το ιστορικό χρήσης, συμπεριλαμβανομένων των αρχείων που προβλήθηκαν και των εντολών που εκτελέστηκαν.
- **Git**: Εξετάστε το _\~/.gitconfig_ και το _.git/logs_ των projects για αλλαγές στα repositories.

### Αρχεία καταγραφής USB

Το [**usbrip**](https://github.com/snovvcrash/usbrip) είναι ένα μικρό λογισμικό γραμμένο εξ ολοκλήρου σε Python 3, το οποίο αναλύει αρχεία καταγραφής του Linux (`/var/log/syslog*` ή `/var/log/messages*`, ανάλογα με τη διανομή) για τη δημιουργία πινάκων ιστορικού συμβάντων USB.

Είναι ενδιαφέρον να **γνωρίζετε όλα τα USB που έχουν χρησιμοποιηθεί** και θα είναι ακόμη πιο χρήσιμο αν διαθέτετε μια εξουσιοδοτημένη λίστα USB, ώστε να εντοπίζετε «συμβάντα παραβίασης» (τη χρήση USB που δεν περιλαμβάνονται σε αυτήν τη λίστα).

### Εγκατάσταση
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Παραδείγματα
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Περισσότερα παραδείγματα και πληροφορίες στο github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Έλεγχος λογαριασμών χρηστών και δραστηριοτήτων σύνδεσης

Εξετάστε τα _**/etc/passwd**_, _**/etc/shadow**_ και τα **security logs** για ασυνήθιστα ονόματα ή λογαριασμούς που δημιουργήθηκαν ή χρησιμοποιήθηκαν κοντά σε γνωστά μη εξουσιοδοτημένα συμβάντα. Επίσης, ελέγξτε για πιθανές επιθέσεις sudo brute-force.\
Επιπλέον, ελέγξτε αρχεία όπως τα _**/etc/sudoers**_ και _**/etc/groups**_ για μη αναμενόμενα δικαιώματα που έχουν δοθεί σε χρήστες.\
Τέλος, αναζητήστε λογαριασμούς με **no passwords** ή **easily guessed** passwords.<sup>[[1]](#references)</sup>

## Εξέταση του File System

### Ανάλυση δομών File System σε Malware Investigation

Κατά τη διερεύνηση περιστατικών malware, η δομή του file system αποτελεί κρίσιμη πηγή πληροφοριών, αποκαλύπτοντας τόσο την ακολουθία των συμβάντων όσο και το περιεχόμενο του malware. Ωστόσο, οι malware authors αναπτύσσουν τεχνικές για να δυσχεραίνουν αυτή την ανάλυση, όπως η τροποποίηση των timestamps των αρχείων ή η αποφυγή χρήσης του file system για την αποθήκευση δεδομένων.<sup>[[1]](#references)</sup>

Για την αντιμετώπιση αυτών των anti-forensic μεθόδων, είναι απαραίτητο να:

- **Πραγματοποιήσετε thorough timeline analysis** χρησιμοποιώντας εργαλεία όπως το **Autopsy** για την οπτικοποίηση των timelines των συμβάντων ή το `mactime` του **Sleuth Kit** για λεπτομερή δεδομένα timeline.
- **Διερευνήσετε unexpected scripts** στο $PATH του συστήματος, τα οποία μπορεί να περιλαμβάνουν shell ή PHP scripts που χρησιμοποιούνται από attackers.
- **Εξετάσετε το `/dev` για atypical files**, καθώς παραδοσιακά περιέχει special files, αλλά μπορεί να φιλοξενεί αρχεία που σχετίζονται με malware.
- **Αναζητήσετε hidden files ή directories** με ονόματα όπως ".. " (dot dot space) ή "..^G" (dot dot control-G), τα οποία μπορεί να αποκρύπτουν malicious content.
- **Εντοπίσετε setuid root files** χρησιμοποιώντας την εντολή: `find / -user root -perm -04000 -print` Αυτή εντοπίζει αρχεία με elevated permissions, τα οποία θα μπορούσαν να χρησιμοποιηθούν καταχρηστικά από attackers.
- **Εξετάσετε τα deletion timestamps** στους inode tables για να εντοπίσετε μαζικές διαγραφές αρχείων, οι οποίες ενδέχεται να υποδεικνύουν την παρουσία rootkits ή trojans.
- **Επιθεωρήσετε consecutive inodes** για κοντινά malicious files αφού εντοπίσετε ένα, καθώς μπορεί να έχουν τοποθετηθεί μαζί.
- **Ελέγξετε τους common binary directories** (_/bin_, _/sbin_) για πρόσφατα τροποποιημένα αρχεία, καθώς αυτά μπορεί να έχουν αλλοιωθεί από malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Σημειώστε ότι ένας **attacker** μπορεί να **τροποποιήσει** τον **χρόνο** ώστε τα **αρχεία να φαίνονται** **νόμιμα**, αλλά **δεν μπορεί** να τροποποιήσει το **inode**. Αν διαπιστώσετε ότι ένα **αρχείο** δείχνει πως δημιουργήθηκε και τροποποιήθηκε την **ίδια χρονική στιγμή** με τα υπόλοιπα αρχεία στον ίδιο φάκελο, αλλά το **inode** είναι **απροσδόκητα μεγαλύτερο**, τότε τα **timestamps** αυτού του αρχείου **τροποποιήθηκαν**.

### Γρήγορο triage με επίκεντρο το inode

Αν υποπτεύεστε anti-forensics, εκτελέστε νωρίς αυτούς τους ελέγχους με επίκεντρο το inode:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Όταν ένα ύποπτο inode βρίσκεται σε ένα image/device συστήματος αρχείων EXT, εξετάστε απευθείας τα μεταδεδομένα του inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Χρήσιμα πεδία:
- **Links**: αν είναι `0`, καμία καταχώριση καταλόγου δεν αναφέρεται επί του παρόντος στο inode.
- **dtime**: timestamp διαγραφής που ορίζεται όταν το inode αποσυνδέεται.
- **ctime/mtime**: βοηθούν στη συσχέτιση των αλλαγών στα μεταδεδομένα/στο περιεχόμενο με το χρονολόγιο του περιστατικού.

### Capabilities, xattrs και preload-based userland rootkits

Η σύγχρονη persistence στο Linux συχνά αποφεύγει τα προφανή δυαδικά αρχεία `setuid` και, αντί γι' αυτό, καταχράται τα **file capabilities**, τα **extended attributes** και τον dynamic loader.
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
Δώστε ιδιαίτερη προσοχή σε libraries που αναφέρονται από **writable** paths όπως `/tmp`, `/dev/shm`, `/var/tmp` ή ασυνήθιστες τοποθεσίες κάτω από το `/usr/local/lib`. Ελέγξτε επίσης binaries με capabilities εκτός της κανονικής ιδιοκτησίας πακέτων και συσχετίστε τα με τα αποτελέσματα επαλήθευσης πακέτων (`rpm -Va`, `dpkg --verify`, `debsums`).

## Σύγκριση αρχείων διαφορετικών εκδόσεων filesystem

### Σύνοψη σύγκρισης εκδόσεων filesystem

Για να συγκρίνουμε εκδόσεις filesystem και να εντοπίσουμε αλλαγές, χρησιμοποιούμε απλοποιημένες εντολές `git diff`:<sup>[[3]](#references)</sup>

- **Για να εντοπίσετε νέα αρχεία**, συγκρίνετε δύο directories:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Για τροποποιημένο περιεχόμενο**, παραθέστε τις αλλαγές αγνοώντας συγκεκριμένες γραμμές:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Για τον εντοπισμό διαγραμμένων αρχείων**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- Οι **επιλογές φιλτραρίσματος** (`--diff-filter`) βοηθούν στον περιορισμό των αποτελεσμάτων σε συγκεκριμένες αλλαγές, όπως αρχεία που προστέθηκαν (`A`), διαγράφηκαν (`D`) ή τροποποιήθηκαν (`M`).
- `A`: Αρχεία που προστέθηκαν
- `C`: Αρχεία που αντιγράφηκαν
- `D`: Αρχεία που διαγράφηκαν
- `M`: Τροποποιημένα αρχεία
- `R`: Μετονομασμένα αρχεία
- `T`: Αλλαγές τύπου (π.χ. από αρχείο σε symlink)
- `U`: Αρχεία χωρίς συγχώνευση
- `X`: Άγνωστα αρχεία
- `B`: Κατεστραμμένα αρχεία

## References

- [1] [Οδηγός πεδίου για την εγκληματολογική ανάλυση Malware σε Linux Systems: Οδηγοί πεδίου ψηφιακής εγκληματολογικής ανάλυσης – Κεφάλαιο 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Επεξήγηση των Linux Logs](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Τεκμηρίωση του git diff – επιλογή --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Patching για persistence: Πώς το Linux malware DripDropper κινείται μέσω του cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Forensic Analysis των Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Έλεγχος του system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Πείτε γεια στον Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Επέκταση SQLite FTS5](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
