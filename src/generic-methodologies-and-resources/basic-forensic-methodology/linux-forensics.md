# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Αρχική Συλλογή Πληροφοριών

### Βασικές Πληροφορίες

Πρώτα απ’ όλα, συνιστάται να έχεις ένα **USB** με **καλά γνωστά binaries και libraries πάνω του** (μπορείς απλώς να πάρεις ubuntu και να αντιγράψεις τους φακέλους _/bin_, _/sbin_, _/lib,_ και _/lib64_), μετά να κάνεις mount το USB και να τροποποιήσεις τις env variables ώστε να χρησιμοποιούν αυτά τα binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Μόλις διαμορφώσετε το σύστημα ώστε να χρησιμοποιεί καλά και γνωστά binaries, μπορείτε να αρχίσετε να **εξάγετε μερικές βασικές πληροφορίες**:
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

Κατά τη συλλογή των βασικών πληροφοριών, πρέπει να ελέγχετε για περίεργα πράγματα όπως:

- **Root processes** συνήθως τρέχουν με χαμηλά PIDS, οπότε αν βρείτε ένα root process με μεγάλο PID μπορεί να υποψιαστείτε
- Ελέγξτε τα **registered logins** χρηστών χωρίς shell μέσα στο `/etc/passwd`
- Ελέγξτε για **password hashes** μέσα στο `/etc/shadow` για χρήστες χωρίς shell

### Memory Dump

Για να αποκτήσετε τη μνήμη του running system, προτείνεται να χρησιμοποιήσετε [**LiME**](https://github.com/504ensicsLabs/LiME).\
Για να το **compile**-άρετε, χρειάζεται να χρησιμοποιήσετε τον **ίδιο kernel** που χρησιμοποιεί το victim machine.

> [!TIP]
> Να θυμάστε ότι **δεν μπορείτε να εγκαταστήσετε το LiME ή οτιδήποτε άλλο** στο victim machine, καθώς θα κάνει αρκετές αλλαγές σε αυτό

Άρα, αν έχετε μια ίδια έκδοση του Ubuntu μπορείτε να χρησιμοποιήσετε `apt-get install lime-forensics-dkms`\
Σε άλλες περιπτώσεις, πρέπει να κατεβάσετε το [**LiME**](https://github.com/504ensicsLabs/LiME) από το github και να το compile-άρετε με τα σωστά kernel headers. Για να **αποκτήσετε τα ακριβή kernel headers** του victim machine, μπορείτε απλώς να **αντιγράψετε τον κατάλογο** `/lib/modules/<kernel version>` στο μηχάνημά σας, και έπειτα να **compile**-άρετε το LiME χρησιμοποιώντας τα:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME υποστηρίζει 3 **formats**:

- Raw (κάθε segment concatenated together)
- Padded (same as raw, but with zeroes in right bits)
- Lime (recommended format with metadata

LiME can also be used to **send the dump via network** instead of storing it on the system using something like: `path=tcp:4444`

### Disk Imaging

#### Shutting down

First of all, you will need to **shut down the system**. This isn't always an option as some times system will be a production server that the company cannot afford to shut down.\
There are **2 ways** of shutting down the system, a **normal shutdown** and a **"plug the plug" shutdown**. The first one will allow the **processes to terminate as usual** and the **filesystem** to be **synchronized**, but it will also allow the possible **malware** to **destroy evidence**. The "pull the plug" approach may carry **some information loss** (not much of the info is going to be lost as we already took an image of the memory ) and the **malware won't have any opportunity** to do anything about it. Therefore, if you **suspect** that there may be a **malware**, just execute the **`sync`** **command** on the system and pull the plug.

#### Taking an image of the disk

It's important to note that **before connecting your computer to anything related to the case**, you need to be sure that it's going to be **mounted as read only** to avoid modifying any information.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Προ-ανάλυση Disk Image

Imaging ενός disk image χωρίς επιπλέον δεδομένα.
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
## Αναζήτηση για γνωστό Malware

### Τροποποιημένα System Files

Το Linux προσφέρει εργαλεία για τη διασφάλιση της ακεραιότητας των system components, κάτι κρίσιμο για τον εντοπισμό δυνητικά προβληματικών αρχείων.

- **RedHat-based systems**: Χρησιμοποίησε `rpm -Va` για έναν ολοκληρωμένο έλεγχο.
- **Debian-based systems**: `dpkg --verify` για αρχική επαλήθευση, και στη συνέχεια `debsums | grep -v "OK$"` (αφού εγκαταστήσεις το `debsums` με `apt-get install debsums`) για να εντοπίσεις τυχόν προβλήματα.

### Malware/Rootkit Detectors

Διάβασε την ακόλουθη σελίδα για να μάθεις για εργαλεία που μπορούν να είναι χρήσιμα για την εύρεση malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Αναζήτηση εγκατεστημένων προγραμμάτων

Για να αναζητήσεις αποτελεσματικά εγκατεστημένα προγράμματα τόσο σε Debian όσο και σε RedHat systems, σκέψου να αξιοποιήσεις system logs και databases παράλληλα με χειροκίνητους ελέγχους σε κοινά directories.

- Για Debian, εξέτασε το _**`/var/lib/dpkg/status`**_ και το _**`/var/log/dpkg.log`**_ για να πάρεις λεπτομέρειες σχετικά με package installations, χρησιμοποιώντας `grep` για να φιλτράρεις συγκεκριμένες πληροφορίες.
- Οι χρήστες RedHat μπορούν να κάνουν query στη RPM database με `rpm -qa --root=/mntpath/var/lib/rpm` για να εμφανίσουν τα εγκατεστημένα packages.

Για να εντοπίσεις software που εγκαταστάθηκε χειροκίνητα ή εκτός αυτών των package managers, εξέτασε directories όπως _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, και _**`/sbin`**_. Συνδύασε listings των directories με system-specific commands για να εντοπίσεις executables που δεν σχετίζονται με γνωστά packages, ενισχύοντας την αναζήτησή σου για όλα τα εγκατεστημένα προγράμματα.
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

Φαντάσου μια διεργασία που εκτελέστηκε από /tmp/exec και μετά διαγράφηκε. Είναι δυνατό να την εξαγάγεις
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Τriage Syscall Trace with SQLite and FTS5

When a process is still running or can be re-executed in a lab, **`strace`** can provide a fast behavioral trace without needing kernel modules or full EDR telemetry. For large traces, avoid reading the raw log directly or pasting it into an LLM: store it in a **SQLite** database and query only the minimal subset you need.

> [!WARNING]
> Attaching `strace` changes process timing and may affect race conditions or other fragile bugs. Prefer reproducing on a copy/lab system when possible.

### Capture

For a new process:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Για μια live process:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Χρήσιμες επιλογές:

- `-ff`: ακολούθησε forks/threads και κράτα ξεχωριστά outputs ανά process
- `-ttt`: epoch timestamps για εύκολη συσχέτιση timeline
- `-yy`: resolve file descriptors σε backing paths/sockets όταν είναι δυνατό
- `-s 4096`: απέφυγε το truncation σε μεγάλα path και buffer arguments

### Normalize

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
Αυτό αποφεύγει την προσπάθεια να ισοπεδωθούν ετερογενείς γραμμές syscall σε έναν ενιαίο φαρδύ πίνακα και κρατά τα joins προβλέψιμα κατά το triage.

### Ευρετηρίασε text-heavy arguments με FTS5

Το naive path hunting με `LIKE "%...%"` γίνεται πολύ αργό σε μεγάλα traces. Δημιούργησε ένα FTS5 index για το κείμενο των arguments και κάνε search σε αυτό αντί αυτού:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Παράδειγμα: ανακτήστε τη δραστηριότητα αρχείων κάτω από `/tmp` χωρίς να σαρώνετε κάθε γραμμή:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Ερευνες υψηλού σήματος

- **PATH hijacking / fake sudo**: αναζητήστε εγγραφές και δραστηριότητα `chmod`/`rename` κάτω από `~/.local/bin/`, και μετά συσχετίστε τες με μεταγενέστερο `execve` ονομάτων που μοιάζουν προνομιούχα, όπως `sudo`.
- **TOCTOU σε προσωρινά αρχεία**: pivot στο ίδιο `/tmp/...` path μέσα από `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, και `execve` για να εντοπίσετε κενά check/use.
- **Αιτία crash root cause**: συσχετίστε `mmap` ενός αρχείου με writes ή truncation του ίδιου inode/path από άλλη διεργασία, και μετά εξετάστε τη σειρά signal/exit για `SIGBUS`.
- **Ανάκτηση destination δικτύου**: φιλτράρετε `connect`, `sendto`, `sendmsg`, `recvfrom`, και socket-related arguments για να εξαγάγετε peer IPs και ports.

### LLM-assisted trace analysis

Αν θέλετε να βοηθήσει ένα LLM, εκθέστε ένα **read-only** SQLite handle και δώστε του ολόκληρο το schema. Αφήστε το να εκτελεί raw SQL αντί να τυλίγετε τη βάση πίσω από στενές helper functions. Αυτό συνήθως δουλεύει καλύτερα για joins, temporal correlation, και FTS lookups.

Practical rules:

- Κρατήστε τη βάση read-only, για παράδειγμα με `sqlite3 'file:trace.db?mode=ro'`.
- Δώστε στο model παραδείγματα έγκυρων `JOIN` και `FTS5 MATCH` queries.
- Μην επικολλάτε raw multi-GB `strace` logs στο prompt.
- Κάντε στοχευμένες ερωτήσεις όπως:
- "List persistent files written by this program."
- "Did it create or replace executables in user-controlled PATH directories?"
- "Explain why this trace ends in SIGBUS."

## Ελέγξτε τοποθεσίες Autostart

### Scheduled Tasks
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
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
Οι επιτιθέμενοι συχνά επεξεργάζονται το stub `0anacron` που υπάρχει κάτω από κάθε κατάλογο `/etc/cron.*/` για να εξασφαλίσουν περιοδική εκτέλεση.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Κυνηγήστε: επαναφορά hardening του SSH και backdoor shells
Οι αλλαγές στο sshd_config και στα shells των system accounts είναι συνηθισμένες μετά από exploitation για τη διατήρηση της πρόσβασης.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Τα Dropbox API beacons συνήθως χρησιμοποιούν api.dropboxapi.com ή content.dropboxapi.com μέσω HTTPS με Authorization: Bearer tokens.
- Κάνε hunt σε proxy/Zeek/NetFlow για απρόσμενο Dropbox egress από servers.
- Το Cloudflare Tunnel (`cloudflared`) παρέχει backup C2 μέσω outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Διαδρομές όπου ένα malware θα μπορούσε να εγκατασταθεί ως service:

- **/etc/inittab**: Καλεί initialization scripts όπως rc.sysinit, προωθώντας στη συνέχεια σε startup scripts.
- **/etc/rc.d/** και **/etc/rc.boot/**: Περιέχουν scripts για service startup, με το δεύτερο να βρίσκεται σε παλαιότερες Linux εκδόσεις.
- **/etc/init.d/**: Χρησιμοποιείται σε ορισμένες Linux εκδόσεις όπως το Debian για την αποθήκευση startup scripts.
- Τα services μπορεί επίσης να ενεργοποιηθούν μέσω **/etc/inetd.conf** ή **/etc/xinetd/**, ανάλογα με την έκδοση του Linux.
- **/etc/systemd/system**: Ένας κατάλογος για scripts του system και service manager.
- **/etc/systemd/system/multi-user.target.wants/**: Περιέχει links προς services που πρέπει να ξεκινούν σε multi-user runlevel.
- **/usr/local/etc/rc.d/**: Για custom ή third-party services.
- **\~/.config/autostart/**: Για applications αυτόματης εκκίνησης ανά χρήστη, που μπορεί να είναι σημείο απόκρυψης για malware στοχευμένο σε χρήστες.
- **/lib/systemd/system/**: Default unit files σε όλο το σύστημα που παρέχονται από εγκατεστημένα packages.

#### Hunt: systemd timers and transient units

Το persistence στο Systemd δεν περιορίζεται σε `.service` files. Ελέγξτε `.timer` units, user-level units, και **transient units** που δημιουργούνται στο runtime.
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
Transient units are easy to miss because `/run/systemd/transient/` is **non-persistent**. If you are collecting a live image, grab it before shutdown.

### Kernel Modules

Τα Linux kernel modules, συχνά χρησιμοποιούμενα από malware ως rootkit components, φορτώνονται κατά το system boot. Οι κατάλογοι και τα αρχεία που είναι κρίσιμα για αυτά τα modules περιλαμβάνουν:

- **/lib/modules/$(uname -r)**: Περιέχει modules για την τρέχουσα έκδοση του kernel.
- **/etc/modprobe.d**: Περιέχει configuration files για τον έλεγχο του module loading.
- **/etc/modprobe** και **/etc/modprobe.conf**: Αρχεία για global module settings.

### Other Autostart Locations

Το Linux χρησιμοποιεί διάφορα αρχεία για την αυτόματη εκτέλεση προγραμμάτων κατά το user login, όπου ενδέχεται να κρύβεται malware:

- **/etc/profile.d/**\*, **/etc/profile**, και **/etc/bash.bashrc**: Εκτελούνται για κάθε user login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, και **\~/.config/autostart**: User-specific αρχεία που εκτελούνται κατά το login τους.
- **/etc/rc.local**: Εκτελείται αφού έχουν ξεκινήσει όλες οι system services, σηματοδοτώντας το τέλος της μετάβασης σε multiuser environment.

## Examine Logs

Τα Linux systems καταγράφουν user activities και system events μέσω διαφόρων log files. Αυτά τα logs είναι καθοριστικά για τον εντοπισμό unauthorized access, malware infections, και άλλων security incidents. Τα βασικά log files περιλαμβάνουν:

- **/var/log/syslog** (Debian) ή **/var/log/messages** (RedHat): Καταγράφουν system-wide messages και activities.
- **/var/log/auth.log** (Debian) ή **/var/log/secure** (RedHat): Καταγράφουν authentication attempts, επιτυχημένα και αποτυχημένα logins.
- Χρησιμοποιήστε `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` για να φιλτράρετε σχετικά authentication events.
- **/var/log/boot.log**: Περιέχει system startup messages.
- **/var/log/maillog** ή **/var/log/mail.log**: Καταγράφουν email server activities, χρήσιμα για την παρακολούθηση email-related services.
- **/var/log/kern.log**: Αποθηκεύει kernel messages, συμπεριλαμβανομένων errors και warnings.
- **/var/log/dmesg**: Περιέχει device driver messages.
- **/var/log/faillog**: Καταγράφει αποτυχημένες login attempts, βοηθώντας σε security breach investigations.
- **/var/log/cron**: Καταγράφει cron job executions.
- **/var/log/daemon.log**: Παρακολουθεί background service activities.
- **/var/log/btmp**: Τεκμηριώνει αποτυχημένες login attempts.
- **/var/log/httpd/**: Περιέχει Apache HTTPD error και access logs.
- **/var/log/mysqld.log** ή **/var/log/mysql.log**: Καταγράφουν MySQL database activities.
- **/var/log/xferlog**: Καταγράφει FTP file transfers.
- **/var/log/**: Πάντα ελέγχετε για unexpected logs εδώ.

> [!TIP]
> Τα Linux system logs και audit subsystems μπορεί να είναι απενεργοποιημένα ή να έχουν διαγραφεί σε ένα intrusion ή malware incident. Επειδή τα logs σε Linux systems γενικά περιέχουν μερικές από τις πιο χρήσιμες πληροφορίες για malicious activities, οι intruders συνήθως τα διαγράφουν. Επομένως, όταν εξετάζετε διαθέσιμα log files, είναι σημαντικό να αναζητάτε κενά ή εγγραφές εκτός σειράς που μπορεί να υποδηλώνουν διαγραφή ή tampering.

### Journald triage (`journalctl`)

Σε σύγχρονους Linux hosts, το **systemd journal** είναι συνήθως η πηγή με τη μεγαλύτερη αξία για **service execution**, **auth events**, **package operations**, και **kernel/user-space messages**. Κατά το live response, προσπαθήστε να διατηρήσετε τόσο το **persistent** journal (`/var/log/journal/`) όσο και το **runtime** journal (`/run/log/journal/`) επειδή η βραχύβια attacker activity μπορεί να υπάρχει μόνο στο δεύτερο.
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
Χρήσιμα πεδία του journal για triage περιλαμβάνουν τα `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, και `MESSAGE`. Αν το journald είχε ρυθμιστεί χωρίς persistent storage, να περιμένετε μόνο πρόσφατα δεδομένα κάτω από `/run/log/journal/`.

### Audit framework triage (`auditd`)

Αν το `auditd` είναι ενεργό, προτιμήστε το όποτε χρειάζεστε **process attribution** για αλλαγές σε αρχεία, εκτέλεση εντολών, activity σύνδεσης, ή εγκατάσταση πακέτων.
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
Όταν οι κανόνες αναπτύχθηκαν με keys, κάνε pivot από αυτούς αντί να κάνεις grep σε raw logs:
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

Επιπλέον, η εντολή `last -Faiwx` παρέχει μια λίστα με logins χρηστών. Ελέγξτε την για άγνωστα ή απροσδόκητα logins.

Ελέγξτε αρχεία που μπορεί να δώσουν επιπλέον rprivileges:

- Ελέγξτε το `/etc/sudoers` για απρόσμενα user privileges που μπορεί να έχουν δοθεί.
- Ελέγξτε το `/etc/sudoers.d/` για απρόσμενα user privileges που μπορεί να έχουν δοθεί.
- Εξετάστε το `/etc/groups` για να εντοπίσετε ασυνήθιστα group memberships ή permissions.
- Εξετάστε το `/etc/passwd` για να εντοπίσετε ασυνήθιστα group memberships ή permissions.

Ορισμένες apps alse δημιουργούν τα δικά τους logs:

- **SSH**: Εξετάστε τα _\~/.ssh/authorized_keys_ και _\~/.ssh/known_hosts_ για μη εξουσιοδοτημένες απομακρυσμένες συνδέσεις.
- **Gnome Desktop**: Δείτε το _\~/.recently-used.xbel_ για πρόσφατα προσπελασμένα αρχεία μέσω Gnome applications.
- **Firefox/Chrome**: Ελέγξτε το browser history και τα downloads στα _\~/.mozilla/firefox_ ή _\~/.config/google-chrome_ για ύποπτη δραστηριότητα.
- **VIM**: Ελέγξτε το _\~/.viminfo_ για λεπτομέρειες χρήσης, όπως accessed file paths και search history.
- **Open Office**: Ελέγξτε για πρόσβαση σε πρόσφατα documents που μπορεί να υποδεικνύουν compromised files.
- **FTP/SFTP**: Ελέγξτε τα logs στο _\~/.ftp_history_ ή _\~/.sftp_history_ για file transfers που μπορεί να είναι μη εξουσιοδοτημένα.
- **MySQL**: Εξετάστε το _\~/.mysql_history_ για εκτελεσμένα MySQL queries, που ενδέχεται να αποκαλύπτουν μη εξουσιοδοτημένες database activities.
- **Less**: Αναλύστε το _\~/.lesshst_ για usage history, συμπεριλαμβανομένων viewed files και commands executed.
- **Git**: Εξετάστε το _\~/.gitconfig_ και το project _.git/logs_ για αλλαγές στα repositories.

### USB Logs

Το [**usbrip**](https://github.com/snovvcrash/usbrip) είναι ένα μικρό software γραμμένο σε pure Python 3 που αναλύει Linux log files (`/var/log/syslog*` ή `/var/log/messages*` ανάλογα με το distro) για τη δημιουργία πινάκων ιστορικού USB events.

Είναι ενδιαφέρον να **γνωρίζετε όλα τα USBs που έχουν χρησιμοποιηθεί** και θα είναι πιο χρήσιμο αν έχετε μια authorized list of USBs για να βρείτε "violation events" (τη χρήση USBs που δεν ανήκουν σε αυτή τη λίστα).

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Ανασκόπηση Λογαριασμών Χρηστών και Δραστηριοτήτων Σύνδεσης

Εξέτασε τα _**/etc/passwd**_, _**/etc/shadow**_ και τα **security logs** για ασυνήθιστα ονόματα ή λογαριασμούς που δημιουργήθηκαν και ή χρησιμοποιήθηκαν σε κοντινή χρονική απόσταση από γνωστά μη εξουσιοδοτημένα γεγονότα. Επίσης, έλεγξε για πιθανά sudo brute-force attacks.\
Επιπλέον, έλεγξε αρχεία όπως τα _**/etc/sudoers**_ και _**/etc/groups**_ για απροσδόκητα προνόμια που δόθηκαν σε χρήστες.\
Τέλος, αναζήτησε λογαριασμούς με **χωρίς κωδικούς πρόσβασης** ή με **εύκολα μαντευόμενους** κωδικούς πρόσβασης.

## Εξέταση του File System

### Ανάλυση Δομών File System σε Έρευνα Malware

Όταν διερευνώνται περιστατικά malware, η δομή του file system αποτελεί κρίσιμη πηγή πληροφοριών, αποκαλύπτοντας τόσο τη σειρά των γεγονότων όσο και το περιεχόμενο του malware. Ωστόσο, οι δημιουργοί malware αναπτύσσουν τεχνικές για να δυσχεράνουν αυτή την ανάλυση, όπως η τροποποίηση των file timestamps ή η αποφυγή του file system για αποθήκευση δεδομένων.

Για να αντιμετωπιστούν αυτές οι anti-forensic μέθοδοι, είναι απαραίτητο να:

- **Διεξάγεις λεπτομερή ανάλυση timeline** χρησιμοποιώντας εργαλεία όπως το **Autopsy** για οπτικοποίηση των event timelines ή το `mactime` του **Sleuth Kit** για λεπτομερή δεδομένα timeline.
- **Ερευνήσεις απροσδόκητα scripts** στο $PATH του συστήματος, τα οποία μπορεί να περιλαμβάνουν shell ή PHP scripts που χρησιμοποιούνται από attackers.
- **Εξετάσεις το `/dev` για άτυπα αρχεία**, καθώς παραδοσιακά περιέχει ειδικά αρχεία, αλλά μπορεί να φιλοξενεί αρχεία σχετιζόμενα με malware.
- **Αναζητήσεις κρυφά αρχεία ή directories** με ονόματα όπως ".. " (dot dot space) ή "..^G" (dot dot control-G), τα οποία μπορεί να αποκρύπτουν κακόβουλο περιεχόμενο.
- **Εντοπίσεις setuid root files** χρησιμοποιώντας την εντολή: `find / -user root -perm -04000 -print` Αυτό βρίσκει αρχεία με αυξημένα permissions, τα οποία θα μπορούσαν να αξιοποιηθούν από attackers.
- **Ελέγξεις timestamps διαγραφής** σε inode tables για να εντοπίσεις μαζικές διαγραφές αρχείων, που πιθανώς υποδηλώνουν την παρουσία rootkits ή trojans.
- **Επιθεωρήσεις διαδοχικά inodes** για κοντινά κακόβουλα αρχεία αφού εντοπίσεις ένα, καθώς μπορεί να έχουν τοποθετηθεί μαζί.
- **Ελέγξεις συνηθισμένα binary directories** (_/bin_, _/sbin_) για αρχεία που τροποποιήθηκαν πρόσφατα, καθώς αυτά μπορεί να έχουν αλλοιωθεί από malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Σημείωσε ότι ένας **attacker** μπορεί να **modify** τον **time** ώστε τα **files appear** **legitimate**, αλλά δεν μπορεί να **modify** το **inode**. Αν διαπιστώσεις ότι ένα **file** δείχνει πως δημιουργήθηκε και τροποποιήθηκε την **same time** με τα υπόλοιπα files στον ίδιο φάκελο, αλλά το **inode** είναι **unexpectedly bigger**, τότε τα **timestamps of that file were modified**.

### Inode-focused quick triage

If you suspect anti-forensics, run these inode-focused checks early:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Όταν ένα ύποπτο inode βρίσκεται σε image/device συστήματος αρχείων EXT, εξέτασε απευθείας τα metadata του inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Χρήσιμα πεδία:
- **Links**: αν είναι `0`, καμία εγγραφή directory δεν αναφέρεται αυτή τη στιγμή στο inode.
- **dtime**: timestamp διαγραφής που ορίζεται όταν το inode αποσυνδέθηκε.
- **ctime/mtime**: βοηθά στη συσχέτιση αλλαγών σε metadata/content με το timeline του incident.

### Capabilities, xattrs, and preload-based userland rootkits

Η σύγχρονη Linux persistence συχνά αποφεύγει τα προφανή **setuid** binaries και αντίθετα καταχράται τα **file capabilities**, τα **extended attributes** και τον dynamic loader.
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
Δώσε ιδιαίτερη προσοχή σε βιβλιοθήκες που αναφέρονται από **writable** διαδρομές όπως `/tmp`, `/dev/shm`, `/var/tmp`, ή περίεργες τοποθεσίες κάτω από `/usr/local/lib`. Επίσης έλεγξε για capability-bearing binaries έξω από τη συνηθισμένη ιδιοκτησία των πακέτων και συσχέτισέ τα με τα αποτελέσματα επαλήθευσης πακέτων (`rpm -Va`, `dpkg --verify`, `debsums`).

## Σύγκριση αρχείων διαφορετικών εκδόσεων filesystem

### Σύνοψη σύγκρισης εκδόσεων filesystem

Για να συγκρίνουμε εκδόσεις filesystem και να εντοπίσουμε αλλαγές, χρησιμοποιούμε απλοποιημένες εντολές `git diff`:

- **Για να βρεις νέα αρχεία**, σύγκρινε δύο καταλόγους:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Για το τροποποιημένο περιεχόμενο**, απαριθμήστε τις αλλαγές αγνοώντας συγκεκριμένες γραμμές:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Για να εντοπίσετε διαγραμμένα αρχεία**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) βοηθούν να περιορίσεις σε συγκεκριμένες αλλαγές όπως προστιθέμενα (`A`), διαγραμμένα (`D`) ή τροποποιημένα (`M`) αρχεία.
- `A`: Προστιθέμενα αρχεία
- `C`: Αντιγραμμένα αρχεία
- `D`: Διαγραμμένα αρχεία
- `M`: Τροποποιημένα αρχεία
- `R`: Μετονομασμένα αρχεία
- `T`: Αλλαγές τύπου (π.χ. αρχείο σε symlink)
- `U`: Unmerged αρχεία
- `X`: Άγνωστα αρχεία
- `B`: Broken αρχεία

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
