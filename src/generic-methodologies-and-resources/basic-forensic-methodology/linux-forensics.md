# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Αρχική Συλλογή Πληροφοριών

### Βασικές Πληροφορίες

Πρώτα απ’ όλα, συνιστάται να έχετε κάποιο **USB** με **καλά γνωστά binaries και libraries** μέσα σε αυτό (μπορείτε απλώς να πάρετε ubuntu και να αντιγράψετε τους φακέλους _/bin_, _/sbin_, _/lib,_ και _/lib64_), έπειτα κάντε mount το USB, και τροποποιήστε τις env variables ώστε να χρησιμοποιούν αυτά τα binaries:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Μόλις διαμορφώσετε το σύστημα ώστε να χρησιμοποιεί καλά και γνωστά binaries, μπορείτε να ξεκινήσετε να **εξάγετε κάποιες βασικές πληροφορίες**:
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

Καθώς συλλέγετε τις βασικές πληροφορίες, θα πρέπει να ελέγχετε για παράξενα πράγματα όπως:

- Οι διαδικασίες **Root** συνήθως εκτελούνται με χαμηλά PIDS, οπότε αν βρείτε μια διαδικασία root με μεγάλο PID μπορεί να υποψιαστείτε
- Ελέγξτε τα **καταγεγραμμένα logins** χρηστών χωρίς shell μέσα στο `/etc/passwd`
- Ελέγξτε για **password hashes** μέσα στο `/etc/shadow` για χρήστες χωρίς shell

### Memory Dump

Για να αποκτήσετε τη μνήμη του τρέχοντος συστήματος, συνιστάται να χρησιμοποιήσετε το [**LiME**](https://github.com/504ensicsLabs/LiME).\
Για να το **compile**-άρετε, πρέπει να χρησιμοποιήσετε τον **ίδιο kernel** που χρησιμοποιεί το μηχάνημα-θύμα.

> [!TIP]
> Να θυμάστε ότι δεν μπορείτε να εγκαταστήσετε το LiME ή οτιδήποτε άλλο στο μηχάνημα-θύμα, καθώς αυτό θα κάνει αρκετές αλλαγές σε αυτό

Άρα, αν έχετε μια ίδια έκδοση του Ubuntu μπορείτε να χρησιμοποιήσετε `apt-get install lime-forensics-dkms`\
Σε άλλες περιπτώσεις, πρέπει να κατεβάσετε το [**LiME**](https://github.com/504ensicsLabs/LiME) από το github και να το compile-άρετε με τα σωστά kernel headers. Για να **αποκτήσετε τα ακριβή kernel headers** του μηχανήματος-θύματος, μπορείτε απλώς να **αντιγράψετε τον κατάλογο** `/lib/modules/<kernel version>` στο μηχάνημά σας, και μετά να **compile**-άρετε το LiME χρησιμοποιώντας τα:
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

Πρώτα απ’ όλα, θα χρειαστεί να **shut down the system**. Αυτό δεν είναι πάντα επιλογή, καθώς μερικές φορές το system θα είναι production server που η εταιρεία δεν μπορεί να αντέξει οικονομικά να shut down.\
Υπάρχουν **2 τρόποι** για να γίνει shut down το system, ένα **normal shutdown** και ένα **"plug the plug" shutdown**. Ο πρώτος θα επιτρέψει στις **processes** να τερματιστούν όπως συνήθως και στο **filesystem** να **synchronized**, αλλά θα επιτρέψει επίσης στο πιθανό **malware** να **destroy evidence**. Η προσέγγιση "pull the plug" μπορεί να συνεπάγεται **some information loss** (όχι πολύ information πρόκειται να χαθεί, καθώς ήδη πήραμε ένα image of the memory ) και το **malware won't have any opportunity** να κάνει κάτι γι’ αυτό. Επομένως, αν **suspect** ότι μπορεί να υπάρχει **malware**, απλώς εκτέλεσε την **`sync`** **command** στο system και pull the plug.

#### Taking an image of the disk

Είναι σημαντικό να σημειωθεί ότι **before connecting your computer to anything related to the case**, πρέπει να βεβαιωθείς ότι θα γίνει **mounted as read only** ώστε να αποφευχθεί η τροποποίηση οποιασδήποτε πληροφορίας.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Προ-ανάλυση Disk Image

Η απεικόνιση ενός disk image χωρίς άλλα δεδομένα.
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

### Τροποποιημένα Αρχεία Συστήματος

Το Linux προσφέρει εργαλεία για τη διασφάλιση της ακεραιότητας των system components, κάτι κρίσιμο για τον εντοπισμό potentially problematic files.

- **RedHat-based systems**: Χρησιμοποιήστε `rpm -Va` για έναν ολοκληρωμένο έλεγχο.
- **Debian-based systems**: `dpkg --verify` για αρχική επαλήθευση, και στη συνέχεια `debsums | grep -v "OK$"` (μετά την εγκατάσταση του `debsums` με `apt-get install debsums`) για να εντοπίσετε τυχόν προβλήματα.

### Malware/Rootkit Detectors

Διαβάστε την ακόλουθη σελίδα για να μάθετε για εργαλεία που μπορούν να είναι χρήσιμα για τον εντοπισμό malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Αναζήτηση εγκατεστημένων προγραμμάτων

Για να αναζητήσετε αποτελεσματικά εγκατεστημένα προγράμματα τόσο σε Debian όσο και σε RedHat systems, εξετάστε τη χρήση system logs και databases μαζί με χειροκίνητους ελέγχους σε συνηθισμένους καταλόγους.

- Για Debian, ελέγξτε τα _**`/var/lib/dpkg/status`**_ και _**`/var/log/dpkg.log`**_ για να λάβετε λεπτομέρειες σχετικά με τις εγκαταστάσεις πακέτων, χρησιμοποιώντας `grep` για να φιλτράρετε συγκεκριμένες πληροφορίες.
- Οι χρήστες RedHat μπορούν να κάνουν query στη RPM database με `rpm -qa --root=/mntpath/var/lib/rpm` για να εμφανίσουν τα εγκατεστημένα πακέτα.

Για να εντοπίσετε λογισμικό που εγκαταστάθηκε χειροκίνητα ή εκτός αυτών των package managers, εξερευνήστε καταλόγους όπως _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_, και _**`/sbin`**_. Συνδυάστε directory listings με system-specific commands για να εντοπίσετε executables που δεν σχετίζονται με γνωστά πακέτα, βελτιώνοντας την αναζήτησή σας για όλα τα εγκατεστημένα προγράμματα.
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
## Ανάκτηση Deleted Running Binaries

Φαντάσου μια process που εκτελέστηκε από το /tmp/exec και μετά deleted. Είναι πιθανό να την εξαγάγεις
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Επιθεώρηση τοποθεσιών autostart

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
#### Κυνηγήστε: Κατάχρηση Cron/Anacron μέσω 0anacron και ύποπτων stubs
Οι επιτιθέμενοι συχνά επεξεργάζονται το 0anacron stub που υπάρχει κάτω από κάθε κατάλογο /etc/cron.*/ για να εξασφαλίσουν περιοδική εκτέλεση.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Κυνηγήστε: επαναφορά σκλήρυνσης SSH και backdoor shells
Οι αλλαγές στο sshd_config και στα shells των λογαριασμών συστήματος είναι συνηθισμένες μετά από exploitation για τη διατήρηση της πρόσβασης.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Τα Dropbox API beacons συνήθως χρησιμοποιούν api.dropboxapi.com ή content.dropboxapi.com μέσω HTTPS με Authorization: Bearer tokens.
- Hunt σε proxy/Zeek/NetFlow για απρόσμενο Dropbox egress από servers.
- Το Cloudflare Tunnel (`cloudflared`) παρέχει backup C2 μέσω outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

Διαδρομές όπου θα μπορούσε να εγκατασταθεί ένα malware ως service:

- **/etc/inittab**: Καλεί initialization scripts όπως rc.sysinit, κατευθύνοντας περαιτέρω σε startup scripts.
- **/etc/rc.d/** και **/etc/rc.boot/**: Περιέχουν scripts για service startup, το δεύτερο βρίσκεται σε παλαιότερες Linux εκδόσεις.
- **/etc/init.d/**: Χρησιμοποιείται σε ορισμένες Linux εκδόσεις όπως το Debian για αποθήκευση startup scripts.
- Τα Services μπορούν επίσης να ενεργοποιηθούν μέσω **/etc/inetd.conf** ή **/etc/xinetd/**, ανάλογα με τη Linux variant.
- **/etc/systemd/system**: Ένας κατάλογος για system και service manager scripts.
- **/etc/systemd/system/multi-user.target.wants/**: Περιέχει links προς services που πρέπει να ξεκινούν σε ένα multi-user runlevel.
- **/usr/local/etc/rc.d/**: Για custom ή third-party services.
- **\~/.config/autostart/**: Για user-specific automatic startup applications, που μπορεί να είναι κρυψώνα για user-targeted malware.
- **/lib/systemd/system/**: System-wide default unit files που παρέχονται από installed packages.

#### Hunt: systemd timers and transient units

Το Systemd persistence δεν περιορίζεται σε `.service` files. Ερευνήστε `.timer` units, user-level units, και **transient units** που δημιουργούνται στο runtime.
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

Linux kernel modules, often utilized by malware as rootkit components, are loaded at system boot. The directories and files critical for these modules include:

- **/lib/modules/$(uname -r)**: Περιέχει modules για την τρέχουσα έκδοση του kernel.
- **/etc/modprobe.d**: Περιέχει αρχεία ρυθμίσεων για τον έλεγχο του loading των modules.
- **/etc/modprobe** and **/etc/modprobe.conf**: Αρχεία για global ρυθμίσεις modules.

### Other Autostart Locations

Το Linux χρησιμοποιεί διάφορα αρχεία για την αυτόματη εκτέλεση προγραμμάτων κατά το user login, τα οποία ενδέχεται να κρύβουν malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: Εκτελούνται για κάθε user login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: User-specific αρχεία που εκτελούνται κατά το login.
- **/etc/rc.local**: Εκτελείται αφού έχουν ξεκινήσει όλες οι system services, σηματοδοτώντας το τέλος της μετάβασης σε multiuser environment.

## Examine Logs

Τα Linux συστήματα καταγράφουν user activities και system events μέσω διαφόρων log files. Αυτά τα logs είναι καθοριστικά για τον εντοπισμό unauthorized access, malware infections, και άλλων security incidents. Τα βασικά log files περιλαμβάνουν:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): Καταγράφουν system-wide messages and activities.
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): Καταγράφουν authentication attempts, successful and failed logins.
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
- **/var/log/boot.log**: Περιέχει system startup messages.
- **/var/log/maillog** or **/var/log/mail.log**: Καταγράφει email server activities, χρήσιμο για την παρακολούθηση email-related services.
- **/var/log/kern.log**: Αποθηκεύει kernel messages, including errors and warnings.
- **/var/log/dmesg**: Περιέχει device driver messages.
- **/var/log/faillog**: Καταγράφει failed login attempts, βοηθώντας σε investigations για security breaches.
- **/var/log/cron**: Καταγράφει cron job executions.
- **/var/log/daemon.log**: Παρακολουθεί background service activities.
- **/var/log/btmp**: Καταγράφει failed login attempts.
- **/var/log/httpd/**: Περιέχει Apache HTTPD error and access logs.
- **/var/log/mysqld.log** or **/var/log/mysql.log**: Καταγράφει MySQL database activities.
- **/var/log/xferlog**: Καταγράφει FTP file transfers.
- **/var/log/**: Ελέγχετε πάντα για unexpected logs εδώ.

> [!TIP]
> Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. Because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.

### Journald triage (`journalctl`)

On modern Linux hosts, the **systemd journal** is usually the highest-value source for **service execution**, **auth events**, **package operations**, and **kernel/user-space messages**. During live response, try to preserve both the **persistent** journal (`/var/log/journal/`) and the **runtime** journal (`/run/log/journal/`) because short-lived attacker activity may only exist in the latter.
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
Χρήσιμα πεδία journal για triage περιλαμβάνουν `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID`, και `MESSAGE`. Αν το journald είχε ρυθμιστεί χωρίς persistent storage, να περιμένεις μόνο πρόσφατα δεδομένα κάτω από `/run/log/journal/`.

### Audit framework triage (`auditd`)

Αν το `auditd` είναι enabled, προτίμησέ το κάθε φορά που χρειάζεσαι **process attribution** για αλλαγές σε αρχεία, εκτέλεση commands, activity σύνδεσης ή εγκατάσταση packages.
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
Όταν οι κανόνες αναπτύχθηκαν με κλειδιά, pivot από αυτούς αντί να κάνεις grep σε raw logs:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Το Linux διατηρεί ιστορικό εντολών για κάθε χρήστη**, αποθηκευμένο στα:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Επιπλέον, η εντολή `last -Faiwx` παρέχει μια λίστα με logins χρηστών. Έλεγξέ την για άγνωστα ή απρόσμενα logins.

Έλεγξε αρχεία που μπορούν να δώσουν επιπλέον rprivileges:

- Έλεγξε το `/etc/sudoers` για απρόβλεπτα user privileges που μπορεί να έχουν δοθεί.
- Έλεγξε το `/etc/sudoers.d/` για απρόβλεπτα user privileges που μπορεί να έχουν δοθεί.
- Εξέτασε το `/etc/groups` για να εντοπίσεις ασυνήθιστα group memberships ή permissions.
- Εξέτασε το `/etc/passwd` για να εντοπίσεις ασυνήθιστα group memberships ή permissions.

Κάποιες εφαρμογές δημιουργούν επίσης τα δικά τους logs:

- **SSH**: Εξέτασε τα _\~/.ssh/authorized_keys_ και _\~/.ssh/known_hosts_ για μη εξουσιοδοτημένες remote συνδέσεις.
- **Gnome Desktop**: Κοίτα το _\~/.recently-used.xbel_ για πρόσφατα προσπελασμένα αρχεία μέσω εφαρμογών Gnome.
- **Firefox/Chrome**: Έλεγξε το browser history και τα downloads στο _\~/.mozilla/firefox_ ή στο _\~/.config/google-chrome_ για ύποπτη δραστηριότητα.
- **VIM**: Έλεγξε το _\~/.viminfo_ για λεπτομέρειες χρήσης, όπως paths αρχείων που προσπελάστηκαν και search history.
- **Open Office**: Έλεγξε για πρόσφατη πρόσβαση σε έγγραφα που μπορεί να υποδηλώνει compromised αρχεία.
- **FTP/SFTP**: Έλεγξε τα logs στο _\~/.ftp_history_ ή στο _\~/.sftp_history_ για μεταφορές αρχείων που μπορεί να είναι μη εξουσιοδοτημένες.
- **MySQL**: Ερεύνησε το _\~/.mysql_history_ για εκτελεσμένα MySQL queries, που ενδέχεται να αποκαλύπτουν μη εξουσιοδοτημένες database activities.
- **Less**: Ανάλυσε το _\~/.lesshst_ για ιστορικό χρήσης, συμπεριλαμβανομένων των αρχείων που προβλήθηκαν και των εντολών που εκτελέστηκαν.
- **Git**: Εξέτασε το _\~/.gitconfig_ και το project _.git/logs_ για αλλαγές στα repositories.

### USB Logs

Το [**usbrip**](https://github.com/snovvcrash/usbrip) είναι ένα μικρό λογισμικό γραμμένο σε καθαρή Python 3, το οποίο αναλύει Linux log files (`/var/log/syslog*` ή `/var/log/messages*` ανάλογα με τη διανομή) για τη δημιουργία πινάκων ιστορικού USB events.

Είναι χρήσιμο να **γνωρίζεις όλα τα USBs που έχουν χρησιμοποιηθεί** και γίνεται ακόμη πιο χρήσιμο αν έχεις μια εξουσιοδοτημένη λίστα USBs, ώστε να εντοπίζεις "violation events" (τη χρήση USBs που δεν περιλαμβάνονται σε αυτή τη λίστα).

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

## Ελέγξτε User Accounts και Logon Activities

Εξετάστε τα _**/etc/passwd**_, _**/etc/shadow**_ και **security logs** για ασυνήθιστα ονόματα ή accounts που δημιουργήθηκαν και ή χρησιμοποιήθηκαν κοντά σε γνωστά μη εξουσιοδοτημένα events. Επίσης, ελέγξτε για πιθανά sudo brute-force attacks.\
Επιπλέον, ελέγξτε αρχεία όπως _**/etc/sudoers**_ και _**/etc/groups**_ για απροσδόκητα privileges που δόθηκαν σε users.\
Τέλος, αναζητήστε accounts με **no passwords** ή με **easily guessed** passwords.

## Εξετάστε File System

### Ανάλυση File System Structures σε Malware Investigation

Όταν ερευνάτε incidents malware, η δομή του file system είναι μια κρίσιμη πηγή πληροφοριών, αποκαλύπτοντας τόσο τη σειρά των events όσο και το περιεχόμενο του malware. Ωστόσο, οι authors malware αναπτύσσουν techniques για να δυσκολέψουν αυτή την ανάλυση, όπως η τροποποίηση file timestamps ή η αποφυγή του file system για αποθήκευση data.

Για να αντιμετωπίσετε αυτές τις anti-forensic methods, είναι απαραίτητο να:

- **Διεξάγετε μια λεπτομερή timeline analysis** χρησιμοποιώντας tools όπως το **Autopsy** για την οπτικοποίηση event timelines ή το `mactime` του **Sleuth Kit** για αναλυτικά timeline data.
- **Ερευνήσετε απροσδόκητα scripts** στο $PATH του συστήματος, τα οποία μπορεί να περιλαμβάνουν shell ή PHP scripts που χρησιμοποιούνται από attackers.
- **Εξετάσετε το `/dev` για άτυπα files**, καθώς παραδοσιακά περιέχει special files, αλλά μπορεί να φιλοξενεί malware-related files.
- **Αναζητήσετε hidden files ή directories** με ονόματα όπως ".. " (dot dot space) ή "..^G" (dot dot control-G), τα οποία μπορεί να κρύβουν malicious content.
- **Εντοπίστε setuid root files** χρησιμοποιώντας την εντολή: `find / -user root -perm -04000 -print` Αυτό βρίσκει files με elevated permissions, τα οποία μπορούν να abused από attackers.
- **Ελέγξτε deletion timestamps** στους inode tables για να εντοπίσετε μαζικές διαγραφές αρχείων, που ίσως υποδηλώνουν την παρουσία rootkits ή trojans.
- **Επιθεωρήστε διαδοχικούς inodes** για κοντινά malicious files αφού εντοπίσετε ένα, καθώς μπορεί να έχουν τοποθετηθεί μαζί.
- **Ελέγξτε common binary directories** (_/bin_, _/sbin_) για recently modified files, καθώς αυτά μπορεί να έχουν τροποποιηθεί από malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Σημείωσε ότι ένας **attacker** μπορεί να **modify** τον **time** για να κάνει τα **files appear** **legitimate**, αλλά δεν μπορεί να **modify** το **inode**. Αν βρεις ότι ένα **file** δείχνει πως δημιουργήθηκε και τροποποιήθηκε την **same time** με τα υπόλοιπα files στον ίδιο φάκελο, αλλά το **inode** είναι **unexpectedly bigger**, τότε τα **timestamps of that file were modified**.

### Inode-focused quick triage

Αν υποψιάζεσαι anti-forensics, τρέξε αυτά τα inode-focused checks νωρίς:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Όταν ένα ύποπτο inode βρίσκεται σε ένα image/device συστήματος αρχείων EXT, εξέτασε απευθείας τα μεταδεδομένα του inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Χρήσιμα πεδία:
- **Links**: αν `0`, καμία εγγραφή καταλόγου δεν αναφέρεται αυτή τη στιγμή στο inode.
- **dtime**: χρονική σήμανση διαγραφής που ορίζεται όταν το inode αποσυνδέθηκε.
- **ctime/mtime**: βοηθά στη συσχέτιση αλλαγών μεταδεδομένων/περιεχομένου με το χρονολόγιο του περιστατικού.

### Capabilities, xattrs, and preload-based userland rootkits

Η σύγχρονη persistence στο Linux συχνά αποφεύγει τα προφανή `setuid` binaries και αντίθετα καταχράται **file capabilities**, **extended attributes**, και τον dynamic loader.
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
Δώσε ιδιαίτερη προσοχή σε βιβλιοθήκες που αναφέρονται από **writable** διαδρομές όπως `/tmp`, `/dev/shm`, `/var/tmp`, ή ασυνήθιστες τοποθεσίες κάτω από `/usr/local/lib`. Επίσης έλεγξε για binaries με capabilities εκτός της κανονικής ιδιοκτησίας πακέτου και συσχέτισέ τα με τα αποτελέσματα επαλήθευσης πακέτων (`rpm -Va`, `dpkg --verify`, `debsums`).

## Σύγκριση αρχείων διαφορετικών filesystem versions

### Σύνοψη Σύγκρισης Filesystem Version

Για να συγκρίνουμε filesystem versions και να εντοπίσουμε αλλαγές, χρησιμοποιούμε απλοποιημένες εντολές `git diff`:

- **Για να βρεις νέα αρχεία**, σύγκρινε δύο directories:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Για τροποποιημένο περιεχόμενο**, απαρίθμησε τις αλλαγές αγνοώντας συγκεκριμένες γραμμές:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Για την ανίχνευση διαγραμμένων αρχείων**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Οι επιλογές φίλτρου** (`--diff-filter`) βοηθούν να περιορίσεις σε συγκεκριμένες αλλαγές όπως προστιθέμενα (`A`), διαγραμμένα (`D`) ή τροποποιημένα (`M`) αρχεία.
- `A`: Προστιθέμενα αρχεία
- `C`: Αντιγραμμένα αρχεία
- `D`: Διαγραμμένα αρχεία
- `M`: Τροποποιημένα αρχεία
- `R`: Μετονομασμένα αρχεία
- `T`: Αλλαγές τύπου (π.χ. αρχείο σε symlink)
- `U`: Μη συγχωνευμένα αρχεία
- `X`: Άγνωστα αρχεία
- `B`: Κατεστραμμένα αρχεία

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}
