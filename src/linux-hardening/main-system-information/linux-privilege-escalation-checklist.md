# Checklist για Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation



### **Καλύτερο εργαλείο για την αναζήτηση vectors για local privilege escalation σε Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες συστήματος](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Λήψη **πληροφοριών OS**
- [ ] Έλεγχος του [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), υπάρχει **writable folder**;
- [ ] Έλεγχος των [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), υπάρχει κάποια ευαίσθητη λεπτομέρεια;
- [ ] Αναζήτηση για [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **με χρήση scripts** (DirtyCow;)
- [ ] **Έλεγχος** αν η [**sudo version** είναι ευάλωτη](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Αποτυχία επαλήθευσης υπογραφής [**Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Έλεγχος [**kernel module και module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, επιβολή υπογραφών και `modules_disabled`.
- [ ] Έλεγχος των [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), αν το helper path μπορεί να τροποποιηθεί ή να ενεργοποιηθεί.
- [ ] Έλεγχος για [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), συμπεριλαμβανομένων writable αρχείων `.ko*` και metadata `modules.*`.
- [ ] Περισσότερο system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate περισσότερες άμυνες](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **List mounted** drives
- [ ] Υπάρχει **unmounted drive**;
- [ ] Υπάρχουν **creds στο fstab**;

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Έλεγχος για**[ **χρήσιμο software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **εγκατεστημένο**
- [ ] **Έλεγχος για** [**ευάλωτο software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **εγκατεστημένο**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Εκτελείται κάποιο **άγνωστο software**;
- [ ] Εκτελείται κάποιο software με **περισσότερα privileges από όσα θα έπρεπε**;
- [ ] Αναζήτηση για **exploits των processes που εκτελούνται** (ειδικά της version που εκτελείται).
- [ ] Μπορείς να **τροποποιήσεις το binary** κάποιου process που εκτελείται;
- [ ] **Παρακολούθηση processes** και έλεγχος αν κάποιο ενδιαφέρον process εκτελείται συχνά.
- [ ] Μπορείς να **διαβάσεις** κάποια ενδιαφέρουσα **process memory** (όπου μπορεί να είναι αποθηκευμένα passwords);

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Τροποποιείται το [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)από κάποιο cron και μπορείς να κάνεις **write** σε αυτό;
- [ ] Υπάρχει κάποιο [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)σε cron job;
- [ ] Κάποιο [**τροποποιήσιμο script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **εκτελείται** ή βρίσκεται μέσα σε **τροποποιήσιμο folder**;
- [ ] Έχεις εντοπίσει κάποιο **script** που μπορεί να ή που ήδη [**εκτελείται** πολύ **συχνά**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs); (κάθε 1, 2 ή 5 λεπτά)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Υπάρχει κάποιο **writable .service** file;
- [ ] Υπάρχει κάποιο **writable binary** που εκτελείται από κάποιο **service**;
- [ ] Υπάρχει κάποιο **writable folder στο systemd PATH**;
- [ ] Υπάρχει κάποιο **writable systemd unit drop-in** στο `/etc/systemd/system/<unit>.d/*.conf` που μπορεί να παρακάμψει τα `ExecStart`/`User`;

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Υπάρχει κάποιο **writable timer**;

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Υπάρχει κάποιο **writable .socket** file;
- [ ] Μπορείς να **επικοινωνήσεις με οποιοδήποτε socket**;
- [ ] **HTTP sockets** με ενδιαφέρουσες πληροφορίες;

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Μπορείς να **επικοινωνήσεις με οποιοδήποτε D-Bus**;

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerate το network για να γνωρίζεις πού βρίσκεσαι
- [ ] **Open ports στα οποία δεν μπορούσες να έχεις πρόσβαση πριν** αποκτήσεις shell μέσα στο machine;
- [ ] Μπορείς να κάνεις **sniff traffic** χρησιμοποιώντας `tcpdump`;

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeration** generic users/groups
- [ ] Έχεις **πολύ μεγάλο UID**; Είναι το **machine** **ευάλωτο**;
- [ ] Μπορείς να [**κάνεις escalate privileges χάρη σε ένα group**](../user-information/interesting-groups-linux-pe/index.html) στο οποίο ανήκεις;
- [ ] Δεδομένα από το **Clipboard**;
- [ ] Password Policy;
- [ ] Προσπάθησε να **χρησιμοποιήσεις** κάθε **γνωστό password** που έχεις ανακαλύψει προηγουμένως για να κάνεις login **με κάθε** πιθανό **user**. Προσπάθησε επίσης να κάνεις login χωρίς password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Αν έχεις **write privileges σε κάποιο folder του PATH**, ίσως μπορείς να κάνεις escalate privileges

### [SUDO και SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Μπορείς να εκτελέσεις **οποιοδήποτε command με sudo**; Μπορείς να το χρησιμοποιήσεις για READ, WRITE ή EXECUTE οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Αν το `sudo -l` επιτρέπει `sudoedit`, έλεγξε για **sudoedit argument injection** (CVE-2023-22809) μέσω `SUDO_EDITOR`/`VISUAL`/`EDITOR` για επεξεργασία αυθαίρετων αρχείων σε ευάλωτες versions (`sudo -V` < 1.9.12p2). Παράδειγμα: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Υπάρχει κάποιο **exploitable SUID binary**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Τα [**sudo** commands περιορίζονται** από το **path**; μπορείς να **παρακάμψεις τους περιορισμούς**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths);
- [ ] [**Sudo/SUID binary χωρίς καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path);
- [ ] [**SUID binary που καθορίζει path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path); Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Έλλειψη .so library σε SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) από writable folder;
- [ ] [**SUID RPATH/RUNPATH ή writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath);
- [ ] [**SUDO tokens διαθέσιμα**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens); [**Μπορείς να δημιουργήσεις SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than);
- [ ] Μπορείς να [**διαβάσεις ή να τροποποιήσεις sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d);
- [ ] Μπορείς να [**τροποποιήσεις το /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration);
- [ ] Command [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Έχει κάποιο binary κάποια **μη αναμενόμενη capability**;

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Έχει κάποιο file κάποια **μη αναμενόμενη ACL**;

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Ενδιαφέρουσες configuration values του SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Ανάγνωση ευαίσθητων δεδομένων; Write για privesc;
- [ ] **passwd/shadow files** - Ανάγνωση ευαίσθητων δεδομένων; Write για privesc;
- [ ] **Έλεγχος συχνά ενδιαφερόντων folders** για ευαίσθητα δεδομένα
- [ ] **Παράξενα Location/Owned files,** στα οποία μπορεί να έχεις πρόσβαση ή να τροποποιήσεις executable files
- [ ] **Τροποποιημένα** τα τελευταία λεπτά
- [ ] **Sqlite DB files**
- [ ] **Κρυφά files**
- [ ] **Scripts/Binaries στο PATH**
- [ ] **Web files** (passwords;)
- [ ] **Backups**;
- [ ] **Γνωστά files που περιέχουν passwords**: Χρησιμοποίησε τα **Linpeas** και **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Τροποποίηση python library** για εκτέλεση αυθαίρετων commands;
- [ ] Μπορείς να **τροποποιήσεις log files**; **Logtotten** exploit
- [ ] Μπορείς να **τροποποιήσεις το /etc/sysconfig/network-scripts/**; Centos/Redhat exploit
- [ ] Μπορείς να [**γράψεις σε ini, int.d, systemd ή rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d);

### [**Άλλα tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Μπορείς να [**κάνεις abuse το NFS για privilege escalation**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation);
- [ ] Χρειάζεται να [**κάνεις escape από restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells);



## Αναφορές

- [Sudo advisory: επεξεργασία αυθαίρετου file μέσω sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
