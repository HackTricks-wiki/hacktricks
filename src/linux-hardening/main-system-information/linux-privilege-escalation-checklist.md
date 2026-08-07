# Checklist Κλιμάκωσης Προνομίων σε Linux

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Κλιμάκωση Προνομίων σε Linux



### **Καλύτερο εργαλείο για την αναζήτηση vectors τοπικής κλιμάκωσης προνομίων σε Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες Συστήματος](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Λήψη **πληροφοριών OS**
- [ ] Έλεγχος του [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), υπάρχει **writable folder**;
- [ ] Έλεγχος των [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), υπάρχει κάποιο ευαίσθητο στοιχείο;
- [ ] Αναζήτηση για [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **με χρήση scripts** (DirtyCow;)
- [ ] **Έλεγχος** αν η [**sudo version** είναι ευάλωτη](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Αποτυχία επαλήθευσης υπογραφής του [**Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Έλεγχος [**kernel module και module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, επιβολή υπογραφών και `modules_disabled`.
- [ ] Έλεγχος των [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), αν η διαδρομή helper μπορεί να τροποποιηθεί ή να ενεργοποιηθεί.
- [ ] Έλεγχος των [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), συμπεριλαμβανομένων των writable αρχείων `.ko*` και των metadata `modules.*`.
- [ ] Περισσότερο system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumeration περισσότερων defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Λίστα των mounted** drives
- [ ] **Υπάρχει unmounted drive;**
- [ ] **Υπάρχουν creds στο fstab;**

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Έλεγχος για**[ **χρήσιμο software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **που είναι εγκατεστημένο**
- [ ] **Έλεγχος για** [**ευάλωτο software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **που είναι εγκατεστημένο**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Εκτελείται κάποιο **άγνωστο software**;
- [ ] Εκτελείται κάποιο software με **περισσότερα privileges από όσα θα έπρεπε**;
- [ ] Αναζήτηση για **exploits running processes** (ειδικά για τη version που εκτελείται).
- [ ] Μπορείς να **τροποποιήσεις το binary** κάποιου running process;
- [ ] **Παρακολούθηση processes** και έλεγχος αν κάποιο ενδιαφέρον process εκτελείται συχνά.
- [ ] Μπορείς να **διαβάσεις** τη μνήμη κάποιου ενδιαφέροντος **process** (όπου μπορεί να έχουν αποθηκευτεί passwords);

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Τροποποιείται το [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)από κάποιο cron και μπορείς να κάνεις **write** σε αυτό;
- [ ] Υπάρχει [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)σε cron job;
- [ ] Κάποιο [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink) **εκτελείται** ή βρίσκεται μέσα σε **modifiable folder**;
- [ ] Έχεις εντοπίσει κάποιο **script** που μπορεί να ή που ήδη [**εκτελείται** πολύ **συχνά**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs); (κάθε 1, 2 ή 5 λεπτά)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Υπάρχει κάποιο **writable .service** file;
- [ ] Υπάρχει κάποιο **writable binary** που εκτελείται από **service**;
- [ ] Υπάρχει κάποιο **writable folder στο systemd PATH**;
- [ ] Υπάρχει κάποιο **writable systemd unit drop-in** στο `/etc/systemd/system/<unit>.d/*.conf` που μπορεί να παρακάμψει τα `ExecStart`/`User`;<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Υπάρχει κάποιο **writable timer**;

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Υπάρχει κάποιο **writable .socket** file;
- [ ] Μπορείς να **επικοινωνήσεις με κάποιο socket**;
- [ ] Υπάρχουν **HTTP sockets** με ενδιαφέρουσες πληροφορίες;

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Μπορείς να **επικοινωνήσεις με κάποιο D-Bus**;

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumeration του network για να γνωρίζεις πού βρίσκεσαι
- [ ] **Open ports στα οποία δεν είχες πρόσβαση προηγουμένως**, αφού απέκτησες shell μέσα στο machine;
- [ ] Μπορείς να κάνεις **sniff traffic** με χρήση `tcpdump`;

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic **enumeration users/groups**
- [ ] Έχεις **πολύ μεγάλο UID**; Είναι το **machine** **ευάλωτο**;
- [ ] Μπορείς να [**κλιμακώσεις privileges χάρη σε κάποιο group**](../user-information/interesting-groups-linux-pe/index.html) στο οποίο ανήκεις;
- [ ] Δεδομένα από το **Clipboard**;
- [ ] Password Policy;
- [ ] Προσπάθησε να **χρησιμοποιήσεις** κάθε **γνωστό password** που έχεις ανακαλύψει προηγουμένως για login **με κάθε** πιθανό **user**. Προσπάθησε επίσης να κάνεις login χωρίς password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Αν έχεις **write privileges σε κάποιο folder του PATH**, μπορεί να μπορέσεις να κλιμακώσεις privileges

### [Εντολές SUDO και SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Μπορείς να εκτελέσεις **οποιαδήποτε εντολή με sudo**; Μπορείς να τη χρησιμοποιήσεις για READ, WRITE ή EXECUTE οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Αν το `sudo -l` επιτρέπει `sudoedit`, έλεγξε για **sudoedit argument injection** (CVE-2023-22809) μέσω `SUDO_EDITOR`/`VISUAL`/`EDITOR`, ώστε να επεξεργαστείς arbitrary files σε ευάλωτες versions (`sudo -V` < 1.9.12p2). Παράδειγμα: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Υπάρχει κάποιο **exploitable SUID binary**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Οι [εντολές **sudo** περιορίζονται από **path**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths); μπορείς να **παρακάμψεις τους περιορισμούς**;
- [ ] [**Sudo/SUID binary χωρίς καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path);
- [ ] [**SUID binary που καθορίζει path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path); Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Έλλειψη .so library σε SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) από writable folder;
- [ ] [**SUID RPATH/RUNPATH ή writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath);
- [ ] [**SUDO tokens διαθέσιμα**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens); [**Μπορείς να δημιουργήσεις SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than);
- [ ] Μπορείς να [**διαβάσεις ή να τροποποιήσεις sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d);
- [ ] Μπορείς να [**τροποποιήσεις το /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration);
- [ ] Εντολή [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Έχει κάποιο binary κάποια **μη αναμενόμενη capability**;

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Έχει κάποιο file κάποια **μη αναμενόμενη ACL**;

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Ενδιαφέρουσες SSH configuration values**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Ανάγνωση sensitive data; Εγγραφή για privesc;
- [ ] **passwd/shadow files** - Ανάγνωση sensitive data; Εγγραφή για privesc;
- [ ] **Έλεγχος συχνά ενδιαφερόντων folders** για sensitive data
- [ ] **Weird Location/Owned files,** στα οποία μπορεί να έχεις πρόσβαση ή να μπορείς να τροποποιήσεις executable files
- [ ] **Τροποποιημένα** τα τελευταία λεπτά
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries στο PATH**
- [ ] **Web files** (passwords;)
- [ ] **Backups**;
- [ ] **Γνωστά files που περιέχουν passwords**: Χρήση των **Linpeas** και **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Τροποποίηση python library** για εκτέλεση arbitrary commands;
- [ ] Μπορείς να **τροποποιήσεις log files**; **Logtotten** exploit
- [ ] Μπορείς να **τροποποιήσεις το /etc/sysconfig/network-scripts/**; Centos/Redhat exploit
- [ ] Μπορείς να [**γράψεις σε ini, int.d, systemd ή rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d);

### [**Άλλα tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Μπορείς να [**κάνεις abuse του NFS για κλιμάκωση προνομίων**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation);
- [ ] Χρειάζεται να [**ξεφύγεις από restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells);

## References

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
