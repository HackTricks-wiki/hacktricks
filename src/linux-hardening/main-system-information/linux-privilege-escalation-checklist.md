# Checklist Ανύψωσης Προνομίων σε Linux

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Ανύψωση Προνομίων σε Linux



### **Καλύτερο tool για αναζήτηση vectors τοπικής ανύψωσης προνομίων σε Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες Συστήματος](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Λήψη **πληροφοριών OS**
- [ ] Έλεγχος του [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), υπάρχει **writable folder**;
- [ ] Έλεγχος των [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), υπάρχει κάποια ευαίσθητη λεπτομέρεια;
- [ ] Αναζήτηση για [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **με χρήση scripts** (DirtyCow;)
- [ ] Πριν από την εκτέλεση ενός kernel PoC, επαλήθευση των **πραγματικών prerequisites**, όχι μόνο του `uname -r`: architecture, απαιτούμενες επιλογές/modules `CONFIG_*`, δημιουργία namespaces και ενεργά mitigations. Για παράδειγμα, δοκιμή της διαθεσιμότητας user/network namespace με `unshare -Urn true`; τα σύγχρονα netfilter exploits ενδέχεται να απαιτούν `CONFIG_USER_NS`, unprivileged user namespaces και `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Έλεγχος** αν η [**έκδοση sudo** είναι vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Αποτυχία επαλήθευσης υπογραφής Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Έλεγχος των [**kernel module και module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement και `modules_disabled`.
- [ ] Έλεγχος των [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), αν το helper path μπορεί να τροποποιηθεί ή να ενεργοποιηθεί.
- [ ] Έλεγχος για [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), συμπεριλαμβανομένων των writable αρχείων `.ko*` και των metadata `modules.*`.
- [ ] Περισσότερο system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate περισσότερα defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Λίστα των mounted** drives
- [ ] **Υπάρχει unmounted drive;**
- [ ] **Υπάρχουν creds στο fstab;**

### [**Εγκατεστημένο Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Έλεγχος για**[ **χρήσιμο software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **που είναι εγκατεστημένο**
- [ ] **Έλεγχος για** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **που είναι εγκατεστημένο**
- [ ] Σε Debian/Ubuntu, έλεγχος αν είναι εγκατεστημένο/ενεργοποιημένο το **needrestart interpreter scanning**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Τα vulnerable builds περνούσαν το privilege boundary επαναχρησιμοποιώντας attacker-controlled `PYTHONPATH`/`RUBYLIB`, κάνοντας race στο `/proc/<pid>/exe` ή σαρώνοντας attacker-controlled Perl paths όταν το APT ή το `unattended-upgrades` καλούσε το needrestart ως root.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Εκτελείται κάποιο **άγνωστο software**;
- [ ] Εκτελείται κάποιο software με **περισσότερα privileges από όσα θα έπρεπε**;
- [ ] Αναζήτηση για **exploits running processes** (ιδιαίτερα της έκδοσης που εκτελείται).
- [ ] Μπορείς να **τροποποιήσεις το binary** κάποιου running process;
- [ ] **Παρακολούθηση processes** και έλεγχος αν εκτελείται συχνά κάποιο ενδιαφέρον process.
- [ ] Μπορείς να **διαβάσεις** τη **μνήμη κάποιου ενδιαφέροντος process** (όπου μπορεί να έχουν αποθηκευτεί passwords);

### [Scheduled/Cron jobs;](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Τροποποιείται το [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)από κάποιο cron και μπορείς να κάνεις **write** σε αυτό;
- [ ] Υπάρχει [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)σε cron job;
- [ ] Εκτελείται κάποιο [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)ή βρίσκεται μέσα σε **modifiable folder**;
- [ ] Έχεις εντοπίσει κάποιο **script** που θα μπορούσε να εκτελείται ή εκτελείται [**πολύ **συχνά**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs); (κάθε 1, 2 ή 5 λεπτά)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Υπάρχει **writable .service** file;
- [ ] Υπάρχει **writable binary** που εκτελείται από κάποιο **service**;
- [ ] Υπάρχει writable **helper, config ή environment file που αναφέρεται από root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`); Έλεγχος του merged unit με `systemctl cat <unit>` και review του [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Υπάρχει **writable folder στο systemd PATH**;
- [ ] Υπάρχει **writable systemd unit drop-in** στο `/etc/systemd/system/<unit>.d/*.conf` που μπορεί να κάνει override τα `ExecStart`/`User`;<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Υπάρχει **writable timer**;

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Υπάρχει κάποιο **writable .socket** file;
- [ ] Μπορείς να **επικοινωνήσεις με κάποιο socket**;
- [ ] Υπάρχουν **HTTP sockets** με ενδιαφέρουσες πληροφορίες;
- [ ] Μπορείς να αποκτήσεις πρόσβαση σε [**container-runtime ή node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), όπως `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ή endpoint kubelet; Δοκίμασε το raw HTTP/gRPC API ακόμη και όταν απουσιάζει το συνηθισμένο CLI.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Μπορείς να **επικοινωνήσεις με κάποιο D-Bus**;

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerate το network για να γνωρίζεις πού βρίσκεσαι
- [ ] **Open ports στα οποία δεν είχες πρόσβαση πριν** αποκτήσεις shell μέσα στο machine;
- [ ] Μπορείς να κάνεις **sniff traffic** χρησιμοποιώντας `tcpdump`;

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic **enumeration χρηστών/groups**
- [ ] Έχεις **πολύ μεγάλο UID**; Είναι το **machine** **vulnerable**;
- [ ] Μπορείς να [**κάνεις escalate privileges χάρη σε κάποιο group**](../user-information/interesting-groups-linux-pe/index.html) στο οποίο ανήκεις;
- [ ] Δεδομένα από το **Clipboard**;
- [ ] Password Policy;
- [ ] Προσπάθησε να **χρησιμοποιήσεις** κάθε **γνωστό password** που έχεις ανακαλύψει προηγουμένως για login με **κάθε** πιθανό **user**. Δοκίμασε επίσης login χωρίς password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Αν έχεις **write privileges σε κάποιο folder του PATH**, μπορεί να είσαι σε θέση να κάνεις escalate privileges

### [SUDO και SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Μπορείς να εκτελέσεις **οποιοδήποτε command με sudo**; Μπορείς να το χρησιμοποιήσεις για READ, WRITE ή EXECUTE οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Αν το `sudo -l` επιτρέπει `sudoedit`, έλεγξε για **sudoedit argument injection** (CVE-2023-22809) μέσω `SUDO_EDITOR`/`VISUAL`/`EDITOR` για επεξεργασία arbitrary files σε vulnerable versions (`sudo -V` < 1.9.12p2). Παράδειγμα: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Υπάρχει κάποιο **exploitable SUID binary**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Περιορίζονται τα [**sudo** commands από **path**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths); μπορείς να κάνεις **bypass τους περιορισμούς**;
- [ ] [**Sudo/SUID binary χωρίς καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path);
- [ ] [**SUID binary που καθορίζει path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path); Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Έλλειψη .so library σε SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) από writable folder;
- [ ] [**SUID RPATH/RUNPATH ή writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath);
- [ ] [**Διαθέσιμα SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens); [**Μπορείς να δημιουργήσεις SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than);
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
- [ ] [**Ενδιαφέρουσες τιμές configuration του SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Ενδιαφέροντα Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Ανάγνωση ευαίσθητων δεδομένων; Write για privesc;
- [ ] **passwd/shadow files** - Ανάγνωση ευαίσθητων δεδομένων; Write για privesc;
- [ ] **Έλεγχος συνηθισμένα ενδιαφερόντων folders** για ευαίσθητα δεδομένα
- [ ] **Weird Location/Owned files,** στα οποία μπορεί να έχεις πρόσβαση ή να τροποποιήσεις executable files
- [ ] **Τροποποιημένα** τα τελευταία λεπτά
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries στο PATH**
- [ ] **Web files** (passwords;)
- [ ] **Backups**;
- [ ] **Γνωστά files που περιέχουν passwords**: Χρησιμοποίησε **Linpeas** και **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Τροποποίηση python library** για εκτέλεση arbitrary commands;
- [ ] Μπορείς να **τροποποιήσεις log files**; **Logtotten** exploit
- [ ] Μπορείς να **τροποποιήσεις το /etc/sysconfig/network-scripts/**; Centos/Redhat exploit
- [ ] Μπορείς να [**γράψεις σε ini, int.d, systemd ή rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d);

### [**Άλλα tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Μπορείς να [**κάνεις abuse το NFS για privilege escalation**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation);
- [ ] Χρειάζεται να [**κάνεις escape από restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells);



## References

- [1] [Sudo advisory: επεξεργασία arbitrary file μέσω sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: configuration drop-in του systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: απαιτήσεις exploit και research για το CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs στο needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
