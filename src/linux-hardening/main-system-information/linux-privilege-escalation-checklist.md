# Checklist για Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation



### **Καλύτερο tool για αναζήτηση Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες συστήματος](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Λήψη **πληροφοριών OS**
- [ ] Έλεγχος του [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), υπάρχει **writable folder**;
- [ ] Έλεγχος των [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), υπάρχει κάποιο ευαίσθητο detail;
- [ ] Αναζήτηση για [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **με χρήση scripts** (DirtyCow;)
- [ ] Πριν από την εκτέλεση ενός kernel PoC, επαλήθευση των **πραγματικών prerequisites**, όχι μόνο του `uname -r`: architecture, απαιτούμενα `CONFIG_*` options/modules, δημιουργία namespaces και ενεργά mitigations. Για παράδειγμα, έλεγχος της διαθεσιμότητας user/network namespaces με `unshare -Urn true`; τα σύγχρονα netfilter exploits ενδέχεται να απαιτούν `CONFIG_USER_NS`, unprivileged user namespaces και `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Έλεγχος** αν η [**sudo version** είναι vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Αποτυχία επαλήθευσης υπογραφής του [**Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Έλεγχος των [**kernel module και module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement και `modules_disabled`.
- [ ] Έλεγχος των [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), αν το helper path μπορεί να τροποποιηθεί ή να γίνει trigger.
- [ ] Έλεγχος για [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), συμπεριλαμβανομένων των writable `.ko*` files και των `modules.*` metadata.
- [ ] Περισσότερο system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate περισσότερα defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **List mounted** drives
- [ ] Υπάρχει **unmounted drive**;
- [ ] Υπάρχουν **creds στο fstab**;

### [**Installed Software**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Έλεγχος για**[ **χρήσιμο software**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **εγκατεστημένο**
- [ ] **Έλεγχος για** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **εγκατεστημένο**
- [ ] Σε Debian/Ubuntu, έλεγχος αν είναι εγκατεστημένο/ενεργοποιημένο το **needrestart interpreter scanning**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Τα vulnerable builds περνούσαν το privilege boundary επαναχρησιμοποιώντας attacker-controlled `PYTHONPATH`/`RUBYLIB`, κάνοντας race στο `/proc/<pid>/exe` ή σαρώνοντας attacker-controlled Perl paths όταν το APT ή το `unattended-upgrades` εκτελούσε το needrestart ως root.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Εκτελείται κάποιο **unknown software**;
- [ ] Εκτελείται κάποιο software με **περισσότερα privileges από όσα θα έπρεπε**;
- [ ] Αναζήτηση για **exploits των processes που εκτελούνται** (ιδίως για την έκδοση που εκτελείται).
- [ ] Μπορείς να **τροποποιήσεις το binary** κάποιου process που εκτελείται;
- [ ] **Monitor processes** και έλεγχος αν κάποιο ενδιαφέρον process εκτελείται συχνά.
- [ ] Μπορείς να **διαβάσεις** κάποια ενδιαφέρουσα **process memory** (όπου θα μπορούσαν να έχουν αποθηκευτεί passwords);

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Τροποποιείται το [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)από κάποιο cron και μπορείς να κάνεις **write** σε αυτό;
- [ ] Υπάρχει [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)σε cron job;
- [ ] Εκτελείται κάποιο [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)ή βρίσκεται μέσα σε **modifiable folder**;
- [ ] Έχεις εντοπίσει κάποιο **script** που μπορεί να ή ήδη [**εκτελείται** πολύ **συχνά**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs); (κάθε 1, 2 ή 5 λεπτά)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Υπάρχει κάποιο **writable .service** file;
- [ ] Υπάρχει κάποιο **writable binary** που εκτελείται από ένα **service**;
- [ ] Υπάρχει writable **helper, config ή environment file που αναφέρεται από root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`); Επιθεώρηση του merged unit με `systemctl cat <unit>` και έλεγχος για [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Υπάρχει **writable folder στο systemd PATH**;
- [ ] Υπάρχει **writable systemd unit drop-in** στο `/etc/systemd/system/<unit>.d/*.conf` που μπορεί να κάνει override τα `ExecStart`/`User`;<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Υπάρχει **writable timer**;

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Υπάρχει κάποιο **writable .socket** file;
- [ ] Μπορείς να **επικοινωνήσεις με οποιοδήποτε socket**;
- [ ] **HTTP sockets** με ενδιαφέρουσες πληροφορίες;
- [ ] Μπορείς να έχεις πρόσβαση σε [**container-runtime ή node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) όπως `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ή σε kubelet endpoint; Κάνε test στο raw HTTP/gRPC API ακόμη και όταν το συνηθισμένο CLI απουσιάζει.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Μπορείς να **επικοινωνήσεις με οποιοδήποτε D-Bus**;

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerate το network για να γνωρίζεις πού βρίσκεσαι
- [ ] **Open ports στα οποία δεν είχες πρόσβαση πριν** αποκτήσεις shell μέσα στο machine;
- [ ] Μπορείς να κάνεις **sniff traffic** με χρήση `tcpdump`;

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic users/groups **enumeration**
- [ ] Έχεις **πολύ μεγάλο UID**; Είναι το **machine** **vulnerable**;
- [ ] Μπορείς να [**κάνεις escalate privileges χάρη σε ένα group**](../user-information/interesting-groups-linux-pe/index.html) στο οποίο ανήκεις;
- [ ] Δεδομένα από το **Clipboard**;
- [ ] Password Policy;
- [ ] Προσπάθησε να **χρησιμοποιήσεις** κάθε **γνωστό password** που έχεις ανακαλύψει προηγουμένως για να κάνεις login **με κάθε** πιθανό **user**. Προσπάθησε επίσης να κάνεις login χωρίς password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Αν έχεις **write privileges σε κάποιο folder του PATH**, ενδέχεται να μπορέσεις να κάνεις escalate privileges

### [SUDO και SUID commands](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Μπορείς να εκτελέσεις **οποιοδήποτε command με sudo**; Μπορείς να το χρησιμοποιήσεις για READ, WRITE ή EXECUTE οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Αν το `sudo -l` επιτρέπει `sudoedit`, έλεγξε για **sudoedit argument injection** (CVE-2023-22809) μέσω `SUDO_EDITOR`/`VISUAL`/`EDITOR`, ώστε να κάνεις edit arbitrary files σε vulnerable versions (`sudo -V` < 1.9.12p2). Παράδειγμα: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Υπάρχει κάποιο **exploitable SUID binary**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Τα [**sudo** commands **περιορίζονται** από **path**; μπορείς να κάνεις **bypass τους περιορισμούς**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths);
- [ ] [**Sudo/SUID binary χωρίς καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path);
- [ ] [**SUID binary με καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path); Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Έλλειψη .so library σε SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) από writable folder;
- [ ] [**SUID RPATH/RUNPATH ή writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath);
- [ ] [**SUDO tokens διαθέσιμα**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens); [**Μπορείς να δημιουργήσεις SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than);
- [ ] Μπορείς να [**διαβάσεις ή να τροποποιήσεις sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d);
- [ ] Μπορείς να [**τροποποιήσεις το /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration);
- [ ] Command [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Έχει κάποιο binary κάποια **unexpected capability**;

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Έχει κάποιο file κάποιο **unexpected ACL**;

### [Open Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Ενδιαφέρουσες τιμές configuration του SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Ανάγνωση sensitive data; Write για privesc;
- [ ] **passwd/shadow files** - Ανάγνωση sensitive data; Write για privesc;
- [ ] **Έλεγχος κοινών interesting folders** για sensitive data
- [ ] **Weird Location/Owned files,** ενδέχεται να έχεις πρόσβαση ή να μπορείς να τροποποιήσεις executable files
- [ ] **Modified** τα τελευταία λεπτά
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

- [1] [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: CVE-2024-1086 exploit requirements and research](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
