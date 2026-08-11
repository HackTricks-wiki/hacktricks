# Λίστα ελέγχου Linux Privilege Escalation

# Λίστα ελέγχου - Linux Privilege Escalation



### **Καλύτερο εργαλείο για αναζήτηση local privilege escalation vectors στο Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες συστήματος](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Λήψη **πληροφοριών OS**
- [ ] Έλεγχος του [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), υπάρχει **writable folder**;
- [ ] Έλεγχος των [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), υπάρχει κάποια ευαίσθητη πληροφορία;
- [ ] Αναζήτηση για [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **με χρήση scripts** (DirtyCow;)
- [ ] Πριν από την εκτέλεση ενός kernel PoC, επαληθεύστε τα **πραγματικά prerequisites** του και όχι μόνο το `uname -r`: architecture, απαιτούμενες επιλογές/modules `CONFIG_*`, δημιουργία namespaces και ενεργά mitigations. Για παράδειγμα, ελέγξτε τη διαθεσιμότητα user/network namespaces με `unshare -Urn true`· τα σύγχρονα netfilter exploits ενδέχεται να απαιτούν `CONFIG_USER_NS`, unprivileged user namespaces και `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Έλεγχος** αν η [**sudo version** είναι vulnerable](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** η επαλήθευση signature απέτυχε](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Έλεγχος των [**kernel module και module-loading misconfigurations**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, signature enforcement και `modules_disabled`.
- [ ] Έλεγχος των [**kernel.modprobe / modprobe_path abuse paths**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), αν το helper path μπορεί να τροποποιηθεί ή να ενεργοποιηθεί.
- [ ] Έλεγχος των [**writable /lib/modules paths**](kernel-modules-and-modprobe.md#writable-libmodules-review), συμπεριλαμβανομένων των writable αρχείων `.ko*` και των metadata `modules.*`.
- [ ] Περισσότερο system enum ([date, system stats, cpu info, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate περισσότερα defenses](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **List mounted** drives
- [ ] Υπάρχει **unmounted drive**;
- [ ] Υπάρχουν **creds στο fstab**;

### [**Εγκατεστημένο λογισμικό**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Έλεγχος για**[ **χρήσιμο λογισμικό**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **εγκατεστημένο**
- [ ] **Έλεγχος για** [**vulnerable software**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **εγκατεστημένο**
- [ ] Σε Debian/Ubuntu, ελέγξτε αν το **needrestart interpreter scanning** είναι εγκατεστημένο/ενεργοποιημένο: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Vulnerable builds παραβίαζαν το privilege boundary επαναχρησιμοποιώντας attacker-controlled `PYTHONPATH`/`RUBYLIB`, κάνοντας race στο `/proc/<pid>/exe` ή σαρώνοντας attacker-controlled Perl paths όταν το APT ή το `unattended-upgrades` καλούσε το needrestart ως root.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Εκτελείται κάποιο **άγνωστο λογισμικό**;
- [ ] Εκτελείται κάποιο λογισμικό με **περισσότερα privileges από όσα θα έπρεπε**;
- [ ] Αναζήτηση για **exploits των running processes** (ειδικά της έκδοσης που εκτελείται).
- [ ] Μπορείτε να **τροποποιήσετε το binary** κάποιου running process;
- [ ] **Παρακολούθηση των processes** και έλεγχος αν κάποιο ενδιαφέρον process εκτελείται συχνά.
- [ ] Μπορείτε να **διαβάσετε** τη **μνήμη κάποιου ενδιαφέροντος process** (όπου μπορεί να έχουν αποθηκευτεί passwords);

### [Scheduled/Cron jobs;](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Τροποποιείται το [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)από κάποιο cron και μπορείτε να κάνετε **write** σε αυτό;
- [ ] Υπάρχει κάποιο [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)σε cron job;
- [ ] Εκτελείται κάποιο [**modifiable script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)ή βρίσκεται μέσα σε **modifiable folder**;
- [ ] Έχετε εντοπίσει κάποιο **script** που μπορεί να εκτελείται ή εκτελείται [**πολύ **συχνά**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs); (κάθε 1, 2 ή 5 λεπτά)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Υπάρχει κάποιο **writable .service** file;
- [ ] Υπάρχει κάποιο **writable binary** που εκτελείται από **service**;
- [ ] Υπάρχει κάποιο writable **helper, config ή environment file που αναφέρεται από root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`); Επιθεωρήστε το merged unit με `systemctl cat <unit>` και ελέγξτε το [service/socket file abuse](../interesting-files-permissions/write-to-root.md).
- [ ] Υπάρχει κάποιο **writable folder στο systemd PATH**;
- [ ] Υπάρχει κάποιο **writable systemd unit drop-in** στο `/etc/systemd/system/<unit>.d/*.conf` που μπορεί να παρακάμψει τα `ExecStart`/`User`;<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Υπάρχει κάποιο **writable timer**;

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Υπάρχει κάποιο **writable .socket** file;
- [ ] Μπορείτε να **επικοινωνήσετε με κάποιο socket**;
- [ ] Υπάρχουν **HTTP sockets** με ενδιαφέρουσες πληροφορίες;
- [ ] Μπορείτε να αποκτήσετε πρόσβαση σε [**container-runtime ή node-agent API**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), όπως `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ή σε kubelet endpoint; Ελέγξτε το raw HTTP/gRPC API ακόμη και όταν απουσιάζει το συνηθισμένο CLI.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Μπορείτε να **επικοινωνήσετε με κάποιο D-Bus**;

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Κάντε enumerate το network για να γνωρίζετε πού βρίσκεστε
- [ ] Υπάρχουν **open ports στα οποία δεν είχατε πρόσβαση πριν** αποκτήσετε shell μέσα στο machine;
- [ ] Μπορείτε να κάνετε **sniff traffic** χρησιμοποιώντας `tcpdump`;

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Generic users/groups **enumeration**
- [ ] Έχετε **πολύ μεγάλο UID**; Είναι το **machine** **vulnerable**;
- [ ] Μπορείτε να [**κάνετε escalate privileges χάρη σε group**](../user-information/interesting-groups-linux-pe/index.html) στο οποίο ανήκετε;
- [ ] Δεδομένα **Clipboard**;
- [ ] Password Policy;
- [ ] Προσπαθήστε να **χρησιμοποιήσετε** κάθε **γνωστό password** που έχετε ανακαλύψει προηγουμένως για login **με κάθε** πιθανό **user**. Δοκιμάστε επίσης login χωρίς password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Αν έχετε **write privileges σε κάποιο folder του PATH**, ενδέχεται να μπορείτε να κάνετε escalate privileges

### [Εντολές SUDO και SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Μπορείτε να εκτελέσετε **οποιαδήποτε εντολή με sudo**; Μπορείτε να τη χρησιμοποιήσετε για READ, WRITE ή EXECUTE οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Αν το `sudo -l` επιτρέπει `sudoedit`, ελέγξτε για **sudoedit argument injection** (CVE-2023-22809) μέσω των `SUDO_EDITOR`/`VISUAL`/`EDITOR`, ώστε να επεξεργαστείτε arbitrary files σε vulnerable versions (`sudo -V` < 1.9.12p2). Παράδειγμα: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Υπάρχει κάποιο **exploitable SUID binary**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Οι [**sudo** commands περιορίζονται από το **path**; μπορείτε να **παρακάμψετε τους περιορισμούς**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths);
- [ ] [**Sudo/SUID binary χωρίς καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path);
- [ ] [**SUID binary με καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path); Bypass
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Έλλειψη .so library σε SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) από writable folder;
- [ ] [**SUID RPATH/RUNPATH ή writable library path**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath);
- [ ] [**Διαθέσιμα SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens); [**Μπορείτε να δημιουργήσετε SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than);
- [ ] Μπορείτε να [**διαβάσετε ή να τροποποιήσετε sudoers files**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d);
- [ ] Μπορείτε να [**τροποποιήσετε το /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration);
- [ ] Εντολή [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Έχει κάποιο binary κάποια **μη αναμενόμενη capability**;

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Έχει κάποιο file κάποια **μη αναμενόμενη ACL**;

### [Ανοιχτές Shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Ενδιαφέρουσες τιμές configuration του SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Ενδιαφέροντα Files](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Ανάγνωση sensitive data; Write για privesc;
- [ ] **passwd/shadow files** - Ανάγνωση sensitive data; Write για privesc;
- [ ] **Έλεγχος συνηθισμένων ενδιαφερόντων folders** για sensitive data
- [ ] **Weird Location/Owned files,** ενδέχεται να έχετε πρόσβαση ή να μπορείτε να τροποποιήσετε executable files
- [ ] **Modified** τα τελευταία λεπτά
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries στο PATH**
- [ ] **Web files** (passwords;)
- [ ] **Backups**;
- [ ] **Γνωστά files που περιέχουν passwords**: Χρησιμοποιήστε **Linpeas** και **LaZagne**
- [ ] **Generic search**

### [**Writ​able Files**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Τροποποίηση python library** για εκτέλεση arbitrary commands;
- [ ] Μπορείτε να **τροποποιήσετε log files**; **Logtotten** exploit
- [ ] Μπορείτε να **τροποποιήσετε το /etc/sysconfig/network-scripts/**; Centos/Redhat exploit
- [ ] Μπορείτε να [**γράψετε σε ini, int.d, systemd ή rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d);

### [**Άλλα tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Μπορείτε να [**κάνετε abuse το NFS για privilege escalation**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation);
- [ ] Χρειάζεται να [**κάνετε escape από restrictive shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells);



## References

- [1] [Συμβουλευτική Sudo: αυθαίρετη επεξεργασία αρχείων μέσω sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Τεκμηρίωση Oracle Linux: διαμόρφωση systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: απαιτήσεις exploit και έρευνα για το CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Qualys Security Advisory: LPEs στο needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
