# Λίστα ελέγχου κλιμάκωσης προνομίων σε Linux

{{#include ../../banners/hacktricks-training.md}}

# Λίστα ελέγχου - Κλιμάκωση προνομίων σε Linux



### **Καλύτερο εργαλείο για την αναζήτηση vectors τοπικής κλιμάκωσης προνομίων σε Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες συστήματος](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Συλλέξτε πληροφορίες για το **OS**
- [ ] Ελέγξτε το [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), υπάρχει κάποιος **εγγράψιμος φάκελος**;
- [ ] Ελέγξτε τις [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), υπάρχει κάποιο ευαίσθητο στοιχείο;
- [ ] Αναζητήστε [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **με scripts** (DirtyCow?)
- [ ] Πριν εκτελέσετε ένα kernel PoC, επαληθεύστε τις **πραγματικές προϋποθέσεις** του και όχι μόνο το `uname -r`: αρχιτεκτονική, απαιτούμενες επιλογές/μονάδες `CONFIG_*`, δημιουργία namespaces και ενεργά mitigations. Για παράδειγμα, ελέγξτε αν είναι διαθέσιμα τα user/network namespaces με `unshare -Urn true`· τα σύγχρονα netfilter exploits ενδέχεται να απαιτούν `CONFIG_USER_NS`, unprivileged user namespaces και `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Ελέγξτε** αν η [**έκδοση sudo** είναι ευάλωτη](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Αποτυχία επαλήθευσης υπογραφής [**Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Εξετάστε [**εσφαλμένες ρυθμίσεις kernel module και φόρτωσης modules**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, επιβολή υπογραφών και `modules_disabled`.
- [ ] Ελέγξτε για [**μονοπάτια κατάχρησης kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), εάν μπορεί να τροποποιηθεί ή να ενεργοποιηθεί το μονοπάτι του helper.
- [ ] Ελέγξτε για [**εγγράψιμα μονοπάτια /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), συμπεριλαμβανομένων εγγράψιμων αρχείων `.ko*` και μεταδεδομένων `modules.*`.
- [ ] Περισσότερη αποτύπωση συστήματος ([ημερομηνία, στατιστικά συστήματος, πληροφορίες CPU, εκτυπωτές](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Καταγράψτε περισσότερες άμυνες](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Καταγράψτε τα προσαρτημένα** drives
- [ ] Υπάρχει **μη προσαρτημένο drive**;
- [ ] Υπάρχουν **διαπιστευτήρια στο fstab**;

### [**Εγκατεστημένο λογισμικό**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Ελέγξτε αν είναι εγκατεστημένο** [**χρήσιμο λογισμικό**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Ελέγξτε αν είναι εγκατεστημένο** [**ευάλωτο λογισμικό**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] Σε Debian/Ubuntu, ελέγξτε αν είναι εγκατεστημένο/ενεργοποιημένο το **needrestart interpreter scanning**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Ευάλωτες εκδόσεις περνούσαν το όριο προνομίων επαναχρησιμοποιώντας ελεγχόμενα από τον attacker `PYTHONPATH`/`RUBYLIB`, κάνοντας race στο `/proc/<pid>/exe` ή σαρώνοντας ελεγχόμενα από τον attacker Perl paths όταν το APT ή το `unattended-upgrades` εκτελούσε το needrestart ως root.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Εκτελείται κάποιο **άγνωστο λογισμικό**;
- [ ] Εκτελείται κάποιο λογισμικό με **περισσότερα προνόμια από όσα θα έπρεπε**;
- [ ] Αναζητήστε **exploits για τις διεργασίες που εκτελούνται** (ειδικά για την έκδοση που εκτελείται).
- [ ] Μπορείτε να **τροποποιήσετε το binary** κάποιας διεργασίας που εκτελείται;
- [ ] **Παρακολουθήστε τις διεργασίες** και ελέγξτε αν εκτελείται συχνά κάποια ενδιαφέρουσα διεργασία.
- [ ] Μπορείτε να **διαβάσετε** τη μνήμη κάποιας ενδιαφέρουσας **διεργασίας** (όπου μπορεί να είναι αποθηκευμένοι κωδικοί πρόσβασης);

### [Προγραμματισμένες εργασίες/Cron;](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Τροποποιείται το [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)από κάποιο cron και μπορείτε να **γράψετε** σε αυτό;
- [ ] Υπάρχει [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)σε κάποια εργασία cron;
- [ ] **Εκτελείται** κάποιο [**τροποποιήσιμο script** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)ή βρίσκεται μέσα σε **τροποποιήσιμο φάκελο**;
- [ ] Εντοπίσατε κάποιο **script** που μπορεί να [**εκτελείται** πολύ **συχνά**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) ή εκτελείται ήδη συχνά; (κάθε 1, 2 ή 5 λεπτά)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Υπάρχει κάποιο **εγγράψιμο αρχείο .service**;
- [ ] Υπάρχει κάποιο **εγγράψιμο binary** που εκτελείται από ένα **service**;
- [ ] Υπάρχει κάποιο εγγράψιμο **helper, config ή environment file που αναφέρεται από root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`); Εξετάστε το συγχωνευμένο unit με `systemctl cat <unit>` και ελέγξτε για [κατάχρηση αρχείων service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Εκτελεί κάποιο workflow με προνόμια κατ' απαίτηση έναν helper μέσα σε εγγράψιμο κατάλογο με χαμηλότερα προνόμια; Ελέγξτε τόσο τον helper όσο και τον γονικό του φάκελο για [εκτέλεση από root διαδρομών τροποποιήσιμων από χρήστες](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries)· οι βραχύβιοι helpers μπορεί να εμφανίζονται μόνο όσο εκτελείται το workflow.
- [ ] Υπάρχει **εγγράψιμος φάκελος στο systemd PATH**;
- [ ] Υπάρχει κάποιο **εγγράψιμο systemd unit drop-in** στο `/etc/systemd/system/<unit>.d/*.conf` που μπορεί να παρακάμψει τα `ExecStart`/`User`;<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Υπάρχει κάποιο **εγγράψιμο timer**;

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Υπάρχει κάποιο **εγγράψιμο αρχείο .socket**;
- [ ] Μπορείτε να **επικοινωνήσετε με κάποιο socket**;
- [ ] Υπάρχουν **HTTP sockets** με ενδιαφέρουσες πληροφορίες;
- [ ] Μπορείτε να αποκτήσετε πρόσβαση σε ένα [**API container-runtime ή node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), όπως `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ή ένα kubelet endpoint; Δοκιμάστε το ακατέργαστο HTTP/gRPC API, ακόμη κι αν απουσιάζει το συνηθισμένο CLI του.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Μπορείτε να **επικοινωνήσετε με κάποιο D-Bus**;

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Αποτυπώστε το δίκτυο για να μάθετε πού βρίσκεστε
- [ ] Υπάρχουν **ανοιχτές θύρες στις οποίες δεν είχατε πρόσβαση πριν** αποκτήσετε shell μέσα στο μηχάνημα;
- [ ] Μπορείτε να **παρακολουθήσετε την κίνηση** με `tcpdump`;

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Γενική **καταγραφή χρηστών/ομάδων**
- [ ] Έχετε **πολύ μεγάλο UID**; Είναι το **μηχάνημα** **ευάλωτο**;
- [ ] Μπορείτε να [**κλιμακώσετε προνόμια χάρη σε κάποια ομάδα**](../user-information/interesting-groups-linux-pe/index.html) στην οποία ανήκετε;
- [ ] Δεδομένα **clipboard**;
- [ ] Πολιτική κωδικών πρόσβασης;
- [ ] Δοκιμάστε να **χρησιμοποιήσετε** κάθε **γνωστό κωδικό πρόσβασης** που έχετε ανακαλύψει προηγουμένως για να συνδεθείτε ως κάθε πιθανός **χρήστης**. Δοκιμάστε επίσης να συνδεθείτε χωρίς κωδικό πρόσβασης.

### [Εγγράψιμο PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Αν έχετε **δικαιώματα εγγραφής σε κάποιον φάκελο του PATH**, ίσως μπορέσετε να κλιμακώσετε προνόμια

### [Εντολές SUDO και SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Μπορείτε να εκτελέσετε **οποιαδήποτε εντολή με sudo**; Μπορείτε να το χρησιμοποιήσετε για να ΔΙΑΒΑΣΕΤΕ, ΓΡΑΨΕΤΕ ή ΕΚΤΕΛΕΣΕΤΕ οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Αν το `sudo -l` επιτρέπει `sudoedit`, ελέγξτε για **sudoedit argument injection** (CVE-2023-22809) μέσω `SUDO_EDITOR`/`VISUAL`/`EDITOR`, ώστε να επεξεργαστείτε αυθαίρετα αρχεία σε ευάλωτες εκδόσεις (`sudo -V` < 1.9.12p2). Παράδειγμα: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Υπάρχει κάποιο **εκμεταλλεύσιμο SUID binary**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Είναι οι εντολές [**sudo** **περιορισμένες** βάσει **path**; μπορείτε να **παρακάμψετε** τους περιορισμούς](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths);
- [ ] [**Εντολή sudo/SUID binary χωρίς καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path);
- [ ] [**SUID binary με καθορισμένο path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path); Παράκαμψη
- [ ] [**Ευπάθεια LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Έλλειψη βιβλιοθήκης .so σε SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) από εγγράψιμο φάκελο;
- [ ] [**SUID RPATH/RUNPATH ή εγγράψιμο path βιβλιοθήκης**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath);
- [ ] Υπάρχουν διαθέσιμα [**SUDO tokens**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens); [**Μπορείτε να δημιουργήσετε ένα SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than);
- [ ] Μπορείτε να [**διαβάσετε ή να τροποποιήσετε αρχεία sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d);
- [ ] Μπορείτε να [**τροποποιήσετε το /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration);
- [ ] Εντολή [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Έχει κάποιο binary **μη αναμενόμενο capability**;

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Έχει κάποιο αρχείο **μη αναμενόμενο ACL**;

### [Ανοιχτές shell sessions](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Προβλέψιμο PRNG του OpenSSL - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Ενδιαφέρουσες τιμές ρυθμίσεων SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Ενδιαφέροντα αρχεία](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Αρχεία profile** - Περιέχουν ευαίσθητα δεδομένα; Μπορούν να γραφτούν για privesc;
- [ ] **Αρχεία passwd/shadow** - Περιέχουν ευαίσθητα δεδομένα; Μπορούν να γραφτούν για privesc;
- [ ] **Ελέγξτε συνήθεις ενδιαφέροντες φακέλους** για ευαίσθητα δεδομένα
- [ ] **Παράξενες τοποθεσίες/αρχεία με ιδιοκτήτη,** στα οποία ίσως έχετε πρόσβαση ή μπορείτε να τροποποιήσετε εκτελέσιμα αρχεία
- [ ] **Τροποποιήθηκαν** τα τελευταία λεπτά
- [ ] **Αρχεία DB Sqlite**
- [ ] **Κρυφά αρχεία**
- [ ] **Scripts/Binaries στο PATH**
- [ ] **Αρχεία Web** (κωδικοί πρόσβασης;)
- [ ] **Αντίγραφα ασφαλείας**;
- [ ] **Γνωστά αρχεία που περιέχουν κωδικούς πρόσβασης**: Χρησιμοποιήστε τα **Linpeas** και **LaZagne**
- [ ] **Γενική αναζήτηση**

### [**Εγγράψιμα αρχεία**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Μπορείτε να **τροποποιήσετε βιβλιοθήκη python** για να εκτελέσετε αυθαίρετες εντολές;
- [ ] Μπορείτε να **τροποποιήσετε αρχεία log**; Exploit **Logtotten**
- [ ] Μπορείτε να **τροποποιήσετε το /etc/sysconfig/network-scripts/**; Exploit Centos/Redhat
- [ ] Μπορείτε να [**γράψετε σε αρχεία ini, int.d, systemd ή rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d);

### [**Άλλα κόλπα**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Μπορείτε να [**καταχραστείτε το NFS για να κλιμακώσετε προνόμια**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation);
- [ ] Χρειάζεται να [**ξεφύγετε από περιοριστικό shell**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells);



## References

- [1] [Συμβουλή ασφαλείας sudo: επεξεργασία αυθαίρετων αρχείων μέσω sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Τεκμηρίωση Oracle Linux: ρύθμιση systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: απαιτήσεις exploit και έρευνα για το CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Συμβουλή ασφαλείας Qualys: LPEs στο needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
