# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες Συστήματος](privilege-escalation/index.html#system-information)

- [ ] Πάρε **πληροφορίες OS**
- [ ] Έλεγξε το [**PATH**](privilege-escalation/index.html#path), υπάρχει **φάκελος εγγράψιμος**;
- [ ] Έλεγξε τις [**env variables**](privilege-escalation/index.html#env-info), υπάρχουν ευαίσθητες πληροφορίες;
- [ ] Ψάξε για [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **χρησιμοποιώντας scripts** (DirtyCow?)
- [ ] **Έλεγξε** αν η έκδοση του [**sudo** είναι ευάλωτη](privilege-escalation/index.html#sudo-version)
- [ ] [Dmesg υπογραφή επαλήθευσης απέτυχε](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Περισσότερη συστηματική καταγραφή ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Καταγραφή πιθανών μηχανισμών άμυνας](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Κατάλογος mounted** drives
- [ ] **Κάποιο unmounted drive;**
- [ ] **Υπάρχουν κωδικοί στο fstab;**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Έλεγξε για** [**χρήσιμο software**](privilege-escalation/index.html#useful-software) **εγκατεστημένο**
- [ ] **Έλεγξε για** [**ευάλωτο software**](privilege-escalation/index.html#vulnerable-software-installed) **εγκατεστημένο**

### [Processes](privilege-escalation/index.html#processes)

- [ ] Τρέχει κάποιο **άγνωστο software**;
- [ ] Τρέχει κάποιο software με **περισσότερα προνόμια από ό,τι πρέπει**;
- [ ] Ψάξε για **exploits των τρεχόντων processes** (ειδικά της έκδοσης που τρέχει).
- [ ] Μπορείς να **τροποποιήσεις το binary** κάποιου τρεχόντος process;
- [ ] **Παρατήρησε processes** και έλεγξε αν κάποιο ενδιαφέρον process τρέχει συχνά.
- [ ] Μπορείς να **διαβάσεις** κάποιο ενδιαφέρον **μνήμης process** (εκεί μπορεί να αποθηκεύονται passwords);

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Η [**PATH** ](privilege-escalation/index.html#cron-path) τροποποιείται από κάποιο cron και μπορείς να **γράψεις** σε αυτήν;
- [ ] Κάποιο cron job χρησιμοποιεί [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection);
- [ ] Κάποιο [**τροποποιήσιμο script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) εκτελείται ή βρίσκεται μέσα σε **τροποποιήσιμο φάκελο**;
- [ ] Έχεις εντοπίσει ότι κάποιο **script** εκτελείται [**πολύ συχνά**](privilege-escalation/index.html#frequent-cron-jobs)? (κάθε 1, 2 ή 5 λεπτά)

### [Services](privilege-escalation/index.html#services)

- [ ] Κάποιο **.service αρχείο εγγράψιμο**;
- [ ] Κάποιο **binary εγγράψιμο** που εκτελείται από **service**;
- [ ] Κάποιος **εγγράψιμος φάκελος στο systemd PATH**;
- [ ] Κάποιο **writable systemd unit drop-in** στο `/etc/systemd/system/<unit>.d/*.conf` που μπορεί να παρακάμψει `ExecStart`/`User`;

### [Timers](privilege-escalation/index.html#timers)

- [ ] Κάποιο **writable timer**;

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Κάποιο **εγγράψιμο .socket αρχείο**;
- [ ] Μπορείς να **επικοινωνήσεις με κάποιο socket**;
- [ ] **HTTP sockets** με ενδιαφέρουσες πληροφορίες;

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Μπορείς να **επικοινωνήσεις με κάποιο D-Bus**;

### [Network](privilege-escalation/index.html#network)

- [ ] Καταγραφή του δικτύου για να ξέρεις που βρίσκεσαι
- [ ] **Άνοιξαν ports που δεν μπορούσες να προσεγγίσεις** πριν αποκτήσεις shell στο μηχάνημα;
- [ ] Μπορείς να **sniffάρεις traffic** χρησιμοποιώντας `tcpdump`;

### [Users](privilege-escalation/index.html#users)

- [ ] Γενική καταγραφή χρηστών/ομάδων
- [ ] Έχεις **πολύ μεγάλο UID**; Είναι το **μηχάνημα** **ευάλωτο**;
- [ ] Μπορείς να [**ανεβάσεις προνόμια χάρη σε ομάδα**](privilege-escalation/interesting-groups-linux-pe/index.html) στην οποία ανήκεις;
- [ ] **Δεδομένα Clipboard;**
- [ ] Πολιτική Κωδικών;
- [ ] Δοκίμασε να **χρησιμοποιήσεις** κάθε **γνωστό password** που ανακάλυψες προηγουμένως για να συνδεθείς **με κάθε** πιθανό **user**. Δοκίμασε να συνδεθείς και χωρίς password.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Αν έχεις **δικαιώματα εγγραφής σε κάποιο φάκελο του PATH** ίσως μπορείς να ανεβάσεις προνόμια

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Μπορείς να εκτελέσεις **οποιαδήποτε εντολή με sudo**; Μπορείς να το χρησιμοποιήσεις για ΝΑ ΔΙΑΒΑΣΕΙΣ, ΝΑ ΓΡΑΨΕΙΣ ή ΝΑ ΕΚΤΕΛΕΣΕΙΣ οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Αν `sudo -l` επιτρέπει `sudoedit`, έλεγξε για **sudoedit argument injection** (CVE-2023-22809) μέσω `SUDO_EDITOR`/`VISUAL`/`EDITOR` για επεξεργασία αυθαίρετων αρχείων σε ευάλωτες εκδόσεις (`sudo -V` < 1.9.12p2). Παράδειγμα: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Υπάρχει κάποιο **εκμεταλλεύσιμο SUID binary**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Είναι οι [**sudo** εντολές **περιορισμένες** από **path**; μπορείς να **παρακάμψεις** τους περιορισμούς](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Έλλειψη .so βιβλιοθήκης σε SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) από έναν εγγράψιμο φάκελο;
- [ ] [**SUDO tokens διαθέσιμα**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Μπορείς να δημιουργήσεις SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Μπορείς να [**διαβάσεις ή τροποποιήσεις τα sudoers αρχεία**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d);
- [ ] Μπορείς να [**τροποποιήσεις /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d);
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) εντολή

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Έχει κάποιο binary **αναπάντεχη capability**;

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Έχει κάποιο αρχείο **αναπάντεχη ACL**;

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Ανάγνωση ευαίσθητων δεδομένων; Εγγραφή για privesc;
- [ ] **passwd/shadow files** - Ανάγνωση ευαίσθητων δεδομένων; Εγγραφή για privesc;
- [ ] **Έλεγξε συνήθως ενδιαφέροντες φακέλους** για ευαίσθητα δεδομένα
- [ ] **Περίεργες τοποθεσίες/αρχεία ιδιοκτησίας,** μπορείς να έχεις πρόσβαση ή να αλλάξεις εκτελέσιμα αρχεία
- [ ] **Τροποποιημένα** τελευταία λεπτά
- [ ] **Sqlite DB αρχεία**
- [ ] **Κρυφά αρχεία**
- [ ] **Script/Binaries στο PATH**
- [ ] **Web αρχεία** (passwords;)
- [ ] **Backups**;
- [ ] **Γνωστά αρχεία που περιέχουν passwords**: Χρησιμοποίησε **Linpeas** και **LaZagne**
- [ ] **Γενική αναζήτηση**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Τροποποιήσεις python library** για εκτέλεση αυθαίρετων εντολών;
- [ ] Μπορείς να **τροποποιήσεις αρχεία logs**; **Logtotten** exploit
- [ ] Μπορείς να **τροποποιήσεις /etc/sysconfig/network-scripts/**; Centos/Redhat exploit
- [ ] Μπορείς να [**γράψεις σε ini, init.d, systemd ή rc.d αρχεία**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Μπορείς να [**κακοποιήσεις NFS για ανύψωση προνομίων**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Χρειάζεται να [**δραπετεύσεις από περιορισμένο shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
