# Λίστα Ελέγχου - Ανύψωση Δικαιωμάτων Linux

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για αναζήτηση τοπικών διαδρομών ανύψωσης δικαιωμάτων Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες Συστήματος](privilege-escalation/index.html#system-information)

- [ ] Λάβετε **πληροφορίες OS**
- [ ] Ελέγξτε το [**PATH**](privilege-escalation/index.html#path), υπάρχει **γραμμή που μπορεί να γραφτεί**;
- [ ] Ελέγξτε [**μεταβλητές περιβάλλοντος**](privilege-escalation/index.html#env-info), υπάρχει κάποια ευαίσθητη λεπτομέρεια;
- [ ] Αναζητήστε [**εκμεταλλεύσεις πυρήνα**](privilege-escalation/index.html#kernel-exploits) **χρησιμοποιώντας σενάρια** (DirtyCow;)
- [ ] **Ελέγξτε** αν η [**έκδοση sudo** είναι ευάλωτη](privilege-escalation/index.html#sudo-version)
- [ ] [**Η επαλήθευση υπογραφής Dmesg** απέτυχε](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Περισσότερη αναγνώριση συστήματος ([ημερομηνία, στατιστικά συστήματος, πληροφορίες CPU, εκτυπωτές](privilege-escalation/index.html#more-system-enumeration))
- [ ] [**Αναγνωρίστε περισσότερες άμυνες**](privilege-escalation/index.html#enumerate-possible-defenses)

### [Δίσκοι](privilege-escalation/index.html#drives)

- [ ] **Λίστα των προσαρτημένων** δίσκων
- [ ] **Κάποιος μη προσαρτημένος δίσκος;**
- [ ] **Κάποια διαπιστευτήρια στο fstab;**

### [**Εγκατεστημένο Λογισμικό**](privilege-escalation/index.html#installed-software)

- [ ] **Ελέγξτε για** [**χρήσιμο λογισμικό**](privilege-escalation/index.html#useful-software) **που είναι εγκατεστημένο**
- [ ] **Ελέγξτε για** [**ευάλωτο λογισμικό**](privilege-escalation/index.html#vulnerable-software-installed) **που είναι εγκατεστημένο**

### [Διεργασίες](privilege-escalation/index.html#processes)

- [ ] Τρέχει κάποιο **άγνωστο λογισμικό**;
- [ ] Τρέχει κάποιο λογισμικό με **περισσότερα δικαιώματα από όσα θα έπρεπε**;
- [ ] Αναζητήστε **εκμεταλλεύσεις τρεχουσών διεργασιών** (ιδιαίτερα την έκδοση που τρέχει).
- [ ] Μπορείτε να **τροποποιήσετε το δυαδικό** οποιασδήποτε τρέχουσας διεργασίας;
- [ ] **Παρακολουθήστε διεργασίες** και ελέγξτε αν τρέχει κάποια ενδιαφέρουσα διεργασία συχνά.
- [ ] Μπορείτε να **διαβάσετε** κάποια ενδιαφέρουσα **μνήμη διεργασίας** (όπου θα μπορούσαν να αποθηκευτούν κωδικοί);

### [Προγραμματισμένα/Δουλειές Cron;](privilege-escalation/index.html#scheduled-jobs)

- [ ] Ελέγχεται το [**PATH**](privilege-escalation/index.html#cron-path) από κάποιο cron και μπορείτε να **γράψετε** σε αυτό;
- [ ] Κάποιο [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) σε μια εργασία cron;
- [ ] Κάποιο [**τροποποιήσιμο σενάριο**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) εκτελείται ή είναι μέσα σε **τροποποιήσιμο φάκελο**;
- [ ] Έχετε ανιχνεύσει ότι κάποιο **σενάριο** θα μπορούσε να είναι ή είναι [**εκτελούμενο** πολύ **συχνά**](privilege-escalation/index.html#frequent-cron-jobs); (κάθε 1, 2 ή 5 λεπτά)

### [Υπηρεσίες](privilege-escalation/index.html#services)

- [ ] Κάποιο **γραμμένο αρχείο .service**;
- [ ] Κάποιο **γραμμένο δυαδικό** που εκτελείται από μια **υπηρεσία**;
- [ ] Κάποιος **γραμμένος φάκελος στο PATH του systemd**;

### [Χρονοδιακόπτες](privilege-escalation/index.html#timers)

- [ ] Κάποιος **γραμμένος χρονοδιακόπτης**;

### [Υποδοχές](privilege-escalation/index.html#sockets)

- [ ] Κάποιο **γραμμένο αρχείο .socket**;
- [ ] Μπορείτε να **επικοινωνήσετε με κάποια υποδοχή**;
- [ ] **HTTP sockets** με ενδιαφέρουσες πληροφορίες;

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Μπορείτε να **επικοινωνήσετε με κάποιο D-Bus**;

### [Δίκτυο](privilege-escalation/index.html#network)

- [ ] Αναγνωρίστε το δίκτυο για να ξέρετε πού βρίσκεστε
- [ ] **Ανοιχτές θύρες που δεν μπορούσατε να αποκτήσετε πρόσβαση πριν** αποκτήσετε ένα shell μέσα στη μηχανή;
- [ ] Μπορείτε να **συλλάβετε την κίνηση** χρησιμοποιώντας `tcpdump`;

### [Χρήστες](privilege-escalation/index.html#users)

- [ ] Γενική **αναγνώριση χρηστών/ομάδων**
- [ ] Έχετε **πολύ μεγάλο UID**; Είναι η **μηχανή** **ευάλωτη**;
- [ ] Μπορείτε να [**ανυψώσετε δικαιώματα χάρη σε μια ομάδα**](privilege-escalation/interesting-groups-linux-pe/index.html) στην οποία ανήκετε;
- [ ] Δεδομένα **Clipboard**;
- [ ] Πολιτική Κωδικών;
- [ ] Δοκιμάστε να **χρησιμοποιήσετε** κάθε **γνωστό κωδικό** που έχετε ανακαλύψει προηγουμένως για να συνδεθείτε **με κάθε** δυνατό **χρήστη**. Δοκιμάστε να συνδεθείτε επίσης χωρίς κωδικό.

### [Γραμμένο PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Αν έχετε **δικαιώματα εγγραφής σε κάποιο φάκελο στο PATH** μπορεί να μπορείτε να ανυψώσετε δικαιώματα

### [Εντολές SUDO και SUID](privilege-escalation/index.html#sudo-and-suid)

- [ ] Μπορείτε να εκτελέσετε **οποιαδήποτε εντολή με sudo**; Μπορείτε να το χρησιμοποιήσετε για να ΔΙΑΒΑΣΕΤΕ, ΓΡΑΨΕΤΕ ή ΕΚΤΕΛΕΣΕΤΕ οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Υπάρχει κάποιο **εκμεταλλεύσιμο SUID δυαδικό**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Είναι οι [**εντολές sudo** **περιορισμένες** από **path**; μπορείτε να **παρακάμψετε** τους περιορισμούς](privilege-escalation/index.html#sudo-execution-bypassing-paths);
- [ ] [**Sudo/SUID δυαδικό χωρίς καθορισμένο path**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path);
- [ ] [**SUID δυαδικό που καθορίζει path**](privilege-escalation/index.html#suid-binary-with-command-path); Παράκαμψη
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Έλλειψη .so βιβλιοθήκης σε SUID δυαδικό**](privilege-escalation/index.html#suid-binary-so-injection) από έναν γραμμένο φάκελο;
- [ ] [**Διαθέσιμα SUDO tokens**](privilege-escalation/index.html#reusing-sudo-tokens); [**Μπορείτε να δημιουργήσετε ένα SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than);
- [ ] Μπορείτε να [**διαβάσετε ή να τροποποιήσετε τα αρχεία sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d);
- [ ] Μπορείτε να [**τροποποιήσετε το /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d);
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) εντολή

### [Δυνατότητες](privilege-escalation/index.html#capabilities)

- [ ] Έχει κάποιο δυαδικό κάποια **αναμενόμενη δυνατότητα**;

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Έχει κάποιο αρχείο κάποια **αναμενόμενη ACL**;

### [Ανοιχτές συνεδρίες Shell](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Ενδιαφέροντα τιμές ρυθμίσεων SSH**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Ενδιαφέροντα Αρχεία](privilege-escalation/index.html#interesting-files)

- [ ] **Αρχεία προφίλ** - Διαβάστε ευαίσθητα δεδομένα; Γράψτε για privesc;
- [ ] **αρχεία passwd/shadow** - Διαβάστε ευαίσθητα δεδομένα; Γράψτε για privesc;
- [ ] **Ελέγξτε κοινά ενδιαφέροντα φακέλους** για ευαίσθητα δεδομένα
- [ ] **Περίεργη τοποθεσία/Αρχεία που ανήκουν,** μπορεί να έχετε πρόσβαση ή να τροποποιήσετε εκτελέσιμα αρχεία
- [ ] **Τροποποιημένα** στα τελευταία λεπτά
- [ ] **Αρχεία Sqlite DB**
- [ ] **Κρυφά αρχεία**
- [ ] **Σενάρια/Δυαδικά στο PATH**
- [ ] **Αρχεία Web** (κωδικοί;)
- [ ] **Αντίγραφα ασφαλείας**;
- [ ] **Γνωστά αρχεία που περιέχουν κωδικούς**: Χρησιμοποιήστε **Linpeas** και **LaZagne**
- [ ] **Γενική αναζήτηση**

### [**Γραμμένα Αρχεία**](privilege-escalation/index.html#writable-files)

- [ ] **Τροποποιήστε τη βιβλιοθήκη python** για να εκτελέσετε αυθαίρετες εντολές;
- [ ] Μπορείτε να **τροποποιήσετε αρχεία καταγραφής**; **Logtotten** εκμετάλλευση
- [ ] Μπορείτε να **τροποποιήσετε το /etc/sysconfig/network-scripts/**; Εκμετάλλευση Centos/Redhat
- [ ] Μπορείτε να [**γράψετε σε αρχεία ini, int.d, systemd ή rc.d**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d);

### [**Άλλες τεχνικές**](privilege-escalation/index.html#other-tricks)

- [ ] Μπορείτε να [**καταχραστείτε το NFS για να ανυψώσετε δικαιώματα**](privilege-escalation/index.html#nfs-privilege-escalation);
- [ ] Χρειάζεστε να [**ξεφύγετε από ένα περιορισμένο shell**](privilege-escalation/index.html#escaping-from-restricted-shells);

{{#include ../banners/hacktricks-training.md}}
