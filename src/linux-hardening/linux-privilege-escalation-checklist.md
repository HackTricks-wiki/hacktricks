# Λίστα Ελέγχου - Ανύψωση Δικαιωμάτων Linux

{{#include ../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για αναζήτηση τοπικών διαδρομών ανύψωσης δικαιωμάτων Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Πληροφορίες Συστήματος](privilege-escalation/#system-information)

- [ ] Λάβετε **πληροφορίες OS**
- [ ] Ελέγξτε το [**PATH**](privilege-escalation/#path), υπάρχει **γραμμή που μπορεί να γραφτεί**;
- [ ] Ελέγξτε [**μεταβλητές περιβάλλοντος**](privilege-escalation/#env-info), υπάρχει κάποια ευαίσθητη λεπτομέρεια;
- [ ] Αναζητήστε [**εκμεταλλεύσεις πυρήνα**](privilege-escalation/#kernel-exploits) **χρησιμοποιώντας scripts** (DirtyCow;)
- [ ] **Ελέγξτε** αν η [**έκδοση sudo** είναι ευάλωτη](privilege-escalation/#sudo-version)
- [ ] [**Η υπογραφή Dmesg** απέτυχε](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Περισσότερη αναγνώριση συστήματος ([ημερομηνία, στατιστικά συστήματος, πληροφορίες CPU, εκτυπωτές](privilege-escalation/#more-system-enumeration))
- [ ] [**Αναγνωρίστε περισσότερες άμυνες**](privilege-escalation/#enumerate-possible-defenses)

### [Δίσκοι](privilege-escalation/#drives)

- [ ] **Λίστα των τοποθετημένων** δίσκων
- [ ] **Κάποιος δίσκος που δεν είναι τοποθετημένος;**
- [ ] **Κάποια διαπιστευτήρια στο fstab;**

### [**Εγκατεστημένο Λογισμικό**](privilege-escalation/#installed-software)

- [ ] **Ελέγξτε για** [**χρήσιμο λογισμικό**](privilege-escalation/#useful-software) **που είναι εγκατεστημένο**
- [ ] **Ελέγξτε για** [**ευάλωτο λογισμικό**](privilege-escalation/#vulnerable-software-installed) **που είναι εγκατεστημένο**

### [Διεργασίες](privilege-escalation/#processes)

- [ ] Τρέχει κάποιο **άγνωστο λογισμικό**;
- [ ] Τρέχει κάποιο λογισμικό με **περισσότερα δικαιώματα από όσα θα έπρεπε**;
- [ ] Αναζητήστε **εκμεταλλεύσεις τρεχουσών διεργασιών** (ιδιαίτερα την έκδοση που τρέχει).
- [ ] Μπορείτε να **τροποποιήσετε το δυαδικό** οποιασδήποτε τρέχουσας διεργασίας;
- [ ] **Παρακολουθήστε διεργασίες** και ελέγξτε αν τρέχει κάποια ενδιαφέρουσα διεργασία συχνά.
- [ ] Μπορείτε να **διαβάσετε** κάποια ενδιαφέρουσα **μνήμη διεργασίας** (όπου θα μπορούσαν να αποθηκευτούν κωδικοί);

### [Προγραμματισμένα/Cron jobs;](privilege-escalation/#scheduled-jobs)

- [ ] Ελέγχεται το [**PATH**](privilege-escalation/#cron-path) από κάποιο cron και μπορείτε να **γράψετε** σε αυτό;
- [ ] Κάποιο [**wildcard**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) σε ένα cron job;
- [ ] Κάποιο [**τροποποιήσιμο script**](privilege-escalation/#cron-script-overwriting-and-symlink) εκτελείται ή είναι μέσα σε **τροποποιήσιμο φάκελο**;
- [ ] Έχετε ανιχνεύσει ότι κάποιο **script** θα μπορούσε να είναι ή είναι [**εκτελούμενο** πολύ **συχνά**](privilege-escalation/#frequent-cron-jobs); (κάθε 1, 2 ή 5 λεπτά)

### [Υπηρεσίες](privilege-escalation/#services)

- [ ] Κάποιο **γραμμένο .service** αρχείο;
- [ ] Κάποιο **γραμμένο δυαδικό** που εκτελείται από μια **υπηρεσία**;
- [ ] Κάποιο **γραμμένο φάκελο στο systemd PATH**;

### [Χρονοδιακόπτες](privilege-escalation/#timers)

- [ ] Κάποιο **γραμμένο χρονοδιακόπτη**;

### [Υποδοχές](privilege-escalation/#sockets)

- [ ] Κάποιο **γραμμένο .socket** αρχείο;
- [ ] Μπορείτε να **επικοινωνήσετε με κάποια υποδοχή**;
- [ ] **HTTP sockets** με ενδιαφέρουσες πληροφορίες;

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Μπορείτε να **επικοινωνήσετε με κάποιο D-Bus**;

### [Δίκτυο](privilege-escalation/#network)

- [ ] Αναγνωρίστε το δίκτυο για να ξέρετε πού βρίσκεστε
- [ ] **Ανοιχτές θύρες που δεν μπορούσατε να αποκτήσετε πρόσβαση πριν** αποκτήσετε shell μέσα στη μηχανή;
- [ ] Μπορείτε να **συλλάβετε κίνηση** χρησιμοποιώντας `tcpdump`;

### [Χρήστες](privilege-escalation/#users)

- [ ] Γενική αναγνώριση χρηστών/ομάδων
- [ ] Έχετε **πολύ μεγάλο UID**; Είναι η **μηχανή** **ευάλωτη**;
- [ ] Μπορείτε να [**ανυψώσετε δικαιώματα χάρη σε μια ομάδα**](privilege-escalation/interesting-groups-linux-pe/) στην οποία ανήκετε;
- [ ] **Δεδομένα Πρόσθεσης**;
- [ ] Πολιτική Κωδικών;
- [ ] Προσπαθήστε να **χρησιμοποιήσετε** κάθε **γνωστό κωδικό** που έχετε ανακαλύψει προηγουμένως για να συνδεθείτε **με κάθε** δυνατό **χρήστη**. Προσπαθήστε να συνδεθείτε επίσης χωρίς κωδικό.

### [Γραμμένο PATH](privilege-escalation/#writable-path-abuses)

- [ ] Αν έχετε **δικαιώματα εγγραφής σε κάποιο φάκελο στο PATH** μπορεί να μπορείτε να ανυψώσετε δικαιώματα

### [Εντολές SUDO και SUID](privilege-escalation/#sudo-and-suid)

- [ ] Μπορείτε να εκτελέσετε **οποιαδήποτε εντολή με sudo**; Μπορείτε να το χρησιμοποιήσετε για να ΔΙΑΒΑΣΕΤΕ, ΓΡΑΨΕΤΕ ή ΕΚΤΕΛΕΣΕΤΕ οτιδήποτε ως root; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Υπάρχει κάποιο **εκμεταλλεύσιμο SUID δυαδικό**; ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Είναι οι [**εντολές sudo** **περιορισμένες** από **path**; μπορείτε να **παρακάμψετε** τους περιορισμούς](privilege-escalation/#sudo-execution-bypassing-paths);
- [ ] [**Sudo/SUID δυαδικό χωρίς καθορισμένο path**](privilege-escalation/#sudo-command-suid-binary-without-command-path);
- [ ] [**SUID δυαδικό που καθορίζει path**](privilege-escalation/#suid-binary-with-command-path); Παράκαμψη
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/#ld_preload)
- [ ] [**Έλλειψη .so βιβλιοθήκης σε SUID δυαδικό**](privilege-escalation/#suid-binary-so-injection) από έναν γραμμένο φάκελο;
- [ ] [**Διαθέσιμα SUDO tokens**](privilege-escalation/#reusing-sudo-tokens); [**Μπορείτε να δημιουργήσετε ένα SUDO token**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than);
- [ ] Μπορείτε να [**διαβάσετε ή να τροποποιήσετε τα αρχεία sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d);
- [ ] Μπορείτε να [**τροποποιήσετε το /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d);
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) εντολή

### [Δυνατότητες](privilege-escalation/#capabilities)

- [ ] Έχει κάποιο δυαδικό κάποια **αναμενόμενη δυνατότητα**;

### [ACLs](privilege-escalation/#acls)

- [ ] Έχει κάποιο αρχείο κάποια **αναμενόμενη ACL**;

### [Ανοιχτές συνεδρίες shell](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Ενδιαφέρουσες τιμές ρυθμίσεων SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Ενδιαφέροντα Αρχεία](privilege-escalation/#interesting-files)

- [ ] **Αρχεία προφίλ** - Διαβάστε ευαίσθητα δεδομένα; Γράψτε για privesc;
- [ ] **αρχεία passwd/shadow** - Διαβάστε ευαίσθητα δεδομένα; Γράψτε για privesc;
- [ ] **Ελέγξτε κοινά ενδιαφέροντα φακέλους** για ευαίσθητα δεδομένα
- [ ] **Περίεργη Τοποθεσία/Αρχεία που ανήκουν,** μπορεί να έχετε πρόσβαση ή να τροποποιήσετε εκτελέσιμα αρχεία
- [ ] **Τροποποιημένα** στα τελευταία λεπτά
- [ ] **Sqlite DB αρχεία**
- [ ] **Κρυφά αρχεία**
- [ ] **Script/Δυαδικά στο PATH**
- [ ] **Web αρχεία** (κωδικοί;)
- [ ] **Αντίγραφα ασφαλείας**;
- [ ] **Γνωστά αρχεία που περιέχουν κωδικούς**: Χρησιμοποιήστε **Linpeas** και **LaZagne**
- [ ] **Γενική αναζήτηση**

### [**Γραμμένα Αρχεία**](privilege-escalation/#writable-files)

- [ ] **Τροποποιήστε τη βιβλιοθήκη python** για να εκτελέσετε αυθαίρετες εντολές;
- [ ] Μπορείτε να **τροποποιήσετε αρχεία καταγραφής**; **Logtotten** exploit
- [ ] Μπορείτε να **τροποποιήσετε το /etc/sysconfig/network-scripts/**; Centos/Redhat exploit
- [ ] Μπορείτε να [**γράψετε σε ini, int.d, systemd ή rc.d αρχεία**](privilege-escalation/#init-init-d-systemd-and-rc-d);

### [**Άλλες τεχνικές**](privilege-escalation/#other-tricks)

- [ ] Μπορείτε να [**καταχραστείτε το NFS για να ανυψώσετε δικαιώματα**](privilege-escalation/#nfs-privilege-escalation);
- [ ] Χρειάζεστε να [**ξεφύγετε από ένα περιορισμένο shell**](privilege-escalation/#escaping-from-restricted-shells);

{{#include ../banners/hacktricks-training.md}}
