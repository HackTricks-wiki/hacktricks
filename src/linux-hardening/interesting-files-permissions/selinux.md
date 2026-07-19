# SELinux

{{#include ../../banners/hacktricks-training.md}}

Το SELinux είναι ένα σύστημα **Mandatory Access Control (MAC) βασισμένο σε labels**. Στην πράξη, αυτό σημαίνει ότι ακόμη και αν τα δικαιώματα DAC, οι ομάδες ή οι δυνατότητες Linux φαίνονται επαρκή για μια ενέργεια, ο kernel μπορεί και πάλι να την απορρίψει, επειδή το **source context** δεν επιτρέπεται να αποκτήσει πρόσβαση στο **target context** με την ζητούμενη κλάση/άδεια.

Ένα context συνήθως έχει την εξής μορφή:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Από την οπτική του privesc, το `type` (domain για processes, type για objects) είναι συνήθως το σημαντικότερο πεδίο:

- Ένα process εκτελείται σε ένα **domain**, όπως `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Τα files και τα sockets έχουν ένα **type**, όπως `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Η policy καθορίζει αν ένα domain μπορεί να κάνει read/write/execute/transition στο άλλο

## Fast Enumeration

Αν το SELinux είναι ενεργοποιημένο, κάνε enumerate νωρίς, επειδή μπορεί να εξηγήσει γιατί συνηθισμένες διαδρομές Linux privesc αποτυγχάνουν ή γιατί ένα privileged wrapper γύρω από ένα «ακίνδυνο» SELinux tool είναι στην πραγματικότητα κρίσιμο:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Χρήσιμοι επακόλουθοι έλεγχοι:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
Ενδιαφέροντα ευρήματα:

- Η λειτουργία `Disabled` ή `Permissive` αφαιρεί το μεγαλύτερο μέρος της αξίας του SELinux ως boundary.
- Το `unconfined_t` συνήθως σημαίνει ότι το SELinux είναι ενεργό, αλλά δεν περιορίζει ουσιαστικά τη συγκεκριμένη διεργασία.
- Τα `default_t`, `file_t` ή προφανώς λανθασμένα labels σε custom paths συχνά υποδεικνύουν λανθασμένη απόδοση labels ή incomplete deployment.
- Τα local overrides στο `file_contexts.local` έχουν προτεραιότητα έναντι των policy defaults, επομένως πρέπει να ελέγχονται προσεκτικά.

## Ανάλυση Policy

Το SELinux είναι πολύ πιο εύκολο να γίνει attack ή bypass όταν μπορείς να απαντήσεις σε δύο ερωτήσεις:

1. **Σε τι μπορεί να έχει πρόσβαση το τρέχον domain μου;**
2. **Σε ποια domains μπορώ να κάνω transition;**

Τα πιο χρήσιμα tools για αυτό είναι τα `sepolicy` και **SETools** (`seinfo`, `sesearch`, `sedta`):
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας host χρησιμοποιεί **confined users** αντί να αντιστοιχίζει όλους στο `unconfined_u`. Σε αυτή την περίπτωση, αναζητήστε:

- αντιστοιχίσεις χρηστών μέσω `semanage login -l`
- επιτρεπόμενους ρόλους μέσω `semanage user -l`
- προσβάσιμα admin domains όπως `sysadm_t`, `secadm_t`, `webadm_t`
- καταχωρίσεις `sudoers` που χρησιμοποιούν `ROLE=` ή `TYPE=`

Αν το `sudo -l` περιέχει καταχωρίσεις όπως αυτή, το SELinux αποτελεί μέρος του ορίου δικαιωμάτων:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Ελέγξτε επίσης αν το `newrole` είναι διαθέσιμο:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` και `newrole` δεν είναι αυτόματα exploitable, αλλά αν ένα privileged wrapper ή ένας κανόνας `sudoers` σάς επιτρέπει να επιλέξετε έναν καλύτερο ρόλο/τύπο, γίνονται high-value escalation primitives.

## Αρχεία, Relabeling και Misconfigurations Υψηλής Αξίας

Η σημαντικότερη λειτουργική διαφορά μεταξύ των συνηθισμένων εργαλείων SELinux είναι:

- `chcon`: προσωρινή αλλαγή label σε ένα συγκεκριμένο path
- `semanage fcontext`: persistent κανόνας αντιστοίχισης path-to-label
- `restorecon` / `setfiles`: εφαρμογή ξανά του label που ορίζεται από την policy/default

Αυτό έχει μεγάλη σημασία κατά το privesc, επειδή το **relabeling δεν είναι απλώς cosmetic**. Μπορεί να μετατρέψει ένα αρχείο από "blocked by policy" σε "readable/executable by a privileged confined service".

Ελέγξτε για local relabel rules και relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Μια λεπτομέρεια που είναι διακριτική αλλά χρήσιμη: το απλό `restorecon` **δεν επαναφέρει πάντα πλήρως μια ύποπτη ετικέτα**. Αν ο τύπος-στόχος βρίσκεται στο `customizable_types`, μπορεί να χρειαστεί το `-F` για να επιβληθεί πλήρης επαναφορά. Από επιθετική σκοπιά, αυτό εξηγεί γιατί ένα ασυνήθιστο `chcon` μπορεί μερικές φορές να παραμένει μετά από έναν επιφανειακό καθαρισμό του τύπου «εκτελέσαμε ήδη το restorecon».
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Εντολές υψηλής αξίας για αναζήτηση στα `sudo -l`, root wrappers, scripts αυτοματοποίησης ή capabilities αρχείων:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Εάν εμφανιστεί οποιαδήποτε από τις δύο δυνατότητες MAC, ελέγξτε επίσης τη [σελίδα Linux capabilities](linux-capabilities.md)· τα `cap_mac_admin` και `cap_mac_override` είναι ασυνήθιστα, αλλά άμεσα σχετικά όταν το SELinux αποτελεί μέρος του boundary.

Ιδιαίτερο ενδιαφέρον παρουσιάζουν:

- `semanage fcontext`: αλλάζει μόνιμα το label που θα πρέπει να λαμβάνει ένα path
- `restorecon` / `setfiles`: εφαρμόζουν ξανά αυτές τις αλλαγές σε μεγάλη κλίμακα
- `semodule -i`: φορτώνει ένα custom policy module
- `semanage permissive -a <domain_t>`: καθιστά ένα domain permissive χωρίς να αλλάξει ολόκληρο το host
- `setsebool -P`: αλλάζει μόνιμα τα policy booleans
- `load_policy`: φορτώνει ξανά την ενεργή policy

Αυτά είναι συχνά **helper primitives** και όχι standalone root exploits. Η αξία τους έγκειται στο ότι σας επιτρέπουν να:

- καταστήσετε ένα target domain permissive
- διευρύνετε την πρόσβαση μεταξύ του domain σας και ενός protected type
- αλλάξετε τα labels σε αρχεία που ελέγχει ο attacker, ώστε μια privileged υπηρεσία να μπορεί να τα διαβάσει ή να τα εκτελέσει
- αποδυναμώσετε μια confined υπηρεσία αρκετά, ώστε ένα υπάρχον local bug να γίνει exploitable

Παραδείγματα ελέγχων:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Αν μπορείς να φορτώσεις ένα policy module ως root, συνήθως ελέγχεις το όριο του SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Γι’ αυτό τα `audit2allow`, `semodule` και `semanage permissive` πρέπει να αντιμετωπίζονται ως ευαίσθητες επιφάνειες διαχείρισης κατά το post-exploitation. Μπορούν σιωπηλά να μετατρέψουν μια αποκλεισμένη αλυσίδα σε λειτουργική, χωρίς να αλλάξουν τα κλασικά δικαιώματα UNIX.

## Κρυφές Αρνήσεις και Εξαγωγή Modules

Μια πολύ συνηθισμένη offensive απογοήτευση είναι μια αλυσίδα που αποτυγχάνει με ένα ασαφές `EACCES`, ενώ η αναμενόμενη άρνηση AVC δεν εμφανίζεται ποτέ. Οι κανόνες `dontaudit` ενδέχεται να αποκρύπτουν το συγκεκριμένο permission που χρειάζεστε. Αν μπορείτε να εκτελέσετε το `semodule` μέσω `sudo` ή κάποιου άλλου privileged wrapper, η προσωρινή απενεργοποίηση του `dontaudit` μπορεί να μετατρέψει μια σιωπηλή αποτυχία σε ένα ακριβές στοιχείο για την policy:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Αυτό είναι επίσης χρήσιμο για τον έλεγχο των αλλαγών που έχουν ήδη κάνει οι local admins. Ένα μικρό custom module ή ένας κανόνας permissive για ένα domain είναι συχνά ο λόγος για τον οποίο μια υπηρεσία-στόχος συμπεριφέρεται πολύ πιο χαλαρά απ’ ό,τι θα υπέδειχνε η βασική policy.

## Ενδείξεις Audit

Οι AVC denials αποτελούν συχνά offensive signal και όχι απλώς defensive noise. Σας ενημερώνουν για τα εξής:

- ποιο target object/type προσπελάσατε
- ποιο permission απορρίφθηκε
- ποιο domain ελέγχετε αυτήν τη στιγμή
- αν μια μικρή αλλαγή στην policy θα έκανε το chain να λειτουργήσει
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Αν ένα local exploit ή μια προσπάθεια persistence αποτυγχάνει συνεχώς με `EACCES` ή παράξενα σφάλματα "permission denied", παρότι τα DAC permissions φαίνονται σαν να παρέχουν root privileges, συνήθως αξίζει να ελέγξετε το SELinux πριν απορρίψετε το vector.

## Χρήστες SELinux

Υπάρχουν SELinux users επιπλέον των κανονικών Linux users. Κάθε Linux user αντιστοιχίζεται σε έναν SELinux user ως μέρος της policy, επιτρέποντας στο σύστημα να επιβάλλει διαφορετικούς allowed roles και domains σε διαφορετικούς λογαριασμούς.

Γρήγοροι έλεγχοι:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Σε πολλά mainstream συστήματα, οι χρήστες αντιστοιχίζονται στο `unconfined_u`, γεγονός που μειώνει τον πρακτικό αντίκτυπο του user confinement. Ωστόσο, σε hardened deployments, οι confined users μπορούν να κάνουν τα `sudo`, `su`, `newrole` και `runcon` πολύ πιο ενδιαφέροντα, επειδή **το escalation path μπορεί να εξαρτάται από την είσοδο σε έναν καλύτερο SELinux role/type και όχι μόνο από την απόκτηση UID 0**. Επίσης, θυμηθείτε ότι ορισμένοι confined users δεν μπορούν να καλέσουν τα `sudo`/`su` καθόλου, εκτός αν η policy επιτρέπει ρητά το υποκείμενο setuid transition. Επομένως, ένα host που χρησιμοποιεί `staff_u` + `sysadm_r` μπορεί να μετατρέψει έναν φαινομενικά ασήμαντο κανόνα `sudo ROLE=` / `TYPE=` στο πραγματικό privilege boundary.

## SELinux σε Containers

Τα Container runtimes συνήθως εκκινούν workloads σε ένα confined domain, όπως το `container_t`, και κάνουν label το περιεχόμενο του container ως `container_file_t`. Αν μια container process κάνει escape αλλά εξακολουθεί να εκτελείται με το container label, τα host writes ενδέχεται και πάλι να αποτυγχάνουν, επειδή το label boundary παρέμεινε intact.

Γρήγορο παράδειγμα:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Το τμήμα `c647,c780` δεν είναι διακοσμητικό. Σε πολλές container deployments, τα runtimes εκχωρούν δυναμικά MCS categories, ώστε δύο processes που εκτελούνται ως `container_t` να εξακολουθούν να είναι απομονωμένα μεταξύ τους. Αν ένα escape σας μεταφέρει σε host namespace, αλλά διατηρεί το αρχικό category set, οι category mismatches μπορούν και πάλι να εξηγήσουν γιατί ορισμένα host paths παραμένουν μη αναγνώσιμα ή μη εγγράψιμα.

Σημαντικές σύγχρονες λειτουργίες container:

- Το `--security-opt label=disable` μπορεί ουσιαστικά να μεταφέρει το workload σε έναν unconfined container-related type, όπως το `spc_t`
- Τα bind mounts με `:z` / `:Z` ενεργοποιούν το relabeling του host path για shared/private χρήση από container
- Το ευρύ relabeling περιεχομένου του host μπορεί από μόνο του να καταστεί security issue

Αυτή η σελίδα διατηρεί σύντομο το περιεχόμενο για τα container, ώστε να αποφεύγεται η duplication. Για τα container-specific abuse cases και τα runtime examples, δείτε:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Αναφορές

- [Τεκμηρίωση Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Εργαλεία policy analysis για SELinux](https://github.com/SELinuxProject/setools)
- [Διαχείριση confined και unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
