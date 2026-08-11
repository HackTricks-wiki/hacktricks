# SELinux

Το SELinux είναι ένα σύστημα **Mandatory Access Control (MAC)** που βασίζεται σε **labels**. Στην πράξη, αυτό σημαίνει ότι ακόμη και αν τα δικαιώματα DAC, οι ομάδες ή οι δυνατότητες Linux φαίνονται επαρκή για μια ενέργεια, ο kernel μπορεί και πάλι να την απορρίψει, επειδή το **source context** δεν επιτρέπεται να προσπελάσει το **target context** με την απαιτούμενη κλάση/άδεια.<sup>[[1]](#references)</sup>

Ένα context συνήθως μοιάζει με:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Από την perspective του privesc, το `type` (domain για processes, type για objects) είναι συνήθως το πιο σημαντικό πεδίο:<sup>[[1]](#references)</sup>

- Ένα process εκτελείται σε ένα **domain**, όπως `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Τα files και τα sockets έχουν ένα **type**, όπως `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Το policy καθορίζει αν ένα domain μπορεί να κάνει read/write/execute/transition στο άλλο

## Fast Enumeration

Αν το SELinux είναι ενεργοποιημένο, κάντε enumeration από νωρίς, επειδή μπορεί να εξηγήσει γιατί συνηθισμένα Linux privesc paths αποτυγχάνουν ή γιατί ένα privileged wrapper γύρω από ένα «ακίνδυνο» SELinux tool είναι στην πραγματικότητα κρίσιμο:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Χρήσιμοι επακόλουθοι έλεγχοι:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Ενδιαφέροντα ευρήματα:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Η λειτουργία `Disabled` ή `Permissive` αφαιρεί το μεγαλύτερο μέρος της αξίας του SELinux ως ορίου ασφαλείας.
- Το `unconfined_t` συνήθως σημαίνει ότι το SELinux είναι ενεργό, αλλά δεν περιορίζει ουσιαστικά τη συγκεκριμένη διεργασία.
- Τα `default_t`, `file_t` ή προφανώς λανθασμένες ετικέτες σε custom paths συχνά υποδεικνύουν λανθασμένη αντιστοίχιση ετικετών ή ελλιπή ανάπτυξη.
- Τα local overrides στο `file_contexts.local` έχουν προτεραιότητα έναντι των προεπιλογών της policy, επομένως ελέγξτε τα προσεκτικά.

## Ανάλυση Policy

Το SELinux είναι πολύ πιο εύκολο να προσβληθεί ή να παρακαμφθεί όταν μπορείτε να απαντήσετε σε δύο ερωτήσεις:

1. **Σε τι μπορεί να έχει πρόσβαση το τρέχον domain μου;**
2. **Σε ποια domains μπορώ να κάνω transition;**

Τα πιο χρήσιμα εργαλεία για αυτό είναι τα `sepolicy` και **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας host χρησιμοποιεί **περιορισμένους χρήστες** αντί να αντιστοιχίζει όλους τους χρήστες στο `unconfined_u`. Σε αυτή την περίπτωση, αναζητήστε:<sup>[[3]](#references)</sup>

- αντιστοιχίσεις χρηστών μέσω του `semanage login -l`
- επιτρεπόμενους ρόλους μέσω του `semanage user -l`
- προσβάσιμα admin domains, όπως `sysadm_t`, `secadm_t`, `webadm_t`
- καταχωρίσεις `sudoers` που χρησιμοποιούν `ROLE=` ή `TYPE=`

Αν το `sudo -l` περιέχει καταχωρίσεις όπως αυτή, το SELinux αποτελεί μέρος του ορίου προνομίων:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Επίσης ελέγξτε αν το `newrole` είναι διαθέσιμο:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
Το `runcon` και το `newrole` δεν είναι αυτόματα exploitable, αλλά αν ένα privileged wrapper ή ένας κανόνας `sudoers` σάς επιτρέπει να επιλέξετε καλύτερο role/type, γίνονται high-value escalation primitives.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Αρχεία, Relabeling και Misconfigurations Υψηλής Αξίας

Η σημαντικότερη operational διαφορά μεταξύ των συνηθισμένων εργαλείων SELinux είναι:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: προσωρινή αλλαγή label σε συγκεκριμένο path
- `semanage fcontext`: persistent κανόνας path-to-label
- `restorecon` / `setfiles`: εκ νέου εφαρμογή του policy/default label

Αυτό έχει μεγάλη σημασία κατά το privesc, επειδή το **relabeling δεν είναι απλώς cosmetic**. Μπορεί να μετατρέψει ένα αρχείο από «blocked by policy» σε «readable/executable by a privileged confined service».<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Ελέγξτε για local relabel rules και relabel drift:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Μια λεπτομέρεια που είναι διακριτική αλλά χρήσιμη: το απλό `restorecon` **δεν επαναφέρει πάντα πλήρως μια ύποπτη label**. Αν ο τύπος-στόχος βρίσκεται στο `customizable_types`, ίσως χρειαστείτε το `-F` για να επιβάλετε πλήρη επαναφορά. Από επιθετική σκοπιά, αυτό εξηγεί γιατί ένα ασυνήθιστο `chcon` μπορεί μερικές φορές να επιβιώσει από έναν επιφανειακό καθαρισμό του τύπου «εκτελέσαμε ήδη το restorecon».<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Εντολές υψηλής αξίας για εντοπισμό στο `sudo -l`, σε root wrappers, scripts αυτοματοποίησης ή capabilities αρχείων:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Αν εμφανιστεί οποιαδήποτε από τις δύο δυνατότητες MAC, ελέγξτε επίσης τη [σελίδα Linux capabilities](linux-capabilities.md)· η τεκμηρίωση των Linux capabilities περιγράφει τις `cap_mac_admin` και `cap_mac_override` ως Smack-specific, επομένως μην υποθέσετε ότι τα ονόματά τους από μόνα τους παρακάμπτουν το SELinux.<sup>[[5]](#references)</sup>

Ιδιαίτερα ενδιαφέροντα:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: αλλάζει μόνιμα το label που πρέπει να λαμβάνει ένα path
- `restorecon` / `setfiles`: επανεφαρμόζουν αυτές τις αλλαγές σε μεγάλη κλίμακα
- `semodule -i`: φορτώνει ένα custom policy module
- `semanage permissive -a <domain_t>`: κάνει ένα domain permissive χωρίς να αλλάξει ολόκληρο το host
- `setsebool -P`: αλλάζει μόνιμα τα policy booleans
- `load_policy`: επαναφορτώνει την ενεργή policy

Αυτά είναι συχνά **helper primitives**, όχι standalone root exploits. Η αξία τους είναι ότι σας επιτρέπουν να:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- κάνετε ένα target domain permissive
- διευρύνετε την πρόσβαση μεταξύ του domain σας και ενός protected type
- αλλάζετε το label σε αρχεία που ελέγχει ο attacker, ώστε μια privileged υπηρεσία να μπορεί να τα διαβάσει ή να τα εκτελέσει
- αποδυναμώνετε μια confined υπηρεσία αρκετά, ώστε ένα υπάρχον local bug να γίνει exploitable

Παραδείγματα ελέγχων:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Αν μπορείτε να φορτώσετε ένα policy module ως root, συνήθως ελέγχετε το όριο του SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Γι’ αυτό τα `audit2allow`, `semodule` και `semanage permissive` πρέπει να αντιμετωπίζονται ως ευαίσθητες επιφάνειες διαχείρισης κατά το post-exploitation. Μπορούν σιωπηλά να μετατρέψουν μια αποκλεισμένη αλυσίδα σε λειτουργική, χωρίς να αλλάξουν τα κλασικά δικαιώματα UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Κρυφές αρνήσεις και εξαγωγή modules

Μια πολύ συνηθισμένη offensive απογοήτευση είναι μια αλυσίδα που αποτυγχάνει με ένα ασαφές `EACCES`, ενώ η αναμενόμενη AVC denial δεν εμφανίζεται ποτέ. Οι κανόνες `dontaudit` ενδέχεται να αποκρύπτουν την ακριβή άδεια που χρειάζεστε. Αν μπορείτε να εκτελέσετε το `semodule` μέσω `sudo` ή κάποιου άλλου προνομιούχου wrapper, η προσωρινή απενεργοποίηση του `dontaudit` μπορεί να μετατρέψει μια σιωπηλή αποτυχία σε μια σαφή ένδειξη πολιτικής:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Αυτό είναι επίσης χρήσιμο για τον έλεγχο των αλλαγών που έχουν ήδη κάνει οι local admins. Ένα μικρό custom module ή ένας permissive κανόνας για ένα domain είναι συχνά ο λόγος που μια υπηρεσία-στόχος συμπεριφέρεται πολύ πιο χαλαρά από ό,τι θα υπέθετε κανείς με βάση το base policy.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Ενδείξεις ελέγχου

Οι απορρίψεις AVC αποτελούν συχνά offensive signal και όχι απλώς defensive noise. Σας δείχνουν:<sup>[[1]](#references)[[15]](#references)</sup>

- ποιο target object/type προσεγγίσατε
- ποιο permission απορρίφθηκε
- ποιο domain ελέγχετε αυτήν τη στιγμή
- αν μια μικρή αλλαγή στο policy θα έκανε το chain να λειτουργήσει
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Αν ένα local exploit ή μια προσπάθεια persistence αποτυγχάνει συνεχώς με `EACCES` ή παράξενα σφάλματα "permission denied", παρότι οι DAC permissions φαίνονται να απαιτούν root, συνήθως αξίζει να ελέγξετε το SELinux πριν απορρίψετε το vector.<sup>[[1]](#references)</sup>

## SELinux Users

Υπάρχουν SELinux users επιπλέον των κανονικών Linux users. Κάθε Linux user αντιστοιχίζεται σε έναν SELinux user ως μέρος της policy, επιτρέποντας στο σύστημα να επιβάλλει διαφορετικούς επιτρεπόμενους roles και domains σε διαφορετικούς λογαριασμούς.<sup>[[3]](#references)</sup>

Γρήγοροι έλεγχοι:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Σε πολλά mainstream συστήματα, οι χρήστες αντιστοιχίζονται στο `unconfined_u`, γεγονός που μειώνει τον πρακτικό αντίκτυπο του user confinement. Σε hardened deployments, ωστόσο, οι confined users μπορούν να κάνουν τα `sudo`, `su`, `newrole` και `runcon` πολύ πιο ενδιαφέροντα, επειδή **το escalation path μπορεί να εξαρτάται από την είσοδο σε έναν καλύτερο SELinux role/type και όχι μόνο από την απόκτηση UID 0**. Να θυμάστε επίσης ότι ορισμένοι confined users δεν μπορούν να εκτελέσουν καθόλου `sudo`/`su`, εκτός αν η policy επιτρέπει ρητά το υποκείμενο setuid transition. Επομένως, ένα host που χρησιμοποιεί `staff_u` + `sysadm_r` μπορεί να μετατρέψει έναν φαινομενικά ασήμαντο κανόνα `sudo ROLE=` / `TYPE=` στο πραγματικό privilege boundary.<sup>[[3]](#references)</sup>

## SELinux σε Containers

Τα container runtimes συνήθως εκκινούν τα workloads σε ένα confined domain όπως το `container_t` και επισημαίνουν το περιεχόμενο των containers ως `container_file_t`. Αν μια container process κάνει escape αλλά εξακολουθεί να εκτελείται με το container label, οι εγγραφές στο host ενδέχεται και πάλι να αποτυγχάνουν, επειδή το label boundary παρέμεινε άθικτο.<sup>[[1]](#references)[[17]](#references)</sup>

Γρήγορο παράδειγμα:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Το τμήμα `c647,c780` δεν είναι διακοσμητικό. Σε πολλές deployments containers, τα runtimes εκχωρούν δυναμικά MCS categories, ώστε δύο processes που εκτελούνται ως `container_t` να εξακολουθούν να είναι απομονωμένα μεταξύ τους. Αν ένα escape σας μεταφέρει σε host namespace, αλλά διατηρεί το αρχικό category set, οι αναντιστοιχίες categories μπορούν και πάλι να εξηγήσουν γιατί ορισμένα host paths παραμένουν μη αναγνώσιμα ή μη εγγράψιμα.<sup>[[17]](#references)</sup>

Σημαντικές σύγχρονες λειτουργίες containers:<sup>[[16]](#references)[[17]](#references)</sup>

- Το `--security-opt label=disable` απενεργοποιεί τον διαχωρισμό SELinux labels για το container
- Τα bind mounts με `:z` / `:Z` ενεργοποιούν το relabeling του host path για shared/private χρήση από containers
- Το ευρύ relabeling περιεχομένου του host μπορεί από μόνο του να αποτελέσει security issue

Αυτή η σελίδα διατηρεί σύντομο το περιεχόμενο για containers, ώστε να αποφεύγεται η duplication. Για τα abuse cases και τα runtime examples που αφορούν ειδικά containers, δείτε:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Τεκμηρίωση Red Hat: Χρήση του SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Εργαλεία policy analysis για το SELinux](https://github.com/SELinuxProject/setools)
- [3] [Διαχείριση confined και unconfined users - Τεκμηρίωση RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Τεκμηρίωση Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Γιατί πρέπει να χρησιμοποιείτε Multi-Category Security για τα Linux containers](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Τεκμηρίωση Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
