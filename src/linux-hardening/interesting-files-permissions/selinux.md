# SELinux

{{#include ../../banners/hacktricks-training.md}}

Το SELinux είναι ένα σύστημα **Υποχρεωτικού Ελέγχου Πρόσβασης (MAC)** που βασίζεται σε **labels**. Στην πράξη, αυτό σημαίνει ότι ακόμη και αν τα δικαιώματα DAC, οι ομάδες ή οι δυνατότητες του Linux φαίνονται επαρκή για μια ενέργεια, ο kernel μπορεί και πάλι να την αρνηθεί, επειδή το **source context** δεν επιτρέπεται να έχει πρόσβαση στο **target context** με την ζητούμενη κλάση/άδεια.

Ένα context συνήθως έχει τη μορφή:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Από την οπτική του privesc, το `type` (domain για processes, type για objects) είναι συνήθως το πιο σημαντικό πεδίο:

- Ένα process εκτελείται σε ένα **domain** όπως `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Τα files και τα sockets έχουν ένα **type** όπως `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Η policy αποφασίζει αν ένα domain μπορεί να κάνει read/write/execute/transition στο άλλο

## Γρήγορη Enumeration

Αν το SELinux είναι ενεργοποιημένο, κάντε enumeration νωρίς, επειδή μπορεί να εξηγήσει γιατί οι συνήθεις διαδρομές Linux privesc αποτυγχάνουν ή γιατί ένα privileged wrapper γύρω από ένα "ακίνδυνο" SELinux tool είναι στην πραγματικότητα κρίσιμο:
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
- Τα `default_t`, `file_t` ή προφανώς λανθασμένα labels σε custom paths συχνά υποδεικνύουν λανθασμένη απόδοση labels ή ελλιπή ανάπτυξη.
- Τα local overrides στο `file_contexts.local` έχουν προτεραιότητα έναντι των προεπιλογών της policy, επομένως ελέγξτε τα προσεκτικά.

## Ανάλυση Policy

Το SELinux είναι πολύ ευκολότερο να γίνει αντικείμενο επίθεσης ή να παρακαμφθεί όταν μπορείτε να απαντήσετε σε δύο ερωτήσεις:

1. **Σε τι μπορεί να έχει πρόσβαση το τρέχον domain μου;**
2. **Σε ποια domains μπορώ να κάνω transition;**

Τα πιο χρήσιμα tools για αυτό είναι τα `sepolicy` και τα **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)</sup>
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας host χρησιμοποιεί **περιορισμένους χρήστες** αντί να αντιστοιχίζει όλους στο `unconfined_u`. Σε αυτήν την περίπτωση, αναζητήστε:<sup>[[3]](#references)</sup>

- user mappings μέσω `semanage login -l`
- επιτρεπόμενους ρόλους μέσω `semanage user -l`
- προσβάσιμα admin domains όπως `sysadm_t`, `secadm_t`, `webadm_t`
- καταχωρίσεις `sudoers` που χρησιμοποιούν `ROLE=` ή `TYPE=`

Αν το `sudo -l` περιέχει καταχωρίσεις όπως αυτή, το SELinux αποτελεί μέρος του privilege boundary:
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

## Αρχεία, Relabeling και High-Value Misconfigurations

Η σημαντικότερη operational διαφορά μεταξύ των συνηθισμένων SELinux tools είναι:<sup>[[1]](#references)</sup>

- `chcon`: προσωρινή αλλαγή label σε ένα συγκεκριμένο path
- `semanage fcontext`: persistent κανόνας path-to-label
- `restorecon` / `setfiles`: εφαρμογή ξανά του policy/default label

Αυτό έχει μεγάλη σημασία κατά το privesc, επειδή το **relabeling δεν είναι απλώς cosmetic**. Μπορεί να μετατρέψει ένα αρχείο από «blocked by policy» σε «readable/executable από μια privileged confined service».

Ελέγξτε για local relabel rules και relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Μια λεπτομέρεια που είναι διακριτική αλλά χρήσιμη: το απλό `restorecon` **δεν επαναφέρει πάντα πλήρως μια ύποπτη label**. Αν ο τύπος-στόχος βρίσκεται στο `customizable_types`, ενδέχεται να χρειαστείτε το `-F` για να επιβάλετε πλήρη επαναφορά. Από offensive perspective, αυτό εξηγεί γιατί ένα ασυνήθιστο `chcon` μπορεί μερικές φορές να επιβιώσει από έναν πρόχειρο καθαρισμό του τύπου «εκτελέσαμε ήδη το restorecon».
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Εντολές υψηλής αξίας για αναζήτηση σε `sudo -l`, root wrappers, scripts αυτοματοποίησης ή capabilities αρχείων:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Αν εμφανιστεί οποιαδήποτε από τις δύο δυνατότητες MAC, κάντε επίσης cross-check στη [Linux capabilities page](linux-capabilities.md)· οι `cap_mac_admin` και `cap_mac_override` είναι ασυνήθιστες, αλλά άμεσα σχετικές όταν το SELinux αποτελεί μέρος του boundary.

Ιδιαίτερα ενδιαφέροντα:

- `semanage fcontext`: αλλάζει μόνιμα το label που πρέπει να λαμβάνει ένα path
- `restorecon` / `setfiles`: εφαρμόζουν ξανά αυτές τις αλλαγές σε μεγάλη κλίμακα
- `semodule -i`: φορτώνει ένα custom policy module
- `semanage permissive -a <domain_t>`: κάνει ένα domain permissive χωρίς να αλλάξει ολόκληρο το host
- `setsebool -P`: αλλάζει μόνιμα τα policy booleans
- `load_policy`: επαναφορτώνει την ενεργή policy

Αυτά είναι συχνά **helper primitives**, όχι standalone root exploits. Η αξία τους είναι ότι σας επιτρέπουν να:

- κάνετε ένα target domain permissive
- διευρύνετε την πρόσβαση μεταξύ του domain σας και ενός protected type
- κάνετε relabel αρχεία που ελέγχονται από attacker, ώστε μια privileged service να μπορεί να τα διαβάσει ή να τα εκτελέσει
- αποδυναμώσετε μια confined service αρκετά, ώστε ένα υπάρχον local bug να γίνει exploitable

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
Γι' αυτό τα `audit2allow`, `semodule` και `semanage permissive` πρέπει να αντιμετωπίζονται ως ευαίσθητες admin επιφάνειες κατά το post-exploitation. Μπορούν να μετατρέψουν αθόρυβα μια μπλοκαρισμένη αλυσίδα σε λειτουργική, χωρίς να αλλάξουν τα κλασικά δικαιώματα UNIX.

## Κρυφές Αρνήσεις και Εξαγωγή Modules

Μια πολύ συνηθισμένη απογοήτευση σε offensive σενάρια είναι μια αλυσίδα που αποτυγχάνει με ένα ασαφές `EACCES`, ενώ η αναμενόμενη AVC denial δεν εμφανίζεται ποτέ. Οι κανόνες `dontaudit` ενδέχεται να αποκρύπτουν το ακριβές permission που χρειάζεστε. Αν μπορείτε να εκτελέσετε το `semodule` μέσω `sudo` ή κάποιου άλλου privileged wrapper, η προσωρινή απενεργοποίηση του `dontaudit` μπορεί να μετατρέψει μια αθόρυβη αποτυχία σε μια σαφή ένδειξη policy:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Αυτό είναι επίσης χρήσιμο για τον έλεγχο των αλλαγών που έχουν ήδη κάνει οι local admins. Ένα μικρό custom module ή ένας permissive rule για ένα domain είναι συχνά ο λόγος που μια target service συμπεριφέρεται πολύ πιο χαλαρά απ’ όσο θα υπέδειχνε η base policy.

## Audit Clues

Οι AVC denials αποτελούν συχνά offensive signal και όχι απλώς defensive noise. Σας δείχνουν:

- ποιο target object/type αγγίξατε
- ποιο permission απορρίφθηκε
- ποιο domain ελέγχετε αυτήν τη στιγμή
- αν μια μικρή αλλαγή στην policy θα έκανε το chain να λειτουργήσει
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Εάν ένα local exploit ή μια προσπάθεια persistence αποτυγχάνει συνεχώς με `EACCES` ή με περίεργα σφάλματα "permission denied", παρόλο που τα DAC permissions φαίνονται σαν permissions του root, συνήθως αξίζει να ελέγξετε το SELinux πριν απορρίψετε το vector.

## SELinux Users

Υπάρχουν SELinux users επιπλέον των κανονικών Linux users. Κάθε Linux user αντιστοιχίζεται σε έναν SELinux user ως μέρος της policy, γεγονός που επιτρέπει στο σύστημα να επιβάλλει διαφορετικούς επιτρεπόμενους roles και domains σε διαφορετικούς accounts.<sup>[[3]](#references)</sup>

Γρήγοροι έλεγχοι:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Σε πολλά mainstream συστήματα, οι χρήστες αντιστοιχίζονται στο `unconfined_u`, γεγονός που μειώνει τον πρακτικό αντίκτυπο του περιορισμού των χρηστών. Σε hardened deployments, ωστόσο, οι περιορισμένοι χρήστες μπορούν να κάνουν τα `sudo`, `su`, `newrole` και `runcon` πολύ πιο ενδιαφέροντα, επειδή **η διαδρομή κλιμάκωσης μπορεί να εξαρτάται από την είσοδο σε έναν καταλληλότερο SELinux ρόλο/τύπο και όχι μόνο από την απόκτηση UID 0**. Να θυμάστε επίσης ότι ορισμένοι περιορισμένοι χρήστες δεν μπορούν να καλέσουν καθόλου τα `sudo`/`su`, εκτός αν η policy επιτρέπει ρητά την υποκείμενη μετάβαση setuid, επομένως ένας host που χρησιμοποιεί `staff_u` + `sysadm_r` μπορεί να μετατρέψει έναν φαινομενικά ασήμαντο κανόνα `sudo ROLE=` / `TYPE=` στο πραγματικό όριο προνομίων.<sup>[[3]](#references)</sup>

## SELinux σε Containers

Τα container runtimes συνήθως εκκινούν τα workloads σε ένα confined domain, όπως το `container_t`, και επισημαίνουν το περιεχόμενο των containers ως `container_file_t`. Αν μια διεργασία container πραγματοποιήσει escape αλλά εξακολουθεί να εκτελείται με το label του container, οι εγγραφές στον host ενδέχεται και πάλι να αποτυγχάνουν, επειδή το όριο των labels παρέμεινε άθικτο.

Γρήγορο παράδειγμα:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Το τμήμα `c647,c780` δεν είναι διακοσμητικό. Σε πολλές αναπτύξεις containers, τα runtimes εκχωρούν δυναμικά κατηγορίες MCS, ώστε δύο διεργασίες που εκτελούνται ως `container_t` να εξακολουθούν να είναι απομονωμένες μεταξύ τους. Αν ένα escape σας μεταφέρει σε ένα host namespace, αλλά διατηρεί το αρχικό σύνολο κατηγοριών, οι ασυμφωνίες κατηγοριών μπορούν και πάλι να εξηγήσουν γιατί ορισμένα host paths παραμένουν μη αναγνώσιμα ή μη εγγράψιμα.

Σημαντικές σύγχρονες λειτουργίες containers:

- Το `--security-opt label=disable` μπορεί ουσιαστικά να μεταφέρει το workload σε έναν unconfined τύπο που σχετίζεται με containers, όπως το `spc_t`
- Τα bind mounts με `:z` / `:Z` ενεργοποιούν το relabeling του host path για shared/private χρήση από containers
- Το ευρύ relabeling περιεχομένου του host μπορεί από μόνο του να εξελιχθεί σε security issue

Αυτή η σελίδα διατηρεί σύντομο το περιεχόμενο για τα containers, ώστε να αποφεύγεται η duplication. Για τα container-specific abuse cases και τα runtime examples, δείτε:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Αναφορές

- [1] [Τεκμηρίωση Red Hat: Χρήση του SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Εργαλεία ανάλυσης policy για το SELinux](https://github.com/SELinuxProject/setools)
- [3] [Διαχείριση confined και unconfined χρηστών - Τεκμηρίωση RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
