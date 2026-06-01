# SELinux

{{#include ../../banners/hacktricks-training.md}}

Το SELinux είναι ένα σύστημα **label-based Mandatory Access Control (MAC)**. Στην πράξη, αυτό σημαίνει ότι ακόμα κι αν τα δικαιώματα DAC, τα groups ή οι Linux capabilities φαίνονται αρκετά για μια ενέργεια, ο kernel μπορεί να την αρνηθεί επειδή το **source context** δεν επιτρέπεται να αποκτήσει πρόσβαση στο **target context** με την requested class/permission.

Ένα context συνήθως μοιάζει ως εξής:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Από την οπτική του privesc, το `type` (domain για processes, type για objects) είναι συνήθως το πιο σημαντικό πεδίο:

- Ένα process εκτελείται σε ένα **domain** όπως `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Τα files και τα sockets έχουν ένα **type** όπως `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Η policy αποφασίζει αν ένα domain μπορεί να read/write/execute/transition στο άλλο

## Fast Enumeration

Αν το SELinux είναι enabled, κάνε enumerate νωρίς γιατί μπορεί να εξηγήσει γιατί κοινά Linux privesc paths αποτυγχάνουν ή γιατί ένα privileged wrapper γύρω από ένα "harmless" SELinux tool είναι στην πραγματικότητα κρίσιμο:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Χρήσιμα επόμενα checks:
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
Interesting findings:

- Το `Disabled` ή `Permissive` mode αφαιρεί το μεγαλύτερο μέρος της αξίας του SELinux ως boundary.
- `unconfined_t` συνήθως σημαίνει ότι το SELinux είναι παρόν αλλά δεν περιορίζει ουσιαστικά εκείνη τη process.
- `default_t`, `file_t`, ή προφανώς λάθος labels σε custom paths συχνά υποδεικνύουν mislabeling ή incomplete deployment.
- Τα local overrides στο `file_contexts.local` έχουν προτεραιότητα έναντι των policy defaults, οπότε review them carefully.

## Policy Analysis

Το SELinux είναι πολύ πιο εύκολο να attack ή bypass όταν μπορείς να απαντήσεις σε δύο ερωτήσεις:

1. **Τι μπορεί να access το current domain μου;**
2. **Σε ποια domains μπορώ να transition into;**

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
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας host χρησιμοποιεί **confined users** αντί να αντιστοιχίζει όλους σε `unconfined_u`. Σε αυτή την περίπτωση, αναζήτησε:

- user mappings μέσω `semanage login -l`
- allowed roles μέσω `semanage user -l`
- reachable admin domains όπως `sysadm_t`, `secadm_t`, `webadm_t`
- καταχωρήσεις `sudoers` που χρησιμοποιούν `ROLE=` ή `TYPE=`

Αν το `sudo -l` περιέχει καταχωρήσεις όπως αυτές, το SELinux αποτελεί μέρος του privilege boundary:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Επίσης, έλεγξε αν το `newrole` είναι διαθέσιμο:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` και `newrole` δεν είναι αυτόματα exploitable, αλλά αν ένα privileged wrapper ή ένα `sudoers` rule σου επιτρέπει να επιλέξεις ένα καλύτερο role/type, γίνονται υψηλής αξίας escalation primitives.

## Files, Relabeling, and High-Value Misconfigurations

Η πιο σημαντική operational διαφορά ανάμεσα στα κοινά SELinux tools είναι:

- `chcon`: προσωρινή αλλαγή label σε ένα συγκεκριμένο path
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: εφαρμόζει ξανά το policy/default label

Αυτό έχει μεγάλη σημασία κατά τη διάρκεια privesc γιατί το **relabeling δεν είναι απλώς cosmetic**. Μπορεί να μετατρέψει ένα file από "blocked by policy" σε "readable/executable by a privileged confined service".

Έλεγξε για local relabel rules και relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Μια λεπτή αλλά χρήσιμη λεπτομέρεια: το απλό `restorecon` **δεν επαναφέρει πάντα πλήρως μια ύποπτη ετικέτα**. Αν ο τύπος-στόχος βρίσκεται στο `customizable_types`, ίσως χρειαστεί το `-F` για να επιβάλεις πλήρη επαναφορά. Από επιθετική σκοπιά, αυτό εξηγεί γιατί ένα ασυνήθιστο `chcon` μπορεί μερικές φορές να επιβιώσει από ένα πρόχειρο "ήδη τρέξαμε restorecon" cleanup.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Εντολές υψηλής αξίας για αναζήτηση σε `sudo -l`, root wrappers, automation scripts, ή file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Αν εμφανιστεί οποιαδήποτε MAC capability, κάνε επίσης cross-check τη [Linux capabilities page](linux-capabilities.md); τα `cap_mac_admin` και `cap_mac_override` είναι ασυνήθιστα αλλά άμεσα σχετικά όταν το SELinux αποτελεί μέρος του boundary.

Ιδιαίτερα ενδιαφέροντα:

- `semanage fcontext`: αλλάζει μόνιμα ποιο label πρέπει να λάβει ένα path
- `restorecon` / `setfiles`: εφαρμόζει ξανά αυτές τις αλλαγές σε κλίμακα
- `semodule -i`: φορτώνει ένα custom policy module
- `semanage permissive -a <domain_t>`: κάνει ένα domain permissive χωρίς να αλλάξει όλο το host
- `setsebool -P`: αλλάζει μόνιμα policy booleans
- `load_policy`: επαναφορτώνει το ενεργό policy

Αυτά συχνά είναι **helper primitives**, όχι standalone root exploits. Η αξία τους είναι ότι σου επιτρέπουν να:

- κάνεις ένα target domain permissive
- διευρύνεις την πρόσβαση μεταξύ του domain σου και ενός protected type
- relabel αρχεία που ελέγχει ο attacker ώστε μια privileged service να μπορεί να τα διαβάσει ή να τα εκτελέσει
- αποδυναμώσεις αρκετά μια confined service ώστε ένα υπάρχον local bug να γίνει exploitable

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
Γι' αυτό το `audit2allow`, το `semodule` και το `semanage permissive` θα πρέπει να αντιμετωπίζονται ως ευαίσθητες admin surfaces κατά το post-exploitation. Μπορούν να μετατρέψουν σιωπηλά μια blocked chain σε working one χωρίς να αλλάξουν τα κλασικά UNIX permissions.

## Hidden Denials and Module Extraction

Ένα πολύ συνηθισμένο offensive frustration είναι μια chain που αποτυγχάνει με ένα αόριστο `EACCES` ενώ το αναμενόμενο AVC denial δεν εμφανίζεται ποτέ. Οι `dontaudit` rules μπορεί να κρύβουν ακριβώς το permission που χρειάζεσαι. Αν μπορείς να τρέξεις το `semodule` μέσω `sudo` ή κάποιου άλλου privileged wrapper, η προσωρινή απενεργοποίηση του `dontaudit` μπορεί να μετατρέψει μια silent failure σε ένα ακριβές policy clue:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Αυτό είναι επίσης χρήσιμο για να ελέγξετε τι έχουν ήδη αλλάξει οι τοπικοί admins. Ένα μικρό custom module ή ένας one-domain permissive rule είναι συχνά ο λόγος που μια target υπηρεσία συμπεριφέρεται πολύ πιο χαλαρά από όσο θα υπέθετε η base policy.

## Audit Clues

Τα AVC denials είναι συχνά offensive signal, όχι απλώς defensive noise. Σας λένε:

- ποιο target object/type χτυπήσατε
- ποια permission απορρίφθηκε
- ποιο domain ελέγχετε αυτή τη στιγμή
- αν μια μικρή policy change θα έκανε το chain να δουλέψει
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Αν μια local exploit ή μια προσπάθεια persistence συνεχίζει να αποτυγχάνει με `EACCES` ή περίεργα σφάλματα "permission denied" παρότι οι DAC permissions φαίνονται σαν root, το SELinux συνήθως αξίζει να ελεγχθεί πριν απορρίψεις το vector.

## SELinux Users

Υπάρχουν SELinux users επιπλέον των κανονικών Linux users. Κάθε Linux user αντιστοιχίζεται σε έναν SELinux user ως μέρος της policy, κάτι που επιτρέπει στο σύστημα να επιβάλλει διαφορετικά επιτρεπόμενα roles και domains σε διαφορετικούς λογαριασμούς.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Σε πολλά mainstream συστήματα, οι χρήστες αντιστοιχίζονται σε `unconfined_u`, κάτι που μειώνει το πρακτικό impact του user confinement. Σε hardened deployments, όμως, οι confined users μπορούν να κάνουν τα `sudo`, `su`, `newrole`, και `runcon` πολύ πιο ενδιαφέροντα επειδή **το escalation path μπορεί να εξαρτάται από την είσοδο σε ένα καλύτερο SELinux role/type, όχι μόνο από το να γίνεις UID 0**. Επίσης θυμήσου ότι κάποιοι confined users δεν μπορούν να καλέσουν καθόλου `sudo`/`su` εκτός αν το policy επιτρέπει ρητά το underlying setuid transition, οπότε ένας host που χρησιμοποιεί `staff_u` + `sysadm_r` μπορεί να μετατρέψει έναν φαινομενικά μικρό `sudo ROLE=` / `TYPE=` rule στο πραγματικό privilege boundary.

## SELinux in Containers

Τα container runtimes συνήθως εκκινούν workloads σε ένα confined domain όπως `container_t` και label το container content ως `container_file_t`. Αν ένα container process διαφύγει αλλά εξακολουθεί να τρέχει με το container label, τα host writes μπορεί ακόμα να αποτύχουν επειδή το label boundary παρέμεινε άθικτο.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Το `c647,c780` μέρος δεν είναι διακόσμηση. Σε πολλές container deployments, τα runtimes αποδίδουν δυναμικά MCS categories, ώστε δύο processes που εκτελούνται ως `container_t` να παραμένουν παρ' όλα αυτά απομονωμένα μεταξύ τους. Αν ένα escape σε φέρει σε host namespace αλλά διατηρεί το αρχικό set κατηγοριών, οι ασυμφωνίες κατηγοριών μπορούν ακόμα να εξηγήσουν γιατί ορισμένα host paths παραμένουν μη αναγνώσιμα ή μη εγγράψιμα.

Σύγχρονες container operations που αξίζει να σημειωθούν:

- `--security-opt label=disable` μπορεί να μεταφέρει αποτελεσματικά το workload σε έναν unconfined container-related type όπως `spc_t`
- bind mounts με `:z` / `:Z` ενεργοποιούν relabeling του host path για shared/private container use
- το ευρύ relabeling του host content μπορεί να γίνει και από μόνο του issue ασφάλειας

Αυτή η σελίδα κρατά το container content σύντομο για να αποφευχθεί η επανάληψη. Για τα container-specific abuse cases και runtime examples, δες:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
