# SELinux

{{#include ../../banners/hacktricks-training.md}}

Το SELinux είναι ένα **βασισμένο σε ετικέτες Mandatory Access Control (MAC)** σύστημα. Στην πράξη, αυτό σημαίνει ότι ακόμη και αν τα δικαιώματα DAC, οι ομάδες ή οι Linux capabilities φαίνονται επαρκή για μια ενέργεια, ο πυρήνας μπορεί παρ' όλα αυτά να την απορρίψει επειδή το context προέλευσης δεν επιτρέπεται να έχει πρόσβαση στο context προορισμού με την ζητούμενη κλάση/άδεια.

Ένα context συνήθως μοιάζει με:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Από την πλευρά του privesc, το `type` (domain για διεργασίες, type για αντικείμενα) είναι συνήθως το πιο σημαντικό πεδίο:

- Μια διεργασία τρέχει σε ένα **domain** όπως `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Αρχεία και sockets έχουν έναν **type** όπως `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Η πολιτική καθορίζει αν ένα domain μπορεί να διαβάσει/γράψει/εκτελέσει/μεταβεί στο άλλο

## Fast Enumeration

If SELinux is enabled, enumerate it early because it can explain why common Linux privesc paths fail or why a privileged wrapper around a "harmless" SELinux tool is actually critical:
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

- Η λειτουργία `Disabled` ή `Permissive` αφαιρεί το μεγαλύτερο μέρος της αξίας του SELinux ως ορίου.
- Το `unconfined_t` συνήθως σημαίνει ότι το SELinux είναι παρόν αλλά δεν περιορίζει ουσιαστικά αυτή τη διεργασία.
- Τα `default_t`, `file_t`, ή προφανώς λανθασμένες ετικέτες σε προσαρμοσμένα μονοπάτια συχνά υποδηλώνουν λανθασμένη επισήμανση ή ελλιπή ανάπτυξη.
- Οι τοπικές παρακάμψεις στο `file_contexts.local` έχουν προτεραιότητα έναντι των προεπιλογών της πολιτικής, οπότε ελέγξτε τις προσεκτικά.

## Ανάλυση Πολιτικής

Το SELinux είναι πολύ πιο εύκολο να επιτεθεί ή να παρακαμφθεί όταν μπορείτε να απαντήσετε σε δύο ερωτήσεις:

1. **Τι μπορεί να προσπελάσει ο τρέχων domain μου;**
2. **Σε ποιους domains μπορώ να μεταβώ;**

Τα πιο χρήσιμα εργαλεία για αυτό είναι `sepolicy` και **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας host χρησιμοποιεί **περιορισμένους χρήστες** αντί να αντιστοιχίζει όλους στο `unconfined_u`. Σε αυτή την περίπτωση, αναζητήστε:

- αντιστοιχίσεις χρηστών μέσω `semanage login -l`
- επιτρεπόμενοι ρόλοι μέσω `semanage user -l`
- προσβάσιμοι τομείς διαχείρισης όπως `sysadm_t`, `secadm_t`, `webadm_t`
- εγγραφές `sudoers` που χρησιμοποιούν `ROLE=` ή `TYPE=`

Αν το `sudo -l` περιέχει εγγραφές όπως αυτές, το SELinux είναι μέρος των ορίων προνομίων:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Επιπλέον, ελέγξτε αν το `newrole` είναι διαθέσιμο:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` και `newrole` δεν είναι αυτομάτως εκμεταλλεύσιμα, αλλά αν ένας privileged wrapper ή ένας κανόνας `sudoers` σου επιτρέπει να επιλέξεις καλύτερο role/type, τότε γίνονται high-value escalation primitives.

## Αρχεία, Relabeling και Κακές Διαμορφώσεις Υψηλής Αξίας

Η πιο σημαντική λειτουργική διαφορά μεταξύ των κοινών εργαλείων SELinux είναι:

- `chcon`: προσωρινή αλλαγή ετικέτας σε μια συγκεκριμένη διαδρομή
- `semanage fcontext`: μόνιμος κανόνας αντιστοίχισης διαδρομής→ετικέτας
- `restorecon` / `setfiles`: εφαρμόζουν ξανά την πολιτική/την προεπιλεγμένη ετικέτα

Αυτό έχει μεγάλη σημασία κατά τη διάρκεια privesc επειδή **το relabeling δεν είναι απλά αισθητικό**. Μπορεί να μετατρέψει ένα αρχείο από «μπλοκαρισμένο από την πολιτική» σε «αναγνώσιμο/εκτελέσιμο από μια privileged confined service».

Check for local relabel rules and relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Εντολές υψηλής αξίας για αναζήτηση σε `sudo -l`, root wrappers, automation scripts ή file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Ιδιαίτερα ενδιαφέρον:

- `semanage fcontext`: αλλάζει μόνιμα ποια ετικέτα (label) πρέπει να λάβει μια διαδρομή
- `restorecon` / `setfiles`: επαναεφαρμόζει αυτές τις αλλαγές σε μεγάλη κλίμακα
- `semodule -i`: φορτώνει ένα προσαρμοσμένο module πολιτικής
- `semanage permissive -a <domain_t>`: καθιστά ένα domain permissive χωρίς να αλλάζει ολόκληρο το host
- `setsebool -P`: αλλάζει μόνιμα τα policy booleans
- `load_policy`: επαναφορτώνει την ενεργή πολιτική

Συχνά πρόκειται για **helper primitives**, όχι αυτόνομα root exploits. Η αξία τους είναι ότι σας επιτρέπουν να:

- καταστήσετε έναν στοχευόμενο domain permissive
- διευρύνετε την πρόσβαση μεταξύ του domain σας και ενός protected type
- επαναεπισημάνετε αρχεία που ελέγχει ο επιτιθέμενος ώστε μια privileged υπηρεσία να μπορεί να τα διαβάσει ή να τα εκτελέσει
- αδυνατίσετε μια περιορισμένη υπηρεσία τόσο ώστε ένα υπάρχον local bug να γίνει εκμεταλλεύσιμο

Παραδείγματα ελέγχων:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Αν μπορείτε να φορτώσετε ένα policy module ως root, συνήθως ελέγχετε το όριο του SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Γι' αυτό το λόγο οι `audit2allow`, `semodule`, και `semanage permissive` πρέπει να θεωρούνται ευαίσθητες επιφάνειες διαχείρισης κατά το post-exploitation. Μπορούν αθόρυβα να μετατρέψουν μια μπλοκαρισμένη αλυσίδα σε λειτουργική χωρίς να αλλάξουν τα κλασικά UNIX δικαιώματα.

## Ενδείξεις Audit

Οι AVC denials συχνά αποτελούν επιθετικό σήμα, όχι απλώς αμυντικό θόρυβο. Σας λένε:

- ποιο αντικείμενο/τύπο στόχου χτυπήσατε
- ποιο δικαίωμα απορρίφθηκε
- ποιο domain ελέγχετε αυτήν τη στιγμή
- εάν μια μικρή αλλαγή στην πολιτική θα έκανε την αλυσίδα να λειτουργήσει
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Αν μια local exploit ή προσπάθεια persistence συνεχίζει να αποτυγχάνει με `EACCES` ή περίεργα σφάλματα "permission denied" παρότι οι root-looking DAC permissions εμφανίζονται σωστές, αξίζει συνήθως να ελέγξετε το SELinux πριν απορρίψετε το vector.

## Χρήστες SELinux

Υπάρχουν χρήστες SELinux πέρα από τους κανονικούς χρήστες Linux. Κάθε χρήστης Linux αντιστοιχίζεται σε έναν χρήστη SELinux ως μέρος της πολιτικής, και αυτό επιτρέπει στο σύστημα να επιβάλει διαφορετικούς επιτρεπόμενους ρόλους και domains σε διαφορετικούς λογαριασμούς.

Γρήγοροι έλεγχοι:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Σε πολλά ευρέως χρησιμοποιούμενα συστήματα, οι χρήστες αντιστοιχίζονται στο `unconfined_u`, κάτι που μειώνει τον πρακτικό αντίκτυπο του περιορισμού χρηστών. Σε σκληροποιημένες αναπτύξεις, ωστόσο, οι περιορισμένοι χρήστες μπορούν να κάνουν τα `sudo`, `su`, `newrole`, και `runcon` πολύ πιο ενδιαφέροντα επειδή **η διαδρομή κλιμάκωσης μπορεί να εξαρτάται από την είσοδο σε έναν καλύτερο SELinux role/type, όχι μόνο από το να γίνει κάποιος UID 0**.

## SELinux σε Containers

Τα container runtimes συνήθως ξεκινούν workloads σε ένα περιορισμένο domain όπως το `container_t` και επισημαίνουν το περιεχόμενο του container ως `container_file_t`. Εάν μια διεργασία container δραπετεύσει αλλά εξακολουθεί να τρέχει με την ετικέτα του container, οι εγγραφές στο host μπορεί να αποτύχουν επειδή το όριο ετικέτας παρέμεινε ακέραιο.

Γρήγορο παράδειγμα:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Modern container operations worth noting:

- `--security-opt label=disable` μπορεί ουσιαστικά να μεταφέρει το workload σε έναν unconfined σχετικό τύπο container, όπως `spc_t`
- bind mounts with `:z` / `:Z` προκαλούν relabeling της host διαδρομής για κοινή/ιδιωτική χρήση από container
- Η ευρεία relabeling του περιεχομένου του host μπορεί να αποτελεί αυτοτελές ζήτημα ασφαλείας

This page keeps the container content short to avoid duplication. For the container-specific abuse cases and runtime examples, check:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Αναφορές

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
