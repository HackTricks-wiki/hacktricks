# SELinux

{{#include ../../banners/hacktricks-training.md}}

Το SELinux είναι ένα σύστημα **label-based Mandatory Access Control (MAC)**. Στην πράξη, αυτό σημαίνει ότι ακόμη κι αν τα DAC permissions, οι ομάδες ή οι Linux capabilities φαίνονται επαρκή για μια ενέργεια, ο kernel μπορεί ακόμα να την αρνηθεί επειδή το **source context** δεν επιτρέπεται να προσπελάσει το **target context** με την ζητούμενη class/permission.

Ένα context συνήθως μοιάζει με:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Από την άποψη του privesc, το `type` (domain για διεργασίες, type για αντικείμενα) είναι συνήθως το πιο σημαντικό πεδίο:

- Μια διεργασία τρέχει σε ένα **domain** όπως `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Αρχεία και sockets έχουν ένα **type** όπως `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Η πολιτική αποφασίζει αν ένα domain μπορεί να διαβάσει/γράψει/εκτελέσει/μεταβεί στο άλλο

## Γρήγορη Απογραφή

Αν το SELinux είναι ενεργό, εντοπίστε το νωρίς γιατί μπορεί να εξηγήσει γιατί κοινές διαδρομές privesc σε Linux αποτυγχάνουν ή γιατί ένας privileged wrapper γύρω από ένα "harmless" SELinux tool είναι στην πραγματικότητα κρίσιμος:
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

- `Disabled` ή `Permissive` λειτουργία αφαιρεί το μεγαλύτερο μέρος της αξίας του SELinux ως όριο.
- `unconfined_t` συνήθως σημαίνει ότι το SELinux είναι παρόν αλλά δεν περιορίζει ουσιαστικά αυτή τη διεργασία.
- `default_t`, `file_t`, ή προφανώς λανθασμένες ετικέτες σε προσαρμοσμένες διαδρομές συχνά υποδηλώνουν λάθος επισήμανση ή ελλιπή ανάπτυξη.
- Οι τοπικές υπερβάσεις στο `file_contexts.local` υπερισχύουν των προεπιλογών πολιτικής, οπότε ελέγξτε τις προσεκτικά.

## Ανάλυση Πολιτικής

Το SELinux είναι πολύ πιο εύκολο να επιτεθεί ή να παρακαμφθεί όταν μπορείτε να απαντήσετε σε δύο ερωτήσεις:

1. **Τι μπορεί να αποκτήσει πρόσβαση το τρέχον domain μου;**
2. **Σε ποια domains μπορώ να μεταβώ;**

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
Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας host χρησιμοποιεί **περιορισμένους χρήστες** αντί να αντιστοιχίζει όλους σε `unconfined_u`. Σε αυτή την περίπτωση, αναζητήστε:

- αντιστοιχίσεις χρηστών μέσω `semanage login -l`
- επιτρεπόμενοι ρόλοι μέσω `semanage user -l`
- προσιτοί διαχειριστικοί τομείς όπως `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` εγγραφές που χρησιμοποιούν `ROLE=` ή `TYPE=`

Αν το `sudo -l` περιέχει εγγραφές όπως αυτές, το SELinux αποτελεί μέρος του ορίου προνομίων:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Επίσης, έλεγξε αν το `newrole` είναι διαθέσιμο:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` και `newrole` δεν είναι αυτόματα εκμεταλλεύσιμα, αλλά αν ένας privileged wrapper ή ένας κανόνας `sudoers` σας επιτρέπει να επιλέξετε καλύτερο role/type, τότε γίνονται primitives υψηλής αξίας για escalation.

## Αρχεία, επανεπισημείωση και διαμορφώσεις υψηλής αξίας που προκαλούν προβλήματα

Η πιο σημαντική λειτουργική διαφορά μεταξύ των κοινών εργαλείων SELinux είναι:

- `chcon`: προσωρινή αλλαγή ετικέτας σε συγκεκριμένο μονοπάτι
- `semanage fcontext`: μόνιμος κανόνας διαδρομής-προς-ετικέτα
- `restorecon` / `setfiles`: εφαρμόζουν ξανά την πολιτική/προεπιλεγμένη ετικέτα

Αυτό έχει μεγάλη σημασία κατά τη διάρκεια του privesc γιατί **η επανεπισημείωση δεν είναι απλώς κοσμητική**. Μπορεί να μετατρέψει ένα αρχείο από «αποκλεισμένο από την πολιτική» σε «αναγνώσιμο/εκτελέσιμο από μια προνομιούχο περιορισμένη υπηρεσία».

Ελέγξτε για τοπικούς κανόνες επανεπισημείωσης και απόκλιση επανεπισημείωσης:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Εντολές υψηλής αξίας για αναζήτηση στο `sudo -l`, root wrappers, automation scripts ή file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Ιδιαίτερα ενδιαφέρον:

- `semanage fcontext`: αλλάζει μόνιμα ποια ετικέτα πρέπει να λάβει ένα μονοπάτι
- `restorecon` / `setfiles`: επαναεφαρμόζει αυτές τις αλλαγές μαζικά
- `semodule -i`: φορτώνει ένα προσαρμοσμένο module πολιτικής
- `semanage permissive -a <domain_t>`: θέτει ένα domain σε permissive χωρίς να αλλάζει όλο το host
- `setsebool -P`: αλλάζει μόνιμα τα boolean της πολιτικής
- `load_policy`: επαναφορτώνει την ενεργή πολιτική

Αυτά είναι συχνά **helper primitives**, όχι standalone root exploits. Η αξία τους είναι ότι σας επιτρέπουν να:

- θέσετε ένα target domain σε permissive
- διευρύνετε την πρόσβαση μεταξύ του domain σας και ενός προστατευμένου τύπου
- επαναεπισημάνετε αρχεία υπό έλεγχο επιτιθέμενου ώστε μια προνόμιακή υπηρεσία να τα διαβάσει ή να τα εκτελέσει
- αδυνατίσετε μια confined υπηρεσία τόσο ώστε ένα υπάρχον τοπικό σφάλμα να γίνει εκμεταλλεύσιμο

Παραδείγματα ελέγχων:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Εάν μπορείτε να φορτώσετε ένα policy module ως root, συνήθως ελέγχετε το όριο του SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Γι' αυτό τα `audit2allow`, `semodule` και `semanage permissive` πρέπει να αντιμετωπίζονται ως ευαίσθητες επιφάνειες διαχείρισης κατά το post-exploitation. Μπορούν σιωπηλά να μετατρέψουν μια μπλοκαρισμένη αλυσίδα σε λειτουργική χωρίς να αλλάξουν τα κλασικά δικαιώματα UNIX.

## Ενδείξεις Audit

Οι AVC denials συχνά είναι ένδειξη επίθεσης, όχι απλώς αμυντικός θόρυβος. Σας δείχνουν:

- ποιο αντικείμενο/τύπος στόχου επλήγη
- ποιο δικαίωμα απορρίφθηκε
- ποιο domain ελέγχετε αυτή τη στιγμή
- αν μια μικρή αλλαγή στην πολιτική θα έκανε την αλυσίδα να λειτουργεί
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Αν μια local exploit ή προσπάθεια persistence συνεχίζει να αποτυγχάνει με `EACCES` ή με περίεργα σφάλματα "permission denied" παρά τις DAC permissions που φαίνονται σαν root, το SELinux συνήθως αξίζει να ελεγχθεί πριν απορρίψετε τον vector.

## SELinux Χρήστες

Υπάρχουν SELinux users επιπλέον των κανονικών Linux users. Κάθε Linux user αντιστοιχίζεται σε έναν SELinux user ως μέρος της πολιτικής, κάτι που επιτρέπει στο σύστημα να επιβάλει διαφορετικούς επιτρεπόμενους ρόλους και domains σε διαφορετικούς λογαριασμούς.

Γρήγοροι έλεγχοι:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Σε πολλά ευρέως διαδεδομένα συστήματα, οι χρήστες αντιστοιχίζονται στο `unconfined_u`, κάτι που μειώνει τον πρακτικό αντίκτυπο του περιορισμού χρήστη. Σε σκληροποιημένα περιβάλλοντα, όμως, οι περιορισμένοι χρήστες μπορούν να κάνουν τα `sudo`, `su`, `newrole` και `runcon` πολύ πιο ενδιαφέροντα επειδή **η διαδρομή escalation μπορεί να εξαρτάται από την είσοδο σε καλύτερο SELinux role/type, και όχι μόνο από το να γίνει κανείς UID 0**.

## SELinux in Containers

Τα container runtimes συνήθως ξεκινούν workloads σε ένα περιορισμένο domain όπως `container_t` και επισημαίνουν το περιεχόμενο του container ως `container_file_t`. Αν μια container διεργασία διαφύγει αλλά εξακολουθεί να τρέχει με το container label, οι εγγραφές στον host μπορεί να αποτύχουν επειδή το όριο της ετικέτας παρέμεινε ανέπαφο.

Γρήγορο παράδειγμα:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Σύγχρονες λειτουργίες container που αξίζει να σημειωθούν:

- `--security-opt label=disable` μπορεί ουσιαστικά να μεταφέρει το workload σε έναν μη περιορισμένο τύπο σχετιζόμενο με container όπως `spc_t`
- bind mounts με `:z` / `:Z` ενεργοποιούν relabeling της διαδρομής του host για κοινή/ιδιωτική χρήση από container
- η ευρεία relabeling του περιεχομένου του host μπορεί από μόνη της να γίνει ζήτημα ασφάλειας

Αυτή η σελίδα διατηρεί το περιεχόμενο σχετικά με container σύντομο για να αποφευχθεί η επανάληψη. Για τις περιπτώσεις κατάχρησης ειδικές σε container και παραδείγματα κατά το runtime, δείτε:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Αναφορές

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
