# SELinux

{{#include ../../banners/hacktricks-training.md}}

Το SELinux είναι ένα σύστημα **Mandatory Access Control (MAC)** βασισμένο σε **labels**. Στην πράξη, αυτό σημαίνει ότι ακόμη κι αν τα δικαιώματα DAC, οι ομάδες ή οι δυνατότητες του Linux φαίνονται επαρκή για μια ενέργεια, ο kernel μπορεί και πάλι να την αρνηθεί, επειδή το **source context** δεν επιτρέπεται να έχει πρόσβαση στο **target context** με την ζητούμενη κλάση/άδεια.<sup>[[1]](#references)</sup>

Ένα context συνήθως έχει την εξής μορφή:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Από την οπτική του privesc, το `type` (domain για διεργασίες, type για αντικείμενα) είναι συνήθως το σημαντικότερο πεδίο:<sup>[[1]](#references)</sup>

- Μια διεργασία εκτελείται σε ένα **domain**, όπως `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Τα αρχεία και τα sockets έχουν ένα **type**, όπως `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Η policy καθορίζει αν ένα domain μπορεί να κάνει read/write/execute ή transition στο άλλο

## Γρήγορο Enumeration

Αν το SELinux είναι ενεργοποιημένο, κάντε enumeration νωρίς, επειδή μπορεί να εξηγήσει γιατί αποτυγχάνουν συνηθισμένα Linux privesc paths ή γιατί ένα privileged wrapper γύρω από ένα «ακίνδυνο» εργαλείο SELinux είναι στην πραγματικότητα κρίσιμο:<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

Χρήσιμοι συμπληρωματικοί έλεγχοι:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

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
- Τα `default_t`, `file_t` ή εμφανώς λανθασμένες ετικέτες σε προσαρμοσμένες διαδρομές συχνά υποδεικνύουν λανθασμένη επισήμανση ή ελλιπή ανάπτυξη.
- Οι τοπικές παρακάμψεις στο `file_contexts.local` έχουν προτεραιότητα έναντι των προεπιλογών της πολιτικής, γι’ αυτό εξετάστε τις προσεκτικά.

## Ανάλυση πολιτικής

Το SELinux είναι πολύ πιο εύκολο να προσβληθεί ή να παρακαμφθεί όταν μπορείτε να απαντήσετε σε δύο ερωτήματα:

1. **Σε τι έχει πρόσβαση ο τρέχων τομέας μου;**
2. **Σε ποιους τομείς μπορώ να μεταβώ;**

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

Αυτό είναι ιδιαίτερα χρήσιμο όταν ένας host χρησιμοποιεί **confined users** αντί να αντιστοιχίζει όλους στο `unconfined_u`. Σε αυτή την περίπτωση, αναζητήστε:<sup>[[3]](#references)</sup>

- αντιστοιχίσεις χρηστών μέσω `semanage login -l`
- επιτρεπόμενους ρόλους μέσω `semanage user -l`
- προσβάσιμα admin domains, όπως `sysadm_t`, `secadm_t`, `webadm_t`
- καταχωρίσεις στο `sudoers` που χρησιμοποιούν `ROLE=` ή `TYPE=`

Αν το `sudo -l` περιέχει καταχωρίσεις όπως αυτή, το SELinux αποτελεί μέρος του ορίου προνομίων:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Επίσης, ελέγξτε αν το `newrole` είναι διαθέσιμο:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` και `newrole` δεν είναι αυτομάτως εκμεταλλεύσιμα, αλλά αν ένα προνομιούχο wrapper ή ένας κανόνας `sudoers` σάς επιτρέπει να επιλέξετε έναν πιο χρήσιμο ρόλο/τύπο, γίνονται πολύτιμα primitives κλιμάκωσης δικαιωμάτων.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Έλεγχος εγγράψιμων σημείων εισόδου μετάβασης

Ένα γράφημα μεταβάσεων αποτελεί μόνο ένδειξη για την πολιτική. Για να το μετατρέψετε σε διαδρομή επίθεσης, εντοπίστε τον τύπο εκτελέσιμου αρχείου που οδηγεί σε έναν πιο χρήσιμο domain και, στη συνέχεια, ελέγξτε αν μπορείτε να τροποποιήσετε ένα εκτελέσιμο με αυτήν την ετικέτα ή να το αντικαταστήσετε μέσω του γονικού καταλόγου του.<sup>[[9]](#references)[[20]](#references)</sup> Μια αυτόματη μετάβαση `execve` απαιτεί έναν εφαρμοστέο κανόνα `type_transition`, δικαίωμα εκτέλεσης από το domain προέλευσης, δικαίωμα `entrypoint` στο domain προορισμού και άδεια μετάβασης μεταξύ των domains.<sup>[[20]](#references)</sup> Το domain προορισμού μπορεί να αποκτήσει πρόσβαση SELinux, αλλά η εκτέλεση από μόνη της δεν αλλάζει το Linux UID· ελέγξτε ξεχωριστά τα [SUID/SGID and ACLs](suid-sgid-and-acl-triage.md).<sup>[[20]](#references)[[21]](#references)</sup>

Χρησιμοποιήστε τον αναφερόμενο τύπο σημείου εισόδου για να ελέγξετε τους υποκείμενους κανόνες και, στη συνέχεια, επιθεωρήστε τη διαδρομή και τον γονικό κατάλογό της για δικαίωμα εγγραφής.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Συσχέτισε τον τύπο entrypoint με μια πραγματική διαδρομή εκτελέσιμου αρχείου. Έλεγξε τα DAC, ACL, τα δικαιώματα εγγραφής SELinux στο αρχείο ή στον γονικό κατάλογο, την ετικέτα του αρχείου και τυχόν conditional boolean, πριν θεωρήσεις ότι είναι εφικτή μια ακμή πολιτικής.<sup>[[20]](#references)[[22]](#references)</sup> Αν μια διαδρομή αντικαθίσταται αντί να τροποποιείται επιτόπου, επαλήθευσε το context του νέου inode: οι ετικέτες του filesystem αποθηκεύονται ως extended attributes και η αντικατάσταση ενδέχεται να μη διατηρήσει τον τύπο entrypoint.<sup>[[21]](#references)</sup> Τα προγράμματα που υποστηρίζουν SELinux μπορούν να ζητήσουν μετάβαση με το `setexeccon`, επομένως η απουσία αυτόματου κανόνα `type_transition` δεν αποκλείει κάθε μετάβαση.<sup>[[20]](#references)</sup>

## Αρχεία, επανασήμανση και misconfigurations υψηλής αξίας

Η σημαντικότερη λειτουργική διαφορά μεταξύ των συνηθισμένων εργαλείων SELinux είναι η εξής:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: προσωρινή αλλαγή ετικέτας σε συγκεκριμένη διαδρομή
- `semanage fcontext`: μόνιμος κανόνας αντιστοίχισης διαδρομής σε ετικέτα
- `restorecon` / `setfiles`: εφαρμογή ξανά της ετικέτας πολιτικής/προεπιλογής

Αυτό έχει μεγάλη σημασία κατά το privesc, επειδή **η επανασήμανση δεν είναι απλώς αισθητική αλλαγή**. Μπορεί να μετατρέψει ένα αρχείο από «αποκλεισμένο από την πολιτική» σε «αναγνώσιμο/εκτελέσιμο από μια προνομιούχα υπηρεσία υπό περιορισμούς».<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Έλεγξε για τοπικούς κανόνες επανασήμανσης και αποκλίσεις στην επανασήμανση:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Μια λεπτή αλλά χρήσιμη λεπτομέρεια: το απλό `restorecon` **δεν επαναφέρει πάντα πλήρως μια ύποπτη ετικέτα**. Αν ο τύπος-στόχος βρίσκεται στο `customizable_types`, ίσως χρειαστεί να χρησιμοποιήσετε το `-F` για να επιβάλετε πλήρη επαναφορά. Από επιθετική σκοπιά, αυτό εξηγεί γιατί ένα ασυνήθιστο `chcon` μπορεί μερικές φορές να επιβιώσει από έναν πρόχειρο καθαρισμό του τύπου «τρέξαμε ήδη το restorecon».<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Εντολές υψηλής αξίας για αναζήτηση με `sudo -l`, σε root wrappers, scripts αυτοματοποίησης ή capabilities αρχείων:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Αν εμφανίζεται οποιαδήποτε από τις δύο δυνατότητες MAC, διασταυρώστε τις πληροφορίες και στη [σελίδα Linux capabilities](linux-capabilities.md)· η τεκμηρίωση του Linux capabilities περιγράφει τα `cap_mac_admin` και `cap_mac_override` ως ειδικά για το Smack, επομένως μην υποθέτετε ότι τα ονόματά τους και μόνο παρακάμπτουν το SELinux.<sup>[[5]](#references)</sup>

Ιδιαίτερο ενδιαφέρον έχουν:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: αλλάζει μόνιμα την ετικέτα που θα πρέπει να λαμβάνει μια διαδρομή
- `restorecon` / `setfiles`: εφαρμόζει ξανά αυτές τις αλλαγές μαζικά
- `semodule -i`: φορτώνει ένα προσαρμοσμένο policy module
- `semanage permissive -a <domain_t>`: θέτει έναν domain σε permissive mode χωρίς να αλλάζει τη ρύθμιση ολόκληρου του host
- `setsebool -P`: αλλάζει μόνιμα τα policy booleans
- `load_policy`: επαναφορτώνει το ενεργό policy

Συχνά πρόκειται για **βοηθητικά primitives**, όχι για αυτοτελή root exploits. Η αξία τους είναι ότι σας επιτρέπουν να:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- θέσετε έναν domain-στόχο σε permissive mode
- διευρύνετε την πρόσβαση μεταξύ του domain σας και ενός προστατευμένου type
- αλλάξετε τις ετικέτες αρχείων που ελέγχει ο επιτιθέμενος, ώστε μια προνομιούχα υπηρεσία να μπορεί να τα διαβάσει ή να τα εκτελέσει
- αποδυναμώσετε έναν περιορισμένο service αρκετά, ώστε ένα υπάρχον τοπικό bug να γίνει εκμεταλλεύσιμο

Παραδείγματα ελέγχων:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Αν μπορείς να φορτώσεις ένα policy module ως root, συνήθως ελέγχεις το όριο ασφαλείας του SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

Γι' αυτό τα `audit2allow`, `semodule` και `semanage permissive` πρέπει να αντιμετωπίζονται ως ευαίσθητες επιφάνειες διαχείρισης κατά το post-exploitation. Μπορούν να μετατρέψουν αθόρυβα μια αλυσίδα που έχει αποκλειστεί σε λειτουργική, χωρίς να αλλάξουν τα κλασικά δικαιώματα UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Κρυφές αρνήσεις και εξαγωγή modules

Μια πολύ συνηθισμένη απογοήτευση στην offensive πλευρά είναι μια αλυσίδα που αποτυγχάνει με ένα αόριστο `EACCES`, ενώ η αναμενόμενη άρνηση AVC δεν εμφανίζεται ποτέ. Οι κανόνες `dontaudit` ενδέχεται να αποκρύπτουν το ακριβές δικαίωμα που χρειάζεστε. Αν μπορείτε να εκτελέσετε το `semodule` μέσω `sudo` ή κάποιου άλλου προνομιούχου wrapper, η προσωρινή απενεργοποίηση του `dontaudit` μπορεί να μετατρέψει μια σιωπηλή αποτυχία σε ένα ακριβές στοιχείο για την πολιτική:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Αυτό είναι επίσης χρήσιμο για να εξετάσετε τι έχουν ήδη αλλάξει οι τοπικοί admins. Ένα μικρό custom module ή ένας permissive κανόνας για ένα domain είναι συχνά ο λόγος που μια υπηρεσία-στόχος συμπεριφέρεται πολύ πιο χαλαρά απ’ όσο υποδηλώνει η βασική policy.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Ενδείξεις από το audit

Οι αρνήσεις AVC συχνά αποτελούν χρήσιμο σήμα για επιθέσεις, όχι απλώς αμυντικό θόρυβο. Σας δείχνουν:<sup>[[1]](#references)[[15]](#references)</sup>

- ποιο αντικείμενο/τύπο-στόχο προσεγγίσατε
- ποια άδεια απορρίφθηκε
- ποιο domain ελέγχετε αυτήν τη στιγμή
- αν μια μικρή αλλαγή στην policy θα έκανε την αλυσίδα να λειτουργήσει

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Αν ένα τοπικό exploit ή μια απόπειρα persistence αποτυγχάνει επανειλημμένα με `EACCES` ή με περίεργα σφάλματα «permission denied», παρότι τα δικαιώματα DAC φαίνονται να ανήκουν στο root, συνήθως αξίζει να ελέγξετε το SELinux πριν απορρίψετε το vector.<sup>[[1]](#references)</sup>

## Χρήστες SELinux

Υπάρχουν χρήστες SELinux επιπλέον των συνηθισμένων χρηστών Linux. Κάθε χρήστης Linux αντιστοιχίζεται σε έναν χρήστη SELinux στο πλαίσιο της πολιτικής, επιτρέποντας στο σύστημα να επιβάλλει διαφορετικούς επιτρεπόμενους ρόλους και domains σε διαφορετικούς λογαριασμούς.<sup>[[3]](#references)</sup>

Γρήγοροι έλεγχοι:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Σε πολλά mainstream συστήματα, οι χρήστες αντιστοιχίζονται στο `unconfined_u`, γεγονός που μειώνει τον πρακτικό αντίκτυπο του περιορισμού των χρηστών. Σε hardened deployments, όμως, οι περιορισμένοι χρήστες μπορούν να κάνουν τα `sudo`, `su`, `newrole` και `runcon` πολύ πιο ενδιαφέροντα, επειδή **η διαδρομή κλιμάκωσης δικαιωμάτων μπορεί να εξαρτάται από τη μετάβαση σε έναν κατάλληλοτερο SELinux role/type και όχι μόνο από την απόκτηση UID 0**. Θυμήσου επίσης ότι ορισμένοι περιορισμένοι χρήστες δεν μπορούν να εκτελέσουν καθόλου `sudo`/`su`, εκτός αν η policy επιτρέπει ρητά την υποκείμενη setuid μετάβαση. Έτσι, ένας host που χρησιμοποιεί `staff_u` + `sysadm_r` μπορεί να μετατρέψει έναν φαινομενικά ασήμαντο κανόνα `sudo ROLE=` / `TYPE=` στο πραγματικό όριο δικαιωμάτων.<sup>[[3]](#references)</sup>

## SELinux σε Containers

Τα runtimes των Containers εκκινούν συνήθως workloads σε ένα περιορισμένο domain, όπως το `container_t`, και επισημαίνουν το περιεχόμενο των Containers ως `container_file_t`. Αν μια διεργασία Container διαφύγει, αλλά εξακολουθεί να εκτελείται με την ετικέτα του Container, οι εγγραφές στον host ενδέχεται και πάλι να αποτυγχάνουν, επειδή το όριο των ετικετών παρέμεινε άθικτο.<sup>[[1]](#references)[[17]](#references)</sup>

Γρήγορο παράδειγμα:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

Το τμήμα `c647,c780` δεν είναι διακοσμητικό. Σε πολλές αναπτύξεις container, τα runtimes εκχωρούν δυναμικά κατηγορίες MCS, ώστε δύο διεργασίες που εκτελούνται ως `container_t` να παραμένουν απομονωμένες μεταξύ τους. Αν μια διαφυγή σε μεταφέρει σε namespace του host, αλλά διατηρεί το αρχικό σύνολο κατηγοριών, οι ασυμφωνίες κατηγοριών μπορούν και πάλι να εξηγήσουν γιατί ορισμένες διαδρομές του host παραμένουν μη αναγνώσιμες ή μη εγγράψιμες.<sup>[[17]](#references)</sup>

Σύγχρονες λειτουργίες container που αξίζει να γνωρίζετε:<sup>[[16]](#references)[[17]](#references)</sup>

- Το `--security-opt label=disable` απενεργοποιεί τον διαχωρισμό με ετικέτες SELinux για το container
- Τα bind mounts με `:z` / `:Z` ενεργοποιούν την αλλαγή ετικετών της διαδρομής του host για κοινή/ιδιωτική χρήση από container
- Η μαζική αλλαγή ετικετών στο περιεχόμενο του host μπορεί από μόνη της να εξελιχθεί σε ζήτημα ασφάλειας

Αυτή η σελίδα διατηρεί σύντομο το περιεχόμενο για τα container, ώστε να αποφευχθούν οι επαναλήψεις. Για περιπτώσεις κατάχρησης ειδικά για container και παραδείγματα runtime, δείτε:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Τεκμηρίωση Red Hat: Χρήση του SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Εργαλεία ανάλυσης πολιτικών για το SELinux](https://github.com/SELinuxProject/setools)
- [3] [Διαχείριση περιορισμένων και μη περιορισμένων χρηστών - Τεκμηρίωση RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
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
- [16] [Τεκμηρίωση της εντολής Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Γιατί πρέπει να χρησιμοποιείτε την ασφάλεια πολλαπλών κατηγοριών για τα Linux container σας](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Τεκμηρίωση της εντολής Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Σελίδα εγχειριδίου Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Σημειωματάριο SELinux: Μεταβάσεις domain και αντικειμένων](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: Χρήση του SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Εγχειρίδιο SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
