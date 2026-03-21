# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

Η πιο σημαντική ιδέα στο container hardening είναι ότι δεν υπάρχει ένας μοναδικός έλεγχος που ονομάζεται "container security". Αυτό που πολλοί αποκαλούν container isolation είναι στην πραγματικότητα το αποτέλεσμα αρκετών μηχανισμών ασφαλείας και διαχείρισης πόρων του Linux που συνεργάζονται. Αν η τεκμηρίωση περιγράφει μόνο έναν από αυτούς, οι αναγνώστες τείνουν να υπερεκτιμούν την ισχύ του. Αν η τεκμηρίωση απαριθμεί όλους χωρίς να εξηγεί πώς αλληλεπιδρούν, οι αναγνώστες αποκτούν έναν κατάλογο ονομάτων αλλά όχι ένα πραγματικό μοντέλο. Αυτή η ενότητα προσπαθεί να αποφύγει και τα δύο λάθη.

Στο κέντρο του μοντέλου βρίσκονται οι **namespaces**, που απομονώνουν όσα μπορεί να δει το workload. Χορηγούν στη διεργασία μια ιδιωτική ή μερικώς ιδιωτική προβολή των filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, και ορισμένων clocks. Αλλά τα namespaces από μόνα τους δεν αποφασίζουν τι επιτρέπεται να κάνει μια διεργασία. Σε αυτό εισέρχονται τα επόμενα στρώματα.

**cgroups** ελέγχουν τη χρήση πόρων. Δεν είναι πρωτίστως ένα όριο απομόνωσης με την ίδια έννοια όπως τα mount ή PID namespaces, αλλά είναι κρίσιμα λειτουργικά επειδή περιορίζουν μνήμη, CPU, PIDs, I/O και πρόσβαση σε συσκευές. Έχουν επίσης σημασία για την ασφάλεια επειδή ιστορικές τεχνικές breakout εκμεταλλεύτηκαν writable cgroup features, ειδικά σε cgroup v1 περιβάλλοντα.

**Capabilities** διασπούν το παλιό παντοδύναμο μοντέλο του root σε μικρότερες μονάδες προνομίων. Αυτό είναι θεμελιώδες για containers επειδή πολλά workloads εξακολουθούν να τρέχουν ως UID 0 μέσα στο container. Το ερώτημα λοιπόν δεν είναι απλώς "is the process root?", αλλά μάλλον "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Γι' αυτό μια root διεργασία σε ένα container μπορεί να είναι σχετικά περιορισμένη ενώ μια root διεργασία σε άλλο container μπορεί στην πράξη να είναι σχεδόν αδιακρίτως από το host root.

**seccomp** φιλτράρει syscalls και μειώνει την επιφάνεια επίθεσης του kernel που εκτίθεται στο workload. Συχνά αυτός είναι ο μηχανισμός που μπλοκάρει προφανώς επικίνδυνες κλήσεις όπως `unshare`, `mount`, `keyctl` ή άλλες syscalls που χρησιμοποιούνται σε breakout chains. Ακόμη κι αν μια διεργασία έχει capability που διαφορετικά θα επέτρεπε μια ενέργεια, το seccomp μπορεί να μπλοκάρει την πορεία του syscall πριν ο kernel τη επεξεργαστεί πλήρως.

**AppArmor** και **SELinux** προσθέτουν Mandatory Access Control πάνω από τους κανονικούς ελέγχους filesystem και προνομίων. Αυτά είναι ιδιαίτερα σημαντικά γιατί εξακολουθούν να έχουν σημασία ακόμη και όταν ένα container έχει περισσότερες capabilities απ' ό,τι θα έπρεπε. Ένα workload μπορεί να έχει το θεωρητικό προνόμιο να επιχειρήσει μια ενέργεια αλλά να εμποδίζεται να την ολοκληρώσει επειδή το label ή το profile του απαγορεύει την πρόσβαση στο σχετικό path, αντικείμενο ή λειτουργία.

Τέλος, υπάρχουν επιπλέον στρώματα hardening που λαμβάνουν λιγότερη προσοχή αλλά έχουν συχνά σημασία σε πραγματικές επιθέσεις: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, και careful runtime defaults. Αυτοί οι μηχανισμοί συχνά σταματούν το "last mile" μιας παραβίασης, ειδικά όταν ένας επιτιθέμενος προσπαθεί να μετατρέψει code execution σε ευρύτερη απόκτηση προνομίων.

Το υπόλοιπο αυτού του φακέλου εξηγεί καθένα από αυτούς τους μηχανισμούς με περισσότερες λεπτομέρειες, συμπεριλαμβανομένου τι κάνει πραγματικά το kernel primitive, πώς να το παρατηρήσετε τοπικά, πώς τα κοινά runtimes το χρησιμοποιούν, και πώς οι operators το εξασθενούν κατά λάθος.

## Read Next

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
