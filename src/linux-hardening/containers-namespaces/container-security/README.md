# Ασφάλεια Containers

{{#include ../../../banners/hacktricks-training.md}}

## Τι Είναι Πραγματικά Ένα Container

Ένας πρακτικός τρόπος να ορίσουμε ένα container είναι ο εξής: ένα container είναι ένα **κανονικό Linux process tree** που έχει ξεκινήσει με μια συγκεκριμένη διαμόρφωση τύπου OCI, ώστε να βλέπει ένα ελεγχόμενο filesystem, ένα ελεγχόμενο σύνολο πόρων του kernel και ένα περιορισμένο μοντέλο προνομίων. Η διεργασία μπορεί να πιστεύει ότι είναι το PID 1, μπορεί να πιστεύει ότι έχει το δικό της network stack, μπορεί να πιστεύει ότι κατέχει το δικό της hostname και τους δικούς της IPC resources, και μπορεί ακόμη να εκτελείται ως root μέσα στο δικό της user namespace. Ωστόσο, στο παρασκήνιο παραμένει μια διεργασία του host που ο kernel προγραμματίζει όπως κάθε άλλη.

Αυτός είναι ο λόγος για τον οποίο η ασφάλεια των containers αφορά στην πραγματικότητα τη μελέτη του τρόπου με τον οποίο κατασκευάζεται αυτή η ψευδαίσθηση και του τρόπου με τον οποίο αποτυγχάνει. Αν το mount namespace είναι αδύναμο, η διεργασία μπορεί να βλέπει το filesystem του host. Αν το user namespace απουσιάζει ή είναι απενεργοποιημένο, το root μέσα στο container μπορεί να αντιστοιχεί υπερβολικά άμεσα στο root του host. Αν το seccomp είναι unconfined και το σύνολο των capabilities είναι υπερβολικά ευρύ, η διεργασία μπορεί να έχει πρόσβαση σε syscalls και προνομιούχα χαρακτηριστικά του kernel που θα έπρεπε να παραμένουν απρόσιτα. Αν το runtime socket είναι mounted μέσα στο container, το container μπορεί να μη χρειάζεται καθόλου kernel breakout, επειδή μπορεί απλώς να ζητήσει από το runtime να εκκινήσει ένα ισχυρότερο sibling container ή να κάνει mount απευθείας το root filesystem του host.

## Πώς Διαφέρουν Τα Containers Από Τις Virtual Machines

Μια VM συνήθως διαθέτει τον δικό της kernel και το δικό της όριο αφαίρεσης hardware. Αυτό σημαίνει ότι ο guest kernel μπορεί να καταρρεύσει, να προκαλέσει panic ή να γίνει αντικείμενο exploitation χωρίς αυτό να συνεπάγεται αυτόματα άμεσο έλεγχο του kernel του host. Στα containers, το workload δεν αποκτά ξεχωριστό kernel. Αντίθετα, αποκτά μια προσεκτικά φιλτραρισμένη και namespaced προβολή του ίδιου kernel που χρησιμοποιεί ο host. Ως αποτέλεσμα, τα containers είναι συνήθως ελαφρύτερα, εκκινούν ταχύτερα, επιτρέπουν πυκνότερη τοποθέτηση σε ένα μηχάνημα και είναι καταλληλότερα για βραχύβια ανάπτυξη εφαρμογών. Το τίμημα είναι ότι το όριο απομόνωσης εξαρτάται πολύ περισσότερο άμεσα από τη σωστή διαμόρφωση του host και του runtime.

Αυτό δεν σημαίνει ότι τα containers είναι "insecure" και οι VMs "secure". Σημαίνει ότι το μοντέλο ασφάλειας είναι διαφορετικό. Ένα σωστά διαμορφωμένο container stack με rootless εκτέλεση, user namespaces, προεπιλεγμένο seccomp, αυστηρό σύνολο capabilities, χωρίς κοινή χρήση host namespaces και με ισχυρή επιβολή SELinux ή AppArmor μπορεί να είναι πολύ ανθεκτικό. Αντίθετα, ένα container που ξεκινά με `--privileged`, κοινή χρήση των host PID/network namespaces, mounted Docker socket στο εσωτερικό του και writable bind mount του `/` είναι λειτουργικά πολύ πιο κοντά σε πρόσβαση host root παρά σε ένα με ασφάλεια απομονωμένο application sandbox. Η διαφορά προκύπτει από τα layers που ενεργοποιήθηκαν ή απενεργοποιήθηκαν.

Υπάρχει επίσης μια ενδιάμεση κατηγορία που οι αναγνώστες πρέπει να κατανοούν, επειδή εμφανίζεται όλο και συχνότερα σε πραγματικά περιβάλλοντα. Τα **Sandboxed container runtimes**, όπως τα **gVisor** και **Kata Containers**, ενισχύουν σκόπιμα το όριο πέρα από ένα κλασικό `runc` container. Το gVisor τοποθετεί ένα userspace kernel layer ανάμεσα στο workload και σε πολλές διεπαφές του host kernel, ενώ το Kata εκκινεί το workload μέσα σε μια lightweight virtual machine. Εξακολουθούν να χρησιμοποιούνται μέσω container ecosystems και orchestration workflows, όμως οι ιδιότητες ασφάλειάς τους διαφέρουν από εκείνες των απλών OCI runtimes και δεν θα πρέπει να ομαδοποιούνται νοητικά με τα "normal Docker containers", σαν να λειτουργούσαν όλα με τον ίδιο τρόπο.

## Το Container Stack: Πολλά Layers, Όχι Ένα

Όταν κάποιος λέει "αυτό το container είναι insecure", η χρήσιμη ερώτηση που ακολουθεί είναι: **ποιο layer το έκανε insecure;** Ένα containerized workload είναι συνήθως αποτέλεσμα της συνεργασίας πολλών components.

Στην κορυφή υπάρχει συχνά ένα **image build layer**, όπως τα BuildKit, Buildah ή Kaniko, το οποίο δημιουργεί το OCI image και τα metadata. Πάνω από το low-level runtime μπορεί να υπάρχει ένα **engine ή manager**, όπως τα Docker Engine, Podman, containerd, CRI-O, Incus ή systemd-nspawn. Σε cluster environments μπορεί επίσης να υπάρχει ένας **orchestrator**, όπως το Kubernetes, που αποφασίζει το ζητούμενο security posture μέσω του workload configuration. Τέλος, ο **kernel** είναι αυτός που στην πράξη επιβάλλει τα namespaces, τα cgroups, το seccomp και την MAC policy.

Αυτό το layered model είναι σημαντικό για την κατανόηση των defaults. Ένας περιορισμός μπορεί να ζητηθεί από το Kubernetes, να μεταφραστεί μέσω CRI από το containerd ή το CRI-O, να μετατραπεί σε OCI spec από το runtime wrapper και μόνο τότε να επιβληθεί από τα `runc`, `crun`, `runsc` ή άλλο runtime στον kernel. Όταν τα defaults διαφέρουν μεταξύ environments, συχνά αυτό συμβαίνει επειδή ένα από αυτά τα layers άλλαξε την τελική διαμόρφωση. Ο ίδιος μηχανισμός μπορεί επομένως να εμφανίζεται στο Docker ή το Podman ως CLI flag, στο Kubernetes ως πεδίο Pod ή `securityContext` και σε lower-level runtime stacks ως OCI configuration που δημιουργήθηκε για το workload. Για αυτόν τον λόγο, τα CLI examples σε αυτή την ενότητα θα πρέπει να διαβάζονται ως **runtime-specific syntax για μια γενική έννοια container** και όχι ως καθολικά flags που υποστηρίζονται από κάθε tool.

## Το Πραγματικό Όριο Ασφάλειας Ενός Container

Στην πράξη, η ασφάλεια των containers προκύπτει από **επικαλυπτόμενα controls**, όχι από ένα μοναδικό τέλειο control. Τα namespaces απομονώνουν την ορατότητα. Τα cgroups ελέγχουν και περιορίζουν τη χρήση πόρων. Τα capabilities μειώνουν όσα μπορεί πραγματικά να κάνει μια διεργασία που φαίνεται προνομιούχα. Το seccomp αποκλείει επικίνδυνα syscalls πριν αυτά φτάσουν στον kernel. Τα AppArmor και SELinux προσθέτουν Mandatory Access Control πάνω από τους κανονικούς ελέγχους DAC. Τα `no_new_privs`, τα masked procfs paths και τα read-only system paths δυσκολεύουν συνηθισμένες αλυσίδες privilege και proc/sys abuse. Σημασία έχει επίσης και το ίδιο το runtime, επειδή αποφασίζει τον τρόπο δημιουργίας των mounts, sockets, labels και namespace joins.

Αυτός είναι ο λόγος για τον οποίο μεγάλο μέρος της τεκμηρίωσης για την ασφάλεια των containers φαίνεται επαναλαμβανόμενο. Η ίδια αλυσίδα escape συχνά εξαρτάται ταυτόχρονα από πολλούς μηχανισμούς. Για παράδειγμα, ένα writable host bind mount είναι κακό, αλλά γίνεται πολύ χειρότερο αν το container εκτελείται επίσης ως πραγματικό root στον host, διαθέτει `CAP_SYS_ADMIN`, είναι unconfined από το seccomp και δεν περιορίζεται από SELinux ή AppArmor. Παρομοίως, η κοινή χρήση host PID είναι σοβαρή έκθεση, αλλά γίνεται δραματικά πιο χρήσιμη σε έναν attacker όταν συνδυάζεται με `CAP_SYS_PTRACE`, αδύναμες προστασίες procfs ή εργαλεία namespace-entry όπως το `nsenter`. Ο σωστός τρόπος τεκμηρίωσης του θέματος, επομένως, δεν είναι η επανάληψη της ίδιας επίθεσης σε κάθε σελίδα, αλλά η εξήγηση της συνεισφοράς κάθε layer στο τελικό όριο.

## Πώς Να Διαβάσετε Αυτή Την Ενότητα

Η ενότητα είναι οργανωμένη από τις πιο γενικές έννοιες προς τις πιο συγκεκριμένες.

Ξεκινήστε με την επισκόπηση των runtimes και του ecosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Στη συνέχεια εξετάστε τα control planes και τα supply-chain surfaces που συχνά καθορίζουν αν ένας attacker χρειάζεται καν kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Στη συνέχεια περάστε στο protection model:

{{#ref}}
protections/
{{#endref}}

Οι σελίδες για τα namespaces εξηγούν ξεχωριστά τα kernel isolation primitives:

{{#ref}}
protections/namespaces/
{{#endref}}

Οι σελίδες για τα cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths και read-only system paths εξηγούν τους μηχανισμούς που συνήθως εφαρμόζονται πάνω από τα namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Μια Καλή Αρχική Νοοτροπία Enumeration

Κατά την αξιολόγηση ενός containerized target, είναι πολύ πιο χρήσιμο να θέσετε ένα μικρό σύνολο ακριβών τεχνικών ερωτήσεων από το να μεταβείτε αμέσως σε γνωστά escape PoCs. Αρχικά, εντοπίστε το **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ή κάτι πιο εξειδικευμένο. Στη συνέχεια εντοπίστε το **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ή άλλη OCI-compatible υλοποίηση. Μετά από αυτό, ελέγξτε αν το περιβάλλον είναι **rootful ή rootless**, αν είναι ενεργά τα **user namespaces**, αν γίνεται κοινή χρήση **host namespaces**, ποιες **capabilities** παραμένουν, αν είναι ενεργοποιημένο το **seccomp**, αν μια **MAC policy** εφαρμόζεται πραγματικά, αν υπάρχουν **επικίνδυνα mounts ή sockets** και αν η διεργασία μπορεί να αλληλεπιδράσει με το container runtime API.

Αυτές οι απαντήσεις σάς πληροφορούν πολύ περισσότερο για το πραγματικό security posture από ό,τι θα σας πληροφορήσει ποτέ το όνομα του base image. Σε πολλές αξιολογήσεις, μπορείτε να προβλέψετε την πιθανή breakout family πριν διαβάσετε έστω και ένα application file, απλώς κατανοώντας την τελική διαμόρφωση του container.

## Κάλυψη

Αυτή η ενότητα καλύπτει το παλαιό Docker-focused υλικό, οργανωμένο γύρω από τα containers: runtime και daemon exposure, authorization plugins, image trust και build secrets, sensitive host mounts, distroless workloads, privileged containers και τις kernel protections που συνήθως εφαρμόζονται γύρω από την εκτέλεση containers.

{{#include ../../../banners/hacktricks-training.md}}
