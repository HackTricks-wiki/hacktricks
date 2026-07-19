# Ασφάλεια Container

{{#include ../../../banners/hacktricks-training.md}}

## Τι Είναι Στην Πραγματικότητα Ένα Container

Ένας πρακτικός τρόπος να ορίσουμε ένα container είναι ο εξής: ένα container είναι ένα **κανονικό Linux process tree** που έχει ξεκινήσει υπό μια συγκεκριμένη διαμόρφωση τύπου OCI, ώστε να βλέπει ένα ελεγχόμενο filesystem, ένα ελεγχόμενο σύνολο kernel resources και ένα περιορισμένο privilege model. Η διεργασία μπορεί να πιστεύει ότι είναι το PID 1, να πιστεύει ότι έχει το δικό της network stack, να πιστεύει ότι διαθέτει το δικό της hostname και IPC resources, και ακόμη να εκτελείται ως root μέσα στο δικό της user namespace. Ωστόσο, κάτω από το επίπεδο abstraction παραμένει μια διεργασία του host, την οποία ο kernel προγραμματίζει όπως οποιαδήποτε άλλη.

Γι' αυτό η ασφάλεια των container αφορά στην πραγματικότητα τη μελέτη του τρόπου με τον οποίο δημιουργείται αυτή η ψευδαίσθηση και του τρόπου με τον οποίο αποτυγχάνει. Αν το mount namespace είναι αδύναμο, η διεργασία μπορεί να δει το filesystem του host. Αν το user namespace απουσιάζει ή είναι απενεργοποιημένο, το root μέσα στο container μπορεί να αντιστοιχεί υπερβολικά άμεσα στο root του host. Αν το seccomp είναι unconfined και το capability set είναι υπερβολικά ευρύ, η διεργασία μπορεί να καλέσει syscalls και privileged kernel features που θα έπρεπε να παραμένουν απρόσιτα. Αν το runtime socket είναι mounted μέσα στο container, το container μπορεί να μη χρειάζεται καν kernel breakout, επειδή μπορεί απλώς να ζητήσει από το runtime να εκκινήσει ένα ισχυρότερο sibling container ή να κάνει mount απευθείας το host root filesystem.

## Πώς Διαφέρουν Τα Containers Από Τα Virtual Machines

Ένα VM συνήθως διαθέτει τον δικό του kernel και το δικό του hardware abstraction boundary. Αυτό σημαίνει ότι ο guest kernel μπορεί να καταρρεύσει, να προκαλέσει panic ή να γίνει exploited, χωρίς αυτό να συνεπάγεται αυτόματα άμεσο έλεγχο του host kernel. Στα containers, το workload δεν αποκτά ξεχωριστό kernel. Αντίθετα, αποκτά μια προσεκτικά φιλτραρισμένη και namespaced προβολή του ίδιου kernel που χρησιμοποιεί ο host. Ως αποτέλεσμα, τα containers είναι συνήθως ελαφρύτερα, ξεκινούν ταχύτερα, επιτρέπουν μεγαλύτερη πυκνότητα workloads σε ένα machine και είναι καταλληλότερα για βραχύβιο application deployment. Το τίμημα είναι ότι το isolation boundary εξαρτάται πολύ περισσότερο από τη σωστή διαμόρφωση του host και του runtime.

Αυτό δεν σημαίνει ότι τα containers είναι "insecure" και τα VMs "secure". Σημαίνει ότι το security model είναι διαφορετικό. Ένα σωστά διαμορφωμένο container stack με rootless execution, user namespaces, default seccomp, αυστηρό capability set, χωρίς host namespace sharing και με ισχυρή επιβολή SELinux ή AppArmor μπορεί να είναι πολύ ανθεκτικό. Αντίθετα, ένα container που ξεκινά με `--privileged`, host PID/network sharing, mounted Docker socket και writable bind mount του `/` είναι λειτουργικά πολύ πιο κοντά στην πρόσβαση host root παρά σε ένα με ασφάλεια απομονωμένο application sandbox. Η διαφορά προκύπτει από τα layers που ενεργοποιήθηκαν ή απενεργοποιήθηκαν.

Υπάρχει επίσης μια ενδιάμεση κατηγορία που οι readers πρέπει να κατανοούν, επειδή εμφανίζεται όλο και συχνότερα σε πραγματικά environments. Τα **Sandboxed container runtimes**, όπως τα **gVisor** και **Kata Containers**, ενισχύουν σκόπιμα το boundary πέρα από ένα κλασικό `runc` container. Το gVisor τοποθετεί ένα userspace kernel layer μεταξύ του workload και πολλών host kernel interfaces, ενώ το Kata εκτελεί το workload μέσα σε ένα lightweight virtual machine. Αυτά εξακολουθούν να χρησιμοποιούνται μέσω container ecosystems και orchestration workflows, όμως οι security properties τους διαφέρουν από εκείνες των plain OCI runtimes και δεν πρέπει νοητικά να ομαδοποιούνται με τα "normal Docker containers", σαν να λειτουργούν όλα με τον ίδιο τρόπο.

## Το Container Stack: Πολλά Layers, Όχι Ένα

Όταν κάποιος λέει "αυτό το container είναι insecure", η χρήσιμη επόμενη ερώτηση είναι: **ποιο layer το έκανε insecure;** Ένα containerized workload είναι συνήθως αποτέλεσμα της συνεργασίας πολλών components.

Στην κορυφή υπάρχει συχνά ένα **image build layer**, όπως τα BuildKit, Buildah ή Kaniko, που δημιουργεί το OCI image και τα metadata. Πάνω από το low-level runtime μπορεί να υπάρχει ένα **engine ή manager**, όπως τα Docker Engine, Podman, containerd, CRI-O, Incus ή systemd-nspawn. Σε cluster environments μπορεί επίσης να υπάρχει ένας **orchestrator**, όπως το Kubernetes, που αποφασίζει το requested security posture μέσω του workload configuration. Τέλος, ο **kernel** είναι αυτός που επιβάλλει στην πράξη τα namespaces, τα cgroups, το seccomp και το MAC policy.

Αυτό το layered model είναι σημαντικό για την κατανόηση των defaults. Ένας περιορισμός μπορεί να ζητηθεί από το Kubernetes, να μεταφραστεί μέσω CRI από το containerd ή το CRI-O, να μετατραπεί σε OCI spec από το runtime wrapper και μόνο τότε να επιβληθεί από τα `runc`, `crun`, `runsc` ή άλλο runtime στον kernel. Όταν τα defaults διαφέρουν μεταξύ environments, συχνά αυτό συμβαίνει επειδή ένα από αυτά τα layers άλλαξε το τελικό configuration. Ο ίδιος μηχανισμός μπορεί επομένως να εμφανίζεται στο Docker ή το Podman ως CLI flag, στο Kubernetes ως Pod ή `securityContext` field και σε lower-level runtime stacks ως OCI configuration που δημιουργήθηκε για το workload. Για τον λόγο αυτό, τα CLI examples σε αυτή την ενότητα πρέπει να διαβάζονται ως **runtime-specific syntax για μια γενική έννοια container** και όχι ως universal flags που υποστηρίζονται από κάθε tool.

## Το Πραγματικό Container Security Boundary

Στην πράξη, η ασφάλεια των container προκύπτει από **επικαλυπτόμενα controls** και όχι από ένα μοναδικό τέλειο control. Τα namespaces απομονώνουν την ορατότητα. Τα cgroups διαχειρίζονται και περιορίζουν τη χρήση resources. Τα capabilities μειώνουν όσα μπορεί πραγματικά να κάνει μια διεργασία που φαίνεται privileged. Το seccomp αποκλείει επικίνδυνα syscalls πριν φτάσουν στον kernel. Τα AppArmor και SELinux προσθέτουν Mandatory Access Control πάνω από τους κανονικούς DAC checks. Τα `no_new_privs`, τα masked procfs paths και τα read-only system paths δυσκολεύουν συνηθισμένες αλυσίδες privilege και proc/sys abuse. Σημαντικό είναι επίσης το ίδιο το runtime, επειδή αποφασίζει πώς δημιουργούνται τα mounts, τα sockets, τα labels και τα namespace joins.

Γι' αυτό πολλά documentation για container security φαίνονται επαναλαμβανόμενα. Η ίδια escape chain συχνά εξαρτάται ταυτόχρονα από πολλούς μηχανισμούς. Για παράδειγμα, ένα writable host bind mount είναι κακό, αλλά γίνεται πολύ χειρότερο αν το container εκτελείται επίσης ως πραγματικό root στον host, διαθέτει `CAP_SYS_ADMIN`, είναι unconfined από το seccomp και δεν περιορίζεται από SELinux ή AppArmor. Παρομοίως, το host PID sharing είναι σοβαρή έκθεση, αλλά γίνεται δραματικά πιο χρήσιμο για έναν attacker όταν συνδυάζεται με `CAP_SYS_PTRACE`, αδύναμες procfs protections ή εργαλεία namespace-entry όπως το `nsenter`. Ο σωστός τρόπος τεκμηρίωσης του θέματος δεν είναι επομένως η επανάληψη της ίδιας επίθεσης σε κάθε σελίδα, αλλά η εξήγηση της συνεισφοράς κάθε layer στο τελικό boundary.

## Πώς Να Διαβάσετε Αυτή Την Ενότητα

Η ενότητα είναι οργανωμένη από τις πιο γενικές έννοιες προς τις πιο συγκεκριμένες.

Ξεκινήστε με το runtime και το ecosystem overview:

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

Οι σελίδες για τα cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths και read-only system paths εξηγούν τους μηχανισμούς που συνήθως εφαρμόζονται επιπλέον των namespaces:

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

## Μια Καλή Αρχική Νοοτροπία Για Enumeration

Κατά την αξιολόγηση ενός containerized target, είναι πολύ πιο χρήσιμο να θέτετε ένα μικρό σύνολο ακριβών τεχνικών ερωτήσεων παρά να μεταπηδάτε αμέσως σε γνωστά escape PoCs. Αρχικά, εντοπίστε το **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ή κάτι πιο εξειδικευμένο. Στη συνέχεια εντοπίστε το **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ή άλλη OCI-compatible υλοποίηση. Μετά από αυτό, ελέγξτε αν το environment είναι **rootful ή rootless**, αν είναι ενεργά τα **user namespaces**, αν γίνεται shared κάποιο **host namespace**, ποια **capabilities** παραμένουν, αν είναι ενεργοποιημένο το **seccomp**, αν ένα **MAC policy** επιβάλλεται πραγματικά, αν υπάρχουν **dangerous mounts ή sockets** και αν η διεργασία μπορεί να αλληλεπιδράσει με το container runtime API.

Αυτές οι απαντήσεις σας πληροφορούν πολύ περισσότερο για το πραγματικό security posture από ό,τι θα σας πληροφορήσει ποτέ το όνομα του base image. Σε πολλές assessments μπορείτε να προβλέψετε την πιθανή breakout family πριν διαβάσετε έστω και ένα application file, απλώς κατανοώντας το τελικό container configuration.

## Κάλυψη

Αυτή η ενότητα καλύπτει το παλιό Docker-focused υλικό σε container-oriented οργάνωση: runtime και daemon exposure, authorization plugins, image trust και build secrets, sensitive host mounts, distroless workloads, privileged containers και τις kernel protections που συνήθως εφαρμόζονται γύρω από την εκτέλεση container.
{{#include ../../../banners/hacktricks-training.md}}
