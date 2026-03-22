# Ασφάλεια Κοντέινερ

{{#include ../../../banners/hacktricks-training.md}}

## Τι ακριβώς είναι ένα κοντέινερ

Ένας πρακτικός τρόπος να ορίσουμε ένα κοντέινερ είναι ο εξής: ένα κοντέινερ είναι ένα κανονικό Linux δέντρο διεργασιών που έχει ξεκινήσει υπό μια συγκεκριμένη διαμόρφωση τύπου OCI, ώστε να βλέπει ένα ελεγχόμενο σύστημα αρχείων, ένα ελεγχόμενο σύνολο πόρων του kernel και ένα περιορισμένο μοντέλο προνομίων. Η διεργασία μπορεί να πιστεύει ότι είναι PID 1, να πιστεύει ότι έχει το δικό της network stack, να πιστεύει ότι κατέχει το δικό της hostname και IPC resources, και ακόμη να τρέχει ως root μέσα στο δικό της user namespace. Αλλά κάτω από την επιφάνεια παραμένει μια διεργασία του host που ο kernel προγραμματίζει όπως οποιαδήποτε άλλη.

Γι’ αυτό η ασφάλεια κοντέινερ είναι στην πραγματικότητα η μελέτη του πώς αυτή η ψευδαίσθηση κατασκευάζεται και πώς αποτυγχάνει. Αν το mount namespace είναι αδύναμο, η διεργασία μπορεί να δει το host filesystem. Αν το user namespace απουσιάζει ή είναι απενεργοποιημένο, το root μέσα στο κοντέινερ μπορεί να αντιστοιχεί πολύ στενά στο root του host. Αν το seccomp είναι μη περιορισμένο και το capability set είναι πολύ ευρύ, η διεργασία μπορεί να φτάσει σε syscalls και προνομιούχες λειτουργίες του kernel που θα έπρεπε να είναι εκτός εμβέλειας. Αν το runtime socket είναι mounted μέσα στο κοντέινερ, το κοντέινερ μπορεί να μην χρειάζεται καν kernel breakout επειδή απλώς μπορεί να ζητήσει από το runtime να εκκινήσει ένα πιο ισχυρό sibling container ή να mount-άρει απευθείας το host root filesystem.

## Πώς διαφέρουν τα κοντέινερ από τις εικονικές μηχανές

Μια VM συνήθως φέρει τον δικό της kernel και ένα όριο αφαίρεσης hardware. Αυτό σημαίνει ότι ο guest kernel μπορεί να καταρρεύσει, να πανικοβληθεί ή να εκμεταλλευτεί χωρίς αυτό να συνεπάγεται άμεσο έλεγχο του host kernel. Στα κοντέινερ, το workload δεν έχει ξεχωριστό kernel. Αντίθετα, έχει μια προσεκτικά φιλτραρισμένη και namespaced άποψη του ίδιου kernel που χρησιμοποιεί ο host. Ως αποτέλεσμα, τα κοντέινερ είναι συνήθως πιο ελαφριά, πιο γρήγορα στο ξεκίνημα, ευκολότερα στο να τοποθετηθούν πυκνά σε ένα μηχάνημα και καλύτερα προσαρμοσμένα για την ανάπτυξη βραχύβιων εφαρμογών. Το κόστος είναι ότι το όριο απομόνωσης εξαρτάται πολύ περισσότερο από τη σωστή διαμόρφωση του host και του runtime.

Αυτό δεν σημαίνει ότι τα κοντέινερ είναι «ανασφαλή» και οι VM «ασφαλείς». Σημαίνει ότι το μοντέλο ασφαλείας είναι διαφορετικό. Μια καλά διαμορφωμένη στοίβα κοντέινερ με rootless execution, user namespaces, default seccomp, ένα αυστηρό capability set, χωρίς κοινή χρήση host namespaces και με ισχυρή επιβολή SELinux ή AppArmor μπορεί να είναι πολύ ανθεκτική. Αντίθετα, ένα κοντέινερ που ξεκινάει με `--privileged`, κοινή χρήση host PID/network, το Docker socket mounted μέσα του, και ένα writable bind mount του `/` είναι λειτουργικά πολύ πιο κοντά σε πρόσβαση host root παρά σε με ασφάλεια απομονωμένο sandbox εφαρμογής. Η διαφορά προέρχεται από τα στρώματα που ενεργοποιήθηκαν ή απενεργοποιήθηκαν.

Υπάρχει επίσης μια μεσοβέζικη λύση που οι αναγνώστες πρέπει να κατανοήσουν γιατί εμφανίζεται όλο και πιο συχνά σε πραγματικά περιβάλλοντα. Οι sandboxed container runtimes όπως gVisor και Kata Containers σκληραίνουν σκόπιμα το όριο πέρα από ένα κλασικό `runc` container. Το gVisor τοποθετεί ένα userspace kernel layer ανάμεσα στο workload και πολλές διεπαφές του host kernel, ενώ το Kata εκκινεί το workload μέσα σε μια ελαφριά virtual machine. Αυτά εξακολουθούν να χρησιμοποιούνται μέσω οικοσυστημάτων container και orchestration workflows, αλλά οι ιδιότητες ασφαλείας τους διαφέρουν από τα απλά OCI runtimes και δεν πρέπει να θεωρούνται νοητικά ισάξια με «κανονικά Docker containers» σαν να συμπεριφέρονται όλα με τον ίδιο τρόπο.

## Η στοίβα του κοντέινερ: Πολλά στρώματα, όχι ένα

Όταν κάποιος λέει «αυτό το κοντέινερ είναι ανασφαλές», η χρήσιμη επόμενη ερώτηση είναι: ποιο στρώμα το έκανε ανασφαλές; Ένα containerized workload συνήθως είναι αποτέλεσμα συνεργασίας πολλών συστατικών.

Στην κορυφή υπάρχει συχνά ένα image build layer όπως BuildKit, Buildah, ή Kaniko, που δημιουργεί το OCI image και τα metadata. Πάνω από το χαμηλού επιπέδου runtime μπορεί να υπάρχει ένας engine ή manager όπως Docker Engine, Podman, containerd, CRI-O, Incus, ή systemd-nspawn. Σε cluster περιβάλλοντα μπορεί επίσης να υπάρχει ένας orchestrator όπως το Kubernetes που αποφασίζει την ζητούμενη security posture μέσω της διαμόρφωσης του workload. Τέλος, ο kernel είναι αυτός που πράγματι επιβάλλει namespaces, cgroups, seccomp και MAC policy.

Αυτό το μοντέλο με στρώματα είναι σημαντικό για την κατανόηση των προεπιλογών. Ένας περιορισμός μπορεί να ζητηθεί από το Kubernetes, να μεταφραστεί μέσω CRI από containerd ή CRI-O, να μετατραπεί σε OCI spec από το runtime wrapper και μόνο τότε να επιβληθεί από `runc`, `crun`, `runsc` ή άλλο runtime έναντι του kernel. Όταν οι προεπιλογές διαφέρουν μεταξύ περιβαλλόντων, συχνά οφείλεται στο ότι ένα από αυτά τα στρώματα άλλαξε την τελική διαμόρφωση. Ο ίδιος μηχανισμός μπορεί επομένως να εμφανίζεται στο Docker ή Podman ως CLI flag, στο Kubernetes ως Pod ή πεδίο `securityContext`, και σε χαμηλότερου επιπέδου runtime stacks ως OCI configuration που παράγεται για το workload. Για αυτόν τον λόγο, τα CLI παραδείγματα σε αυτή την ενότητα θα πρέπει να διαβάζονται ως runtime-specific σύνταξη για μια γενική έννοια container, όχι ως καθολικές σημαίες που υποστηρίζονται από κάθε εργαλείο.

## Το πραγματικό όριο ασφάλειας του κοντέινερ

Στην πράξη, η ασφάλεια κοντέινερ προέρχεται από επικαλυπτόμενους ελέγχους, όχι από έναν τέλειο έλεγχο. Οι namespaces απομονώνουν την ορατότητα. Οι cgroups ρυθμίζουν και περιορίζουν τη χρήση πόρων. Οι capabilities μειώνουν το τι μπορεί πραγματικά να κάνει μια διεργασία που φαίνεται προνομιούχα. Το seccomp μπλοκάρει επικίνδυνα syscalls πριν φτάσουν στον kernel. Το AppArmor και το SELinux προσθέτουν Mandatory Access Control πάνω από τους κανονικούς DAC ελέγχους. Τα `no_new_privs`, τα masked procfs paths και τα read-only system paths κάνουν τις κοινές αλυσίδες κατάχρησης προνομίων και proc/sys δυσκολότερες. Το ίδιο το runtime επίσης έχει σημασία επειδή αποφασίζει πώς δημιουργούνται mounts, sockets, labels και namespace joins.

Γι’ αυτό πολλή τεκμηρίωση για την ασφάλεια κοντέινερ φαίνεται επαναληπτική. Η ίδια αλυσίδα απόδρασης συχνά εξαρτάται από πολλαπλούς μηχανισμούς ταυτόχρονα. Για παράδειγμα, ένα writable host bind mount είναι κακό, αλλά γίνεται πολύ χειρότερο αν το κοντέινερ επίσης τρέχει ως πραγματικό root στο host, έχει `CAP_SYS_ADMIN`, είναι μη περιορισμένο από seccomp και δεν περιορίζεται από SELinux ή AppArmor. Ομοίως, η κοινή χρήση host PID είναι μια σοβαρή έκθεση, αλλά γίνεται δραματικά πιο χρήσιμη σε έναν attacker όταν συνδυάζεται με `CAP_SYS_PTRACE`, αδύνατες προστασίες procfs, ή εργαλεία εισόδου σε namespace όπως `nsenter`. Ο σωστός τρόπος να τεκμηριωθεί το θέμα λοιπόν δεν είναι να επαναληφθεί η ίδια επίθεση σε κάθε σελίδα, αλλά να εξηγηθεί τι συμβάλλει κάθε στρώμα στο τελικό όριο.

## Πώς να διαβάσετε αυτή την ενότητα

Η ενότητα είναι οργανωμένη από τις πιο γενικές έννοιες προς τις πιο συγκεκριμένες.

Ξεκινήστε με την επισκόπηση του runtime και του οικοσυστήματος:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Έπειτα ανασκοπήστε τα control planes και τις επιφάνειες supply-chain που συχνά αποφασίζουν αν ένας attacker χρειάζεται καν kernel escape:

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

Έπειτα προχωρήστε στο protection model:

{{#ref}}
protections/
{{#endref}}

Οι σελίδες σχετικά με namespaces εξηγούν μεμονωμένα τα primitives απομόνωσης του kernel:

{{#ref}}
protections/namespaces/
{{#endref}}

Οι σελίδες για cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths και read-only system paths εξηγούν τους μηχανισμούς που συνήθως τοποθετούνται πάνω από τα namespaces:

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

## Μια καλή αρχική νοοτροπία για enumeration

Κατά την αξιολόγηση ενός containerized στόχου, είναι πολύ πιο χρήσιμο να τεθούν λίγες ακριβείς τεχνικές ερωτήσεις παρά να πηδήξει κανείς αμέσως σε διάσημα escape PoCs. Πρώτα, προσδιορίστε το stack: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ή κάτι πιο εξειδικευμένο. Έπειτα προσδιορίστε το runtime: `runc`, `crun`, `runsc`, `kata-runtime` ή άλλη OCI-compatible υλοποίηση. Μετά ελέγξτε αν το περιβάλλον είναι rootful ή rootless, αν τα user namespaces είναι ενεργά, αν μοιράζονται host namespaces, ποιες capabilities παραμένουν, αν το seccomp είναι ενεργοποιημένο, αν μια MAC policy όντως επιβάλλεται, αν υπάρχουν επικίνδυνα mounts ή sockets, και αν η διεργασία μπορεί να αλληλεπιδράσει με το container runtime API.

Αυτές οι απαντήσεις σας λένε πολύ περισσότερα για την πραγματική ασφάλεια από το όνομα της base image. Σε πολλές αξιολογήσεις, μπορείτε να προβλέψετε την πιθανή οικογένεια breakout πριν διαβάσετε ένα μόνο αρχείο εφαρμογής απλώς κατανοώντας την τελική διαμόρφωση του κοντέινερ.

## Κάλυψη

Αυτή η ενότητα καλύπτει το παλιό Docker-focused υλικό υπό container-oriented οργάνωση: runtime and daemon exposure, authorization plugins, image trust and build secrets, sensitive host mounts, distroless workloads, privileged containers και τους kernel protections που συνήθως στοιβάζονται γύρω από την εκτέλεση container.
{{#include ../../../banners/hacktricks-training.md}}
