# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

Ένας πρακτικός τρόπος να ορίσουμε ένα container είναι ο εξής: ένα container είναι ένα **regular Linux process tree** που έχει ξεκινήσει κάτω από μια συγκεκριμένη OCI-style configuration έτσι ώστε να βλέπει ένα ελεγχόμενο filesystem, ένα ελεγχόμενο σύνολο kernel resources, και ένα περιορισμένο μοντέλο προνομίων. Η διεργασία μπορεί να πιστεύει ότι είναι PID 1, να νομίζει ότι έχει το δικό της network stack, ότι κατέχει το δικό της hostname και IPC resources, και μπορεί ακόμη να τρέχει ως root μέσα στο δικό της user namespace. Αλλά κάτω από την επιφάνεια είναι ακόμη μια διεργασία του host που ο kernel χρονοδρομεί όπως κάθε άλλη.

Γι' αυτό το container security είναι στην ουσία η μελέτη του πώς αυτή η ψευδαίσθηση κατασκευάζεται και πώς αποτυγχάνει. Αν το mount namespace είναι αδύναμο, η διεργασία μπορεί να δει το host filesystem. Αν το user namespace απουσιάζει ή είναι απενεργοποιημένο, το root μέσα στο container μπορεί να αντιστοιχεί πολύ κοντά στο root του host. Αν το seccomp είναι ανεπεξέργαστο και το capability set είναι πολύ ευρύ, η διεργασία μπορεί να φτάσει syscalls και privileged kernel features που θα έπρεπε να παραμείνουν εκτός εμβέλειας. Αν το runtime socket είναι mounted μέσα στο container, το container μπορεί να μην χρειαστεί καν kernel breakout επειδή απλώς μπορεί να ζητήσει από το runtime να ξεκινήσει ένα πιο ισχυρό sibling container ή να mountάρει απευθείας το host root filesystem.

## How Containers Differ From Virtual Machines

Ένα VM συνήθως φέρει το δικό του kernel και ένα hardware abstraction boundary. Αυτό σημαίνει ότι ο guest kernel μπορεί να καταρρεύσει, να panicάρει, ή να εκμεταλλευτεί χωρίς αυτό να συνεπάγεται αυτόματα άμεσο έλεγχο του host kernel. Στα containers, το workload δεν παίρνει ξεχωριστό kernel. Αντίθετα, παίρνει μια προσεκτικά φιλτραρισμένη και namespaced view του ίδιου kernel που χρησιμοποιεί ο host. Ως αποτέλεσμα, τα containers συνήθως είναι πιο ελαφριά, γρηγορότερα στο start, πιο εύκολα στο να πακεταριστούν πυκνά σε μια μηχανή, και καλύτερα προσαρμοσμένα για short-lived application deployment. Το κόστος είναι ότι το isolation boundary εξαρτάται πολύ πιο άμεσα από τη σωστή host και runtime configuration.

Αυτό δεν σημαίνει ότι τα containers είναι "insecure" και τα VMs "secure". Σημαίνει ότι το security model είναι διαφορετικό. Ένα καλά-διαμορφωμένο container stack με rootless execution, user namespaces, default seccomp, ένα strict capability set, χωρίς host namespace sharing, και ισχυρή SELinux ή AppArmor enforcement μπορεί να είναι πολύ ανθεκτικό. Αντίθετα, ένα container που ξεκίνησε με `--privileged`, host PID/network sharing, το Docker socket mounted μέσα του, και ένα writable bind mount του `/` είναι λειτουργικά πολύ πιο κοντά σε host root access παρά σε ένα ασφαλισμένο application sandbox. Η διαφορά προκύπτει από τα layers που ενεργοποιήθηκαν ή απενεργοποιήθηκαν.

Υπάρχει επίσης ένας μεσαίος δρόμος που οι αναγνώστες πρέπει να κατανοήσουν επειδή εμφανίζεται όλο και πιο συχνά σε πραγματικά περιβάλλοντα. **Sandboxed container runtimes** όπως **gVisor** και **Kata Containers** σκόπιμα ενισχύουν το boundary πέρα από έναν κλασικό `runc` container. Το gVisor τοποθετεί ένα userspace kernel layer ανάμεσα στο workload και πολλές host kernel interfaces, ενώ το Kata εκκινεί το workload μέσα σε ένα lightweight virtual machine. Αυτά εξακολουθούν να χρησιμοποιούνται μέσω container ecosystems και orchestration workflows, αλλά οι security ιδιότητές τους διαφέρουν από τα απλά OCI runtimes και δεν πρέπει να ομαδοποιούνται νοητικά με τα "normal Docker containers" σαν να συμπεριφέρονται όλα το ίδιο.

## The Container Stack: Several Layers, Not One

Όταν κάποιος λέει "this container is insecure", η χρήσιμη επόμενη ερώτηση είναι: **ποιο layer το έκανε insecure;** Ένα containerized workload είναι συνήθως το αποτέλεσμα αρκετών components που συνεργάζονται.

Στην κορυφή, υπάρχει συχνά ένα **image build layer** όπως BuildKit, Buildah, ή Kaniko, το οποίο δημιουργεί το OCI image και τα metadata. Πάνω από το low-level runtime, μπορεί να υπάρχει ένας **engine or manager** όπως Docker Engine, Podman, containerd, CRI-O, Incus, ή systemd-nspawn. Σε cluster περιβάλλοντα, μπορεί επίσης να υπάρχει ένας **orchestrator** όπως Kubernetes που αποφασίζει το ζητούμενο security posture μέσω workload configuration. Τέλος, ο **kernel** είναι αυτός που στην πράξη επιβάλει namespaces, cgroups, seccomp, και MAC policy.

Αυτό το layered model είναι σημαντικό για την κατανόηση των defaults. Μια restriction μπορεί να ζητηθεί από Kubernetes, να μεταφραστεί μέσω CRI από containerd ή CRI-O, να μετατραπεί σε OCI spec από τον runtime wrapper, και μόνο τότε να επιβληθεί από `runc`, `crun`, `runsc`, ή άλλο runtime απέναντι στον kernel. Όταν τα defaults διαφέρουν μεταξύ περιβαλλόντων, συχνά οφείλεται στο ότι ένα από αυτά τα layers άλλαξε την τελική configuration. Ο ίδιος μηχανισμός μπορεί επομένως να εμφανίζεται σε Docker ή Podman ως CLI flag, σε Kubernetes ως Pod ή πεδίο `securityContext`, και σε lower-level runtime stacks ως OCI configuration που παράχθηκε για το workload. Για αυτόν τον λόγο, τα CLI παραδείγματα σε αυτή την ενότητα πρέπει να διαβαστούν ως **runtime-specific syntax για ένα γενικό container concept**, όχι ως universal flags που υποστηρίζονται από κάθε εργαλείο.

## The Real Container Security Boundary

Στην πράξη, το container security προέρχεται από **overlapping controls**, όχι από ένα τέλειο μόνο control. Τα namespaces απομονώνουν την ορατότητα. Τα cgroups διέπουν και περιορίζουν τη χρήση πόρων. Οι Capabilities μειώνουν το τι μια διεργασία που φαίνεται privileged μπορεί πραγματικά να κάνει. Το seccomp μπλοκάρει επικίνδυνες syscalls πριν φτάσουν στον kernel. AppArmor και SELinux προσθέτουν Mandatory Access Control πάνω από τους κανονικούς DAC ελέγχους. Το `no_new_privs`, masked procfs paths, και read-only system paths κάνουν τις κοινές αλυσίδες κατάχρησης προνομίων και proc/sys πιο δύσκολες. Το ίδιο το runtime επίσης μετράει επειδή αποφασίζει πώς δημιουργούνται mounts, sockets, labels, και namespace joins.

Γι' αυτό πολλά documentation για container security φαίνεται επαναλαμβανόμενο. Η ίδια escape chain συχνά εξαρτάται από πολλούς μηχανισμούς ταυτόχρονα. Για παράδειγμα, ένα writable host bind mount είναι κακό, αλλά γίνεται πολύ χειρότερο αν το container επίσης τρέχει ως real root στο host, έχει `CAP_SYS_ADMIN`, δεν περιορίζεται από seccomp, και δεν ελέγχεται από SELinux ή AppArmor. Ομοίως, το host PID sharing είναι σοβαρή έκθεση, αλλά γίνεται δραματικά πιο χρήσιμο για έναν attacker όταν συνδυάζεται με `CAP_SYS_PTRACE`, αδύνατες procfs protections, ή εργαλεία entry όπως `nsenter`. Ο σωστός τρόπος να τεκμηριώσεις το θέμα επομένως δεν είναι να επαναλαμβάνεις την ίδια επίθεση σε κάθε σελίδα, αλλά να εξηγείς τι συμβάλλει κάθε layer στο τελικό boundary.

## How To Read This Section

Η ενότητα είναι οργανωμένη από τις πιο γενικές έννοιες προς τις πιο συγκεκριμένες.

Ξεκινήστε με το runtime και ecosystem overview:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Στη συνέχεια ελέγξτε τα control planes και supply-chain surfaces που συχνά αποφασίζουν αν ένας attacker χρειάζεται καν kernel escape:

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

Έπειτα μεταβείτε στο protection model:

{{#ref}}
protections/
{{#endref}}

Οι σελίδες για τα namespaces εξηγούν τα kernel isolation primitives ξεχωριστά:

{{#ref}}
protections/namespaces/
{{#endref}}

Οι σελίδες για cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, και read-only system paths εξηγούν τους μηχανισμούς που συνήθως στρωματώνονται πάνω από τα namespaces:

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

## A Good First Enumeration Mindset

Όταν αξιολογείτε έναν containerized στόχο, είναι πολύ πιο χρήσιμο να κάνετε μια μικρή σειρά ακριβών τεχνικών ερωτήσεων παρά να πηδήξετε αμέσως σε διάσημα escape PoCs. Πρώτα, εντοπίστε το **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, ή κάτι πιο εξειδικευμένο. Έπειτα εντοπίστε το **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, ή κάποια άλλη OCI-compatible implementation. Μετά από αυτό, ελέγξτε αν το περιβάλλον είναι **rootful ή rootless**, αν τα **user namespaces** είναι ενεργά, αν κοινάζονται **host namespaces**, ποιες **capabilities** παραμένουν, αν το **seccomp** είναι ενεργοποιημένο, αν μια **MAC policy** πραγματικά επιβάλλεται, αν υπάρχουν **dangerous mounts or sockets**, και αν η διεργασία μπορεί να αλληλεπιδράσει με το container runtime API.

Αυτές οι απαντήσεις σας λένε πολύ περισσότερα για το πραγματικό security posture από το όνομα της base image. Σε πολλές αξιολογήσεις, μπορείτε να προβλέψετε την πιθανή οικογένεια breakout πριν διαβάσετε ένα μόνο αρχείο εφαρμογής απλώς κατανοώντας την τελική container configuration.

## Coverage

Αυτή η ενότητα καλύπτει το παλιό Docker-focused υλικό υπό container-oriented οργάνωση: runtime and daemon exposure, authorization plugins, image trust and build secrets, sensitive host mounts, distroless workloads, privileged containers, και τις kernel protections που συνήθως στρωματώνονται γύρω από το container execution.
