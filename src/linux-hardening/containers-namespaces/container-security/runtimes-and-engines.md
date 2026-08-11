# Container Runtimes, Engines, Builders, And Sandboxes

Μία από τις μεγαλύτερες πηγές σύγχυσης στο container security είναι ότι αρκετά εντελώς διαφορετικά components συχνά συγχέονται και αναφέρονται με την ίδια λέξη. Το "Docker" μπορεί να αναφέρεται σε format image, CLI, daemon, build system, runtime stack ή απλώς στην ιδέα των containers γενικότερα. Για το security work, αυτή η ασάφεια αποτελεί πρόβλημα, επειδή διαφορετικά layers είναι υπεύθυνα για διαφορετικές προστασίες. Ένα breakout που προκαλείται από ένα λανθασμένο bind mount δεν είναι το ίδιο με ένα breakout που προκαλείται από bug σε low-level runtime, και κανένα από τα δύο δεν είναι το ίδιο με ένα λάθος σε cluster policy στο Kubernetes.

Αυτή η σελίδα διαχωρίζει το ecosystem ανά ρόλο, ώστε το υπόλοιπο section να μπορεί να αναφέρεται με ακρίβεια στο πού βρίσκεται πραγματικά μία προστασία ή αδυναμία.

## OCI As The Common Language

Τα σύγχρονα Linux container stacks συχνά συνεργάζονται επειδή χρησιμοποιούν ένα σύνολο από OCI specifications. Το **OCI Image Specification** περιγράφει τον τρόπο αναπαράστασης των images και των layers. Το **OCI Runtime Specification** περιγράφει τον τρόπο με τον οποίο το runtime πρέπει να εκκινεί το process, συμπεριλαμβανομένων των namespaces, mounts, cgroups και security settings. Το **OCI Distribution Specification** τυποποιεί τον τρόπο με τον οποίο τα registries εκθέτουν content.

Αυτό έχει σημασία επειδή εξηγεί γιατί ένα container image που δημιουργήθηκε με ένα tool μπορεί συχνά να εκτελεστεί με ένα άλλο και γιατί αρκετά engines μπορούν να χρησιμοποιούν το ίδιο low-level runtime. Εξηγεί επίσης γιατί η συμπεριφορά του security μπορεί να φαίνεται παρόμοια σε διαφορετικά products: πολλά από αυτά δημιουργούν το ίδιο OCI runtime configuration και το παραδίδουν στο ίδιο μικρό σύνολο runtimes.

## Low-Level OCI Runtimes

Το low-level runtime είναι το component που βρίσκεται πιο κοντά στο όριο του kernel. Είναι το μέρος που δημιουργεί πραγματικά namespaces, γράφει cgroup settings, εφαρμόζει capabilities και seccomp filters και, τέλος, εκτελεί `execve()` για το container process. Όταν γίνεται συζήτηση για το "container isolation" σε μηχανικό επίπεδο, συνήθως αναφέρονται σε αυτό το layer, ακόμη και αν δεν το δηλώνουν ρητά.

### `runc`

Το `runc` είναι το reference OCI runtime και παραμένει η πιο γνωστή implementation. Χρησιμοποιείται ευρέως κάτω από τα Docker, containerd και πολλά Kubernetes deployments. Μεγάλο μέρος του public research και του exploitation material στοχεύει σε `runc`-style environments, απλώς επειδή είναι συνηθισμένα και επειδή το `runc` ορίζει το baseline που πολλοί έχουν στο μυαλό τους όταν φαντάζονται ένα Linux container. Επομένως, η κατανόηση του `runc` προσφέρει στον αναγνώστη ένα ισχυρό mental model για το κλασικό container isolation.

### `crun`

Το `crun` είναι ένα ακόμη OCI runtime, γραμμένο σε C και ευρέως χρησιμοποιούμενο σε σύγχρονα Podman environments. Συχνά επαινείται για την καλή υποστήριξη του cgroup v2, τα ισχυρά rootless χαρακτηριστικά και το χαμηλότερο overhead. Από την πλευρά του security, το σημαντικό δεν είναι ότι είναι γραμμένο σε διαφορετική γλώσσα, αλλά ότι εξακολουθεί να έχει τον ίδιο ρόλο: είναι το component που μετατρέπει το OCI configuration σε ένα running process tree κάτω από τον kernel. Ένα rootless Podman workflow συχνά φαίνεται πιο ασφαλές όχι επειδή το `crun` διορθώνει μαγικά τα πάντα, αλλά επειδή το συνολικό stack γύρω του τείνει να βασίζεται περισσότερο στα user namespaces και στο least privilege.

### `runsc` From gVisor

Το `runsc` είναι το runtime που χρησιμοποιείται από το gVisor. Εδώ το boundary αλλάζει ουσιαστικά. Αντί να προωθεί τα περισσότερα syscalls απευθείας στον host kernel με τον συνηθισμένο τρόπο, το gVisor εισάγει ένα userspace kernel layer που εξομοιώνει ή διαμεσολαβεί σε μεγάλα τμήματα του Linux interface. Το αποτέλεσμα δεν είναι ένα κανονικό `runc` container με μερικά επιπλέον flags· είναι ένα διαφορετικό sandbox design, σκοπός του οποίου είναι η μείωση του attack surface του host kernel. Οι συμβιβασμοί σε compatibility και performance αποτελούν μέρος αυτού του design, επομένως τα environments που χρησιμοποιούν `runsc` θα πρέπει να τεκμηριώνονται διαφορετικά από τα κανονικά OCI runtime environments.

### `kata-runtime`

Τα Kata Containers μετακινούν ακόμη περισσότερο το boundary, εκκινώντας το workload μέσα σε lightweight virtual machine. Σε επίπεδο administration, αυτό μπορεί να μοιάζει ακόμη με container deployment και τα orchestration layers μπορεί να συνεχίζουν να το αντιμετωπίζουν έτσι, όμως το υποκείμενο isolation boundary είναι πιο κοντά στο virtualization παρά σε ένα κλασικό container που μοιράζεται τον host kernel. Αυτό καθιστά το Kata χρήσιμο όταν απαιτείται ισχυρότερο tenant isolation χωρίς εγκατάλειψη των container-centric workflows.

## Engines And Container Managers

Αν το low-level runtime είναι το component που επικοινωνεί απευθείας με τον kernel, το engine ή manager είναι το component με το οποίο αλληλεπιδρούν συνήθως οι users και οι operators. Διαχειρίζεται image pulls, metadata, logs, networks, volumes, lifecycle operations και API exposure. Αυτό το layer έχει τεράστια σημασία επειδή πολλά compromises στον πραγματικό κόσμο συμβαίνουν εδώ: η πρόσβαση σε runtime socket ή daemon API μπορεί να ισοδυναμεί με host compromise, ακόμη και αν το ίδιο το low-level runtime λειτουργεί άψογα.

### Docker Engine

Το Docker Engine είναι η πιο αναγνωρίσιμη container platform για developers και ένας από τους λόγους για τους οποίους το container vocabulary απέκτησε τόσο έντονα Docker χαρακτηριστικά. Η τυπική διαδρομή είναι από το `docker` CLI στο `dockerd`, το οποίο στη συνέχεια συντονίζει lower-level components όπως τα `containerd` και ένα OCI runtime. Ιστορικά, τα Docker deployments ήταν συχνά **rootful**, επομένως η πρόσβαση στο Docker socket αποτελούσε ιδιαίτερα ισχυρό primitive. Γι' αυτό μεγάλο μέρος του practical privilege-escalation material επικεντρώνεται στο `docker.sock`: αν ένα process μπορεί να ζητήσει από το `dockerd` να δημιουργήσει ένα privileged container, να κάνει mount host paths ή να συνδεθεί στα host namespaces, μπορεί να μη χρειάζεται καθόλου kernel exploit.

### Podman

Το Podman σχεδιάστηκε γύρω από ένα περισσότερο daemonless model. Σε operational επίπεδο, αυτό ενισχύει την ιδέα ότι τα containers είναι απλώς processes που διαχειρίζονται μέσω standard Linux mechanisms και όχι μέσω ενός long-lived privileged daemon. Το Podman διαθέτει επίσης πολύ ισχυρότερο **rootless** story από τα κλασικά Docker deployments με τα οποία ξεκίνησαν να μαθαίνουν πολλοί. Αυτό δεν καθιστά το Podman αυτόματα ασφαλές, αλλά αλλάζει σημαντικά το default risk profile, ειδικά όταν συνδυάζεται με user namespaces, SELinux και `crun`.

### containerd

Το containerd είναι ένα core runtime management component σε πολλά σύγχρονα stacks. Χρησιμοποιείται κάτω από το Docker και αποτελεί επίσης ένα από τα κυρίαρχα Kubernetes runtime backends. Εκθέτει ισχυρά APIs, διαχειρίζεται images και snapshots και αναθέτει την τελική δημιουργία του process σε ένα low-level runtime. Οι συζητήσεις για το security του containerd θα πρέπει να τονίζουν ότι η πρόσβαση στο containerd socket ή στη λειτουργικότητα των `ctr`/`nerdctl` μπορεί να είναι εξίσου επικίνδυνη με την πρόσβαση στο Docker API, ακόμη και αν το interface και το workflow φαίνονται λιγότερο "developer friendly".

### CRI-O

Το CRI-O είναι πιο εστιασμένο από το Docker Engine. Αντί να αποτελεί general-purpose developer platform, έχει δημιουργηθεί γύρω από την καθαρή υλοποίηση του Kubernetes Container Runtime Interface. Αυτό το καθιστά ιδιαίτερα συνηθισμένο σε Kubernetes distributions και SELinux-heavy ecosystems όπως το OpenShift. Από την πλευρά του security, αυτό το πιο περιορισμένο scope είναι χρήσιμο επειδή μειώνει το conceptual clutter: το CRI-O ανήκει ξεκάθαρα στο layer "run containers for Kubernetes" και όχι σε μία platform για τα πάντα.

### Incus, LXD, And LXC

Τα συστήματα Incus/LXD/LXC αξίζει να διαχωρίζονται από τα Docker-style application containers, επειδή χρησιμοποιούνται συχνά ως **system containers**. Συνήθως αναμένεται από ένα system container να μοιάζει περισσότερο με lightweight machine, με πληρέστερο userspace, long-running services, πλουσιότερο device exposure και εκτενέστερη host integration. Οι μηχανισμοί isolation εξακολουθούν να είναι kernel primitives, όμως οι operational προσδοκίες είναι διαφορετικές. Ως αποτέλεσμα, τα misconfigurations εδώ μοιάζουν συχνά λιγότερο με "bad app-container defaults" και περισσότερο με λάθη σε lightweight virtualization ή host delegation.

### systemd-nspawn

Το systemd-nspawn κατέχει μία ενδιαφέρουσα θέση, επειδή είναι systemd-native και ιδιαίτερα χρήσιμο για testing, debugging και εκτέλεση OS-like environments. Δεν είναι το κυρίαρχο cloud-native production runtime, όμως εμφανίζεται αρκετά συχνά σε labs και distro-oriented environments ώστε να αξίζει αναφορά. Για το security analysis, αποτελεί ακόμη μία υπενθύμιση ότι η έννοια "container" καλύπτει πολλά ecosystems και operational styles.

### Apptainer / Singularity

Το Apptainer (πρώην Singularity) είναι συνηθισμένο σε research και HPC environments. Τα trust assumptions, το user workflow και το execution model του διαφέρουν σημαντικά από τα Docker/Kubernetes-centric stacks. Ειδικότερα, αυτά τα environments συχνά δίνουν μεγάλη σημασία στη δυνατότητα των users να εκτελούν packaged workloads χωρίς να τους παρέχουν ευρείες privileged container-management δυνατότητες. Αν ένας reviewer θεωρεί ότι κάθε container environment είναι ουσιαστικά "Docker on a server", θα παρερμηνεύσει σοβαρά αυτά τα deployments.

## Build-Time Tooling

Πολλές συζητήσεις για το security αφορούν μόνο το run time, όμως το build-time tooling έχει επίσης σημασία, επειδή καθορίζει τα image contents, την έκθεση των build secrets και το πόσο trusted context ενσωματώνεται στο τελικό artifact.

Τα **BuildKit** και `docker buildx` είναι σύγχρονα build backends που υποστηρίζουν features όπως caching, secret mounting, SSH forwarding και multi-platform builds. Αυτά είναι χρήσιμα features, αλλά από την πλευρά του security δημιουργούν επίσης σημεία στα οποία secrets μπορούν να διαρρεύσουν σε image layers ή όπου ένα υπερβολικά ευρύ build context μπορεί να εκθέσει αρχεία που δεν θα έπρεπε ποτέ να έχουν συμπεριληφθεί. Το **Buildah** έχει παρόμοιο ρόλο σε OCI-native ecosystems, ειδικά γύρω από το Podman, ενώ το **Kaniko** χρησιμοποιείται συχνά σε CI environments που δεν θέλουν να παραχωρήσουν privileged Docker daemon στο build pipeline.

Το βασικό συμπέρασμα είναι ότι η δημιουργία image και η εκτέλεση image είναι διαφορετικές phases, όμως ένα αδύναμο build pipeline μπορεί να δημιουργήσει ένα αδύναμο runtime posture πολύ πριν εκκινηθεί το container.

## Orchestration Is Another Layer, Not The Runtime

Το Kubernetes δεν θα πρέπει να εξισώνεται νοητικά με το runtime. Το Kubernetes είναι ο orchestrator. Προγραμματίζει Pods, αποθηκεύει desired state και εκφράζει security policy μέσω workload configuration. Στη συνέχεια, το kubelet επικοινωνεί με μία CRI implementation όπως το containerd ή το CRI-O, η οποία με τη σειρά της καλεί ένα low-level runtime όπως τα `runc`, `crun`, `runsc` ή `kata-runtime`.

Αυτός ο διαχωρισμός έχει σημασία επειδή πολλοί αποδίδουν λανθασμένα μία προστασία στο "Kubernetes", ενώ στην πραγματικότητα επιβάλλεται από το node runtime, ή κατηγορούν τα "containerd defaults" για συμπεριφορά που προήλθε από ένα Pod spec. Στην πράξη, το τελικό security posture είναι σύνθεση: ο orchestrator ζητά κάτι, το runtime stack το μεταφράζει και ο kernel το επιβάλλει τελικά.

## Why Runtime Identification Matters During Assessment

Αν εντοπίσετε νωρίς το engine και το runtime, πολλές μεταγενέστερες παρατηρήσεις γίνονται ευκολότερες στην ερμηνεία. Ένα rootless Podman container υποδηλώνει ότι τα user namespaces είναι πιθανότατα μέρος της εικόνας. Ένα Docker socket mounted σε ένα workload υποδηλώνει ότι το API-driven privilege escalation αποτελεί ρεαλιστική διαδρομή. Ένα CRI-O/OpenShift node θα πρέπει αμέσως να σας κάνει να σκεφτείτε SELinux labels και restricted workload policy. Ένα gVisor ή Kata environment θα πρέπει να σας κάνει πιο προσεκτικούς ως προς την υπόθεση ότι ένα κλασικό `runc` breakout PoC θα συμπεριφερθεί με τον ίδιο τρόπο.

Γι' αυτό ένα από τα πρώτα βήματα σε ένα container assessment θα πρέπει πάντα να είναι η απάντηση σε δύο απλές ερωτήσεις: **ποιο component διαχειρίζεται το container** και **ποιο runtime εκκίνησε πραγματικά το process**. Μόλις γίνουν σαφείς αυτές οι απαντήσεις, το υπόλοιπο environment συνήθως γίνεται πολύ ευκολότερο στην ανάλυση.

## Runtime Vulnerabilities

Δεν προέρχεται κάθε container escape από misconfiguration του operator. Μερικές φορές το ίδιο το runtime είναι το vulnerable component. Αυτό έχει σημασία επειδή ένα workload μπορεί να εκτελείται με configuration που φαίνεται προσεκτικό και παρ' όλα αυτά να είναι εκτεθειμένο μέσω ενός low-level runtime flaw.

Το κλασικό παράδειγμα είναι το **CVE-2019-5736** στο `runc`, όπου ένα malicious container μπορούσε να overwrite το host `runc` binary και στη συνέχεια να περιμένει μια μεταγενέστερη κλήση `docker exec` ή παρόμοια runtime invocation για να ενεργοποιήσει attacker-controlled code. Η exploit path διαφέρει σημαντικά από ένα απλό bind-mount ή capability mistake, επειδή εκμεταλλεύεται τον τρόπο με τον οποίο το runtime επανεισέρχεται στο container process space κατά τον χειρισμό του exec.<sup>[[1]](#references)</sup>

Ένα minimal reproduction workflow από την οπτική του red-team είναι:
```bash
go build main.go
./main
```
Έπειτα, από το host:
```bash
docker exec -it <container-name> /bin/sh
```
Το βασικό συμπέρασμα δεν είναι η ακριβής ιστορική υλοποίηση του exploit, αλλά η σημασία για την αξιολόγηση: αν η έκδοση του runtime είναι ευάλωτη, η απλή εκτέλεση κώδικα μέσα στο container μπορεί να αρκεί για την παραβίαση του host, ακόμη και όταν η ορατή διαμόρφωση του container δεν φαίνεται εμφανώς αδύναμη.

Πρόσφατα runtime CVEs, όπως το `CVE-2024-21626` στο `runc`, τα race conditions σε mounts του BuildKit και τα σφάλματα parsing του containerd, ενισχύουν το ίδιο σημείο. Η έκδοση και το patch level του runtime αποτελούν μέρος του security boundary και όχι απλώς ασήμαντες λεπτομέρειες συντήρησης.

## References

- [1] [Έξοδος από το Docker μέσω του runC – Επεξήγηση του CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
