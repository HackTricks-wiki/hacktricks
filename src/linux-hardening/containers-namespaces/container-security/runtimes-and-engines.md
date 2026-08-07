# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Μία από τις μεγαλύτερες πηγές σύγχυσης στο container security είναι ότι αρκετά εντελώς διαφορετικά components συχνά συγχωνεύονται κάτω από την ίδια λέξη. Το "Docker" μπορεί να αναφέρεται σε format images, CLI, daemon, build system, runtime stack ή απλώς στη γενική ιδέα των containers. Για το security work, αυτή η ασάφεια αποτελεί πρόβλημα, επειδή διαφορετικά layers είναι υπεύθυνα για διαφορετικές protections. Ένα breakout που προκαλείται από κακό bind mount δεν είναι το ίδιο με ένα breakout που προκαλείται από low-level runtime bug, ενώ κανένα από τα δύο δεν είναι το ίδιο με ένα cluster policy mistake στο Kubernetes.

Αυτή η σελίδα διαχωρίζει το ecosystem ανά ρόλο, ώστε το υπόλοιπο section να μπορεί να αναφέρεται με ακρίβεια στο πού βρίσκεται πραγματικά μια protection ή weakness.

## OCI As The Common Language

Τα σύγχρονα Linux container stacks συχνά συνεργάζονται επειδή χρησιμοποιούν ένα σύνολο από OCI specifications. Το **OCI Image Specification** περιγράφει τον τρόπο αναπαράστασης των images και των layers. Το **OCI Runtime Specification** περιγράφει τον τρόπο με τον οποίο το runtime πρέπει να εκκινεί το process, συμπεριλαμβανομένων των namespaces, mounts, cgroups και security settings. Το **OCI Distribution Specification** τυποποιεί τον τρόπο με τον οποίο τα registries εκθέτουν content.

Αυτό έχει σημασία επειδή εξηγεί γιατί ένα container image που δημιουργήθηκε με ένα tool μπορεί συχνά να εκτελεστεί με κάποιο άλλο και γιατί αρκετά engines μπορούν να μοιράζονται το ίδιο low-level runtime. Εξηγεί επίσης γιατί η security συμπεριφορά μπορεί να μοιάζει μεταξύ διαφορετικών products: πολλά από αυτά δημιουργούν το ίδιο OCI runtime configuration και το παραδίδουν στο ίδιο μικρό σύνολο runtimes.

## Low-Level OCI Runtimes

Το low-level runtime είναι το component που βρίσκεται πιο κοντά στο kernel boundary. Είναι το τμήμα που δημιουργεί πραγματικά namespaces, γράφει cgroup settings, εφαρμόζει capabilities και seccomp filters και τελικά εκτελεί `execve()` για το container process. Όταν γίνεται συζήτηση για "container isolation" σε μηχανικό επίπεδο, συνήθως αναφέρονται σε αυτό το layer, ακόμη κι αν δεν το δηλώνουν ρητά.

### `runc`

Το `runc` είναι το reference OCI runtime και παραμένει η πιο γνωστή implementation. Χρησιμοποιείται ευρέως κάτω από Docker, containerd και πολλά Kubernetes deployments. Μεγάλο μέρος του public research και του exploitation material στοχεύει σε `runc`-style environments, απλώς επειδή είναι συνηθισμένα και επειδή το `runc` ορίζει το baseline που έχουν στο μυαλό τους πολλοί όταν σκέφτονται ένα Linux container. Επομένως, η κατανόηση του `runc` προσφέρει στον reader ένα ισχυρό mental model για το κλασικό container isolation.

### `crun`

Το `crun` είναι ένα ακόμη OCI runtime, γραμμένο σε C και ευρέως χρησιμοποιούμενο σε σύγχρονα Podman environments. Συχνά επαινείται για το καλό cgroup v2 support, το ισχυρό rootless ergonomics και το μικρότερο overhead. Από security perspective, το σημαντικό δεν είναι ότι είναι γραμμένο σε διαφορετική γλώσσα, αλλά ότι εξακολουθεί να έχει τον ίδιο ρόλο: είναι το component που μετατρέπει το OCI configuration σε ένα running process tree κάτω από το kernel. Ένα rootless Podman workflow συχνά φαίνεται ασφαλέστερο όχι επειδή το `crun` διορθώνει μαγικά τα πάντα, αλλά επειδή το συνολικό stack γύρω του τείνει να βασίζεται περισσότερο σε user namespaces και least privilege.

### `runsc` From gVisor

Το `runsc` είναι το runtime που χρησιμοποιεί το gVisor. Εδώ το boundary αλλάζει ουσιαστικά. Αντί να περνά τα περισσότερα syscalls απευθείας στο host kernel με τον συνηθισμένο τρόπο, το gVisor εισάγει ένα userspace kernel layer που κάνει emulate ή mediate μεγάλα τμήματα του Linux interface. Το αποτέλεσμα δεν είναι ένα κανονικό `runc` container με μερικά επιπλέον flags· είναι ένα διαφορετικό sandbox design, με σκοπό τη μείωση του host-kernel attack surface. Τα compatibility και performance tradeoffs αποτελούν μέρος αυτού του design, επομένως τα environments που χρησιμοποιούν `runsc` θα πρέπει να τεκμηριώνονται διαφορετικά από τα κανονικά OCI runtime environments.

### `kata-runtime`

Τα Kata Containers μετακινούν το boundary ακόμη περισσότερο, εκκινώντας το workload μέσα σε ένα lightweight virtual machine. Σε επίπεδο administration, αυτό μπορεί να μοιάζει ακόμη με container deployment και τα orchestration layers μπορεί να συνεχίζουν να το αντιμετωπίζουν έτσι, όμως το underlying isolation boundary είναι πιο κοντά στο virtualization παρά σε ένα κλασικό container που μοιράζεται το host kernel. Αυτό καθιστά το Kata χρήσιμο όταν απαιτείται ισχυρότερο tenant isolation χωρίς εγκατάλειψη των container-centric workflows.

## Engines And Container Managers

Αν το low-level runtime είναι το component που επικοινωνεί απευθείας με το kernel, το engine ή manager είναι το component με το οποίο συνήθως αλληλεπιδρούν οι users και operators. Διαχειρίζεται image pulls, metadata, logs, networks, volumes, lifecycle operations και API exposure. Αυτό το layer έχει τεράστια σημασία, επειδή πολλά compromises στον πραγματικό κόσμο συμβαίνουν εδώ: η πρόσβαση σε runtime socket ή daemon API μπορεί να ισοδυναμεί με host compromise, ακόμη κι αν το low-level runtime είναι απολύτως υγιές.

### Docker Engine

Το Docker Engine είναι η πιο αναγνωρίσιμη container platform για developers και ένας από τους λόγους για τους οποίους το container vocabulary απέκτησε τόσο Docker-centric χαρακτήρα. Η συνηθισμένη διαδρομή είναι από το `docker` CLI στο `dockerd`, το οποίο με τη σειρά του συντονίζει lower-level components όπως τα `containerd` και ένα OCI runtime. Ιστορικά, τα Docker deployments είναι συχνά **rootful**, επομένως η πρόσβαση στο Docker socket αποτελεί ένα ιδιαίτερα ισχυρό primitive. Γι' αυτό μεγάλο μέρος του πρακτικού privilege-escalation material επικεντρώνεται στο `docker.sock`: αν ένα process μπορεί να ζητήσει από το `dockerd` να δημιουργήσει privileged container, να κάνει mount host paths ή να συνδεθεί με host namespaces, μπορεί να μη χρειάζεται καθόλου kernel exploit.

### Podman

Το Podman σχεδιάστηκε γύρω από ένα περισσότερο daemonless model. Σε operational επίπεδο, αυτό ενισχύει την ιδέα ότι τα containers είναι απλώς processes που διαχειρίζονται μέσω standard Linux mechanisms και όχι μέσω ενός μακρόβιου privileged daemon. Το Podman διαθέτει επίσης πολύ ισχυρότερο **rootless** story από τα κλασικά Docker deployments με τα οποία έμαθαν αρχικά πολλοί users. Αυτό δεν καθιστά το Podman αυτόματα ασφαλές, αλλά αλλάζει σημαντικά το default risk profile, ιδιαίτερα σε συνδυασμό με user namespaces, SELinux και `crun`.

### containerd

Το containerd είναι ένα βασικό runtime management component σε πολλά σύγχρονα stacks. Χρησιμοποιείται κάτω από το Docker και είναι επίσης ένα από τα dominant Kubernetes runtime backends. Εκθέτει powerful APIs, διαχειρίζεται images και snapshots και αναθέτει την τελική δημιουργία του process σε ένα low-level runtime. Οι συζητήσεις security γύρω από το containerd θα πρέπει να τονίζουν ότι η πρόσβαση στο containerd socket ή στη λειτουργικότητα των `ctr`/`nerdctl` μπορεί να είναι εξίσου επικίνδυνη με την πρόσβαση στο API του Docker, ακόμη κι αν το interface και το workflow φαίνονται λιγότερο "developer friendly".

### CRI-O

Το CRI-O έχει πιο συγκεκριμένο scope από το Docker Engine. Αντί να είναι μια general-purpose developer platform, έχει σχεδιαστεί γύρω από την καθαρή υλοποίηση του Kubernetes Container Runtime Interface. Αυτό το καθιστά ιδιαίτερα συνηθισμένο σε Kubernetes distributions και SELinux-heavy ecosystems όπως το OpenShift. Από security perspective, αυτό το πιο περιορισμένο scope είναι χρήσιμο επειδή μειώνει το conceptual clutter: το CRI-O ανήκει ξεκάθαρα στο layer "run containers for Kubernetes" και όχι σε μια everything-platform.

### Incus, LXD, And LXC

Τα Incus/LXD/LXC systems αξίζει να διαχωρίζονται από τα Docker-style application containers, επειδή συχνά χρησιμοποιούνται ως **system containers**. Από ένα system container συνήθως αναμένεται να μοιάζει περισσότερο με lightweight machine, με πληρέστερο userspace, long-running services, πλουσιότερο device exposure και εκτενέστερη host integration. Οι isolation mechanisms εξακολουθούν να είναι kernel primitives, όμως οι operational expectations είναι διαφορετικές. Ως αποτέλεσμα, οι misconfigurations εδώ συχνά μοιάζουν λιγότερο με "bad app-container defaults" και περισσότερο με λάθη σε lightweight virtualization ή host delegation.

### systemd-nspawn

Το systemd-nspawn καταλαμβάνει μια ενδιαφέρουσα θέση, επειδή είναι systemd-native και ιδιαίτερα χρήσιμο για testing, debugging και εκτέλεση OS-like environments. Δεν είναι το dominant cloud-native production runtime, όμως εμφανίζεται αρκετά συχνά σε labs και distro-oriented environments ώστε να αξίζει αναφορά. Για το security analysis, αποτελεί ακόμη μία υπενθύμιση ότι η έννοια "container" περιλαμβάνει πολλά ecosystems και operational styles.

### Apptainer / Singularity

Το Apptainer (πρώην Singularity) είναι συνηθισμένο σε research και HPC environments. Τα trust assumptions, το user workflow και το execution model του διαφέρουν σημαντικά από τα Docker/Kubernetes-centric stacks. Ειδικότερα, αυτά τα environments συχνά δίνουν μεγάλη σημασία στο να επιτρέπουν στους users να εκτελούν packaged workloads χωρίς να τους παρέχουν ευρείες privileged container-management powers. Αν ένας reviewer υποθέσει ότι κάθε container environment είναι ουσιαστικά "Docker on a server", θα κατανοήσει πολύ λάθος αυτά τα deployments.

## Build-Time Tooling

Πολλές συζητήσεις security αναφέρονται μόνο στο run time, όμως τα build-time tools έχουν επίσης σημασία, επειδή καθορίζουν τα image contents, την έκθεση των build secrets και το πόσο trusted context ενσωματώνεται στο τελικό artifact.

Τα **BuildKit** και `docker buildx` είναι σύγχρονα build backends που υποστηρίζουν features όπως caching, secret mounting, SSH forwarding και multi-platform builds. Αυτά είναι χρήσιμα features, όμως από security perspective δημιουργούν επίσης σημεία όπου secrets μπορεί να κάνουν leak σε image layers ή όπου ένα υπερβολικά ευρύ build context μπορεί να εκθέσει files που δεν θα έπρεπε ποτέ να έχουν συμπεριληφθεί. Το **Buildah** έχει παρόμοιο ρόλο σε OCI-native ecosystems, ιδιαίτερα γύρω από το Podman, ενώ το **Kaniko** χρησιμοποιείται συχνά σε CI environments που δεν θέλουν να παραχωρήσουν privileged Docker daemon στο build pipeline.

Το βασικό lesson είναι ότι η δημιουργία image και η εκτέλεση image είναι διαφορετικές phases, όμως ένα weak build pipeline μπορεί να δημιουργήσει weak runtime posture πολύ πριν γίνει launch του container.

## Orchestration Is Another Layer, Not The Runtime

Το Kubernetes δεν θα πρέπει να εξισώνεται νοητικά με το ίδιο το runtime. Το Kubernetes είναι ο orchestrator. Προγραμματίζει Pods, αποθηκεύει desired state και εκφράζει security policy μέσω workload configuration. Στη συνέχεια, το kubelet επικοινωνεί με ένα CRI implementation όπως το containerd ή το CRI-O, το οποίο με τη σειρά του καλεί ένα low-level runtime όπως τα `runc`, `crun`, `runsc` ή `kata-runtime`.

Αυτός ο διαχωρισμός έχει σημασία επειδή πολλοί αποδίδουν λανθασμένα μια protection στο "Kubernetes", ενώ στην πραγματικότητα εφαρμόζεται από το node runtime, ή κατηγορούν τα "containerd defaults" για συμπεριφορά που προήλθε από ένα Pod spec. Στην πράξη, το τελικό security posture είναι σύνθεση: ο orchestrator ζητά κάτι, το runtime stack το μεταφράζει και το kernel τελικά το επιβάλλει.

## Why Runtime Identification Matters During Assessment

Αν εντοπίσετε νωρίς το engine και το runtime, πολλές μεταγενέστερες παρατηρήσεις γίνονται ευκολότερες στην ερμηνεία. Ένα rootless Podman container υποδεικνύει ότι τα user namespaces πιθανότατα αποτελούν μέρος της εικόνας. Ένα Docker socket mounted σε workload υποδεικνύει ότι το API-driven privilege escalation είναι ρεαλιστική διαδρομή. Ένα CRI-O/OpenShift node θα πρέπει αμέσως να σας κάνει να σκεφτείτε SELinux labels και restricted workload policy. Ένα gVisor ή Kata environment θα πρέπει να σας κάνει πιο προσεκτικούς όταν υποθέτετε ότι ένα κλασικό `runc` breakout PoC θα συμπεριφερθεί με τον ίδιο τρόπο.

Γι' αυτό ένα από τα πρώτα βήματα σε ένα container assessment θα πρέπει πάντα να είναι η απάντηση σε δύο απλές ερωτήσεις: **ποιο component διαχειρίζεται το container** και **ποιο runtime εκκίνησε πραγματικά το process**. Μόλις ξεκαθαρίσουν αυτές οι απαντήσεις, το υπόλοιπο environment συνήθως γίνεται πολύ ευκολότερο να αναλυθεί.

## Runtime Vulnerabilities

Δεν προέρχεται κάθε container escape από operator misconfiguration. Μερικές φορές το ίδιο το runtime είναι το vulnerable component. Αυτό έχει σημασία επειδή ένα workload μπορεί να εκτελείται με configuration που φαίνεται προσεγμένο και παρ' όλα αυτά να εκτίθεται μέσω ενός low-level runtime flaw.

Το κλασικό παράδειγμα είναι το **CVE-2019-5736** στο `runc`, όπου ένα malicious container μπορούσε να κάνει overwrite το host `runc` binary και στη συνέχεια να περιμένει μια μεταγενέστερη εκτέλεση `docker exec` ή παρόμοια runtime invocation για να ενεργοποιήσει attacker-controlled code. Η exploit path διαφέρει σημαντικά από ένα απλό bind-mount ή capability mistake, επειδή κάνει abuse στον τρόπο με τον οποίο το runtime επανεισέρχεται στο container process space κατά το exec handling.<sup>[[1]](#references)</sup>

Ένα minimal reproduction workflow από red-team perspective είναι:
```bash
go build main.go
./main
```
Έπειτα, από το host:
```bash
docker exec -it <container-name> /bin/sh
```
Το βασικό συμπέρασμα δεν αφορά την ακριβή ιστορική υλοποίηση του exploit, αλλά την επίπτωση στην αξιολόγηση: αν η έκδοση του runtime είναι ευάλωτη, η εκτέλεση κώδικα μέσα στο container μπορεί να αρκεί για την παραβίαση του host, ακόμη και όταν η ορατή διαμόρφωση του container δεν φαίνεται προφανώς αδύναμη.

Πρόσφατα runtime CVEs, όπως το `CVE-2024-21626` στο `runc`, τα race conditions σε mount του BuildKit και τα σφάλματα parsing του containerd, ενισχύουν το ίδιο συμπέρασμα. Η έκδοση και το επίπεδο patch του runtime αποτελούν μέρος του security boundary και όχι απλώς ασήμαντες λεπτομέρειες συντήρησης.

## Αναφορές

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
