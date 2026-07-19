# Αξιολόγηση και Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια καλή αξιολόγηση container θα πρέπει να απαντά σε δύο παράλληλα ερωτήματα. Πρώτον, τι μπορεί να κάνει ένας attacker από το τρέχον workload; Δεύτερον, ποιες επιλογές του operator το κατέστησαν δυνατό; Τα εργαλεία enumeration βοηθούν στο πρώτο ερώτημα, ενώ οι οδηγίες hardening στο δεύτερο. Η διατήρηση και των δύο στην ίδια σελίδα κάνει αυτή την ενότητα πιο χρήσιμη ως field reference και όχι απλώς ως κατάλογο escape tricks.

Μια πρακτική ενημέρωση για τα σύγχρονα environments είναι ότι πολλά παλαιότερα container writeups θεωρούν σιωπηρά ένα **rootful runtime**, **χωρίς user namespace isolation** και συχνά **cgroup v1**. Αυτές οι παραδοχές δεν είναι πλέον ασφαλείς. Πριν αφιερώσετε χρόνο σε παλιά escape primitives, επιβεβαιώστε πρώτα αν το workload είναι rootless ή userns-remapped, αν το host χρησιμοποιεί cgroup v2 και αν το Kubernetes ή το runtime εφαρμόζει πλέον τα default seccomp και AppArmor profiles. Αυτές οι λεπτομέρειες συχνά καθορίζουν αν ένα γνωστό breakout εξακολουθεί να εφαρμόζεται.

## Εργαλεία Enumeration

Ορισμένα εργαλεία παραμένουν χρήσιμα για τον γρήγορο χαρακτηρισμό ενός container environment:

- Το `linpeas` μπορεί να εντοπίσει πολλά container indicators, mounted sockets, capability sets, επικίνδυνα filesystems και breakout hints.
- Το `CDK` επικεντρώνεται ειδικά σε container environments και περιλαμβάνει enumeration, καθώς και ορισμένους αυτοματοποιημένους escape checks.
- Το `amicontained` είναι lightweight και χρήσιμο για τον εντοπισμό container restrictions, capabilities, namespace exposure και πιθανών breakout classes.
- Το `deepce` είναι ακόμη ένα container-focused enumerator με breakout-oriented checks.
- Το `grype` είναι χρήσιμο όταν η αξιολόγηση περιλαμβάνει vulnerability review των image packages και όχι μόνο runtime escape analysis.
- Το `Tracee` είναι χρήσιμο όταν χρειάζεστε **runtime evidence** και όχι μόνο static posture, ειδικά για ύποπτη εκτέλεση processes, πρόσβαση σε αρχεία και container-aware event collection.
- Το `Inspektor Gadget` είναι χρήσιμο σε Kubernetes και Linux-host investigations όταν χρειάζεστε eBPF-backed visibility που συνδέεται με pods, containers, namespaces και άλλες έννοιες υψηλότερου επιπέδου.

Η αξία αυτών των εργαλείων είναι η ταχύτητα και η κάλυψη, όχι η βεβαιότητα. Βοηθούν να αποκαλυφθεί γρήγορα η γενική posture, όμως τα ενδιαφέροντα findings εξακολουθούν να χρειάζονται manual interpretation με βάση το πραγματικό runtime, το namespace, τα capabilities και το mount model.

## Προτεραιότητες Hardening

Οι σημαντικότερες αρχές hardening είναι εννοιολογικά απλές, παρόλο που η υλοποίησή τους διαφέρει ανά platform. Αποφύγετε τα privileged containers. Αποφύγετε τα mounted runtime sockets. Μην δίνετε στα containers writable host paths, εκτός αν υπάρχει πολύ συγκεκριμένος λόγος. Χρησιμοποιείτε user namespaces ή rootless execution όπου είναι εφικτό. Κάντε drop όλα τα capabilities και προσθέστε ξανά μόνο όσα χρειάζεται πραγματικά το workload. Διατηρείτε ενεργά τα seccomp, AppArmor και SELinux αντί να τα απενεργοποιείτε για την επίλυση προβλημάτων application compatibility. Περιορίστε τους πόρους, ώστε ένα compromised container να μην μπορεί εύκολα να προκαλέσει denial of service στον host.

Η υγιεινή των images και των builds είναι εξίσου σημαντική με τη runtime posture. Χρησιμοποιείτε minimal images, κάνετε συχνά rebuild, σκανάρετέ τα, απαιτείτε provenance όπου είναι πρακτικό και κρατάτε τα secrets εκτός των layers. Ένα container που εκτελείται ως non-root, με μικρό image και περιορισμένη επιφάνεια syscall και capability, είναι πολύ πιο εύκολο να προστατευτεί από ένα μεγάλο convenience image που εκτελείται ως host-equivalent root και έχει προεγκατεστημένα debugging tools.

Για το Kubernetes, τα τρέχοντα hardening baselines είναι πιο αυστηρά από όσο εξακολουθούν να θεωρούν πολλοί operators. Τα ενσωματωμένα **Pod Security Standards** αντιμετωπίζουν το `restricted` ως το "current best practice" profile: το `allowPrivilegeEscalation` θα πρέπει να είναι `false`, τα workloads θα πρέπει να εκτελούνται ως non-root, το seccomp θα πρέπει να έχει οριστεί ρητά ως `RuntimeDefault` ή `Localhost` και τα capability sets θα πρέπει να γίνονται drop επιθετικά. Κατά την αξιολόγηση, αυτό έχει σημασία επειδή ένα cluster που χρησιμοποιεί μόνο `warn` ή `audit` labels μπορεί να φαίνεται hardened στα χαρτιά, ενώ στην πράξη εξακολουθεί να επιτρέπει risky pods.

## Σύγχρονες Ερωτήσεις Triage

Πριν προχωρήσετε σε σελίδες που αφορούν ειδικά escape, απαντήστε σε αυτές τις σύντομες ερωτήσεις:

1. Είναι το workload **rootful**, **rootless** ή **userns-remapped**;
2. Χρησιμοποιεί ο node **cgroup v1** ή **cgroup v2**;
3. Έχουν ρυθμιστεί ρητά τα **seccomp** και **AppArmor/SELinux** ή απλώς κληρονομούνται όταν είναι διαθέσιμα;
4. Στο Kubernetes, επιβάλλει πραγματικά το namespace τα `baseline` ή `restricted` ή απλώς εμφανίζει warnings/καταγράφει audits;

Χρήσιμοι έλεγχοι:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Αν το `/proc/self/uid_map` δείχνει ότι το container root αντιστοιχίζεται σε **υψηλό εύρος host UID**, πολλά παλαιότερα writeups για host-root γίνονται λιγότερο σχετικά, επειδή το root μέσα στο container δεν είναι πλέον ισοδύναμο με host-root.
- Αν το `/sys/fs/cgroup` είναι `cgroup2fs`, παλαιότερα writeups ειδικά για **cgroup v1**, όπως το abuse του `release_agent`, δεν θα πρέπει πλέον να είναι η πρώτη σας υπόθεση.
- Αν τα seccomp και AppArmor κληρονομούνται μόνο implicit, η portability μπορεί να είναι ασθενέστερη από όσο περιμένουν οι defenders. Στο Kubernetes, ο ρητός ορισμός του `RuntimeDefault` είναι συχνά ισχυρότερος από την αθόρυβη εξάρτηση από τα node defaults.
- Αν το `supplementalGroupsPolicy` έχει οριστεί σε `Strict`, το pod θα πρέπει να αποφεύγει την αθόρυβη κληρονόμηση επιπλέον group memberships από το `/etc/group` μέσα στο image, γεγονός που κάνει πιο predictable τη συμπεριφορά πρόσβασης σε volumes και αρχεία βάσει groups.
- Αξίζει να ελέγχετε απευθείας labels του namespace, όπως το `pod-security.kubernetes.io/enforce=restricted`. Τα `warn` και `audit` είναι χρήσιμα, αλλά δεν εμποδίζουν τη δημιουργία ενός risky pod.

## Runtime Baseline Triage

Ένα runtime baseline είναι ο γρήγορος έλεγχος που δείχνει αν ένα container μοιάζει με συνηθισμένο isolated workload ή με foothold σε control plane που μπορεί να επηρεάσει το host. Θα πρέπει να συλλέγει αρκετά facts, ώστε να ιεραρχηθεί η επόμενη σελίδα που πρέπει να διαβαστεί: abuse του runtime socket, host mounts, namespaces, cgroups, capabilities ή review των image secrets.

Χρήσιμοι έλεγχοι μέσα από ένα workload:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Ερμηνεία:

- Η απουσία ή η απεριόριστη τιμή των `memory.max` / `pids.max` υποδεικνύει ανεπαρκείς ελέγχους blast radius, ακόμη και χωρίς ένα καθαρό escape.
- Ένα root shell με `NoNewPrivs: 0`, εκτεταμένες capabilities και permissive seccomp είναι πολύ πιο ενδιαφέρον από ένα περιορισμένο non-root workload.
- Τα runtime sockets και τα writable host mounts συνήθως έχουν υψηλότερη προτεραιότητα από τα kernel exploits, επειδή ήδη εκθέτουν μια διαδρομή ελέγχου management ή filesystem.
- Τα shared PID, network, IPC ή cgroup namespaces δεν αποτελούν πάντα από μόνα τους πλήρη escapes, αλλά διευκολύνουν τον εντοπισμό του επόμενου βήματος.

## Παραδείγματα Resource-Exhaustion

Οι resource controls δεν είναι εντυπωσιακοί, αλλά αποτελούν μέρος του container security, επειδή περιορίζουν το blast radius ενός compromise. Χωρίς memory, CPU ή PID limits, ένα απλό shell μπορεί να αρκεί για να υποβαθμίσει το host ή γειτονικά workloads.

Παραδείγματα tests με επίδραση στο host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Αυτά τα παραδείγματα είναι χρήσιμα, επειδή δείχνουν ότι δεν αποτελεί κάθε επικίνδυνο αποτέλεσμα σε container ένα καθαρό «escape». Οι αδύναμοι περιορισμοί cgroup μπορούν και πάλι να μετατρέψουν το code execution σε πραγματικό operational impact.

Σε περιβάλλοντα που υποστηρίζονται από Kubernetes, ελέγξτε επίσης αν υπάρχουν resource controls εξαρχής, προτού θεωρήσετε το DoS θεωρητικό:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Εργαλεία Hardening

Για περιβάλλοντα που βασίζονται στο Docker, το `docker-bench-security` παραμένει ένα χρήσιμο baseline για audit στην πλευρά του host, επειδή ελέγχει συνηθισμένα ζητήματα ρυθμίσεων με βάση ευρέως αναγνωρισμένες οδηγίες benchmark:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Το εργαλείο δεν υποκαθιστά το threat modeling, αλλά παραμένει χρήσιμο για τον εντοπισμό απρόσεκτων προεπιλογών σε daemon, mount, network και runtime, οι οποίες συσσωρεύονται με την πάροδο του χρόνου.

Για Kubernetes και περιβάλλοντα με έντονη χρήση runtime, συνδυάστε τους στατικούς ελέγχους με ορατότητα runtime:

- Το `Tracee` είναι χρήσιμο για runtime detection με επίγνωση container και για γρήγορο forensics, όταν χρειάζεται να επιβεβαιώσετε τι άγγιξε πραγματικά ένα compromised workload.
- Το `Inspektor Gadget` είναι χρήσιμο όταν η assessment απαιτεί telemetry σε επίπεδο kernel, αντιστοιχισμένο σε pods, containers, δραστηριότητα DNS, εκτέλεση αρχείων ή συμπεριφορά δικτύου.

## Έλεγχοι

Χρησιμοποιήστε τα παρακάτω ως γρήγορες εντολές πρώτου ελέγχου κατά την assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Τι είναι ενδιαφέρον εδώ:

- Μια root διεργασία με ευρείες capabilities και `Seccomp: 0` αξίζει άμεση προσοχή.
- Μια root διεργασία που έχει επίσης **1:1 UID map** είναι πολύ πιο ενδιαφέρουσα από το "root" μέσα σε ένα σωστά απομονωμένο user namespace.
- Το `cgroup2fs` συνήθως σημαίνει ότι πολλά παλαιότερα **cgroup v1** escape chains δεν είναι το καλύτερο σημείο εκκίνησης, ενώ η απουσία των `memory.max` ή `pids.max` εξακολουθεί να υποδεικνύει αδύναμους ελέγχους blast radius.
- Ύποπτα mounts και runtime sockets συχνά προσφέρουν ταχύτερη διαδρομή προς impact από οποιοδήποτε kernel exploit.
- Ο συνδυασμός αδύναμης runtime posture και αδύναμων resource limits συνήθως υποδεικνύει ένα γενικά permissive container environment και όχι ένα μεμονωμένο λάθος.

## Αναφορές

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
