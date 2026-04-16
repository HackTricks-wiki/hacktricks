# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Μια καλή assessment container θα πρέπει να απαντά σε δύο παράλληλες ερωτήσεις. Πρώτον, τι μπορεί να κάνει ένας attacker από το τρέχον workload; Δεύτερον, ποιες επιλογές του operator το έκαναν αυτό δυνατό; Τα enumeration tools βοηθούν με την πρώτη ερώτηση, και το hardening guidance βοηθά με τη δεύτερη. Το να κρατάς και τα δύο σε μία σελίδα κάνει την ενότητα πιο χρήσιμη ως field reference αντί απλώς ως κατάλογο από escape tricks.

Μια πρακτική ενημέρωση για σύγχρονα environments είναι ότι πολλά παλαιότερα container writeups υποθέτουν σιωπηρά ένα **rootful runtime**, **no user namespace isolation**, και συχνά **cgroup v1**. Αυτές οι υποθέσεις δεν είναι πλέον ασφαλείς. Πριν αφιερώσεις χρόνο σε παλιά escape primitives, επιβεβαίωσε πρώτα αν το workload είναι rootless ή userns-remapped, αν ο host χρησιμοποιεί cgroup v2, και αν Kubernetes ή το runtime εφαρμόζει πλέον default seccomp και AppArmor profiles. Αυτές οι λεπτομέρειες συχνά καθορίζουν αν ένα διάσημο breakout εξακολουθεί να ισχύει.

## Enumeration Tools

Ένας αριθμός από tools παραμένουν χρήσιμα για γρήγορη χαρακτηριστική ανάλυση ενός container environment:

- `linpeas` can identify many container indicators, mounted sockets, capability sets, dangerous filesystems, and breakout hints.
- `CDK` focuses specifically on container environments and includes enumeration plus some automated escape checks.
- `amicontained` is lightweight and useful for identifying container restrictions, capabilities, namespace exposure, and likely breakout classes.
- `deepce` is another container-focused enumerator with breakout-oriented checks.
- `grype` is useful when the assessment includes image-package vulnerability review instead of only runtime escape analysis.
- `Tracee` is useful when you need **runtime evidence** rather than static posture alone, especially for suspicious process execution, file access, and container-aware event collection.
- `Inspektor Gadget` is useful in Kubernetes and Linux-host investigations when you need eBPF-backed visibility tied back to pods, containers, namespaces, and other higher-level concepts.

Η αξία αυτών των tools είναι η ταχύτητα και η κάλυψη, όχι η βεβαιότητα. Βοηθούν να αποκαλυφθεί γρήγορα η γενική κατάσταση, αλλά τα ενδιαφέροντα findings εξακολουθούν να χρειάζονται χειροκίνητη ερμηνεία σε σχέση με το πραγματικό runtime, το namespace, το capability, και το mount model.

## Hardening Priorities

Οι σημαντικότερες αρχές hardening είναι εννοιολογικά απλές, παρότι η υλοποίησή τους διαφέρει ανά platform. Απόφυγε privileged containers. Απόφυγε mounted runtime sockets. Μην δίνεις σε containers writable host paths εκτός αν υπάρχει πολύ συγκεκριμένος λόγος. Χρησιμοποίησε user namespaces ή rootless execution όπου είναι εφικτό. Αφαίρεσε όλα τα capabilities και πρόσθεσε πίσω μόνο εκείνα που πραγματικά χρειάζεται το workload. Κράτα ενεργά τα seccomp, AppArmor, και SELinux αντί να τα απενεργοποιείς για να λύσεις προβλήματα συμβατότητας εφαρμογών. Περιόρισε τους πόρους ώστε ένα compromised container να μην μπορεί εύκολα να προκαλέσει denial of service στον host.

Η υγιεινή εικόνας και build είναι εξίσου σημαντική με το runtime posture. Χρησιμοποίησε minimal images, κάνε rebuild συχνά, σκάναρέ τα, απαίτησε provenance όπου είναι πρακτικό, και κράτα secrets έξω από layers. Ένα container που τρέχει ως non-root με μικρό image και στενή syscall και capability surface είναι πολύ πιο εύκολο να αμυνθείς από ένα μεγάλο convenience image που τρέχει ως host-equivalent root με debugging tools προεγκατεστημένα.

Για Kubernetes, τα τρέχοντα hardening baselines είναι πιο opinionated από όσο πολλοί operators εξακολουθούν να υποθέτουν. Τα ενσωματωμένα **Pod Security Standards** αντιμετωπίζουν το `restricted` ως το "current best practice" profile: το `allowPrivilegeEscalation` θα πρέπει να είναι `false`, τα workloads θα πρέπει να τρέχουν ως non-root, το seccomp θα πρέπει να ορίζεται ρητά σε `RuntimeDefault` ή `Localhost`, και τα capability sets θα πρέπει να απορρίπτονται επιθετικά. Κατά την assessment, αυτό έχει σημασία επειδή ένα cluster που χρησιμοποιεί μόνο `warn` ή `audit` labels μπορεί να φαίνεται hardened στα χαρτιά ενώ στην πράξη εξακολουθεί να δέχεται risky pods.

## Modern Triage Questions

Πριν εμβαθύνεις σε escape-specific pages, απάντησε σε αυτές τις γρήγορες ερωτήσεις:

1. Is the workload **rootful**, **rootless**, or **userns-remapped**?
2. Is the node using **cgroup v1** or **cgroup v2**?
3. Are **seccomp** and **AppArmor/SELinux** explicitly configured, or merely inherited when available?
4. In Kubernetes, is the namespace actually **enforcing** `baseline` or `restricted`, or only warning/auditing?

Useful checks:
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

- Αν το `/proc/self/uid_map` δείχνει ότι το container root είναι mapped σε ένα **υψηλό host UID range**, πολλά παλαιότερα host-root writeups γίνονται λιγότερο σχετικά, επειδή το root μέσα στο container δεν είναι πλέον ισοδύναμο με host-root.
- Αν το `/sys/fs/cgroup` είναι `cgroup2fs`, παλιά **cgroup v1**-specific writeups όπως η κατάχρηση `release_agent` δεν θα πρέπει πλέον να είναι η πρώτη σου υπόθεση.
- Αν τα seccomp και AppArmor κληρονομούνται μόνο implicitly, η portability μπορεί να είναι πιο αδύναμη απ’ όσο περιμένουν οι defenders. Στο Kubernetes, το να ορίζεις ρητά `RuntimeDefault` είναι συχνά ισχυρότερο από το να βασίζεσαι σιωπηρά στα node defaults.
- Αν το `supplementalGroupsPolicy` έχει οριστεί σε `Strict`, το pod θα πρέπει να αποφεύγει να κληρονομεί σιωπηρά επιπλέον group memberships από το `/etc/group` μέσα στο image, κάτι που κάνει τη συμπεριφορά των group-based volume και file access πιο προβλέψιμη.
- Namespace labels όπως `pod-security.kubernetes.io/enforce=restricted` αξίζει να ελέγχονται άμεσα. Τα `warn` και `audit` είναι χρήσιμα, αλλά δεν σταματούν τη δημιουργία ενός risky pod.

## Παραδείγματα Resource-Exhaustion

Τα resource controls δεν είναι glamorous, αλλά αποτελούν μέρος της container security επειδή περιορίζουν το blast radius του compromise. Χωρίς limits σε memory, CPU ή PID, ένα απλό shell μπορεί να αρκεί για να υποβαθμίσει το host ή τα neighboring workloads.

Παραδείγματα tests που επηρεάζουν το host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Αυτά τα παραδείγματα είναι χρήσιμα επειδή δείχνουν ότι δεν είναι κάθε επικίνδυνο αποτέλεσμα σε container ένα καθαρό "escape". Τα αδύναμα cgroup limits μπορούν ακόμα να μετατρέψουν το code execution σε πραγματικό operational impact.

Σε περιβάλλοντα που βασίζονται σε Kubernetes, έλεγξε επίσης αν υπάρχουν καθόλου resource controls πριν θεωρήσεις το DoS ως θεωρητικό:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Εργαλεία Hardening

Για περιβάλλοντα με επίκεντρο το Docker, το `docker-bench-security` παραμένει ένα χρήσιμο baseline για audit από την πλευρά του host, επειδή ελέγχει συνηθισμένα ζητήματα ρύθμισης σε σχέση με ευρέως αναγνωρισμένη guidance benchmark:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Το εργαλείο δεν αποτελεί υποκατάστατο του threat modeling, αλλά εξακολουθεί να είναι πολύτιμο για τον εντοπισμό απρόσεκτων daemon, mount, network και runtime defaults που συσσωρεύονται με τον χρόνο.

Για Kubernetes και environments με έντονο runtime, συνδύασε static checks με runtime visibility:

- Το `Tracee` είναι χρήσιμο για container-aware runtime detection και γρήγορο forensics όταν χρειάζεται να επιβεβαιώσεις τι ακριβώς άγγιξε ένα compromised workload.
- Το `Inspektor Gadget` είναι χρήσιμο όταν η assessment χρειάζεται kernel-level telemetry χαρτογραφημένο πίσω σε pods, containers, DNS activity, file execution ή network behavior.

## Checks

Χρησιμοποίησε τα ως γρήγορες commands πρώτης διέλευσης κατά τη διάρκεια της assessment:
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
- `cgroup2fs` συνήθως σημαίνει ότι πολλές παλαιότερες αλυσίδες διαφυγής του **cgroup v1** δεν είναι το καλύτερο σημείο εκκίνησης, ενώ το να λείπουν τα `memory.max` ή `pids.max` εξακολουθεί να δείχνει αδύναμα blast-radius controls.
- Ύποπτα mounts και runtime sockets συχνά προσφέρουν ταχύτερο δρόμο προς impact από οποιοδήποτε kernel exploit.
- Ο συνδυασμός αδύναμης runtime posture και αδύναμων resource limits συνήθως υποδεικνύει ένα γενικά permissive container environment και όχι ένα μεμονωμένο απομονωμένο λάθος.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
