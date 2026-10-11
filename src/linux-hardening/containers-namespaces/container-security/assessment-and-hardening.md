# Αξιολόγηση Και Ενίσχυση Ασφάλειας

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια καλή αξιολόγηση container πρέπει να απαντά σε δύο παράλληλα ερωτήματα. Πρώτον, τι μπορεί να κάνει ένας attacker από το τρέχον workload; Δεύτερον, ποιες επιλογές του operator το κατέστησαν δυνατό; Τα εργαλεία enumeration βοηθούν με το πρώτο ερώτημα, ενώ οι οδηγίες ενίσχυσης ασφάλειας βοηθούν με το δεύτερο. Η διατήρηση και των δύο στην ίδια σελίδα κάνει αυτή την ενότητα πιο χρήσιμη ως πρακτικό οδηγό πεδίου και όχι απλώς ως κατάλογο μεθόδων escape.

Μια πρακτική ενημέρωση για τα σύγχρονα περιβάλλοντα είναι ότι πολλά παλαιότερα κείμενα για containers θεωρούν σιωπηρά δεδομένα ένα **rootful runtime**, **χωρίς απομόνωση user namespace** και συχνά **cgroup v1**. Αυτές οι παραδοχές δεν είναι πλέον ασφαλείς. Πριν αφιερώσετε χρόνο σε παλιές μεθόδους escape, επιβεβαιώστε πρώτα αν το workload είναι rootless ή userns-remapped, αν ο host χρησιμοποιεί cgroup v2 και αν το Kubernetes ή το runtime εφαρμόζει πλέον τα προεπιλεγμένα προφίλ seccomp και AppArmor. Αυτές οι λεπτομέρειες συχνά καθορίζουν αν εξακολουθεί να ισχύει ένα γνωστό breakout.

## Εργαλεία Enumeration

Ορισμένα εργαλεία εξακολουθούν να είναι χρήσιμα για τον γρήγορο χαρακτηρισμό ενός περιβάλλοντος container:

- Το `linpeas` μπορεί να εντοπίσει πολλές ενδείξεις container, προσαρτημένα sockets, σύνολα capabilities, επικίνδυνα filesystems και ενδείξεις για breakout.
- Το `CDK` εστιάζει ειδικά σε περιβάλλοντα container και περιλαμβάνει enumeration, καθώς και ορισμένους αυτοματοποιημένους ελέγχους escape.
- Το `amicontained` είναι ελαφρύ και χρήσιμο για τον εντοπισμό περιορισμών container, capabilities, έκθεσης namespaces και πιθανών κατηγοριών breakout.
- Το `deepce` είναι ένα ακόμη εργαλείο enumeration που εστιάζει σε containers και περιλαμβάνει ελέγχους προσανατολισμένους σε breakout.
- Το `grype` είναι χρήσιμο όταν η αξιολόγηση περιλαμβάνει έλεγχο ευπαθειών στα πακέτα της εικόνας και όχι μόνο ανάλυση escape κατά τον χρόνο εκτέλεσης.
- Το `Tracee` είναι χρήσιμο όταν χρειάζεστε **τεκμήρια κατά τον χρόνο εκτέλεσης** και όχι μόνο στατική εικόνα της κατάστασης ασφάλειας, ειδικά για ύποπτη εκτέλεση διεργασιών, πρόσβαση σε αρχεία και συλλογή συμβάντων με επίγνωση των containers.
- Το `Inspektor Gadget` είναι χρήσιμο σε έρευνες Kubernetes και Linux host, όταν χρειάζεστε ορατότητα μέσω eBPF που συσχετίζεται με pods, containers, namespaces και άλλες έννοιες υψηλότερου επιπέδου.

Η αξία αυτών των εργαλείων έγκειται στην ταχύτητα και την κάλυψη, όχι στη βεβαιότητα. Βοηθούν να αποκαλυφθεί γρήγορα η γενική κατάσταση ασφάλειας, αλλά τα ενδιαφέροντα ευρήματα εξακολουθούν να χρειάζονται χειροκίνητη ερμηνεία με βάση το πραγματικό μοντέλο runtime, namespace, capability και mount.

## Προτεραιότητες Ενίσχυσης Ασφάλειας

Οι σημαντικότερες αρχές ενίσχυσης ασφάλειας είναι απλές ως προς τη σύλληψή τους, παρότι η εφαρμογή τους διαφέρει ανά πλατφόρμα. Αποφύγετε τα privileged containers. Αποφύγετε τα προσαρτημένα sockets του runtime. Μην παραχωρείτε στα containers εγγράψιμες διαδρομές του host, εκτός αν υπάρχει πολύ συγκεκριμένος λόγος. Χρησιμοποιήστε user namespaces ή rootless εκτέλεση όπου είναι εφικτό. Αφαιρέστε όλα τα capabilities και προσθέστε ξανά μόνο όσα χρειάζεται πραγματικά το workload. Διατηρήστε ενεργά τα seccomp, AppArmor και SELinux αντί να τα απενεργοποιείτε για να λύσετε προβλήματα συμβατότητας εφαρμογών. Περιορίστε τους πόρους, ώστε ένα compromised container να μην μπορεί να προκαλέσει εύκολα άρνηση υπηρεσίας στον host.

Η υγιεινή των εικόνων και των build είναι εξίσου σημαντική με την κατάσταση ασφάλειας κατά τον χρόνο εκτέλεσης. Χρησιμοποιήστε minimal εικόνες, δημιουργείτε ξανά τακτικά, σαρώστε τις, απαιτείτε provenance όπου είναι πρακτικό και κρατήστε τα secrets έξω από τα layers. Ένα container που εκτελείται ως non-root, με μικρή εικόνα και περιορισμένη επιφάνεια syscall και capability, είναι πολύ πιο εύκολο να προστατευτεί από μια μεγάλη εικόνα ευκολίας που εκτελείται ως root με δικαιώματα ισοδύναμα με του host και έχει προεγκατεστημένα εργαλεία debugging.

Για το Kubernetes, οι τρέχουσες βασικές γραμμές ενίσχυσης ασφάλειας είναι πιο αυστηρές απ’ όσο εξακολουθούν να υποθέτουν πολλοί operators. Τα ενσωματωμένα **Pod Security Standards** θεωρούν το `restricted` προφίλ ως την «τρέχουσα βέλτιστη πρακτική»: το `allowPrivilegeEscalation` πρέπει να είναι `false`, τα workloads πρέπει να εκτελούνται ως non-root, το seccomp πρέπει να ορίζεται ρητά σε `RuntimeDefault` ή `Localhost` και τα σύνολα capabilities πρέπει να περιορίζονται επιθετικά. Κατά την αξιολόγηση, αυτό έχει σημασία επειδή ένα cluster που χρησιμοποιεί μόνο labels `warn` ή `audit` μπορεί να φαίνεται ενισχυμένο στα χαρτιά, ενώ στην πράξη εξακολουθεί να επιτρέπει επικίνδυνα pods.<sup>[[1]](#references)</sup>

Όταν ένα Pod έχει προσαρτημένο service-account token, αξιολογήστε τα δικαιώματά του **ανά namespace-στόχο**. Ένας κανόνας που απαριθμεί Pods σε ένα namespace δεν τεκμηριώνει δικαιώματα σε κάποιο άλλο· ένα token προσαρτημένο σε διαφορετικό Pod μπορεί να έχει διαφορετικά δικαιώματα. Χρησιμοποιήστε τα `kubectl auth can-i list pods -n <target-namespace>` και `kubectl auth can-i list secrets -n <target-namespace>` με την ταυτότητα που εξετάζεται. Ένας επιτυχής έλεγχος λίστας Secret είναι σοβαρή ένδειξη, επειδή μια απόκριση λίστας μπορεί να περιλαμβάνει τα περιεχόμενα των Secret, αλλά δεν αποδεικνύει ότι υπάρχει privileged token. Η πρόσβαση στον host απαιτεί επιπλέον δικαίωμα δημιουργίας workload που να μπορεί να χρησιμοποιηθεί, αποδοχή του προτεινόμενου mount `hostPath` και security context κόμβου/pod που να επιτρέπει την επιθυμητή λειτουργία αρχείου. Δείτε τους [ελέγχους εξουσιοδότησης](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) του Kubernetes και τις [οδηγίες RBAC για κλιμάκωση προνομίων](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## Ερωτήματα Σύγχρονου Triage

Πριν προχωρήσετε στις σελίδες που αφορούν συγκεκριμένα escape, απαντήστε σε αυτές τις σύντομες ερωτήσεις:

1. Είναι το workload **rootful**, **rootless** ή **userns-remapped**;
2. Χρησιμοποιεί ο node **cgroup v1** ή **cgroup v2**;
3. Είναι τα **seccomp** και **AppArmor/SELinux** ρυθμισμένα ρητά ή απλώς κληρονομούνται όταν είναι διαθέσιμα;
4. Στο Kubernetes, το namespace **εφαρμόζει** πράγματι την πολιτική `baseline` ή `restricted`, ή απλώς εκδίδει προειδοποιήσεις/καταγράφει ελέγχους;

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

- Αν το `/proc/self/uid_map` δείχνει ότι το root του container αντιστοιχίζεται σε **υψηλό εύρος UID του host**, πολλά παλαιότερα writeups για host-root είναι λιγότερο σχετικά, επειδή το root μέσα στο container δεν είναι πλέον ισοδύναμο με το root του host.
- Αν το `/sys/fs/cgroup` είναι `cgroup2fs`, τα παλιά writeups που αφορούν ειδικά το **cgroup v1**, όπως η κατάχρηση του `release_agent`, δεν θα πρέπει πλέον να είναι η πρώτη σας σκέψη.
- Αν τα seccomp και AppArmor κληρονομούνται μόνο έμμεσα, η φορητότητα μπορεί να είναι μικρότερη απ’ όσο περιμένουν οι defenders. Στο Kubernetes, ο ρητός ορισμός του `RuntimeDefault` είναι συχνά ισχυρότερος από την αθόρυβη εξάρτηση από τις προεπιλεγμένες ρυθμίσεις του node.
- Αν το `supplementalGroupsPolicy` έχει οριστεί σε `Strict`, το pod θα πρέπει να αποφεύγει την αθόρυβη κληρονόμηση επιπλέον ιδιότητας μέλους σε ομάδες από το `/etc/group` μέσα στο image, κάτι που καθιστά πιο προβλέψιμη τη συμπεριφορά πρόσβασης σε volumes και αρχεία βάσει ομάδων.
- Αξίζει να ελέγχετε απευθείας labels των namespaces, όπως `pod-security.kubernetes.io/enforce=restricted`. Τα `warn` και `audit` είναι χρήσιμα, αλλά δεν εμποδίζουν τη δημιουργία ενός επικίνδυνου pod.

## Αρχική διαλογή βάσει runtime

Η αρχική διαλογή βάσει runtime είναι ένας γρήγορος έλεγχος που δείχνει αν ένα container μοιάζει με συνηθισμένο απομονωμένο workload ή με foothold σε control plane που μπορεί να επηρεάσει το host. Θα πρέπει να συλλέγει αρκετά στοιχεία ώστε να ιεραρχήσετε τι θα διαβάσετε στη συνέχεια: κατάχρηση runtime socket, mounts του host, namespaces, cgroups, capabilities ή έλεγχο secrets του image.

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

- Τα `memory.max` / `pids.max` που λείπουν ή είναι απεριόριστα υποδηλώνουν ανεπαρκή έλεγχο της ακτίνας επιπτώσεων, ακόμη κι αν δεν υπάρχει σαφής διαφυγή.
- Ένα root shell με `NoNewPrivs: 0`, ευρείες capabilities και permissive seccomp είναι πολύ πιο ενδιαφέρον από ένα περιορισμένο workload χωρίς root.
- Τα runtime sockets και τα writable host mounts συνήθως έχουν υψηλότερη προτεραιότητα από τα kernel exploits, επειδή ήδη παρέχουν διαδρομή ελέγχου για τη διαχείριση ή το filesystem.
- Τα κοινόχρηστα PID, network, IPC ή cgroup namespaces δεν αποτελούν πάντα από μόνα τους πλήρεις διαφυγές, αλλά διευκολύνουν τον εντοπισμό του επόμενου βήματος.

## Παραδείγματα Εξάντλησης Πόρων

Οι έλεγχοι πόρων δεν είναι εντυπωσιακοί, αλλά αποτελούν μέρος της ασφάλειας των containers, επειδή περιορίζουν την ακτίνα επιπτώσεων μιας παραβίασης. Χωρίς όρια μνήμης, CPU ή PID, ένα απλό shell μπορεί να αρκεί για να υποβαθμίσει τον host ή γειτονικά workloads.

Παραδείγματα δοκιμών που επηρεάζουν τον host:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Αυτά τα παραδείγματα είναι χρήσιμα, επειδή δείχνουν ότι δεν οδηγεί κάθε επικίνδυνη έκβαση σε container σε καθαρό «escape». Τα αδύναμα όρια cgroup μπορούν και πάλι να μετατρέψουν την εκτέλεση κώδικα σε πραγματικό λειτουργικό αντίκτυπο.

Σε περιβάλλοντα που βασίζονται στο Kubernetes, ελέγξτε επίσης αν υπάρχουν καθόλου έλεγχοι πόρων, προτού θεωρήσετε το DoS θεωρητικό:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Εργαλεία ενίσχυσης ασφάλειας

Για περιβάλλοντα που βασίζονται στο Docker, το `docker-bench-security` παραμένει χρήσιμο σημείο αναφοράς για ελέγχους στην πλευρά του host, καθώς ελέγχει συνήθη ζητήματα διαμόρφωσης βάσει ευρέως αναγνωρισμένων οδηγιών αναφοράς. Οι προειδοποιήσεις για το runtime θα πρέπει να εξετάζονται ξεχωριστά, καθώς ένα benchmark διαμόρφωσης δεν μπορεί να εντοπίσει αν το εγκατεστημένο runtime επηρεάζεται από μια πρόσφατα δημοσιοποιημένη ευπάθεια. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Το εργαλείο δεν υποκαθιστά τη μοντελοποίηση απειλών, αλλά παραμένει χρήσιμο για τον εντοπισμό απρόσεκτων προεπιλεγμένων ρυθμίσεων σε daemon, mount, network και runtime, οι οποίες συσσωρεύονται με την πάροδο του χρόνου.

Για Kubernetes και περιβάλλοντα με έντονη χρήση runtime, συνδυάστε τους στατικούς ελέγχους με ορατότητα κατά τον χρόνο εκτέλεσης:

- Το `Tracee` είναι χρήσιμο για ανίχνευση κατά τον χρόνο εκτέλεσης με επίγνωση των containers και για γρήγορη εγκληματολογική διερεύνηση, όταν χρειάζεται να επιβεβαιώσετε τι ακριβώς άγγιξε ένα παραβιασμένο workload.
- Το `Inspektor Gadget` είναι χρήσιμο όταν η αξιολόγηση απαιτεί τηλεμετρία σε επίπεδο kernel, συσχετισμένη με pods, containers, δραστηριότητα DNS, εκτέλεση αρχείων ή συμπεριφορά δικτύου.

## Έλεγχοι

Χρησιμοποιήστε τις παρακάτω εντολές για έναν γρήγορο πρώτο έλεγχο κατά την αξιολόγηση:

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

- Μια διεργασία root με ευρείες δυνατότητες και `Seccomp: 0` χρήζει άμεσης προσοχής.
- Μια διεργασία root που έχει επίσης **αντιστοίχιση UID 1:1** είναι πολύ πιο ενδιαφέρουσα από το «root» μέσα σε ένα σωστά απομονωμένο user namespace.
- Το `cgroup2fs` συνήθως σημαίνει ότι πολλές παλαιότερες αλυσίδες διαφυγής από **cgroup v1** δεν αποτελούν το καλύτερο σημείο εκκίνησης, ενώ η απουσία των `memory.max` ή `pids.max` υποδηλώνει αδύναμους ελέγχους περιορισμού της ακτίνας επιπτώσεων.
- Οι ύποπτες προσαρτήσεις και τα runtime sockets συχνά προσφέρουν ταχύτερο δρόμο προς την επίτευξη αντίκτυπου από οποιοδήποτε kernel exploit.
- Ο συνδυασμός αδύναμης στάσης runtime και αδύναμων ορίων πόρων συνήθως υποδεικνύει ένα γενικά επιτρεπτικό περιβάλλον container, και όχι ένα μεμονωμένο λάθος.

## References

- [1] [Πρότυπα ασφάλειας Pod του Kubernetes](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Ενημέρωση ασφάλειας Docker: Πολλαπλές ευπάθειες στα runc, BuildKit και Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
