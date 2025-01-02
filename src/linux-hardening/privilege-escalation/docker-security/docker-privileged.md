# Docker --privileged

{{#include ../../../banners/hacktricks-training.md}}

## Τι Επηρεάζει

Όταν εκτελείτε ένα κοντέινερ ως privileged, αυτές είναι οι προστασίες που απενεργοποιείτε:

### Mount /dev

Σε ένα privileged κοντέινερ, όλες οι ** συσκευές είναι προσβάσιμες στο `/dev/`**. Επομένως, μπορείτε να **escape** με το **mounting** του δίσκου του host.

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{{#endtab}}

{{#tab name="Μέσα σε Προνομιακό Κοντέινερ"}}
```bash
# docker run --rm --privileged -it alpine sh
ls /dev
cachefiles       mapper           port             shm              tty24            tty44            tty7
console          mem              psaux            stderr           tty25            tty45            tty8
core             mqueue           ptmx             stdin            tty26            tty46            tty9
cpu              nbd0             pts              stdout           tty27            tty47            ttyS0
[...]
```
{{#endtab}}
{{#endtabs}}

### Σύστημα αρχείων πυρήνα μόνο για ανάγνωση

Τα συστήματα αρχείων πυρήνα παρέχουν έναν μηχανισμό για μια διαδικασία να τροποποιήσει τη συμπεριφορά του πυρήνα. Ωστόσο, όταν πρόκειται για διαδικασίες κοντέινερ, θέλουμε να αποτρέψουμε την πραγματοποίηση οποιωνδήποτε αλλαγών στον πυρήνα. Επομένως, τοποθετούμε τα συστήματα αρχείων πυρήνα ως **μόνο για ανάγνωση** εντός του κοντέινερ, διασφαλίζοντας ότι οι διαδικασίες του κοντέινερ δεν μπορούν να τροποποιήσουν τον πυρήνα.

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{{#endtab}}

{{#tab name="Μέσα σε Προνομιακό Κοντέινερ"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{{#endtab}}
{{#endtabs}}

### Απόκρυψη πάνω από τα συστήματα αρχείων πυρήνα

Το **/proc** σύστημα αρχείων είναι επιλεκτικά εγγράψιμο, αλλά για λόγους ασφαλείας, ορισμένα μέρη είναι προστατευμένα από πρόσβαση εγγραφής και ανάγνωσης, επικαλύπτοντάς τα με **tmpfs**, διασφαλίζοντας ότι οι διαδικασίες κοντέινερ δεν μπορούν να έχουν πρόσβαση σε ευαίσθητες περιοχές.

> [!NOTE] > **tmpfs** είναι ένα σύστημα αρχείων που αποθηκεύει όλα τα αρχεία στη εικονική μνήμη. Το tmpfs δεν δημιουργεί κανένα αρχείο στον σκληρό σας δίσκο. Έτσι, αν αποσυνδέσετε ένα σύστημα αρχείων tmpfs, όλα τα αρχεία που βρίσκονται σε αυτό χάνονται για πάντα.

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
mount  | grep /proc.*tmpfs
tmpfs on /proc/acpi type tmpfs (ro,relatime)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755)
```
{{#endtab}}

{{#tab name="Μέσα σε Προνομιακό Κοντέινερ"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{{#endtab}}
{{#endtabs}}

### Δυνατότητες Linux

Οι μηχανές κοντέινερ εκκινούν τα κοντέινερ με **περιορισμένο αριθμό δυνατοτήτων** για να ελέγχουν τι συμβαίνει μέσα στο κοντέινερ από προεπιλογή. Οι **προνομιακές** έχουν **όλες** τις **δυνατότητες** προσβάσιμες. Για να μάθετε για τις δυνατότητες διαβάστε:

{{#ref}}
../linux-capabilities.md
{{#endref}}

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{{#endtab}}

{{#tab name="Μέσα σε Προνομιακό Κοντέινερ"}}
```bash
# docker run --rm --privileged -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: =eip cap_perfmon,cap_bpf,cap_checkpoint_restore-eip
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
[...]
```
{{#endtab}}
{{#endtabs}}

Μπορείτε να χειριστείτε τις δυνατότητες που είναι διαθέσιμες σε ένα κοντέινερ χωρίς να τρέχετε σε λειτουργία `--privileged` χρησιμοποιώντας τις σημαίες `--cap-add` και `--cap-drop`.

### Seccomp

**Seccomp** είναι χρήσιμο για να **περιορίσει** τις **syscalls** που μπορεί να καλέσει ένα κοντέινερ. Ένα προεπιλεγμένο προφίλ seccomp είναι ενεργοποιημένο από προεπιλογή όταν τρέχουν κοντέινερ docker, αλλά σε λειτουργία privileged είναι απενεργοποιημένο. Μάθετε περισσότερα για το Seccomp εδώ:

{{#ref}}
seccomp.md
{{#endref}}

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	2
Seccomp_filters:	1
```
{{#endtab}}

{{#tab name="Μέσα σε Προνομιακό Κοντέινερ"}}
```bash
# docker run --rm --privileged -it alpine sh
grep Seccomp /proc/1/status
Seccomp:	0
Seccomp_filters:	0
```
{{#endtab}}
{{#endtabs}}
```bash
# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined
```
Επίσης, σημειώστε ότι όταν χρησιμοποιούνται οι Docker (ή άλλες CRIs) σε ένα **Kubernetes** cluster, το **seccomp filter είναι απενεργοποιημένο από προεπιλογή**

### AppArmor

**AppArmor** είναι μια βελτίωση του πυρήνα για να περιορίσει τα **containers** σε ένα **περιορισμένο** σύνολο **πόρων** με **προφίλ ανά πρόγραμμα**. Όταν εκτελείτε με την επιλογή `--privileged`, αυτή η προστασία είναι απενεργοποιημένη.

{{#ref}}
apparmor.md
{{#endref}}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Η εκτέλεση ενός κοντέινερ με την επιλογή `--privileged` απενεργοποιεί τις **ετικέτες SELinux**, προκαλώντας να κληρονομήσει την ετικέτα της μηχανής κοντέινερ, συνήθως `unconfined`, παρέχοντας πλήρη πρόσβαση παρόμοια με αυτή της μηχανής κοντέινερ. Σε λειτουργία χωρίς δικαιώματα root, χρησιμοποιεί `container_runtime_t`, ενώ σε λειτουργία root, εφαρμόζεται το `spc_t`.

{{#ref}}
../selinux.md
{{#endref}}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Τι Δεν Επηρεάζει

### Namespaces

Τα Namespaces **ΔΕΝ επηρεάζονται** από την επιλογή `--privileged`. Αν και δεν έχουν ενεργοποιημένους τους περιορισμούς ασφαλείας, **δεν βλέπουν όλες τις διεργασίες στο σύστημα ή το δίκτυο του host, για παράδειγμα**. Οι χρήστες μπορούν να απενεργοποιήσουν μεμονωμένα namespaces χρησιμοποιώντας τις επιλογές **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** των μηχανών κοντέινερ.

{{#tabs}}
{{#tab name="Inside default privileged container"}}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{{#endtab}}

{{#tab name="Μέσα --pid=host Container"}}
```bash
# docker run --rm --privileged --pid=host -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:03 /sbin/init
2 root      0:00 [kthreadd]
3 root      0:00 [rcu_gp]ount | grep /proc.*tmpfs
[...]
```
{{#endtab}}
{{#endtabs}}

### Χώρος ονομάτων χρήστη

**Από προεπιλογή, οι μηχανές κοντέινερ δεν χρησιμοποιούν χώρους ονομάτων χρηστών, εκτός από τα κοντέινερ χωρίς δικαιώματα root**, τα οποία τα απαιτούν για την τοποθέτηση συστήματος αρχείων και τη χρήση πολλαπλών UIDs. Οι χώροι ονομάτων χρηστών, που είναι αναγκαίοι για τα κοντέινερ χωρίς δικαιώματα root, δεν μπορούν να απενεργοποιηθούν και ενισχύουν σημαντικά την ασφάλεια περιορίζοντας τα δικαιώματα.

## Αναφορές

- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{{#include ../../../banners/hacktricks-training.md}}
