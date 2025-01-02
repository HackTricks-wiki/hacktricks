# Docker --privileged

{{#include ../../../banners/hacktricks-training.md}}

## Was betroffen ist

Wenn Sie einen Container als privilegiert ausführen, deaktivieren Sie die folgenden Schutzmaßnahmen:

### Mount /dev

In einem privilegierten Container können alle **Geräte in `/dev/`** zugegriffen werden. Daher können Sie durch **Mounten** der Festplatte des Hosts **entkommen**.

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{{#endtab}}

{{#tab name="Innerhalb des privilegierten Containers"}}
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

### Schreibgeschützte Kernel-Dateisysteme

Kernel-Dateisysteme bieten einen Mechanismus, um das Verhalten des Kernels durch einen Prozess zu ändern. Wenn es jedoch um Containerprozesse geht, wollen wir verhindern, dass sie Änderungen am Kernel vornehmen. Daher montieren wir Kernel-Dateisysteme als **schreibgeschützt** innerhalb des Containers, um sicherzustellen, dass die Containerprozesse den Kernel nicht ändern können.

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

{{#tab name="Inside Privileged Container"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{{#endtab}}
{{#endtabs}}

### Maskierung über Kernel-Dateisysteme

Das **/proc**-Dateisystem ist selektiv beschreibbar, aber aus Sicherheitsgründen sind bestimmte Teile durch Überlagerung mit **tmpfs** vor Lese- und Schreibzugriff geschützt, sodass Containerprozesse nicht auf sensible Bereiche zugreifen können.

> [!NOTE] > **tmpfs** ist ein Dateisystem, das alle Dateien im virtuellen Speicher speichert. tmpfs erstellt keine Dateien auf Ihrer Festplatte. Wenn Sie ein tmpfs-Dateisystem aushängen, gehen alle darin befindlichen Dateien für immer verloren.

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

{{#tab name="Innerhalb des privilegierten Containers"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{{#endtab}}
{{#endtabs}}

### Linux-Fähigkeiten

Container-Engines starten die Container mit einer **begrenzten Anzahl von Fähigkeiten**, um standardmäßig zu kontrollieren, was im Inneren des Containers passiert. **Privilegierte** haben **alle** **Fähigkeiten** zugänglich. Um mehr über Fähigkeiten zu erfahren, lesen Sie:

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

{{#tab name="Innerhalb des privilegierten Containers"}}
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

Sie können die verfügbaren Berechtigungen für einen Container manipulieren, ohne im `--privileged`-Modus zu laufen, indem Sie die Flags `--cap-add` und `--cap-drop` verwenden.

### Seccomp

**Seccomp** ist nützlich, um die **syscalls**, die ein Container aufrufen kann, **einzuschränken**. Ein standardmäßiges Seccomp-Profil ist standardmäßig aktiviert, wenn Docker-Container ausgeführt werden, aber im privilegierten Modus ist es deaktiviert. Erfahren Sie hier mehr über Seccomp:

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

{{#tab name="Innerhalb des privilegierten Containers"}}
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
Beachten Sie auch, dass, wenn Docker (oder andere CRIs) in einem **Kubernetes**-Cluster verwendet werden, der **seccomp-Filter standardmäßig deaktiviert** ist.

### AppArmor

**AppArmor** ist eine Kernel-Erweiterung, um **Container** auf eine **begrenzte** Menge von **Ressourcen** mit **programmbezogenen Profilen** zu beschränken. Wenn Sie mit dem `--privileged`-Flag ausführen, ist dieser Schutz deaktiviert.

{{#ref}}
apparmor.md
{{#endref}}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Das Ausführen eines Containers mit dem `--privileged`-Flag deaktiviert **SELinux-Labels**, wodurch er das Label der Container-Engine erbt, typischerweise `unconfined`, was vollen Zugriff ähnlich der Container-Engine gewährt. Im rootlosen Modus wird `container_runtime_t` verwendet, während im Root-Modus `spc_t` angewendet wird.

{{#ref}}
../selinux.md
{{#endref}}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Was Nicht Beeinflusst

### Namespaces

Namespaces sind **NICHT betroffen** von dem `--privileged` Flag. Auch wenn sie die Sicherheitsbeschränkungen nicht aktiviert haben, **sehen sie beispielsweise nicht alle Prozesse im System oder im Host-Netzwerk**. Benutzer können einzelne Namespaces deaktivieren, indem sie die **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** Container-Engine-Flags verwenden.

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

{{#tab name="Inside --pid=host Container"}}
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

### Benutzer-Namespace

**Standardmäßig nutzen Container-Engines keine Benutzer-Namensräume, außer für rootlose Container**, die sie für die Dateisystemeinbindung und die Verwendung mehrerer UIDs benötigen. Benutzer-Namensräume, die für rootlose Container unerlässlich sind, können nicht deaktiviert werden und verbessern die Sicherheit erheblich, indem sie die Berechtigungen einschränken.

## Referenzen

- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{{#include ../../../banners/hacktricks-training.md}}
