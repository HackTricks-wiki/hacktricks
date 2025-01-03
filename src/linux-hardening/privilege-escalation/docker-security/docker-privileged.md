# Docker --privileged

{{#include ../../../banners/hacktricks-training.md}}

## Cosa Influisce

Quando esegui un contenitore come privilegiato, queste sono le protezioni che stai disabilitando:

### Monta /dev

In un contenitore privilegiato, tutti i **dispositivi possono essere accessibili in `/dev/`**. Pertanto puoi **uscire** montando il disco dell'host.

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{{#endtab}}

{{#tab name="Dentro il Contenitore Privilegiato"}}
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

### File system del kernel in sola lettura

I file system del kernel forniscono un meccanismo per un processo per modificare il comportamento del kernel. Tuttavia, quando si tratta di processi container, vogliamo impedire loro di apportare modifiche al kernel. Pertanto, montiamo i file system del kernel come **sola lettura** all'interno del container, garantendo che i processi del container non possano modificare il kernel.

{{#tabs}}
{{#tab name="Dentro il container predefinito"}}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{{#endtab}}

{{#tab name="Dentro il Contenitore Privilegiato"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{{#endtab}}
{{#endtabs}}

### Mascheramento dei file system del kernel

Il file system **/proc** è selettivamente scrivibile, ma per motivi di sicurezza, alcune parti sono protette da accesso in scrittura e lettura sovrapponendole con **tmpfs**, garantendo che i processi del container non possano accedere ad aree sensibili.

> [!NOTE] > **tmpfs** è un file system che memorizza tutti i file nella memoria virtuale. tmpfs non crea alcun file sul tuo disco rigido. Quindi, se smonti un file system tmpfs, tutti i file in esso contenuti andranno persi per sempre.

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

{{#tab name="Dentro il Contenitore Privilegiato"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{{#endtab}}
{{#endtabs}}

### Capacità di Linux

I motori dei container avviano i container con un **numero limitato di capacità** per controllare cosa avviene all'interno del container per impostazione predefinita. Quelli **privilegiati** hanno **tutte** le **capacità** accessibili. Per saperne di più sulle capacità, leggi:

{{#ref}}
../linux-capabilities.md
{{#endref}}

{{#tabs}}
{{#tab name="Dentro il container predefinito"}}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{{#endtab}}

{{#tab name="Dentro il contenitore privilegiato"}}
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

Puoi manipolare le capacità disponibili per un container senza eseguire in modalità `--privileged` utilizzando i flag `--cap-add` e `--cap-drop`.

### Seccomp

**Seccomp** è utile per **limitare** le **syscalls** che un container può chiamare. Un profilo seccomp predefinito è abilitato per impostazione predefinita quando si eseguono container docker, ma in modalità privilegiata è disabilitato. Scopri di più su Seccomp qui:

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

{{#tab name="Dentro il Contenitore Privilegiato"}}
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
Inoltre, nota che quando Docker (o altri CRI) sono utilizzati in un cluster **Kubernetes**, il **filtraggio seccomp è disabilitato per impostazione predefinita**

### AppArmor

**AppArmor** è un miglioramento del kernel per confinare i **container** a un insieme **limitato** di **risorse** con **profili per programma**. Quando esegui con il flag `--privileged`, questa protezione è disabilitata.

{{#ref}}
apparmor.md
{{#endref}}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Eseguire un container con il flag `--privileged` disabilita le **etichette SELinux**, facendogli ereditare l'etichetta del motore del container, tipicamente `unconfined`, concedendo accesso completo simile a quello del motore del container. In modalità senza root, utilizza `container_runtime_t`, mentre in modalità root, viene applicato `spc_t`.

{{#ref}}
../selinux.md
{{#endref}}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Cosa Non Influisce

### Namespace

I namespace **NON sono influenzati** dal flag `--privileged`. Anche se non hanno i vincoli di sicurezza abilitati, **non vedono tutti i processi sul sistema o sulla rete host, per esempio**. Gli utenti possono disabilitare singoli namespace utilizzando i flag dei motori container **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{{#tabs}}
{{#tab name="Dentro il container privilegiato predefinito"}}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{{#endtab}}

{{#tab name="Dentro --pid=host Container"}}
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

### Spazio dei nomi utente

**Per impostazione predefinita, i motori dei container non utilizzano spazi dei nomi utente, tranne che per i container senza root**, che li richiedono per il montaggio del file system e l'uso di più UID. Gli spazi dei nomi utente, fondamentali per i container senza root, non possono essere disabilitati e migliorano significativamente la sicurezza limitando i privilegi.

## Riferimenti

- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{{#include ../../../banners/hacktricks-training.md}}
