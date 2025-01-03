# Docker --privileged

{{#include ../../../banners/hacktricks-training.md}}

## Co wpływa

Kiedy uruchamiasz kontener jako uprzywilejowany, wyłączasz następujące zabezpieczenia:

### Montowanie /dev

W uprzywilejowanym kontenerze wszystkie **urządzenia są dostępne w `/dev/`**. Dlatego możesz **uciec** przez **zamontowanie** dysku hosta.

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{{#endtab}}

{{#tab name="Wewnątrz kontenera z uprawnieniami"}}
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

### Systemy plików jądra tylko do odczytu

Systemy plików jądra zapewniają mechanizm, który pozwala procesowi modyfikować zachowanie jądra. Jednak w przypadku procesów kontenerowych chcemy zapobiec ich wprowadzaniu jakichkolwiek zmian w jądrze. Dlatego montujemy systemy plików jądra jako **tylko do odczytu** w obrębie kontenera, zapewniając, że procesy kontenera nie mogą modyfikować jądra.

{{#tabs}}
{{#tab name="Wewnątrz domyślnego kontenera"}}
```bash
# docker run --rm -it alpine sh
mount | grep '(ro'
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cpuset on /sys/fs/cgroup/cpuset type cgroup (ro,nosuid,nodev,noexec,relatime,cpuset)
cpu on /sys/fs/cgroup/cpu type cgroup (ro,nosuid,nodev,noexec,relatime,cpu)
cpuacct on /sys/fs/cgroup/cpuacct type cgroup (ro,nosuid,nodev,noexec,relatime,cpuacct)
```
{{#endtab}}

{{#tab name="Wewnątrz kontenera z uprawnieniami"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{{#endtab}}
{{#endtabs}}

### Maskowanie nad systemami plików jądra

System plików **/proc** jest selektywnie zapisywalny, ale dla bezpieczeństwa, niektóre części są chronione przed dostępem do zapisu i odczytu poprzez nałożenie na nie **tmpfs**, co zapewnia, że procesy kontenera nie mogą uzyskać dostępu do wrażliwych obszarów.

> [!NOTE] > **tmpfs** to system plików, który przechowuje wszystkie pliki w pamięci wirtualnej. tmpfs nie tworzy żadnych plików na twoim dysku twardym. Więc jeśli odmontujesz system plików tmpfs, wszystkie pliki w nim zawarte zostaną na zawsze utracone.

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

{{#tab name="Wewnątrz kontenera z uprawnieniami"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{{#endtab}}
{{#endtabs}}

### Możliwości Linuxa

Silniki kontenerów uruchamiają kontenery z **ograniczoną liczbą możliwości**, aby kontrolować, co dzieje się wewnątrz kontenera domyślnie. **Privileged** mają **wszystkie** **możliwości** dostępne. Aby dowiedzieć się więcej o możliwościach, przeczytaj:

{{#ref}}
../linux-capabilities.md
{{#endref}}

{{#tabs}}
{{#tab name="Wewnątrz domyślnego kontenera"}}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{{#endtab}}

{{#tab name="Wewnątrz kontenera z uprawnieniami"}}
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

Możesz manipulować możliwościami dostępnymi dla kontenera bez uruchamiania w trybie `--privileged`, używając flag `--cap-add` i `--cap-drop`.

### Seccomp

**Seccomp** jest przydatny do **ograniczenia** **syscalli**, które kontener może wywołać. Domyślny profil seccomp jest włączony domyślnie podczas uruchamiania kontenerów docker, ale w trybie uprzywilejowanym jest wyłączony. Dowiedz się więcej o Seccomp tutaj:

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

{{#tab name="Wewnątrz kontenera z uprawnieniami"}}
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
Również zauważ, że gdy Docker (lub inne CRI) są używane w klastrze **Kubernetes**, **filtr seccomp jest domyślnie wyłączony**.

### AppArmor

**AppArmor** to ulepszenie jądra, które ogranicza **kontenery** do **ograniczonego** zestawu **zasobów** z **profilami per program**. Gdy uruchamiasz z flagą `--privileged`, ta ochrona jest wyłączona.

{{#ref}}
apparmor.md
{{#endref}}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Uruchomienie kontenera z flagą `--privileged` wyłącza **etykiety SELinux**, powodując, że dziedziczy on etykietę silnika kontenerowego, zazwyczaj `unconfined`, co przyznaje pełny dostęp podobny do silnika kontenerowego. W trybie bezrootowym używa `container_runtime_t`, podczas gdy w trybie rootowym stosuje `spc_t`.

{{#ref}}
../selinux.md
{{#endref}}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Co nie ma wpływu

### Przestrzenie nazw

Przestrzenie nazw **NIE są dotknięte** flagą `--privileged`. Chociaż nie mają włączonych ograniczeń bezpieczeństwa, **nie widzą wszystkich procesów w systemie ani sieci hosta, na przykład**. Użytkownicy mogą wyłączyć poszczególne przestrzenie nazw, używając flag silnika kontenerów **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

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

### Przestrzeń użytkownika

**Domyślnie silniki kontenerów nie wykorzystują przestrzeni użytkownika, z wyjątkiem kontenerów bezrootowych**, które wymagają ich do montowania systemu plików i używania wielu UID. Przestrzenie użytkownika, niezbędne dla kontenerów bezrootowych, nie mogą być wyłączane i znacznie zwiększają bezpieczeństwo, ograniczając uprawnienia.

## Odniesienia

- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{{#include ../../../banners/hacktricks-training.md}}
