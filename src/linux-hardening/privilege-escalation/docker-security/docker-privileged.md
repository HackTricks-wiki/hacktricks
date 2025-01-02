# Docker --privileged

{{#include ../../../banners/hacktricks-training.md}}

## Що впливає

Коли ви запускаєте контейнер з привілеями, ви вимикаєте такі захисти:

### Монтування /dev

У контейнері з привілеями всі **пристрої можуть бути доступні в `/dev/`**. Тому ви можете **втекти**, **монтувавши** диск хоста.

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{{#endtab}}

{{#tab name="Всередині привілейованого контейнера"}}
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

### Файлові системи ядра тільки для читання

Файлові системи ядра забезпечують механізм для процесу, щоб змінити поведінку ядра. Однак, коли мова йде про процеси контейнера, ми хочемо запобігти їх внесенню будь-яких змін до ядра. Тому ми монтуємо файлові системи ядра як **тільки для читання** всередині контейнера, що забезпечує неможливість модифікації ядра процесами контейнера.

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

{{#tab name="Всередині привілейованого контейнера"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{{#endtab}}
{{#endtabs}}

### Маскування над файловими системами ядра

Файлова система **/proc** є вибірково записуваною, але для безпеки певні частини захищені від запису та читання, накладаючи на них **tmpfs**, що забезпечує недоступність чутливих областей для процесів контейнера.

> [!NOTE] > **tmpfs** - це файлова система, яка зберігає всі файли у віртуальній пам'яті. tmpfs не створює жодних файлів на вашому жорсткому диску. Тому, якщо ви демонтуєте файлову систему tmpfs, всі файли, що в ній знаходяться, будуть втрачені назавжди.

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

{{#tab name="Всередині привілейованого контейнера"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{{#endtab}}
{{#endtabs}}

### Лінукс-можливості

Контейнерні движки запускають контейнери з **обмеженою кількістю можливостей**, щоб контролювати, що відбувається всередині контейнера за замовчуванням. **Привілейовані** мають **всі** **можливості** доступні. Щоб дізнатися про можливості, прочитайте:

{{#ref}}
../linux-capabilities.md
{{#endref}}

{{#tabs}}
{{#tab name="Всередині стандартного контейнера"}}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{{#endtab}}

{{#tab name="Всередині привілейованого контейнера"}}
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

Ви можете маніпулювати можливостями, доступними контейнеру, не запускаючи в режимі `--privileged`, використовуючи прапори `--cap-add` та `--cap-drop`.

### Seccomp

**Seccomp** корисний для **обмеження** **syscalls**, які контейнер може викликати. За замовчуванням профіль seccomp увімкнено при запуску контейнерів docker, але в режимі привілейованого доступу він вимкнений. Дізнайтеся більше про Seccomp тут:

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

{{#tab name="Всередині привілейованого контейнера"}}
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
Також зверніть увагу, що коли Docker (або інші CRI) використовуються в кластері **Kubernetes**, **фільтр seccomp за замовчуванням вимкнений**.

### AppArmor

**AppArmor** - це покращення ядра для обмеження **контейнерів** до **обмеженого** набору **ресурсів** з **профілями для кожної програми**. Коли ви запускаєте з прапором `--privileged`, ця захист вимкнена.

{{#ref}}
apparmor.md
{{#endref}}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

Запуск контейнера з прапором `--privileged` вимикає **мітки SELinux**, внаслідок чого він успадковує мітку контейнерного движка, зазвичай `unconfined`, надаючи повний доступ, подібний до контейнерного движка. У безкореневому режимі використовується `container_runtime_t`, тоді як у кореневому режимі застосовується `spc_t`.

{{#ref}}
../selinux.md
{{#endref}}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Що не впливає

### Простори імен

Простори імен **НЕ підлягають** впливу прапора `--privileged`. Навіть якщо у них не ввімкнені обмеження безпеки, вони **не бачать усіх процесів на системі або на хост-мережі, наприклад**. Користувачі можуть вимкнути окремі простори імен, використовуючи прапори контейнерних движків **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`**.

{{#tabs}}
{{#tab name="Всередині контейнера з привілеями за замовчуванням"}}
```bash
# docker run --rm --privileged -it alpine sh
ps -ef
PID   USER     TIME  COMMAND
1 root      0:00 sh
18 root      0:00 ps -ef
```
{{#endtab}}

{{#tab name="Всередині --pid=host Контейнера"}}
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

### Простір користувачів

**За замовчуванням, контейнерні движки не використовують простори користувачів, за винятком контейнерів без кореня**, які потребують їх для монтування файлової системи та використання кількох UID. Простори користувачів, які є невід'ємною частиною контейнерів без кореня, не можуть бути вимкнені і значно підвищують безпеку, обмежуючи привілеї.

## Посилання

- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{{#include ../../../banners/hacktricks-training.md}}
