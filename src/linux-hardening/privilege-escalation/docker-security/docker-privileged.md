# Docker --privileged

{{#include ../../../banners/hacktricks-training.md}}

## Ne Etkiler

Bir konteyneri ayrıcalıklı olarak çalıştırdığınızda, devre dışı bıraktığınız korumalar şunlardır:

### Mount /dev

Ayrıcalıklı bir konteynerde, tüm **cihazlar `/dev/` içinde erişilebilir**. Bu nedenle, **diskin** ana makineden **mount edilmesiyle** **kaçabilirsiniz**. 

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{{#endtab}}

{{#tab name="İçeride Yetkili Konteyner"}}
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

### Sadece okunur çekirdek dosya sistemleri

Çekirdek dosya sistemleri, bir sürecin çekirdeğin davranışını değiştirmesi için bir mekanizma sağlar. Ancak, konteyner süreçleri söz konusu olduğunda, onların çekirdekte herhangi bir değişiklik yapmalarını önlemek istiyoruz. Bu nedenle, çekirdek dosya sistemlerini konteyner içinde **sadece okunur** olarak monte ediyoruz ve böylece konteyner süreçlerinin çekirdeği değiştirmesini engelliyoruz.

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

{{#tab name="İçeride Yetkili Konteyner"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{{#endtab}}
{{#endtabs}}

### Çekirdek dosya sistemlerini maskeleme

**/proc** dosya sistemi seçici olarak yazılabilir, ancak güvenlik için, belirli kısımlar **tmpfs** ile örtülerek yazma ve okuma erişiminden korunur, bu da konteyner süreçlerinin hassas alanlara erişememesini sağlar.

> [!NOTE] > **tmpfs**, tüm dosyaları sanal bellekte depolayan bir dosya sistemidir. tmpfs, sabit diskinizde herhangi bir dosya oluşturmaz. Bu nedenle, bir tmpfs dosya sistemini kaldırırsanız, içinde bulunan tüm dosyalar sonsuza dek kaybolur.

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

{{#tab name="İçeride Yetkili Konteyner"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{{#endtab}}
{{#endtabs}}

### Linux yetenekleri

Konteyner motorları, konteynerin içinde neler olduğunu kontrol etmek için konteynerleri **sınırlı sayıda yetenekle** başlatır. **Ayrıcalıklı** olanlar **tüm** **yeteneklere** erişim sağlar. Yetenekler hakkında bilgi edinmek için okuyun:

{{#ref}}
../linux-capabilities.md
{{#endref}}

{{#tabs}}
{{#tab name="Varsayılan konteyner içinde"}}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{{#endtab}}

{{#tab name="İçinde Yetkili Konteyner"}}
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

Bir konteynerin kullanılabilir yeteneklerini `--privileged` modda çalıştırmadan `--cap-add` ve `--cap-drop` bayraklarını kullanarak manipüle edebilirsiniz.

### Seccomp

**Seccomp**, bir konteynerin çağırabileceği **syscall'ları** **sınırlamak** için faydalıdır. Docker konteynerleri çalıştırıldığında varsayılan olarak bir seccomp profili etkinleştirilir, ancak ayrıcalıklı modda devre dışı bırakılır. Seccomp hakkında daha fazla bilgi edinin:

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

{{#tab name="İçeride Yetkili Konteyner"}}
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
Ayrıca, Docker (veya diğer CRI'ler) bir **Kubernetes** kümesinde kullanıldığında, **seccomp filtresi varsayılan olarak devre dışıdır.**

### AppArmor

**AppArmor**, **konteynerleri** **sınırlı** bir **kaynak** kümesine **per-program profilleri** ile sınırlamak için bir çekirdek geliştirmesidir. `--privileged` bayrağı ile çalıştığınızda, bu koruma devre dışıdır.

{{#ref}}
apparmor.md
{{#endref}}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

`--privileged` bayrağı ile bir konteyner çalıştırmak **SELinux etiketlerini** devre dışı bırakır ve konteyner motorunun etiketini, genellikle `unconfined`, miras almasına neden olur; bu da konteyner motoruna benzer şekilde tam erişim sağlar. Rootless modda `container_runtime_t` kullanılırken, root modda `spc_t` uygulanır.

{{#ref}}
../selinux.md
{{#endref}}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## Ne Etkilemez

### Ad Alanları

Ad alanları **`--privileged`** bayrağından **ETKİLENMEZ**. Güvenlik kısıtlamaları etkin olmasa da, **örneğin sistemdeki veya ana ağdaki tüm süreçleri göremezler**. Kullanıcılar, **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** konteyner motoru bayraklarını kullanarak bireysel ad alanlarını devre dışı bırakabilirler.

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

{{#tab name="İçeride --pid=host Konteyner"}}
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

### Kullanıcı ad alanı

**Varsayılan olarak, konteyner motorları kullanıcı ad alanlarını kullanmaz, köksüz konteynerler hariç**, bu konteynerler dosya sistemi montajı ve birden fazla UID kullanmak için bunlara ihtiyaç duyar. Köksüz konteynerler için hayati öneme sahip olan kullanıcı ad alanları devre dışı bırakılamaz ve ayrıcalıkları kısıtlayarak güvenliği önemli ölçüde artırır.

## Referanslar

- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{{#include ../../../banners/hacktricks-training.md}}
