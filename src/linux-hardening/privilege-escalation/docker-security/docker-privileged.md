# Docker --privileged

{{#include ../../../banners/hacktricks-training.md}}

## 影响

当您以特权模式运行容器时，您正在禁用以下保护：

### 挂载 /dev

在特权容器中，所有的 **设备可以在 `/dev/` 中访问**。因此，您可以通过 **挂载** 主机的磁盘来 **逃逸**。

{{#tabs}}
{{#tab name="Inside default container"}}
```bash
# docker run --rm -it alpine sh
ls /dev
console  fd       mqueue   ptmx     random   stderr   stdout   urandom
core     full     null     pts      shm      stdin    tty      zero
```
{{#endtab}}

{{#tab name="Inside Privileged Container"}}
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

### 只读内核文件系统

内核文件系统为进程提供了一种修改内核行为的机制。然而，对于容器进程，我们希望防止它们对内核进行任何更改。因此，我们在容器内将内核文件系统挂载为**只读**，确保容器进程无法修改内核。

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

{{#tab name="内部特权容器"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep '(ro'
```
{{#endtab}}
{{#endtabs}}

### 遮蔽内核文件系统

**/proc** 文件系统是选择性可写的，但出于安全考虑，某些部分通过覆盖 **tmpfs** 进行保护，确保容器进程无法访问敏感区域。

> [!NOTE] > **tmpfs** 是一个将所有文件存储在虚拟内存中的文件系统。tmpfs 不会在你的硬盘上创建任何文件。因此，如果你卸载一个 tmpfs 文件系统，里面的所有文件将永远丢失。

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

{{#tab name="内部特权容器"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{{#endtab}}
{{#endtabs}}

### Linux 能力

容器引擎以 **有限数量的能力** 启动容器，以控制默认情况下容器内部发生的事情。 **特权** 容器具有 **所有** 可访问的 **能力**。要了解能力，请阅读：

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

{{#tab name="内部特权容器"}}
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

您可以通过使用 `--cap-add` 和 `--cap-drop` 标志来操纵容器可用的能力，而无需以 `--privileged` 模式运行。

### Seccomp

**Seccomp** 对于 **限制** 容器可以调用的 **syscalls** 非常有用。默认情况下，在运行 docker 容器时启用默认的 seccomp 配置文件，但在特权模式下它是禁用的。有关 Seccomp 的更多信息，请访问：

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

{{#tab name="内部特权容器"}}
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
另外，请注意，当在 **Kubernetes** 集群中使用 Docker（或其他 CRI）时，**seccomp 过滤器默认是禁用的**。

### AppArmor

**AppArmor** 是一种内核增强，用于将 **容器** 限制在 **有限** 的 **资源** 集合中，具有 **每个程序的配置文件**。当您使用 `--privileged` 标志运行时，此保护将被禁用。

{{#ref}}
apparmor.md
{{#endref}}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

运行带有 `--privileged` 标志的容器会禁用 **SELinux 标签**，使其继承容器引擎的标签，通常为 `unconfined`，授予与容器引擎相似的完全访问权限。在无根模式下，它使用 `container_runtime_t`，而在根模式下，应用 `spc_t`。

{{#ref}}
../selinux.md
{{#endref}}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## 什么不受影响

### 命名空间

命名空间**不受**`--privileged`标志的影响。尽管它们没有启用安全约束，但它们**并不能看到系统或主机网络上的所有进程，例如**。用户可以通过使用**`--pid=host`、`--net=host`、`--ipc=host`、`--uts=host`**容器引擎标志来禁用单个命名空间。

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

{{#tab name="内部 --pid=host 容器"}}
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

### 用户命名空间

**默认情况下，容器引擎不使用用户命名空间，除了无根容器**，无根容器需要它们进行文件系统挂载和使用多个 UID。用户命名空间对于无根容器至关重要，无法禁用，并通过限制特权显著增强安全性。

## 参考

- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{{#include ../../../banners/hacktricks-training.md}}
