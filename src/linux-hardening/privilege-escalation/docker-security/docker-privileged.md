# Docker --privileged

{{#include ../../../banners/hacktricks-training.md}}

## 영향을 미치는 것

특권이 있는 컨테이너를 실행할 때 비활성화되는 보호 기능은 다음과 같습니다:

### /dev 마운트

특권 컨테이너에서는 모든 **장치가 `/dev/`에서 접근 가능합니다**. 따라서 **호스트의** 디스크를 **마운트**하여 **탈출**할 수 있습니다.

{{#tabs}}
{{#tab name="기본 컨테이너 내부"}}
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

### 읽기 전용 커널 파일 시스템

커널 파일 시스템은 프로세스가 커널의 동작을 수정할 수 있는 메커니즘을 제공합니다. 그러나 컨테이너 프로세스의 경우, 커널에 대한 변경을 방지하고자 합니다. 따라서 우리는 커널 파일 시스템을 컨테이너 내에서 **읽기 전용**으로 마운트하여 컨테이너 프로세스가 커널을 수정할 수 없도록 합니다.

{{#tabs}}
{{#tab name="기본 컨테이너 내부"}}
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

### 커널 파일 시스템 마스킹

**/proc** 파일 시스템은 선택적으로 쓰기가 가능하지만 보안을 위해 특정 부분은 **tmpfs**로 덮어씌워져 쓰기 및 읽기 접근이 차단되어 컨테이너 프로세스가 민감한 영역에 접근할 수 없도록 합니다.

> [!NOTE] > **tmpfs**는 모든 파일을 가상 메모리에 저장하는 파일 시스템입니다. tmpfs는 하드 드라이브에 파일을 생성하지 않습니다. 따라서 tmpfs 파일 시스템을 언마운트하면 그 안에 있는 모든 파일은 영원히 사라집니다.

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

{{#tab name="Inside Privileged Container"}}
```bash
# docker run --rm --privileged -it alpine sh
mount  | grep /proc.*tmpfs
```
{{#endtab}}
{{#endtabs}}

### 리눅스 기능

컨테이너 엔진은 기본적으로 컨테이너 내부에서 발생하는 일을 제어하기 위해 **제한된 수의 기능**으로 컨테이너를 시작합니다. **특권**이 있는 경우 **모든** **기능**에 접근할 수 있습니다. 기능에 대해 알아보려면 읽어보세요:

{{#ref}}
../linux-capabilities.md
{{#endref}}

{{#tabs}}
{{#tab name="기본 컨테이너 내부"}}
```bash
# docker run --rm -it alpine sh
apk add -U libcap; capsh --print
[...]
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
[...]
```
{{#endtab}}

{{#tab name="Inside Privileged Container"}}
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

컨테이너에서 `--privileged` 모드로 실행하지 않고도 사용할 수 있는 기능을 `--cap-add` 및 `--cap-drop` 플래그를 사용하여 조작할 수 있습니다.

### Seccomp

**Seccomp**는 컨테이너가 호출할 수 있는 **syscalls**를 **제한**하는 데 유용합니다. 기본적으로 도커 컨테이너를 실행할 때 기본 seccomp 프로필이 활성화되지만, 특권 모드에서는 비활성화됩니다. Seccomp에 대해 더 알아보려면 여기를 참조하세요:

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

{{#tab name="Inside Privileged Container"}}
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
또한, **Kubernetes** 클러스터에서 Docker(또는 다른 CRI)를 사용할 때 **seccomp 필터는 기본적으로 비활성화되어 있습니다.**

### AppArmor

**AppArmor**는 **컨테이너**를 **제한된** **리소스** 집합에 **프로그램별 프로필**로 제한하는 커널 향상 기능입니다. `--privileged` 플래그로 실행할 때 이 보호 기능은 비활성화됩니다.

{{#ref}}
apparmor.md
{{#endref}}
```bash
# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined
```
### SELinux

`--privileged` 플래그로 컨테이너를 실행하면 **SELinux 레이블**이 비활성화되어 컨테이너 엔진의 레이블, 일반적으로 `unconfined`를 상속받아 컨테이너 엔진과 유사한 전체 액세스를 부여합니다. 루트리스 모드에서는 `container_runtime_t`를 사용하고, 루트 모드에서는 `spc_t`가 적용됩니다.

{{#ref}}
../selinux.md
{{#endref}}
```bash
# You can manually disable selinux in docker with
--security-opt label:disable
```
## 영향을 미치지 않는 것

### 네임스페이스

네임스페이스는 **`--privileged`** 플래그의 영향을 **받지 않습니다**. 보안 제약이 활성화되어 있지 않더라도, 예를 들어 **시스템이나 호스트 네트워크의 모든 프로세스를 볼 수는 없습니다**. 사용자는 **`--pid=host`, `--net=host`, `--ipc=host`, `--uts=host`** 컨테이너 엔진 플래그를 사용하여 개별 네임스페이스를 비활성화할 수 있습니다.

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

### 사용자 네임스페이스

**기본적으로, 컨테이너 엔진은 루트 없는 컨테이너를 제외하고 사용자 네임스페이스를 사용하지 않습니다.** 루트 없는 컨테이너는 파일 시스템 마운팅 및 여러 UID 사용을 위해 사용자 네임스페이스가 필요합니다. 루트 없는 컨테이너에 필수적인 사용자 네임스페이스는 비활성화할 수 없으며, 권한을 제한하여 보안을 크게 향상시킵니다.

## 참조

- [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

{{#include ../../../banners/hacktricks-training.md}}
