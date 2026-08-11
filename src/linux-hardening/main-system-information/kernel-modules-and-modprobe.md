# Kernel Modules 및 modprobe Abuse

## Kernel module 및 module-loading misconfigurations

Kernel module 지원은 Linux privilege escalation 검토 중 영향도가 높은 영역입니다. 모든 unsigned-module 메시지를 그 자체로 exploit 가능한 것으로 간주하지 말고, 이를 활용해 실질적인 질문에 답해야 합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 현재 사용자가 `sudo`, capabilities 또는 writable helper path를 통해 modules를 로드할 수 있는가?
- module loading이 아직 활성화되어 있는가?
- module signature enforcement가 비활성화되어 있는가?
- module directories 또는 module files가 writable한가?
- kernel logs를 읽어 무슨 일이 발생했는지 확인할 수 있는가?

빠른 triage는 다음 module-status, signature, logging 및 module-tree checks로 시작합니다.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretation:

- `modules_disabled=1`은 모듈을 로드하거나 언로드할 수 없게 하며, 재부팅하기 전까지 값을 `0`으로 재설정할 수 없습니다.<sup>[[1]](#references)</sup>
- 커널 command line의 `module.sig_enforce=1` 또는 `CONFIG_MODULE_SIG_FORCE=y`는 유효하게 서명된 모듈을 요구합니다. 그렇지 않으면 서명되지 않은 모듈이 로드되어 커널을 taint할 수 있습니다.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0`은 `dmesg`에 제한을 적용하지 않습니다. `1`인 경우 액세스하려면 `CAP_SYSLOG`가 필요합니다.<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 아래의 쓰기 가능한 경로는 위험합니다. 모듈을 로드할 때 `modprobe`가 해당 트리와 의존성 데이터를 검색하기 때문입니다.<sup>[[8]](#references)</sup>

### 모듈 로드 및 커널 출력 읽기

로컬 모듈을 로드할 정당한 권한이 있다면 `insmod`는 지정한 정확한 `.ko` 파일을 삽입합니다. 모듈의 init 함수는 로드 과정의 일부로 실행되며, `printk()`로 기록된 메시지는 일반적으로 `dmesg`로 읽는 커널 로그 버퍼로 전달됩니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

최소한의 검토 workflow에서는 `modinfo`로 metadata를 검사하고, `insmod`와 `rmmod`로 모듈을 로드 및 제거하며, `lsmod`로 로드된 상태를 확인하고, `dmesg`로 커널 로그를 검사합니다.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
`sudo -l`에서 `insmod`, `modprobe` 또는 이를 둘러싼 wrapper의 사용이 허용된다면 이를 critical로 간주해야 합니다. `sudo -l`은 명령을 실행하는 사용자의 권한을 나열하며, kernel module을 로드하려면 `CAP_SYS_MODULE`이 필요합니다.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

사용자가 `insmod`를 실행할 수 있도록 허용하는 sudo rule은 일반적인 administrative helper 실행을 허용하는 것과는 비교할 수 없습니다. module의 initialization code는 insertion 과정의 일부로 실행되므로, 실질적인 review question은 이 사용자가 load되는 module을 선택하거나 수정할 수 있는지 여부입니다.<sup>[[3]](#references)</sup>

다음 generic review flow는 candidate module에 대해 inspection, load, state, log 및 removal checks를 반복합니다.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
사용자가 임의의 `.ko` 파일을 제공할 수 있다면, authorized assessment에서는 해당 규칙을 전체 시스템 compromise로 간주해야 합니다. 더 안전한 운영 방식은 sudo를 통한 module loading 위임을 피하는 것입니다. 불가피한 경우에는 정확한 경로, 소유권, 권한, signing policy 및 제거 workflow를 제한해야 합니다.<sup>[[3]](#references)[[10]](#references)</sup>

통제된 lab에서 harmless module-building pattern을 사용하는 경우, 아래에 최소한의 source와 Makefile이 나와 있습니다. `make -C /lib/modules/$(uname -r)/build M=$PWD` 형식은 external modules에 대한 kernel의 문서화된 kbuild workflow를 따릅니다.<sup>[[5]](#references)[[7]](#references)</sup>
```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
printk(KERN_INFO "demo module loaded\n");
return 0;
}

static void __exit demo_exit(void) {
printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
허가된 lab에서만 build하고 load하십시오. kbuild는 external module을 build하며, load/remove 명령은 kernel module interfaces를 호출합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` 악용 점검

`kernel.modprobe`는 kernel이 module autoload 요청을 위해 실행하는 userspace helper를 지정합니다. 이 sysctl은 명시적인 module 삽입이 아니라 autoloading에 영향을 줍니다. 공격자가 이를 쓰기 가능한 executable path로 변경하고 module 요청을 트리거할 수 있다면, 해당 helper는 권한 있는 code execution 경로가 됩니다.<sup>[[1]](#references)</sup>

kernel sysctl interface를 통해 현재 helper path를 확인하고 대상의 소유권과 mode를 검사합니다.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
sysctl, 위임된 sudo 규칙 또는 파일 capabilities에 영향을 줄 수 있는지 확인합니다.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
다음 lab 전용 패턴은 helper path를 변경하고 문서화된 module-autoload 요청을 트리거합니다. 격리되고 권한이 부여된 시스템에서만 사용하세요.<sup>[[1]](#references)</sup>

현재 Linux kernel에서는 알 수 없는 executable을 generic trigger로 사용하지 마세요. legacy custom binary-format module autoloading은 Linux 6.14에서 제거되었으며, kernel documentation은 알 수 없는 filesystem type을 module-autoload 요청 경로로 식별합니다.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
강화된 시스템에서는 권한으로 인해 권한이 없는 사용자가 `kernel.modprobe`에 쓰거나, helper path에 쓸 수 없거나, 모듈 자동 로딩이 비활성화된 경우 이 작업이 실패해야 합니다.<sup>[[1]](#references)</sup>

### 쓰기 가능한 `/lib/modules` 검토

쓰기 가능한 모듈 디렉터리는 이후 `modprobe`가 호출되는 방식에 따라 모듈 교체, 악성 모듈 심기 또는 자동 로드 악용을 허용할 수 있습니다. `modprobe`는 모듈을 확인할 때 `/lib/modules/$(uname -r)`를 검색하고 해당 디렉터리의 dependency data를 사용합니다.<sup>[[8]](#references)</sup>

활성 커널 릴리스의 모듈 트리에서 쓰기 가능한 모듈 파일과 dependency/alias metadata를 검토합니다.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
쓰기 가능한 module content를 찾았다면, `modprobe`가 dependencies를 확인하는 방식과 `modinfo`가 module metadata를 보고하는 방식을 검사합니다.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
방어 참고 사항:

- `/lib/modules`의 소유자를 `root:root`로 유지하고 사용자가 쓸 수 없도록 설정합니다.<sup>[[8]](#references)</sup>
- 운영상 가능한 경우 부팅 후 `kernel.modules_disabled=1`을 설정합니다.<sup>[[1]](#references)</sup>
- loadable modules가 필요한 시스템에서는 module signing을 적용합니다.<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules`에 대한 쓰기 작업과 예상치 못한 `insmod`/`modprobe` 실행을 모니터링합니다.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [/proc/sys/kernel/ 문서 — Linux Kernel 문서](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing 기능 — Linux Kernel 문서](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — Linux Kernel 문서](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk를 사용한 메시지 로깅 — Linux Kernel 문서](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [External Modules 빌드 — Linux Kernel 문서](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [태그 'execve-v6.14-rc1' 병합 — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
