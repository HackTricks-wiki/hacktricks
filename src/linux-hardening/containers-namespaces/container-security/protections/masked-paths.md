# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths는 특히 민감한 kernel-facing filesystem 위치를 bind-mount로 덮어쓰거나 다른 방식으로 접근할 수 없게 만들어 container에서 숨기는 runtime 보호 기능입니다. 목적은 일반적인 애플리케이션이 직접 사용할 필요가 없는 인터페이스, 특히 procfs 내부의 인터페이스와 workload가 직접 상호작용하지 못하도록 하는 것입니다.

이는 많은 container escape와 host에 영향을 미치는 기법이 `/proc` 또는 `/sys` 아래의 특수 파일을 읽거나 쓰는 것에서 시작하기 때문에 중요합니다. 이러한 위치가 masked되면, 공격자는 container 내부에서 code execution을 획득한 이후에도 kernel control surface의 유용한 부분에 직접 접근할 수 없게 됩니다.

## Operation

Runtime은 일반적으로 다음과 같은 선택된 경로를 mask합니다:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

정확한 목록은 runtime과 host configuration에 따라 달라집니다. 중요한 점은 host에는 해당 경로가 여전히 존재하더라도, container의 관점에서는 해당 경로에 접근할 수 없거나 다른 것으로 대체된다는 것입니다.

## Lab

Docker에서 노출된 masked-path configuration을 확인합니다:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
워크로드 내부에서 실제 마운트 동작을 검사합니다:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## 보안 영향

Masking은 주요 isolation boundary를 생성하지 않지만, 가치가 높은 여러 post-exploitation 대상을 제거합니다. Masking이 없으면 compromised container가 kernel state를 검사하거나, 민감한 process 또는 keying 정보를 읽거나, 애플리케이션에 절대 노출되어서는 안 되는 procfs/sysfs 객체와 상호작용할 수 있습니다.

## 잘못된 설정

가장 일반적인 실수는 편의성이나 debugging을 위해 광범위한 경로 클래스를 unmask하는 것입니다. Podman에서는 `--security-opt unmask=ALL` 또는 특정 경로의 unmasking으로 나타날 수 있습니다. Kubernetes에서는 과도하게 광범위한 proc 노출이 `procMount: Unmasked`를 통해 발생할 수 있습니다. 또 다른 심각한 문제는 bind mount를 통해 host의 `/proc` 또는 `/sys`를 노출하는 것으로, 이는 제한된 container view라는 개념을 완전히 우회합니다.

## 악용

Masking이 약하거나 존재하지 않는 경우, 먼저 직접 접근할 수 있는 민감한 procfs/sysfs 경로를 식별합니다:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
마스킹되었다고 알려진 경로에 접근할 수 있다면, 주의 깊게 조사하세요:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
이 명령으로 확인할 수 있는 내용:

- `/proc/timer_list`는 호스트의 timer 및 scheduler 데이터를 노출할 수 있습니다. 이는 대부분 reconnaissance primitive이지만, container가 일반적으로 숨겨진 kernel-facing 정보를 읽을 수 있음을 확인해 줍니다.
- `/proc/keys`는 훨씬 더 민감합니다. 호스트 설정에 따라 keyring entries, key descriptions, 그리고 kernel keyring subsystem을 사용하는 호스트 서비스 간의 관계를 노출할 수 있습니다.
- `/sys/firmware`는 boot mode, firmware interfaces, platform details를 식별하는 데 도움을 줍니다. 이러한 정보는 host fingerprinting과 workload가 host-level state를 보고 있는지 파악하는 데 유용합니다.
- `/proc/config.gz`는 실행 중인 kernel configuration을 노출할 수 있습니다. 이는 public kernel exploit prerequisites를 대조하거나 특정 feature에 접근할 수 있는 이유를 이해하는 데 유용합니다.
- `/proc/sched_debug`는 scheduler state를 노출하며, PID namespace가 관련 없는 process 정보를 완전히 숨겨야 한다는 직관적인 예상이 우회되는 경우가 많습니다.

Interesting results에는 해당 파일에서 직접 읽은 내용, 데이터가 제한된 container view가 아니라 host에 속한다는 증거, 또는 기본적으로 흔히 masked되는 다른 procfs/sysfs locations에 대한 access가 포함됩니다.

## Checks

이러한 checks의 목적은 runtime이 어떤 paths를 의도적으로 숨겼는지, 그리고 현재 workload가 여전히 축소된 kernel-facing filesystem을 보고 있는지를 확인하는 것입니다.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
흥미롭게 살펴볼 부분:

- Hardened runtime에서 긴 masked-path 목록은 정상입니다.
- 민감한 procfs 항목에 masking이 누락되어 있다면 자세히 검사할 필요가 있습니다.
- 민감한 path에 접근할 수 있고 container에 강력한 capabilities 또는 광범위한 mounts가 함께 설정되어 있다면 해당 노출의 영향이 더 커집니다.

## Runtime 기본값

| Runtime / platform | 기본 상태 | 기본 동작 | 일반적인 수동 약화 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화 | Docker가 기본 masked path 목록을 정의합니다 | host proc/sys mounts 노출, `--privileged` |
| Podman | 기본적으로 활성화 | 수동으로 unmask하지 않는 한 Podman이 기본 masked paths를 적용합니다 | `--security-opt unmask=ALL`, 특정 대상 unmask, `--privileged` |
| Kubernetes | Runtime 기본값 상속 | Pod 설정이 proc 노출을 약화하지 않는 한 underlying runtime의 masking 동작을 사용합니다 | `procMount: Unmasked`, privileged workload 패턴, 광범위한 host mounts |
| containerd / CRI-O under Kubernetes | Runtime 기본값 | 일반적으로 재정의되지 않는 한 OCI/runtime masked paths를 적용합니다 | 직접적인 runtime 설정 변경, 동일한 Kubernetes 약화 경로 |

Masked paths는 일반적으로 기본적으로 존재합니다. 주요 운영 문제는 runtime에서 해당 항목이 없다는 것이 아니라, 의도적인 unmask 또는 보호 기능을 무효화하는 host bind mounts입니다.
{{#include ../../../../banners/hacktricks-training.md}}
