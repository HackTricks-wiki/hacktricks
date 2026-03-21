# 마스킹된 경로

{{#include ../../../../banners/hacktricks-training.md}}

마스킹된 경로는 런타임 보호기법으로, 특히 민감한 커널에 노출되는 파일시스템 위치를 바인드 마운트하거나 접근 불가능하게 만들어 컨테이너로부터 숨깁니다. 목적은 워크로드가 일반 애플리케이션에 필요하지 않은 인터페이스와 직접 상호작용하는 것을 방지하는 것으로, 특히 procfs 내부에서 그러합니다.

이것이 중요한 이유는 많은 컨테이너 탈출 및 호스트 영향 기법들이 `/proc` 또는 `/sys` 아래의 특수 파일을 읽거나 쓰는 것에서 시작하기 때문입니다. 해당 위치들이 마스킹되어 있으면, 공격자는 컨테이너 내에서 코드 실행을 얻은 이후에도 커널 제어 표면의 유용한 부분에 직접 접근하는 것을 잃게 됩니다.

## 동작

런타임은 일반적으로 다음과 같은 경로들을 마스킹합니다:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

정확한 목록은 런타임과 호스트 구성에 따라 다릅니다. 중요한 점은 해당 경로가 호스트에는 여전히 존재하더라도 컨테이너 관점에서는 접근 불가능해지거나 대체된다는 것입니다.

## 실습

Docker가 노출하는 마스킹된 경로 구성을 확인하세요:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
워크로드 내부에서 실제 마운트 동작을 확인하세요:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## 보안 영향

Masking은 주된 격리 경계를 생성하지는 않지만, 여러 고가치 post-exploitation 타깃을 제거합니다. Masking이 없으면 침해된 컨테이너가 커널 상태를 검사하거나 민감한 프로세스나 키 관련 정보를 읽거나 애플리케이션에 절대 노출되어서는 안 되는 procfs/sysfs 객체와 상호작용할 수 있습니다.

## 잘못된 구성

주된 실수는 편의나 디버깅을 위해 광범위한 경로 클래스를 unmasking 하는 것입니다. Podman에서는 `--security-opt unmask=ALL` 또는 특정 대상 unmasking으로 나타날 수 있습니다. Kubernetes에서는 지나치게 넓은 proc 노출이 `procMount: Unmasked`로 나타날 수 있습니다. 또 다른 심각한 문제는 호스트의 `/proc` 또는 `/sys`를 bind mount로 노출하는 것으로, 이는 축소된 컨테이너 뷰라는 개념을 완전히 무시합니다.

## 악용

Masking이 약하거나 없으면, 먼저 어떤 민감한 procfs/sysfs 경로가 직접 접근 가능한지 식별하는 것부터 시작하세요:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
만약 마스킹된 것으로 보이는 경로에 접근할 수 있다면, 이를 주의 깊게 검사하세요:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- `/proc/keys` is much more sensitive. Depending on the host configuration, it may reveal keyring entries, key descriptions, and relationships between host services using the kernel keyring subsystem.
- `/sys/firmware` helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- `/proc/config.gz` may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- `/proc/sched_debug` exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Interesting results include direct reads from those files, evidence that the data belongs to the host rather than to a constrained container view, or access to other procfs/sysfs locations that are commonly masked by default.

## 점검

이 점검들의 목적은 런타임이 의도적으로 숨긴 경로가 무엇인지, 그리고 현재 워크로드가 여전히 축소된 커널 관련 파일시스템을 보고 있는지를 판별하는 것입니다.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
여기서 흥미로운 점:

- 하드닝된 런타임에서는 긴 마스킹된 경로 목록이 정상이다.
- 민감한 procfs 항목에 대한 마스킹 누락은 더 면밀한 조사가 필요하다.
- 민감한 경로에 접근 가능하고 컨테이너가 강력한 capabilities(권한) 또는 광범위한 마운트를 가진 경우, 노출 위험이 더 커진다.

## 런타임 기본값

| Runtime / 플랫폼 | 기본 상태 | 기본 동작 | 일반적인 수동 약화 방법 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화됨 | Docker는 기본 마스킹된 경로 목록을 정의함 | 호스트의 proc/sys 마운트 노출, `--privileged` |
| Podman | 기본적으로 활성화됨 | Podman은 수동으로 마스킹을 해제(unmask)하지 않는 한 기본 마스킹 경로를 적용함 | `--security-opt unmask=ALL`, 특정 대상 마스킹 해제, `--privileged` |
| Kubernetes | 런타임 기본값을 상속함 | Pod 설정이 proc 노출을 약화시키지 않는 한 기본 런타임의 마스킹 동작을 사용함 | `procMount: Unmasked`, privileged 워크로드 패턴, 광범위한 호스트 마운트 |
| containerd / CRI-O under Kubernetes | 런타임 기본값 | 오버라이드되지 않는 한 보통 OCI/런타임 마스킹 경로를 적용함 | 직접 런타임 구성 변경, 동일한 Kubernetes 약화 경로 |

마스킹된 경로는 보통 기본적으로 존재한다. 주요 운영 문제는 런타임에서의 부재가 아니라, 의도적인 마스킹 해제나 보호를 무효화하는 호스트 바인드 마운트이다.
