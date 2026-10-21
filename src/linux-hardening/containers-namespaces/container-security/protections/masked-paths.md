# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths는 특히 민감한 커널 관련 파일시스템 위치를 그 위에 bind-mount하거나 다른 방식으로 접근할 수 없게 만들어 컨테이너에서 숨기는 런타임 보호 기능입니다. OCI runtime specification은 `maskedPaths`를 컨테이너 내부에서 읽을 수 없어야 하는 절대 경로로 정의합니다. <sup>[[1]](#references)</sup>

이는 많은 컨테이너 탈출 및 호스트에 영향을 미치는 기법이 `/proc` 또는 `/sys` 아래의 특수 파일을 읽거나 쓰는 데서 시작되기 때문에 중요합니다. 해당 위치가 masked되면 공격자는 컨테이너 내부에서 코드 실행 권한을 얻더라도 커널 제어 인터페이스의 유용한 부분에 직접 접근할 수 없습니다.

## Operation

런타임은 일반적으로 다음과 같은 경로를 선택해 mask합니다.

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

정확한 목록은 런타임과 호스트 구성에 따라 다릅니다. 중요한 점은 호스트에는 해당 경로가 여전히 존재하더라도 컨테이너 관점에서는 접근할 수 없거나 다른 항목으로 대체된다는 것입니다.

## Lab

Docker에서 제공하는 masked-path 구성을 확인합니다.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

워크로드 내부의 실제 마운트 동작을 확인합니다:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

나열된 경로라고 해서 반드시 읽을 수 있는 것은 아닙니다. runc는 파일을 `/dev/null` bind mount로, 디렉터리를 읽기 전용 빈 tmpfs로 가릴 수 있습니다. `ls`가 성공하는지만 확인하지 말고 정확한 mountpoint를 확인하세요. <sup>[[4]](#references)</sup>

## 보안 영향

마스킹이 주요 격리 경계를 만들지는 않지만, post-exploitation에서 가치가 높은 여러 대상을 제거합니다. 마스킹이 없으면 침해된 컨테이너가 커널 상태를 조사하거나, 민감한 프로세스 정보 또는 키 관련 정보를 읽거나, 애플리케이션에 절대 노출되어서는 안 되는 procfs/sysfs 객체와 상호작용할 수 있습니다.

## 잘못된 설정

주된 실수는 편의나 디버깅을 위해 광범위한 경로를 마스킹 해제하는 것입니다. Podman에서는 `--security-opt unmask=ALL` 또는 특정 경로의 마스킹 해제로 나타날 수 있습니다. <sup>[[2]](#references)</sup> Kubernetes에서는 과도하게 넓은 proc 노출이 `procMount: Unmasked`로 나타날 수 있습니다. 현재 Kubernetes에서는 이 설정을 사용하려면 `spec.hostUsers: false`(user namespace)가 필요하지만, 버전 1.12–1.29에서는 이 요구사항을 적용하지 않았습니다. <sup>[[3]](#references)</sup> 또 다른 심각한 문제는 bind mount를 통해 호스트의 `/proc` 또는 `/sys`를 노출하는 것입니다. 이는 컨테이너에 축소된 뷰를 제공한다는 개념 자체를 우회합니다.

## 악용

마스킹이 허술하거나 적용되지 않았다면, 먼저 민감한 procfs/sysfs 경로 중 어떤 경로에 직접 접근할 수 있는지 확인합니다:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

마스킹된 것으로 알려진 경로에 접근할 수 있다면, 주의 깊게 살펴보세요:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

이 명령으로 확인할 수 있는 정보:

- `/proc/timer_list`는 호스트의 타이머 및 스케줄러 데이터를 노출할 수 있습니다. 이는 주로 정찰에 사용되지만, 컨테이너에서 일반적으로 숨겨지는 커널 관련 정보를 읽을 수 있음을 확인해 줍니다.
- `/proc/keys`는 LSM 검사를 거쳐 읽기 권한이 **있는** 키의 메타데이터만 나열합니다. 키 유형과 설명은 확인할 수 있지만, 키 payload를 덤프하지는 않습니다. <sup>[[6]](#references)</sup>
- `/sys/firmware`를 통해 부팅 모드, 펌웨어 인터페이스, 플랫폼 세부 정보를 확인할 수 있습니다. 이러한 정보는 호스트 fingerprinting과 워크로드가 호스트 수준의 상태를 보고 있는지 파악하는 데 유용합니다.
- `/proc/config.gz`에는 실행 중인 커널 설정이 포함되어 있을 수 있습니다. 이는 공개된 커널 exploit의 전제 조건을 대조하거나 특정 기능에 접근할 수 있는 이유를 파악하는 데 유용합니다.
- `/proc/sched_debug`는 스케줄러 상태를 노출하며, PID namespace가 관련 없는 프로세스 정보를 완전히 숨길 것이라는 직관적 예상과 달리 정보를 노출하는 경우가 많습니다.

주목할 만한 결과로는 해당 파일을 직접 읽을 수 있는 경우, 데이터가 제한된 컨테이너 뷰가 아닌 호스트에 속한다는 증거, 또는 기본적으로 흔히 mask되는 다른 procfs/sysfs 위치에 접근할 수 있는 경우가 있습니다.

### 컨테이너 시작 중 mask 소스 race

취약한 runc 구현에서는 파일 mask가 컨테이너의 `/dev/null` inode에 의존합니다. BuildKit 단계 병렬 실행을 포함해 공유 mount를 사용하는 컨테이너를 동시에 실행할 수 있는 공격자는 runc가 `/dev/null`을 mask 대상 procfs 파일에 bind하기 전에 이를 제거해 race를 유발할 수 있습니다. 그러면 런타임은 소스가 없는 상황을 mask 대상이 없는 것처럼 처리하고 해당 파일 mask를 조용히 건너뜁니다. 이 문제는 런타임 설정 중 race에 따라 달라집니다. 시작 후 `/dev/null`을 제거해도 이미 적용된 mask는 해제되지 않습니다. <sup>[[4]](#references)</sup>

통제된 테스트를 마친 뒤에는 새 컨테이너 내부에서 요청된 mask 목록과 정확한 mountpoint를 비교하세요. <sup>[[4]](#references)</sup> `findmnt -M`은 상위 mount로 대체하지 않고 지정된 mountpoint를 확인합니다. `findmnt`가 없으면 `/proc/self/mountinfo`를 살펴보세요. <sup>[[5]](#references)</sup> `ls`가 성공하거나 `cat`의 출력이 비어 있다고 해서 mask가 적용되지 않았다고 입증할 수는 없습니다. <sup>[[4]](#references)</sup>

새 컨테이너에서 요청된 mask와 정확한 mount를 비교하려면 [아래 검사](#checks)를 사용하세요.

파일 mask가 건너뛰어지면 일반 권한과 LSM 정책이 허용하는 경우 procfs 데이터가 노출될 수 있습니다. 하지만 그 자체로 `/proc/sys`를 쓰기 가능하게 만들지는 않습니다. 이는 별도의 [read-only-path](read-only-paths.md) 제어입니다. bind mount가 쓰기 가능한 procfs 대상으로 리디렉션될 수 있는 별개의 `/dev/null` symlink 대체 문제는 [PID-namespace runtime race](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs)에서 다룹니다. <sup>[[4]](#references)</sup>

## 검사

이 검사의 목적은 런타임이 의도적으로 숨긴 경로와 현재 워크로드에서 커널 관련 파일시스템이 여전히 축소된 상태로 보이는지를 확인하는 것입니다.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

정확한 mount 확인을 사용하세요. masked file이 여전히 존재할 수 있고, 읽기 결과가 `/dev/null`에서 온 빈 값일 수도 있습니다. mountpoint가 없다는 점은 조사할 만한 발견이지만, 그 자체로 호스트 데이터를 읽을 수 있다는 증거는 아닙니다. <sup>[[4]](#references)[[5]](#references)</sup>

여기서 주목할 점:

- hardened runtime에서는 masked path 목록이 긴 것이 일반적입니다.
- 민감한 procfs 항목의 masking이 누락되었다면 더 자세히 살펴볼 필요가 있습니다.
- 민감한 경로에 접근할 수 있고 컨테이너에 강력한 capabilities나 광범위한 mounts까지 있다면 노출 위험은 더 커집니다.

## Runtime 기본 설정

| Runtime / platform | 기본 상태 | 기본 동작 | 흔히 수동으로 보호를 약화하는 방법 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화 | Docker가 기본 masked path 목록을 정의함 | 호스트 proc/sys mounts 노출, `--privileged` |
| Podman | 기본적으로 활성화 | 수동으로 unmask하지 않는 한 Podman이 기본 masked paths를 적용함 | `--security-opt unmask=ALL`, 특정 경로 unmask, `--privileged` |
| Kubernetes | Runtime 기본 설정을 상속 | Pod 설정으로 proc 노출을 약화하지 않는 한 기반 runtime의 masking 동작을 사용함 | `procMount: Unmasked`(현재 릴리스에서는 `hostUsers: false` 필요), privileged workload 패턴, 광범위한 host mounts |
| Kubernetes에서 사용하는 containerd / CRI-O | Runtime 기본 설정 | 일반적으로 재정의되지 않는 한 OCI/runtime masked paths를 적용함 | runtime 설정 직접 변경, Kubernetes에서 동일한 보호 약화 방법 사용 |

Masked paths는 대개 기본적으로 설정되어 있습니다. 주요 운영 문제는 runtime에 설정이 없는 것이 아니라, 의도적으로 unmask하거나 보호를 무력화하는 host bind mounts를 사용하는 것입니다.

## References

- [1] [Open Container Initiative - Linux 컨테이너 설정: Masked Paths](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman 문서 - `podman run` 보안 옵션](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes 문서 - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc 보안 권고: masked-path mount source 경쟁 조건](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [findmnt(8) 매뉴얼](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [keyrings(7) 매뉴얼](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
