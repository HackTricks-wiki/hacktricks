# PID 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

PID 네임스페이스는 프로세스에 어떻게 번호가 할당되는지와 어떤 프로세스가 보이는지를 제어한다. 이 때문에 컨테이너는 실제 기계가 아님에도 자체적인 PID 1을 가질 수 있다. 네임스페이스 내부에서는 워크로드가 로컬 프로세스 트리처럼 보이는 것을 본다. 네임스페이스 바깥에서는 호스트가 실제 호스트 PID와 전체 프로세스 지형을 여전히 본다.

보안 관점에서 PID 네임스페이스가 중요한 이유는 프로세스 가시성이 가치가 있기 때문이다. 워크로드가 호스트 프로세스를 볼 수 있게 되면 서비스 이름, 명령행 인수, 프로세스 인수로 전달된 비밀, `/proc`을 통해 얻는 환경 기반 상태, 그리고 잠재적인 네임스페이스 진입 대상 등을 관찰할 수 있다. 만약 단순히 프로세스를 보는 것 이상으로, 예를 들어 적절한 조건에서 시그널을 보내거나 ptrace를 사용하는 등의 행동이 가능해진다면 문제는 훨씬 더 심각해진다.

## 동작

새 PID 네임스페이스는 자체 내부 프로세스 번호 체계로 시작한다. 그 안에서 생성된 첫 번째 프로세스는 네임스페이스 관점에서 PID 1이 되며, 이는 고아가 된 자식 프로세스와 시그널 동작에 대해 특수한 init-like 의미를 갖는다는 것을 뜻한다. 이것이 init 프로세스, 좀비 프로세스 수거(zombie reaping)와 관련된 많은 컨테이너 특이 현상과, 왜 컨테이너에서 작은 init 래퍼가 가끔 사용되는지를 설명해 준다.

중요한 보안 교훈은, 프로세스가 자신의 PID 트리만 보기 때문에 격리되어 보일 수 있지만 그 격리는 의도적으로 제거될 수 있다는 것이다. Docker는 이를 `--pid=host`로 노출하고, Kubernetes는 `hostPID: true`로 설정한다. 컨테이너가 호스트 PID 네임스페이스에 합류하면 워크로드는 호스트 프로세스를 직접 보게 되고 이후의 많은 공격 경로가 훨씬 현실적으로 된다.

## 실습

수동으로 PID 네임스페이스를 생성하려면:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
쉘은 이제 개인 프로세스 뷰를 보게 됩니다. `--mount-proc` 플래그는 새로운 PID namespace와 일치하는 procfs 인스턴스를 마운트하기 때문에 중요하며, 내부에서 볼 때 프로세스 목록을 일관되게 만듭니다.

컨테이너 동작을 비교하려면:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
차이는 즉시 드러나고 이해하기 쉬워 독자들에게 좋은 첫 실습 과제다.

## 런타임 사용

Docker, Podman, containerd, CRI-O의 일반 컨테이너는 각자 고유한 PID namespace를 갖는다. Kubernetes Pod도 보통 워크로드가 명시적으로 호스트 PID 공유를 요청하지 않는 한 격리된 PID 뷰를 받는다. LXC/Incus 환경도 동일한 커널 primitive에 의존하지만, system-container 사용 사례는 더 복잡한 프로세스 트리를 노출시키고 더 많은 디버깅 지름길을 유도할 수 있다.

어디든 같은 규칙이 적용된다: 런타임이 PID namespace를 격리하지 않기로 선택했다면, 이는 의도적인 컨테이너 경계 축소이다.

## 잘못된 구성

대표적인 잘못된 구성은 호스트 PID 공유다. 팀들은 디버깅, 모니터링, 또는 서비스 관리의 편의성을 이유로 이를 정당화하는 경우가 많지만, 항상 중요한 보안 예외로 취급해야 한다. 컨테이너가 호스트 프로세스에 대해 즉각적인 쓰기 primitive를 가지지 않더라도, 가시성만으로도 시스템에 대해 많은 정보를 드러낼 수 있다. 일단 `CAP_SYS_PTRACE` 같은 capabilities나 유용한 procfs 접근이 추가되면 위험은 크게 확대된다.

또 다른 실수는 워크로드가 기본적으로 호스트 프로세스를 kill하거나 ptrace할 수 없으니 호스트 PID 공유는 무해하다고 가정하는 것이다. 그런 결론은 enumeration의 가치, namespace-entry 대상의 이용 가능성, 그리고 PID 가시성이 다른 약화된 제어들과 결합되는 방식을 무시한다.

## 악용

호스트 PID namespace가 공유되어 있다면, 공격자는 호스트 프로세스를 검사하거나, 프로세스 인자를 수집하거나, 흥미로운 서비스를 식별하거나, `nsenter`용 후보 PID를 찾거나, 프로세스 가시성을 ptrace 관련 권한과 결합해 호스트나 인접 워크로드를 방해할 수 있다. 어떤 경우에는 적절한 장기 실행 프로세스를 확인하는 것만으로도 나머지 공격 계획을 재구성하기에 충분하다.

첫 번째 실용적 단계는 항상 호스트 프로세스가 실제로 보이는지 확인하는 것이다:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
호스트 PIDs가 보이면, process arguments와 namespace-entry targets는 종종 가장 유용한 정보원이 된다:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
만약 `nsenter`가 사용 가능하고 충분한 권한이 있다면, 보이는 호스트 프로세스를 namespace bridge로 사용할 수 있는지 테스트하세요:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
접근이 차단되더라도, 호스트 PID 공유는 서비스 구성, 런타임 구성요소, 다음으로 공격 대상으로 삼을 수 있는 권한이 높은 프로세스 후보를 드러내기 때문에 이미 유용하다.

호스트 PID 가시성은 파일 디스크립터 악용을 더 현실적으로 만든다. 권한 있는 호스트 프로세스나 인접 워크로드가 민감한 파일이나 소켓을 열어둔 경우, 공격자는 소유권, procfs 마운트 옵션, 대상 서비스 모델에 따라 `/proc/<pid>/fd/`를 검사하고 해당 핸들을 재사용할 수 있다.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
이 명령들은 `hidepid=1` 또는 `hidepid=2`가 프로세스 간 가시성을 줄이는지, 그리고 열린 비밀 파일, 로그 또는 Unix sockets와 같은 명백히 흥미로운 디스크립터들이 전혀 보이는지 여부를 알려주기 때문에 유용합니다.

### 전체 예제: host PID + `nsenter`

프로세스가 host namespaces에 합류할 수 있을 만큼 충분한 권한을 가지면, Host PID 공유는 직접적인 host escape가 됩니다:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
명령이 성공하면, 컨테이너 프로세스는 이제 호스트의 mount, UTS, network, IPC 및 PID 네임스페이스에서 실행됩니다. 영향은 즉각적인 호스트 침해입니다.

설령 `nsenter` 자체가 없더라도, 호스트 파일시스템이 마운트되어 있다면 호스트 바이너리를 통해 동일한 결과를 얻을 수 있습니다:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 최근 런타임 노트

일부 PID 네임스페이스 관련 공격은 전통적인 `hostPID: true` 설정 오류가 아니라, 컨테이너 설정 중 procfs 보호가 적용되는 방식의 런타임 구현 버그입니다.

#### `maskedPaths`의 host procfs 레이스

취약한 `runc` 버전에서는 컨테이너 이미지나 `runc exec` 작업을 제어할 수 있는 공격자가 컨테이너 쪽의 `/dev/null`을 `/proc/sys/kernel/core_pattern` 같은 민감한 procfs 경로를 가리키는 심볼릭 링크로 교체해 masking 단계에서 레이스를 걸 수 있습니다. 레이스가 성공하면 masked-path bind mount가 잘못된 대상에 걸려 호스트 전역의 procfs knobs를 새 컨테이너에 노출시킬 수 있습니다.

검토에 유용한 명령:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
이는 결국 procfs 노출과 동일한 영향을 초래할 수 있기 때문에 중요하다: 쓰기 가능한 `core_pattern` 또는 `sysrq-trigger`가 생기고, 이어서 host code execution 또는 denial of service가 발생할 수 있다.

#### Namespace injection with `insject`

`insject`와 같은 Namespace injection 도구는 PID-namespace 상호작용이 프로세스 생성 전에 대상 네임스페이스에 미리 들어가 있어야만 하는 것이 아님을 보여준다. 헬퍼는 나중에 attach하여 `setns()`를 사용하고, 대상 PID 공간에 대한 가시성을 유지한 채 실행할 수 있다:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
이러한 기법은 주로 고급 디버깅, offensive tooling, 그리고 런타임이 이미 워크로드를 초기화한 이후에 네임스페이스 컨텍스트에 조인해야 하는 post-exploitation 워크플로우에서 중요하다.

### 관련 FD 악용 패턴

호스트 PID가 보이는 경우 명시적으로 언급할 가치가 있는 패턴이 두 가지 있다. 첫째, 권한이 높은 프로세스가 `O_CLOEXEC`로 표시되지 않아 민감한 파일 디스크립터를 `execve()` 이후에도 열린 상태로 유지할 수 있다. 둘째, 서비스는 `SCM_RIGHTS`를 통해 Unix 소켓으로 파일 디스크립터를 전달할 수 있다. 두 경우 모두 흥미로운 객체는 더 이상 경로명이 아니라, 권한이 낮은 프로세스가 상속하거나 받을 수 있는 이미 열린 핸들이다.

컨테이너 작업에서 이것은 중요하다. 왜냐하면 그 핸들이 컨테이너 파일시스템에서 경로 자체에 직접 접근할 수 없더라도 `docker.sock`, 권한 있는 로그, 호스트 비밀 파일, 또는 다른 고가치 객체를 가리킬 수 있기 때문이다.

## 검사

이 명령들의 목적은 해당 프로세스가 프라이빗 PID 뷰를 가지고 있는지, 아니면 이미 훨씬 넓은 프로세스 영역을 열거할 수 있는지를 판단하는 것이다.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
여기서 흥미로운 점:

- 프로세스 목록에 명백한 호스트 서비스가 포함되어 있다면, 호스트 PID 공유가 이미 활성화되어 있을 가능성이 큽니다.
- 작고 컨테이너 로컬한 트리만 보이는 것이 정상 기본 상태입니다; `systemd`, `dockerd`, 또는 관련 없는 데몬이 보이는 것은 그렇지 않습니다.
- 호스트 PID가 보이게 되면, 읽기 전용인 프로세스 정보조차도 유용한 정찰 정보가 됩니다.

호스트 PID 공유로 실행 중인 컨테이너를 발견하면, 이를 단순한 외형상의 차이로 보지 마세요. 이는 워크로드가 관찰하고 잠재적으로 영향을 줄 수 있는 범위에 있어 중대한 변화입니다.
