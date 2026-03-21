# 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

네임스페이스는 프로세스 트리로 동작하는 호스트 프로세스임에도 불구하고 컨테이너가 "자기만의 머신"처럼 느껴지게 하는 커널 기능입니다. 네임스페이스는 새로운 커널을 생성하지 않고 모든 것을 가상화하지도 않지만, 커널이 선택된 리소스에 대해 서로 다른 프로세스 그룹에 다른 뷰를 제공하도록 허용합니다. 이것이 컨테이너 환상의 핵심입니다: 워크로드는 로컬처럼 보이는 파일시스템, 프로세스 테이블, 네트워크 스택, hostname, IPC 리소스 및 사용자/그룹 동일성 모델을 보지만, 실제로는 기반 시스템이 공유됩니다.

이 때문에 네임스페이스는 대부분의 사람이 컨테이너 작동 방식을 배울 때 처음 접하는 개념입니다. 동시에 많은 사람들이 "네임스페이스가 있다"면 "안전하게 격리되어 있다"고 잘못 가정하기 때문에 가장 오해받기 쉬운 개념 중 하나이기도 합니다. 실제로 네임스페이스는 설계된 특정 리소스 종류만 격리합니다. 프로세스가 private PID 네임스페이스를 갖고 있어도 쓰기 가능한 호스트 바인드 마운트를 가지고 있으면 여전히 위험할 수 있습니다. private network 네임스페이스를 가지고 있어도 `CAP_SYS_ADMIN`을 보유하고 seccomp 없이 실행되면 여전히 위험할 수 있습니다. 네임스페이스는 기초적이지만 최종 경계에서는 단지 한 층에 불과합니다.

## 네임스페이스 유형

Linux 컨테이너는 일반적으로 여러 네임스페이스 유형을 동시에 사용합니다. **mount namespace**는 프로세스에 별도의 마운트 테이블을 제공하여 제어된 파일시스템 뷰를 제공합니다. **PID namespace**는 프로세스 가시성과 번호 체계를 변경하여 워크로드가 자체 프로세스 트리를 보도록 합니다. **network namespace**는 인터페이스, 라우트, 소켓 및 방화벽 상태를 격리합니다. **IPC namespace**는 SysV IPC 및 POSIX 메시지 큐를 격리합니다. **UTS namespace**는 hostname 및 NIS 도메인 이름을 격리합니다. **user namespace**는 사용자 및 그룹 ID를 재매핑하여 컨테이너 내부의 root가 호스트의 root를 의미하지 않도록 합니다. **cgroup namespace**는 보이는 cgroup 계층을 가상화하고, **time namespace**는 최신 커널에서 선택된 시계를 가상화합니다.

각 네임스페이스는 서로 다른 문제를 해결합니다. 따라서 실제 컨테이너 보안 분석은 종종 **어떤 네임스페이스가 격리되어 있는지**와 **어떤 네임스페이스가 의도적으로 호스트와 공유되었는지**를 확인하는 것으로 귀결됩니다.

## 호스트 네임스페이스 공유

많은 컨테이너 탈출은 커널 취약점에서 시작하지 않습니다. 운영자가 고의로 격리 모델을 약화시키면서 시작됩니다. 예시인 `--pid=host`, `--network=host`, 및 `--userns=host`는 호스트 네임스페이스 공유의 구체적 예로 사용된 **Docker/Podman-style CLI flags**입니다. 다른 런타임은 같은 아이디어를 다르게 표현합니다. Kubernetes에서는 보통 `hostPID: true`, `hostNetwork: true` 또는 `hostIPC: true` 같은 Pod 설정으로 나타납니다. containerd나 CRI-O 같은 하위 수준 런타임 스택에서는 동일한 동작이 같은 이름의 사용자 인터페이스 플래그 대신 생성된 OCI runtime configuration을 통해 달성되는 경우가 많습니다. 이 모든 경우에서 결과는 유사합니다: 워크로드는 더 이상 기본 격리된 네임스페이스 뷰를 받지 않습니다.

이 때문에 네임스페이스 검토는 "프로세스가 어떤 네임스페이스에 있다"에 그쳐서는 안 됩니다. 중요한 질문은 해당 네임스페이스가 컨테이너에만 사적인지, 형제 컨테이너들과 공유되는지, 아니면 직접 호스트에 연결되어 있는지입니다. Kubernetes에서는 같은 아이디어가 `hostPID`, `hostNetwork`, 및 `hostIPC` 같은 플래그로 나타납니다. 플랫폼마다 이름은 바뀌지만 위험 패턴은 동일합니다: 호스트 네임스페이스를 공유하면 컨테이너의 남은 권한과 도달 가능한 호스트 상태의 의미가 훨씬 커집니다.

## 검사

가장 간단한 개요는:
```bash
ls -l /proc/self/ns
```
각 항목은 inode-like 식별자를 가진 심볼릭 링크입니다. 두 프로세스가 동일한 namespace 식별자를 가리키면, 해당 유형의 동일한 namespace에 속합니다. 이 때문에 `/proc`는 현재 프로세스를 머신의 다른 흥미로운 프로세스들과 비교하기에 매우 유용한 장소입니다.

다음의 간단한 명령들은 시작하기에 충분한 경우가 많습니다:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
거기서 다음 단계는 container process를 host 또는 neighboring processes와 비교하여 해당 namespace가 실제로 격리되어 있는지 여부를 판단하는 것이다.

### Host에서 Namespace 인스턴스 열거

이미 host access가 있고 주어진 타입의 서로 다른 namespace가 몇 개 존재하는지 이해하고 싶다면, `/proc`가 빠른 인벤토리를 제공한다:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
특정 네임스페이스 식별자에 속한 프로세스를 찾으려면 `readlink` 대신 `ls -l`로 전환하고 대상 네임스페이스 번호를 grep하세요:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
이 명령들은 호스트가 하나의 격리된 워크로드를 실행하는지, 여러 개의 격리된 워크로드를 실행하는지, 또는 공유 및 개인 namespace 인스턴스가 혼합되어 있는지 여부를 확인할 수 있게 해주기 때문에 유용합니다.

### 대상 namespace에 진입

호출자가 충분한 권한을 가지고 있다면, `nsenter`는 다른 프로세스의 namespace에 들어가는 표준 방법입니다:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
이 양식들을 함께 나열한 목적은 모든 평가에 이들이 전부 필요해서가 아니라, namespace-specific post-exploitation은 운영자가 전체 네임스페이스 형태만 기억하는 대신 정확한 진입 문법을 알게 되면 훨씬 쉬워지기 때문이다.

## 페이지

다음 페이지들에서 각 네임스페이스를 더 자세히 설명한다:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

읽어보면서 두 가지를 염두에 두라. 첫째, 각 네임스페이스는 단 하나의 종류의 뷰만 격리한다. 둘째, 프라이빗 네임스페이스는 권한 모델의 나머지 요소가 그 격리를 여전히 의미 있게 만들 때에만 유용하다.

## 런타임 기본값

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | 기본적으로 새로운 mount, PID, network, IPC, 및 UTS 네임스페이스를 생성한다; user namespaces는 사용 가능하지만 표준 rootful 설정에서는 기본적으로 활성화되어 있지 않다 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | 기본적으로 새로운 네임스페이스 생성; rootless Podman은 자동으로 user namespace를 사용한다; cgroup namespace의 기본값은 cgroup 버전에 따라 다르다 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods는 기본적으로 호스트 PID, network, 또는 IPC를 공유하지 않는다; Pod 네트워킹은 각 개별 컨테이너가 아니라 Pod 단위로 사적이다; user namespaces는 지원되는 클러스터에서 `spec.hostUsers: false`를 통해 옵트인된다 | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | 대체로 Kubernetes Pod 기본값을 따른다 | Kubernetes 행과 동일; 직접적인 CRI/OCI 스펙도 호스트 네임스페이스 참가를 요청할 수 있다 |

주요 이식성 규칙은 간단하다: 호스트 네임스페이스 공유의 **개념**은 런타임 전반에 공통되지만, 호스트 네임스페이스 공유의 **구문**은 런타임별로 다르다.
