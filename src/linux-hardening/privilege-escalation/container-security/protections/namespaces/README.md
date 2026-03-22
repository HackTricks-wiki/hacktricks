# 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

네임스페이스는 컨테이너가 실제로는 단순한 호스트 프로세스 트리임에도 불구하고 "자기만의 머신"처럼 느껴지게 하는 커널 기능입니다. 네임스페이스는 새로운 커널을 만들지 않으며 모든 것을 가상화하지도 않지만, 커널이 선택된 리소스에 대해 서로 다른 프로세스 그룹에 서로 다른 뷰를 제공할 수 있게 합니다. 이것이 컨테이너 환상의 핵심입니다: 워크로드는 로컬로 보이는 파일시스템, 프로세스 테이블, 네트워크 스택, 호스트명, IPC 리소스, 그리고 사용자/그룹 식별 모델을 보지만, 실제로는 기반 시스템이 공유됩니다.

이 때문에 네임스페이스는 대부분의 사람이 컨테이너 작동 방식을 배울 때 처음 접하는 개념입니다. 동시에 많은 오해를 낳는 개념이기도 합니다. 독자들은 종종 "네임스페이스가 있다"는 것이 "안전하게 격리되어 있다"는 뜻이라고 가정하기 때문입니다. 실제로 네임스페이스는 설계된 특정 자원 클래스만 격리합니다. 프로세스는 private PID 네임스페이스를 가졌더라도 호스트의 쓰기 가능한 bind mount가 있으면 여전히 위험할 수 있습니다. private network 네임스페이스를 갖고 있더라도 `CAP_SYS_ADMIN`을 보유하고 seccomp 없이 실행되면 여전히 위험할 수 있습니다. 네임스페이스는 기초적이지만 최종 경계의 한 레이어에 불과합니다.

## 네임스페이스 유형

Linux 컨테이너는 일반적으로 여러 네임스페이스 유형을 동시에 사용합니다. **mount namespace**는 프로세스에 별도의 마운트 테이블을 제공하여 통제된 파일시스템 보기를 제공합니다. **PID namespace**는 프로세스 가시성과 번호 매김을 변경하여 워크로드가 자체 프로세스 트리를 보도록 합니다. **network namespace**는 인터페이스, 라우트, 소켓, 방화벽 상태를 격리합니다. **IPC namespace**는 SysV IPC와 POSIX 메시지 큐를 격리합니다. **UTS namespace**는 호스트명과 NIS 도메인명을 격리합니다. **user namespace**는 사용자 및 그룹 ID를 리맵핑하여 컨테이너 내부의 root가 호스트의 root를 반드시 의미하지 않게 합니다. **cgroup namespace**는 보이는 cgroup 계층을 가상화하고, **time namespace**는 최신 커널에서 선택된 시계를 가상화합니다.

각 네임스페이스는 다른 문제를 해결합니다. 따라서 실제적인 컨테이너 보안 분석은 종종 **어떤 네임스페이스가 격리되어 있는가**와 **어떤 네임스페이스가 호스트와 의도적으로 공유되었는가**를 확인하는 것으로 귀결됩니다.

## 호스트 네임스페이스 공유

많은 컨테이너 탈주(container breakout)는 커널 취약점에서 시작하지 않습니다. 운영자가 의도적으로 격리 모델을 약화시키면서 시작됩니다. 예로 `--pid=host`, `--network=host`, `--userns=host` 같은 것은 **Docker/Podman-style CLI flags**로 여기서는 호스트 네임스페이스 공유의 구체적 예로 사용합니다. 다른 런타임은 같은 개념을 다르게 표현합니다. Kubernetes에서는 동등한 설정이 보통 `hostPID: true`, `hostNetwork: true`, 또는 `hostIPC: true` 같은 Pod 설정으로 나타납니다. containerd나 CRI-O 같은 하위 레벨 런타임 스택에서는 동일한 동작이 사용자용 플래그 대신 생성된 OCI 런타임 구성(configuration)을 통해 달성되는 경우가 많습니다. 이 모든 경우 결과는 비슷합니다: 워크로드는 더 이상 기본으로 제공되는 격리된 네임스페이스 뷰를 받지 못합니다.

이 때문에 네임스페이스 검토는 "프로세스가 어떤 네임스페이스에 있다"에서 멈춰서는 안 됩니다. 중요한 질문은 해당 네임스페이스가 컨테이너에 대해 프라이빗한지, 동급 컨테이너들과 공유되는지, 아니면 호스트에 직접 조인되어 있는지입니다. Kubernetes에서는 같은 아이디어가 `hostPID`, `hostNetwork`, `hostIPC` 같은 플래그로 나타납니다. 플랫폼마다 이름은 다르지만 위험 패턴은 동일합니다: 호스트와 공유된 네임스페이스는 컨테이너의 남은 권한과 도달 가능한 호스트 상태를 훨씬 더 의미 있게 만듭니다.

## Inspection

The simplest overview is:
```bash
ls -l /proc/self/ns
```
각 항목은 inode-like 식별자를 가진 symbolic link입니다. 두 프로세스가 동일한 namespace 식별자를 가리키면, 그들은 해당 타입의 동일한 namespace에 속합니다. 이 때문에 `/proc`은 현재 프로세스를 시스템의 다른 흥미로운 프로세스들과 비교하는 데 매우 유용한 장소가 됩니다.

이러한 빠른 명령들은 시작하기에 종종 충분합니다:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
그 다음 단계는 container process를 host 또는 인접한 프로세스와 비교하여 해당 namespace가 실제로 private한지 아닌지를 판단하는 것이다.

### 호스트에서 Namespace 인스턴스 열거

이미 host access가 있고 특정 타입의 서로 다른 namespace가 몇 개 존재하는지 파악하고 싶다면, `/proc`는 빠른 인벤토리를 제공한다:
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
특정 네임스페이스 식별자에 속한 프로세스를 찾으려면 `readlink` 대신 `ls -l`을 사용하고 대상 네임스페이스 번호를 grep하세요:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
이 명령들은 호스트가 하나의 격리된 workload를 실행하는지, 여러 개의 격리된 workload를 실행하는지, 또는 shared와 private namespace 인스턴스가 혼재되어 있는지를 판단할 수 있게 해주기 때문에 유용합니다.

### 대상 namespace로 진입하기

권한이 충분하면, `nsenter`는 다른 프로세스의 namespace에 들어가는 표준 방법입니다:
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
이들 형태를 함께 나열한 목적은 모든 평가에 이들 모두가 필요해서가 아니라, 운영자가 모든 네임스페이스를 지정하는 형태만 기억하는 대신 정확한 진입 구문을 알면 namespace-specific post-exploitation가 훨씬 쉬워지는 경우가 많기 때문이다.

## Pages

다음 페이지들은 각 네임스페이스를 더 자세히 설명한다:

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

읽는 동안 두 가지를 염두에 두어라. 첫째, 각 네임스페이스는 오직 한 종류의 뷰만 격리한다. 둘째, 사설 네임스페이스는 나머지 권한 모델이 그 격리를 여전히 의미 있게 만들 때에만 유용하다.

## Runtime Defaults

| Runtime / platform | 기본 네임스페이스 구성 | 일반적인 수동 약화 방법 |
| --- | --- | --- |
| Docker Engine | 기본적으로 새로운 mount, PID, network, IPC, UTS 네임스페이스 생성; user namespaces는 사용 가능하지만 표준 rootful 설정에서는 기본적으로 활성화되어 있지 않음 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | 기본적으로 새로운 네임스페이스 생성; rootless Podman은 자동으로 user namespace를 사용함; cgroup namespace의 기본값은 cgroup 버전에 따라 다름 | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods는 기본적으로 호스트 PID, network, IPC를 공유하지 않음; Pod 네트워킹은 각 컨테이너가 아니라 Pod 단위로 프라이빗임; user namespaces는 지원되는 클러스터에서 `spec.hostUsers: false`로 옵트인 방식 | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / user-namespace 옵트인을 생략함, privileged 워크로드 설정 |
| containerd / CRI-O under Kubernetes | 보통 Kubernetes Pod 기본값을 따름 | Kubernetes 행과 동일; 직접적인 CRI/OCI 스펙으로도 호스트 네임스페이스 조인을 요청할 수 있음 |

주된 이식성 규칙은 단순하다: 호스트 네임스페이스 공유의 **개념**은 런타임 전반에 걸쳐 공통적이지만, 호스트 네임스페이스를 지정하는 **구문**은 런타임별로 다르다.
{{#include ../../../../../banners/hacktricks-training.md}}
