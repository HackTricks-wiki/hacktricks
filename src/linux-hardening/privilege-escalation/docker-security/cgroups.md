# CGroups

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**Linux Control Groups** 또는 **cgroups**는 CPU, 메모리 및 디스크 I/O와 같은 시스템 리소스를 프로세스 그룹 간에 할당, 제한 및 우선 순위를 지정할 수 있는 리눅스 커널의 기능입니다. 이는 리소스 제한, 작업 부하 격리 및 다양한 프로세스 그룹 간의 리소스 우선 순위 지정과 같은 목적을 위해 프로세스 컬렉션의 리소스 사용을 **관리하고 격리하는** 메커니즘을 제공합니다.

**cgroups의 두 가지 버전**이 있습니다: 버전 1과 버전 2. 두 버전 모두 시스템에서 동시에 사용할 수 있습니다. 주요 차이점은 **cgroups 버전 2**가 **계층적이고 트리와 같은 구조**를 도입하여 프로세스 그룹 간의 리소스 분배를 보다 세밀하고 상세하게 할 수 있게 한다는 것입니다. 또한, 버전 2는 **새로운 리소스 컨트롤러**에 대한 지원, 레거시 애플리케이션에 대한 더 나은 지원 및 성능 향상과 같은 다양한 개선 사항을 가져옵니다.

전반적으로 cgroups **버전 2는 버전 1보다 더 많은 기능과 더 나은 성능**을 제공하지만, 후자는 구형 시스템과의 호환성이 우려되는 특정 시나리오에서 여전히 사용될 수 있습니다.

프로세스의 cgroup 파일을 /proc/\<pid>에서 확인하여 v1 및 v2 cgroups를 나열할 수 있습니다. 이 명령어로 셸의 cgroups를 확인하는 것부터 시작할 수 있습니다:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
- **숫자 2–12**: cgroups v1, 각 줄은 다른 cgroup을 나타냅니다. 이들의 컨트롤러는 숫자 옆에 지정되어 있습니다.
- **숫자 1**: 또한 cgroups v1이지만 관리 목적으로만 사용되며(예: systemd에 의해 설정됨) 컨트롤러가 없습니다.
- **숫자 0**: cgroups v2를 나타냅니다. 컨트롤러가 나열되지 않으며, 이 줄은 cgroups v2만 실행하는 시스템에서 독점적입니다.
- **이름은 계층적이며**, 파일 경로를 닮아 서로 다른 cgroups 간의 구조와 관계를 나타냅니다.
- **/user.slice 또는 /system.slice**와 같은 이름은 cgroups의 분류를 지정하며, user.slice는 일반적으로 systemd에 의해 관리되는 로그인 세션을 위해, system.slice는 시스템 서비스를 위해 사용됩니다.

### cgroups 보기

파일 시스템은 일반적으로 **cgroups**에 접근하는 데 사용되며, 전통적으로 커널 상호작용에 사용되는 Unix 시스템 호출 인터페이스와는 다릅니다. 셸의 cgroup 구성을 조사하려면 **/proc/self/cgroup** 파일을 확인해야 하며, 이 파일은 셸의 cgroup을 보여줍니다. 그런 다음 **/sys/fs/cgroup** (또는 **`/sys/fs/cgroup/unified`**) 디렉토리로 이동하여 cgroup의 이름과 공유하는 디렉토리를 찾으면 cgroup과 관련된 다양한 설정 및 리소스 사용 정보를 관찰할 수 있습니다.

![Cgroup Filesystem](<../../../images/image (1128).png>)

cgroups의 주요 인터페이스 파일은 **cgroup**으로 접두사가 붙습니다. **cgroup.procs** 파일은 표준 명령(cat 등)으로 볼 수 있으며, cgroup 내의 프로세스를 나열합니다. 또 다른 파일인 **cgroup.threads**는 스레드 정보를 포함합니다.

![Cgroup Procs](<../../../images/image (281).png>)

셸을 관리하는 cgroups는 일반적으로 메모리 사용량과 프로세스 수를 조절하는 두 개의 컨트롤러를 포함합니다. 컨트롤러와 상호작용하려면 컨트롤러의 접두사가 붙은 파일을 참조해야 합니다. 예를 들어, **pids.current**를 참조하여 cgroup 내의 스레드 수를 확인할 수 있습니다.

![Cgroup Memory](<../../../images/image (677).png>)

값에 **max**가 표시되면 cgroup에 대한 특정 제한이 없음을 나타냅니다. 그러나 cgroups의 계층적 특성으로 인해 디렉토리 계층의 하위 수준에 있는 cgroup에서 제한이 부과될 수 있습니다.

### cgroups 조작 및 생성

프로세스는 **`cgroup.procs` 파일에 프로세스 ID (PID)를 작성하여** cgroups에 할당됩니다. 이는 루트 권한이 필요합니다. 예를 들어, 프로세스를 추가하려면:
```bash
echo [pid] > cgroup.procs
```
유사하게, **PID 제한을 설정하는 것과 같은 cgroup 속성을 수정하는** 것은 원하는 값을 관련 파일에 작성함으로써 수행됩니다. cgroup에 대해 최대 3,000개의 PID를 설정하려면:
```bash
echo 3000 > pids.max
```
**새 cgroup 생성**은 cgroup 계층 내에 새로운 하위 디렉토리를 만드는 것을 포함하며, 이는 커널이 필요한 인터페이스 파일을 자동으로 생성하도록 유도합니다. 활성 프로세스가 없는 cgroup은 `rmdir`로 제거할 수 있지만, 특정 제약 사항을 인지해야 합니다:

- **프로세스는 리프 cgroup에만 배치될 수 있습니다** (즉, 계층에서 가장 중첩된 것들).
- **cgroup은 부모에 없는 컨트롤러를 가질 수 없습니다**.
- **자식 cgroup의 컨트롤러는 `cgroup.subtree_control` 파일에 명시적으로 선언되어야 합니다**. 예를 들어, 자식 cgroup에서 CPU 및 PID 컨트롤러를 활성화하려면:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**루트 cgroup**은 이러한 규칙의 예외로, 직접 프로세스를 배치할 수 있습니다. 이는 systemd 관리에서 프로세스를 제거하는 데 사용될 수 있습니다.

**cgroup 내에서 CPU 사용량 모니터링**은 `cpu.stat` 파일을 통해 가능하며, 총 CPU 시간 소비를 표시하여 서비스의 하위 프로세스에서 사용량을 추적하는 데 유용합니다:

<figure><img src="../../../images/image (908).png" alt=""><figcaption><p>cpu.stat 파일에 표시된 CPU 사용 통계</p></figcaption></figure>

## 참고문헌

- **책: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**

{{#include ../../../banners/hacktricks-training.md}}
