# PID 네임스페이스

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

PID (프로세스 식별자) 네임스페이스는 Linux 커널의 기능으로, 프로세스 그룹이 다른 네임스페이스의 PID와 분리된 고유한 PID 집합을 가지도록 하여 프로세스 격리를 제공합니다. 이는 프로세스 격리가 보안과 자원 관리에 필수적인 컨테이너화에서 특히 유용합니다.

새 PID 네임스페이스가 생성되면, 해당 네임스페이스의 첫 번째 프로세스에 PID 1이 할당됩니다. 이 프로세스는 새 네임스페이스의 "init" 프로세스가 되어 네임스페이스 내의 다른 프로세스들을 관리할 책임이 있습니다. 네임스페이스 내에서 생성되는 이후의 각 프로세스는 해당 네임스페이스 내에서 고유한 PID를 가지며, 이 PID들은 다른 네임스페이스의 PID와 독립적입니다.

PID 네임스페이스 내의 프로세스 관점에서는 같은 네임스페이스에 있는 다른 프로세스만 볼 수 있습니다. 다른 네임스페이스의 프로세스는 인식하지 못하며, 전통적인 프로세스 관리 도구(예: `kill`, `wait` 등)를 사용해 상호작용할 수 없습니다. 이는 프로세스들이 서로 간섭하지 못하도록 돕는 수준의 격리를 제공합니다.

### 동작 방식:

1. 새 프로세스가 생성될 때(예: `clone()` 시스템 콜을 사용하여), 그 프로세스는 새 또는 기존 PID 네임스페이스에 할당될 수 있습니다. **If a new namespace is created, the process becomes the "init" process of that namespace**.
2. **커널**은 새 네임스페이스의 PID들과 부모 네임스페이스(즉, 새 네임스페이스가 생성된 네임스페이스)의 해당 PID들 사이의 **매핑을 유지합니다**. 이 매핑은 **필요할 때 커널이 PID를 변환할 수 있게 해줍니다**, 예를 들어 서로 다른 네임스페이스에 있는 프로세스들 간에 신호를 보낼 때처럼.
3. **PID 네임스페이스 내의 프로세스들은 동일한 네임스페이스에 있는 다른 프로세스들만 보고 상호작용할 수 있습니다**. 그들은 다른 네임스페이스의 프로세스를 인식하지 못하며, 그들의 PID는 자신의 네임스페이스 내에서 고유합니다.
4. **PID 네임스페이스가 파괴되면**(예: 네임스페이스의 "init" 프로세스가 종료될 때), **해당 네임스페이스 내의 모든 프로세스는 종료됩니다**. 이는 네임스페이스와 연관된 모든 자원이 적절히 정리되도록 보장합니다.

## 실습:

### 서로 다른 네임스페이스 생성

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

`unshare`를 `-f` 옵션 없이 실행하면, Linux가 새로운 PID (Process ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 내용과 해결책은 다음과 같습니다:

1. **Problem Explanation**:

- Linux 커널은 `unshare` 시스템 콜을 통해 프로세스가 새로운 네임스페이스를 생성하도록 허용합니다. 그러나 새로운 PID 네임스페이스 생성을 시작한 프로세스(일명 "unshare" 프로세스)는 새 네임스페이스로 들어가지 않으며, 오직 그 자식 프로세스들만 들어갑니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스들은 원래의 PID 네임스페이스에 있게 됩니다.
- 새 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스가 PID 1이 됩니다. 이 프로세스가 종료하면(다른 프로세스가 없을 경우) 네임스페이스 정리가 트리거됩니다. PID 1은 고아 프로세스를 입양(adopt)하는 특별한 역할을 가지기 때문입니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **Consequence**:

- 새 네임스페이스에서 PID 1이 종료되면 `PIDNS_HASH_ADDING` 플래그가 정리됩니다. 이로 인해 새로운 프로세스 생성 시 `alloc_pid` 함수가 새로운 PID를 할당하지 못하여 "Cannot allocate memory" 오류가 발생합니다.

3. **Solution**:
- 이 문제는 `unshare`에 `-f` 옵션을 사용하는 것으로 해결할 수 있습니다. 이 옵션은 새로운 PID 네임스페이스를 생성한 후 `unshare`가 새로운 프로세스를 fork 하도록 합니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새 네임스페이스에서 PID 1이 됩니다. 그러면 `/bin/bash`와 그 자식 프로세스들은 안전하게 이 새 네임스페이스 안에 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당이 가능해집니다.

`unshare`를 `-f` 플래그와 함께 실행하면 새 PID 네임스페이스가 올바르게 유지되어 `/bin/bash`와 그 하위 프로세스들이 메모리 할당 오류 없이 정상적으로 동작할 수 있습니다.

</details>

`--mount-proc` 파라미터를 사용해 `/proc` 파일시스템의 새로운 인스턴스를 마운트하면, 새로운 마운트 네임스페이스가 그 네임스페이스에 특정한 프로세스 정보를 **정확하고 격리된 뷰**로 보도록 보장합니다.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 프로세스가 어떤 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### 모든 PID 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Note that the root use from the initial (default) PID namespace can see all the processes, even the ones in new PID names paces, thats why we can see all the PID namespaces.

### Enter inside a PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

Also, you can only **enter in another process PID namespace if you are root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/pid`)

## 최근 악용 노트

### CVE-2025-31133: `maskedPaths`를 악용해 호스트 PIDs에 접근하기

runc ≤1.2.7은 컨테이너 이미지나 `runc exec` 워크로드를 제어하는 공격자가 런타임이 민감한 procfs 항목들을 masked하기 직전에 컨테이너 측 `/dev/null`을 교체할 수 있도록 허용했습니다. 경쟁 상태(race)가 성공하면 `/dev/null`을 임의의 호스트 경로(예: `/proc/sys/kernel/core_pattern`)를 가리키는 심볼릭 링크로 바꿀 수 있으므로, 새 컨테이너 PID namespace는 자신의 네임스페이스를 벗어나지 않았음에도 불구하고 호스트 전역 procfs 제어 지점에 대한 읽기/쓰기 접근을 갑자기 상속받게 됩니다. `core_pattern` 또는 `/proc/sysrq-trigger`가 쓰기 가능해지면, coredump를 생성하거나 SysRq를 트리거함으로써 호스트 PID namespace에서 코드 실행이나 서비스 거부가 발생할 수 있습니다.

실전 절차:

1. rootfs가 `/dev/null`을 원하는 호스트 경로를 가리키는 링크로 교체된 OCI bundle을 빌드합니다 (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. 패치 적용 이전에 컨테이너를 시작하여 runc가 링크 위에 호스트 procfs 대상 경로를 bind-mount 하도록 합니다.
3. 컨테이너 네임스페이스 내부에서 이제 노출된 procfs 파일에 쓰기(예: `core_pattern`을 리버스 셸 헬퍼로 지정)하고, 호스트 커널이 해당 헬퍼를 PID 1 컨텍스트로 실행하도록 임의의 프로세스를 크래시시킵니다.

컨테이너를 시작하기 전에 번들이 올바른 파일들을 마스킹하는지 빠르게 감사할 수 있습니다:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
런타임에 기대한 마스킹 항목이 없거나(`/dev/null`이 사라져서 건너뛸 경우), 컨테이너를 host PID visibility를 가질 가능성이 있는 것으로 간주하라.

### Namespace injection with `insject`

NCC Group’s `insject`는 LD_PRELOAD payload로 로드되어 타깃 프로그램의 후기 단계(기본값 `main`)에 훅을 걸고 `execve()` 이후 일련의 `setns()` 호출을 수행합니다. 이를 통해 호스트(또는 다른 컨테이너)에서 피해자의 PID namespace에 런타임이 초기화된 *후에* attach할 수 있어, 컨테이너 파일시스템에 바이너리를 복사할 필요 없이 `/proc/<pid>` 뷰를 보존할 수 있습니다. 또한 `insject`는 포크할 때까지 PID namespace에 합류하는 것을 지연시킬 수 있기 때문에, 하나의 스레드를 host namespace에 (CAP_SYS_PTRACE를 가진 상태로) 유지하고 다른 스레드가 target PID namespace에서 실행되게 하여 강력한 디버깅 또는 offensive primitives를 만들 수 있습니다.

사용 예:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
namespace injection을 악용하거나 방어할 때의 주요 요점:

- Use `-S/--strict` to force `insject` to abort if threads already exist or namespace joins fail, otherwise you may leave partly-migrated threads straddling host and container PID spaces.
- Never attach tools that still hold writable host file descriptors unless you also join the mount namespace—otherwise any process inside the PID namespace can ptrace your helper and reuse those descriptors to tamper with host resources.

## 참조

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
