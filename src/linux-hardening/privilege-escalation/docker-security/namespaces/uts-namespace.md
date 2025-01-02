# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

UTS (UNIX Time-Sharing System) 네임스페이스는 두 개의 시스템 식별자: **호스트 이름**과 **NIS** (Network Information Service) 도메인 이름의 **격리를 제공하는** 리눅스 커널 기능입니다. 이 격리는 각 UTS 네임스페이스가 **자신의 독립적인 호스트 이름과 NIS 도메인 이름**을 가질 수 있게 하며, 이는 각 컨테이너가 자신의 호스트 이름을 가진 별도의 시스템으로 나타나야 하는 컨테이너화 시나리오에서 특히 유용합니다.

### How it works:

1. 새로운 UTS 네임스페이스가 생성되면, **부모 네임스페이스의 호스트 이름과 NIS 도메인 이름의 복사본**으로 시작합니다. 이는 생성 시 새로운 네임스페이스가 **부모와 동일한 식별자를 공유**함을 의미합니다. 그러나 네임스페이스 내에서 호스트 이름이나 NIS 도메인 이름에 대한 이후의 변경은 다른 네임스페이스에 영향을 미치지 않습니다.
2. UTS 네임스페이스 내의 프로세스는 각각 `sethostname()` 및 `setdomainname()` 시스템 호출을 사용하여 **호스트 이름과 NIS 도메인 이름을 변경할 수 있습니다**. 이러한 변경은 네임스페이스에 국한되며 다른 네임스페이스나 호스트 시스템에 영향을 미치지 않습니다.
3. 프로세스는 `setns()` 시스템 호출을 사용하여 네임스페이스 간에 이동하거나 `unshare()` 또는 `clone()` 시스템 호출을 사용하여 `CLONE_NEWUTS` 플래그와 함께 새로운 네임스페이스를 생성할 수 있습니다. 프로세스가 새로운 네임스페이스로 이동하거나 생성할 때, 해당 네임스페이스와 연결된 호스트 이름과 NIS 도메인 이름을 사용하기 시작합니다.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
새로운 인스턴스의 `/proc` 파일 시스템을 마운트하면 `--mount-proc` 매개변수를 사용하여 새로운 마운트 네임스페이스가 **해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰를 갖도록** 보장합니다.

<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없습니다</summary>

`unshare`가 `-f` 옵션 없이 실행될 때, Linux가 새로운 PID(프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부사항과 해결책은 아래에 설명되어 있습니다:

1. **문제 설명**:

- Linux 커널은 프로세스가 `unshare` 시스템 호출을 사용하여 새로운 네임스페이스를 생성할 수 있도록 허용합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스(이를 "unshare" 프로세스라고 함)는 새로운 네임스페이스에 들어가지 않으며, 오직 그 자식 프로세스만 들어갑니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스는 원래 PID 네임스페이스에 있습니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없을 경우 네임스페이스의 정리가 트리거됩니다. PID 1은 고아 프로세스를 입양하는 특별한 역할을 가지고 있습니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:

- 새로운 네임스페이스에서 PID 1의 종료는 `PIDNS_HASH_ADDING` 플래그의 정리를 초래합니다. 이로 인해 새로운 프로세스를 생성할 때 `alloc_pid` 함수가 새로운 PID를 할당하지 못하게 되어 "메모리를 할당할 수 없습니다" 오류가 발생합니다.

3. **해결책**:
- 이 문제는 `unshare`와 함께 `-f` 옵션을 사용하여 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후 새로운 프로세스를 포크하도록 만듭니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새로운 네임스페이스에서 PID 1이 됩니다. 그 결과 `/bin/bash`와 그 자식 프로세스는 이 새로운 네임스페이스 내에서 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당을 허용합니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써 새로운 PID 네임스페이스가 올바르게 유지되며, `/bin/bash`와 그 하위 프로세스가 메모리 할당 오류 없이 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;프로세스가 어떤 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### 모든 UTS 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### UTS 네임스페이스 내부로 들어가기
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
