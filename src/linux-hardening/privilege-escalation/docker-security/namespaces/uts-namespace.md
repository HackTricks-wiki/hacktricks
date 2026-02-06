# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

A UTS (UNIX Time-Sharing System) namespace is a Linux kernel feature that provides i**두 시스템 식별자의 격리**: the **hostname** and the **NIS** (Network Information Service) domain name. 이 격리를 통해 각 UTS 네임스페이스는 **자체 독립적인 hostname 및 NIS 도메인 이름**을 가질 수 있으며, 이는 각 컨테이너가 자체 hostname을 가진 별도의 시스템처럼 보이도록 해야 하는 containerization 환경에서 특히 유용합니다.

### How it works:

1. When a new UTS namespace is created, it starts with a **copy of the hostname and NIS domain name from its parent namespace**. This means that, at creation, the new namespace s**상위 네임스페이스와 동일한 식별자를 공유합니다**. 그러나 네임스페이스 내에서 hostname이나 NIS 도메인 이름에 대한 이후 변경은 다른 네임스페이스에 영향을 주지 않습니다.
2. Processes within a UTS namespace **can change the hostname and NIS domain name** using the `sethostname()` and `setdomainname()` system calls, respectively. 이러한 변경은 네임스페이스 로컬이며 다른 네임스페이스나 호스트 시스템에 영향을 주지 않습니다.
3. Processes can move between namespaces using the `setns()` system call or create new namespaces using the `unshare()` or `clone()` system calls with the `CLONE_NEWUTS` flag. 프로세스가 새 네임스페이스로 이동하거나 새 네임스페이스를 생성하면 해당 네임스페이스에 연관된 hostname 및 NIS 도메인 이름을 사용하기 시작합니다.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **해당 네임스페이스에 특화된 프로세스 정보를 정확하고 격리된 관점으로 볼 수 있도록**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **문제 설명**:

- Linux 커널은 프로세스가 `unshare` 시스템 콜을 사용해 새 네임스페이스를 생성하는 것을 허용합니다. 하지만 새로운 PID (Process ID) 네임스페이스 생성을 시작한 프로세스(이를 "unshare" 프로세스라고 칭함)는 새 네임스페이스로 들어가지 않으며, 오직 그 자식 프로세스들만 들어갑니다.
- Running %unshare -p /bin/bash% starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- 새 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스가 PID 1이 됩니다. 이 프로세스가 종료되면(다른 프로세스가 없을 경우) 네임스페이스 정리가 트리거됩니다. PID 1은 고아 프로세스를 인계하는 특수한 역할을 가지기 때문입니다. 그 후 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:

- 새 네임스페이스에서 PID 1의 종료는 `PIDNS_HASH_ADDING` 플래그의 정리로 이어집니다. 이로 인해 `alloc_pid` 함수가 새 프로세스 생성 시 새로운 PID를 할당하지 못하고 "Cannot allocate memory" 오류가 발생합니다.

3. **해결책**:
- 이 문제는 `unshare`에 `-f` 옵션을 사용하면 해결됩니다. 이 옵션은 새로운 PID 네임스페이스를 만든 후 `unshare`가 새 프로세스를 fork 하게 만듭니다.
- %unshare -fp /bin/bash%를 실행하면 `unshare` 자신이 새 네임스페이스에서 PID 1이 됩니다. 그러면 `/bin/bash`와 그 자식 프로세스들은 이 새 네임스페이스 내에 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당이 가능해집니다.

`unshare`를 `-f` 플래그와 함께 실행하도록 하면 새 PID 네임스페이스가 올바르게 유지되어 `/bin/bash`와 그 하위 프로세스들이 메모리 할당 오류 없이 동작할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 프로세스가 어떤 네임스페이스에 있는지 확인
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### 모든 UTS namespaces 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### UTS namespace에 들어가기
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## 호스트 UTS 공유 악용

컨테이너가 `--uts=host`로 시작되면, 격리된 UTS 네임스페이스를 얻는 대신 호스트의 UTS 네임스페이스에 합류합니다. `--cap-add SYS_ADMIN` 같은 권한이 있을 경우, 컨테이너 내의 코드는 `sethostname()`/`setdomainname()`을 통해 호스트의 hostname/NIS name을 변경할 수 있습니다:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
호스트 이름을 변경하면 로그/알림을 조작할 수 있고, 클러스터 검색을 혼란시키거나 호스트 이름을 고정(pin)한 TLS/SSH 설정을 깨뜨릴 수 있습니다.

### 호스트와 UTS를 공유하는 컨테이너 감지
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
죄송하지만 저는 로컬 파일이나 리포지토리에 직접 접근할 수 없습니다. 번역하려는 src/linux-hardening/privilege-escalation/docker-security/namespaces/uts-namespace.md 파일의 내용을 여기 대화창에 붙여넣어 주시겠어요? 붙여넣어 주시면 요청하신 규칙(코드·태그·경로 보존 등)을 지켜 정확하게 한국어로 번역해 드리겠습니다.
