# UTS 네임스페이스

{{#include ../../../../banners/hacktricks-training.md}}

## 기본 정보

UTS (UNIX Time-Sharing System) 네임스페이스는 두 시스템 식별자 i**격리**를 제공하는 Linux 커널 기능입니다: **hostname**과 **NIS** (Network Information Service) 도메인 이름. 이 i**격리**는 각 UTS 네임스페이스가 **자기만의 독립적인 hostname 및 NIS 도메인 이름**을 가질 수 있게 해주며, 각 컨테이너가 자체 hostname을 가진 별도의 시스템으로 보이게 해야 하는 컨테이너화 시나리오에서 특히 유용합니다.

### 동작 방식:

1. 새로운 UTS 네임스페이스가 생성되면, 부모 네임스페이스로부터 **hostname 및 NIS 도메인 이름의 복사본**으로 시작합니다. 이는 생성 시 새로운 네임스페이스가 s**부모와 동일한 식별자들을 공유한다는 뜻입니다. 그러나 네임스페이스 내부에서 hostname 또는 NIS 도메인 이름에 대한 이후 변경은 다른 네임스페이스에 영향을 주지 않습니다.
2. UTS 네임스페이스 내의 프로세스는 `sethostname()` 및 `setdomainname()` 시스템 호출을 각각 사용하여 **hostname 및 NIS 도메인 이름을 변경할 수 있습니다**. 이러한 변경은 네임스페이스에 국한되며 다른 네임스페이스나 호스트 시스템에 영향을 주지 않습니다.
3. 프로세스는 `setns()` 시스템 호출을 사용하여 네임스페이스 간 이동할 수 있고, `unshare()` 또는 `clone()` 시스템 호출에 `CLONE_NEWUTS` 플래그를 사용하여 새 네임스페이스를 생성할 수 있습니다. 프로세스가 새 네임스페이스로 이동하거나 새 네임스페이스를 생성하면 해당 네임스페이스에 연결된 hostname 및 NIS 도메인 이름을 사용하기 시작합니다.

## 실습:

### 서로 다른 네임스페이스 생성

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **새 네임스페이스에 특정한 프로세스 정보를 정확하고 격리된 보기**.

<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없습니다</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. 문제 설명:

- Linux 커널은 `unshare` 시스템 콜을 사용해 프로세스가 새로운 네임스페이스를 생성하도록 허용합니다. 그러나 새로운 PID 네임스페이스 생성을 시작한 프로세스(이를 "unshare" 프로세스라고 함)는 새 네임스페이스에 들어가지 않고, 오직 그 자식 프로세스들만 들어갑니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 따라서 `/bin/bash`와 그 자식 프로세스들은 원래의 PID 네임스페이스에 있게 됩니다.
- 새 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없을 경우 네임스페이스 정리가 트리거됩니다. PID 1은 고아 프로세스를 인계받는 특별한 역할을 갖고 있기 때문입니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. 결과:

- 새 네임스페이스에서 PID 1이 종료되면 `PIDNS_HASH_ADDING` 플래그가 정리됩니다. 이로 인해 새로운 프로세스를 생성할 때 `alloc_pid` 함수가 새 PID를 할당하지 못하게 되어 "메모리를 할당할 수 없습니다" 오류가 발생합니다.

3. 해결책:
- 이 문제는 `unshare`에 `-f` 옵션을 사용하는 것으로 해결할 수 있습니다. 이 옵션은 새로운 PID 네임스페이스를 생성한 후 `unshare`가 새로운 프로세스를 fork 하도록 만듭니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 자체가 새 네임스페이스에서 PID 1이 됩니다. 그러면 `/bin/bash`와 그 자식 프로세스들은 이 새 네임스페이스 안에 안전하게 포함되며, PID 1의 조기 종료를 방지하고 정상적인 PID 할당이 가능해집니다.

`unshare`를 `-f` 플래그로 실행하도록 하면 새 PID 네임스페이스가 올바르게 유지되어 `/bin/bash`와 그 하위 프로세스들이 메모리 할당 오류 없이 동작할 수 있습니다.

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
### 모든 UTS 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### UTS 네임스페이스 안으로 들어가기
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## 호스트 UTS 공유 악용

컨테이너가 `--uts=host`로 시작되면 격리된 UTS 네임스페이스를 얻지 못하고 호스트 UTS 네임스페이스에 참여합니다. `--cap-add SYS_ADMIN` 같은 권한을 부여하면, 컨테이너 내의 코드는 `sethostname()`/`setdomainname()`을 통해 호스트의 hostname/NIS name을 변경할 수 있습니다:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
호스트 이름을 변경하면 로그/경보를 변조하거나 클러스터 검색을 혼란시키거나 호스트 이름을 고정(pin)한 TLS/SSH 구성을 깨뜨릴 수 있다.

### 호스트와 UTS를 공유하는 컨테이너 탐지
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
