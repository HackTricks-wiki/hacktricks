# Time Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Linux의 시간 네임스페이스는 시스템 단조 및 부팅 시간 시계에 대한 네임스페이스별 오프셋을 허용합니다. 이는 Linux 컨테이너에서 컨테이너 내의 날짜/시간을 변경하고 체크포인트 또는 스냅샷에서 복원한 후 시계를 조정하는 데 일반적으로 사용됩니다.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
새로운 `/proc` 파일 시스템 인스턴스를 마운트하면 `--mount-proc` 매개변수를 사용하여 새로운 마운트 네임스페이스가 **해당 네임스페이스에 특정한 프로세스 정보에 대한 정확하고 격리된 뷰를 갖도록** 보장합니다.

<details>

<summary>오류: bash: fork: 메모리를 할당할 수 없습니다</summary>

`unshare`가 `-f` 옵션 없이 실행될 때, Linux가 새로운 PID(프로세스 ID) 네임스페이스를 처리하는 방식 때문에 오류가 발생합니다. 주요 세부사항과 해결책은 아래에 설명되어 있습니다:

1. **문제 설명**:

- Linux 커널은 프로세스가 `unshare` 시스템 호출을 사용하여 새로운 네임스페이스를 생성할 수 있도록 허용합니다. 그러나 새로운 PID 네임스페이스를 생성하는 프로세스(이를 "unshare" 프로세스라고 함)는 새로운 네임스페이스에 들어가지 않으며, 오직 그 자식 프로세스만 들어갑니다.
- `%unshare -p /bin/bash%`를 실행하면 `/bin/bash`가 `unshare`와 동일한 프로세스에서 시작됩니다. 결과적으로 `/bin/bash`와 그 자식 프로세스는 원래 PID 네임스페이스에 있습니다.
- 새로운 네임스페이스에서 `/bin/bash`의 첫 번째 자식 프로세스는 PID 1이 됩니다. 이 프로세스가 종료되면, 다른 프로세스가 없을 경우 네임스페이스의 정리가 트리거됩니다. PID 1은 고아 프로세스를 입양하는 특별한 역할을 가지고 있습니다. 그러면 Linux 커널은 해당 네임스페이스에서 PID 할당을 비활성화합니다.

2. **결과**:

- 새로운 네임스페이스에서 PID 1의 종료는 `PIDNS_HASH_ADDING` 플래그의 정리를 초래합니다. 이로 인해 새로운 프로세스를 생성할 때 `alloc_pid` 함수가 새로운 PID를 할당하는 데 실패하여 "메모리를 할당할 수 없습니다" 오류가 발생합니다.

3. **해결책**:
- 이 문제는 `unshare`와 함께 `-f` 옵션을 사용하여 해결할 수 있습니다. 이 옵션은 `unshare`가 새로운 PID 네임스페이스를 생성한 후 새로운 프로세스를 포크하도록 만듭니다.
- `%unshare -fp /bin/bash%`를 실행하면 `unshare` 명령 자체가 새로운 네임스페이스에서 PID 1이 됩니다. `/bin/bash`와 그 자식 프로세스는 이 새로운 네임스페이스 내에서 안전하게 포함되어 PID 1의 조기 종료를 방지하고 정상적인 PID 할당을 허용합니다.

`unshare`가 `-f` 플래그와 함께 실행되도록 보장함으로써 새로운 PID 네임스페이스가 올바르게 유지되며, `/bin/bash`와 그 하위 프로세스가 메모리 할당 오류 없이 작동할 수 있습니다.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 프로세스가 어떤 네임스페이스에 있는지 확인하기
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### 모든 시간 네임스페이스 찾기
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Time 네임스페이스에 들어가기
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## 시간 오프셋 조작

Linux 5.6부터, 두 개의 시계를 시간 네임스페이스별로 가상화할 수 있습니다:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

그들의 네임스페이스별 델타는 `/proc/<PID>/timens_offsets` 파일을 통해 노출되며 (수정할 수 있음):
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
파일에는 **나노초** 단위의 오프셋이 있는 시계당 한 줄이 포함되어 있습니다. **CAP_SYS_TIME** _시간 네임스페이스_를 보유한 프로세스는 값을 변경할 수 있습니다:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
벽시계(`CLOCK_REALTIME`)도 변경해야 하는 경우 여전히 고전적인 메커니즘(`date`, `hwclock`, `chronyd`, …)에 의존해야 합니다; 이는 **네임스페이스화**되지 않습니다.


### `unshare(1)` 헬퍼 플래그 (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
긴 옵션은 네임스페이스가 생성된 직후 선택한 델타를 `timens_offsets`에 자동으로 기록하여 수동 `echo`를 저장합니다.

---

## OCI 및 런타임 지원

* **OCI 런타임 사양 v1.1** (2023년 11월)은 컨테이너 엔진이 휴대 가능한 방식으로 시간 가상화를 요청할 수 있도록 전용 `time` 네임스페이스 유형과 `linux.timeOffsets` 필드를 추가했습니다.
* **runc >= 1.2.0**은 사양의 해당 부분을 구현합니다. 최소한의 `config.json` 조각은 다음과 같습니다:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
그런 다음 `runc run <id>`로 컨테이너를 실행합니다.

>  주의: runc **1.2.6** (2025년 2월)은 "개인 timens로 컨테이너에 exec" 버그를 수정하여 정지 및 잠재적인 DoS를 초래할 수 있습니다. 프로덕션에서 ≥ 1.2.6을 사용하고 있는지 확인하십시오.

---

## 보안 고려사항

1. **필수 권한** – 프로세스는 오프셋을 변경하기 위해 사용자/시간 네임스페이스 내에서 **CAP_SYS_TIME**이 필요합니다. 컨테이너에서 해당 권한을 제거하면 (Docker 및 Kubernetes의 기본값) 변조를 방지할 수 있습니다.
2. **벽시계 변경 없음** – `CLOCK_REALTIME`이 호스트와 공유되기 때문에 공격자는 timens만으로 인증서 수명, JWT 만료 등을 스푸핑할 수 없습니다.
3. **로그/탐지 회피** – `CLOCK_MONOTONIC`에 의존하는 소프트웨어(예: 가동 시간 기반의 속도 제한기)는 네임스페이스 사용자가 오프셋을 조정하면 혼란스러워질 수 있습니다. 보안 관련 타임스탬프에는 `CLOCK_REALTIME`을 선호하십시오.
4. **커널 공격 표면** – `CAP_SYS_TIME`이 제거되더라도 커널 코드는 여전히 접근 가능하므로 호스트를 패치 상태로 유지하십시오. Linux 5.6 → 5.12는 여러 timens 버그 수정(NULl-deref, 부호 문제)을 받았습니다.

### 강화 체크리스트

* 컨테이너 런타임 기본 프로필에서 `CAP_SYS_TIME`을 제거하십시오.
* 런타임을 업데이트 상태로 유지하십시오 (runc ≥ 1.2.6, crun ≥ 1.12).
* `--monotonic/--boottime` 도우미에 의존하는 경우 util-linux ≥ 2.38을 고정하십시오.
* 보안에 중요한 논리를 위해 **uptime** 또는 **CLOCK_MONOTONIC**을 읽는 컨테이너 내 소프트웨어를 감사하십시오.

## 참조

* man7.org – 시간 네임스페이스 매뉴얼 페이지: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI 블로그 – "OCI v1.1: 새로운 시간 및 RDT 네임스페이스" (2023년 11월 15일): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
