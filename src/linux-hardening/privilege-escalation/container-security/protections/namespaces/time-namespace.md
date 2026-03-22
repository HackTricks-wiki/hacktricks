# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

time namespace는 선택된 시계들을 가상화하며, 특히 **`CLOCK_MONOTONIC`** 및 **`CLOCK_BOOTTIME`**를 가상화합니다. 이는 mount, PID, network, or user namespaces보다 더 새롭고 전문화된 네임스페이스이며, 운영자가 컨테이너 하드닝을 논할 때 가장 먼저 떠올리는 요소는 아닙니다. 그럼에도 불구하고 현대 네임스페이스 계열의 일부로서 개념적으로 이해할 가치가 있습니다.

주된 목적은 프로세스가 호스트의 전역 시간 뷰를 변경하지 않으면서 특정 시계에 대해 제어된 오프셋을 관찰할 수 있게 하는 것입니다. 이는 체크포인트/복원 워크플로우(checkpoint/restore workflows), 결정론적 테스트(deterministic testing), 및 일부 고급 런타임 동작에 유용합니다. 일반적으로 mount나 user namespaces와 같은 주요 격리 수단은 아니지만, 여전히 프로세스 환경을 보다 자립적으로 만드는 데 기여합니다.

## 실습

호스트 커널과 userspace가 이를 지원하면, 다음으로 네임스페이스를 검사할 수 있습니다:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
지원은 커널 및 도구 버전에 따라 달라지므로, 이 페이지는 모든 실습 환경에서 항상 확인할 수 있다고 기대하기보다는 메커니즘을 이해하는 데 중점을 둡니다.

### Time Offsets

Linux time namespaces는 `CLOCK_MONOTONIC` 및 `CLOCK_BOOTTIME`에 대한 오프셋을 가상화합니다. 네임스페이스별 현재 오프셋은 `/proc/<pid>/timens_offsets`를 통해 노출되며, 해당 커널이 지원하면 관련 네임스페이스 내부에서 `CAP_SYS_TIME` 권한을 가진 프로세스가 이를 수정할 수도 있습니다:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
파일은 나노초 단위의 델타를 포함하고 있다. `monotonic`을 이틀만큼 조정하면 호스트의 wall clock을 변경하지 않고도 해당 네임스페이스 내의 uptime과 유사한 관측값들이 변경된다.

### `unshare` 헬퍼 플래그

최신 `util-linux` 버전은 오프셋을 자동으로 기록하는 편의 플래그를 제공한다:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
이 플래그들은 주로 사용성 향상을 위한 것이지만, 문서화 및 테스트에서 해당 기능을 식별하기 쉽게 만들어 준다.

## 런타임 사용

time 네임스페이스는 mount 또는 PID 네임스페이스보다 새롭고 덜 널리 사용된다. OCI Runtime Specification v1.1은 `time` 네임스페이스와 `linux.timeOffsets` 필드에 대한 명시적 지원을 추가했으며, 최신 `runc` 릴리스는 모델의 해당 부분을 구현한다. 최소한의 OCI 조각은 다음과 같다:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
이것이 중요한 이유는 time namespacing을 틈새 kernel primitive에서 runtimes가 portably 요청할 수 있는 기능으로 바꿔 놓기 때문입니다.

## Security Impact

다른 namespace 유형들에 비해 time namespace를 중심으로 한 고전적인 breakout 사례는 적습니다. 이 경우 위험은 대개 time namespace가 직접적으로 escape를 가능하게 하는 것이 아니라, 사람들이 이를 완전히 무시하여 advanced runtimes가 프로세스 동작을 어떻게 형성하는지를 놓치는 데 있습니다. 특수한 환경에서는 변경된 clock views가 checkpoint/restore, observability, 또는 forensic 가정에 영향을 줄 수 있습니다.

## Abuse

여기에는 보통 직접적인 breakout primitive는 없지만, altered clock behavior는 execution environment를 이해하고 advanced runtime features를 식별하는 데 여전히 유용할 수 있습니다:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
If you are comparing two processes, differences here can help explain odd timing behavior, checkpoint/restore artifacts, or environment-specific logging mismatches.

Impact:

- 거의 항상 reconnaissance 또는 환경 이해
- 로깅, 업타임, 또는 checkpoint/restore 이상을 설명하는 데 유용함
- 보통 그 자체만으로는 직접적인 container-escape 메커니즘이 아니다

The important abuse nuance is that time namespaces do not virtualize `CLOCK_REALTIME`, so they do not by themselves let an attacker falsify the host wall clock or directly break certificate-expiry checks system-wide. Their value is mostly in confusing monotonic-time-based logic, reproducing environment-specific bugs, or understanding advanced runtime behavior.

## Checks

이 확인 항목들은 주로 런타임이 private time 네임스페이스를 사용하고 있는지 여부를 확인하는 것에 관한 것이다.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
- 많은 환경에서 이러한 값들은 즉각적인 보안 결과를 초래하지 않을 수 있지만, 특수한 runtime 기능이 동작 중인지 알려줍니다.
- 두 프로세스를 비교하는 경우, 여기서의 차이는 혼란스러운 타이밍이나 checkpoint/restore 동작을 설명할 수 있습니다.

대부분의 container breakouts에서는 time namespace가 먼저 조사할 제어 수단이 아닙니다. 그럼에도 불구하고 완전한 container-security 섹션에서는 이를 언급해야 합니다. 이는 현대 kernel model의 일부이며, 가끔 advanced runtime scenarios에서 중요하게 작용합니다.
{{#include ../../../../../banners/hacktricks-training.md}}
