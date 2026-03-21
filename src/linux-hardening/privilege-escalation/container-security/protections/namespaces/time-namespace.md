# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

time namespace는 선택한 시계를 가상화하며, 특히 **`CLOCK_MONOTONIC`** 및 **`CLOCK_BOOTTIME`**을 가상화합니다. 이는 mount, PID, network 또는 user namespaces보다 더 새롭고 특화된 namespace로, container 하드닝을 논할 때 운영자가 가장 먼저 떠올리는 요소는 아닙니다. 그럼에도 불구하고 현대 namespace 계열에 속하며 개념적으로 이해할 가치가 있습니다.

주된 목적은 프로세스가 호스트의 전역 시간 뷰를 변경하지 않고 특정 시계에 대해 제어된 오프셋을 관찰하도록 허용하는 것입니다. 이는 checkpoint/restore workflows, deterministic testing, 및 일부 고급 런타임 동작에 유용합니다. 일반적으로 mount 또는 user namespaces와 같은 주요 격리 수단처럼 주목받지는 않지만, 프로세스 환경을 보다 자립적으로 만드는 데 기여합니다.

## 실습

If the host kernel and userspace support it, you can inspect the namespace with:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
지원은 커널 및 도구 버전에 따라 다르므로, 이 페이지는 모든 실습 환경에서 항상 확인할 수 있다고 기대하기보다는 메커니즘을 이해하는 데 중점을 둡니다.

### 시간 오프셋

Linux time namespaces는 `CLOCK_MONOTONIC` 및 `CLOCK_BOOTTIME`의 오프셋을 가상화합니다. 현재 네임스페이스별 오프셋은 `/proc/<pid>/timens_offsets`를 통해 노출되며, 지원되는 커널에서는 해당 네임스페이스 내부에서 `CAP_SYS_TIME`을 보유한 프로세스가 이를 수정할 수도 있습니다:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
해당 파일은 나노초 단위 델타를 포함합니다. `monotonic`을 이틀(2일)만큼 조정하면 해당 네임스페이스 내부의 uptime 유사 관측값은 변경되지만 host wall clock은 변경되지 않습니다.

### `unshare` 도우미 플래그

최근 `util-linux` 버전에는 오프셋을 자동으로 기록하는 편의 플래그가 제공됩니다:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
이 플래그들은 주로 사용성 개선이지만, 문서화와 테스트에서 해당 기능을 더 쉽게 인식할 수 있게 해준다.

## 런타임 사용

시간 네임스페이스는 mount 또는 PID 네임스페이스보다 새롭고 널리 사용되지 않는다. OCI Runtime Specification v1.1은 `time` 네임스페이스와 `linux.timeOffsets` 필드에 대한 명시적 지원을 추가했으며, 최신의 `runc` 릴리스는 해당 모델 부분을 구현한다. 간단한 OCI 단편은 다음과 같다:
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
이는 time namespacing을 틈새 kernel primitive에서 runtimes가 포터블하게 요청할 수 있는 기능으로 전환시킨다는 점에서 중요하다.

## 보안 영향

다른 namespace 유형에 비해 time namespace를 중심으로 한 전형적인 breakout 사례는 적다. 여기서의 위험은 대개 time namespace가 직접적으로 escape를 가능하게 하는 것이 아니라, 사람들이 이를 완전히 무시해 advanced runtimes가 프로세스 동작을 어떻게 형성하고 있는지를 놓치는 것이다. 특수 환경에서는 변경된 시계 관점이 checkpoint/restore, observability, 또는 forensic 가정에 영향을 줄 수 있다.

## 악용

여기에는 보통 직접적인 breakout primitive는 없지만, 변경된 clock behavior는 실행 환경을 이해하고 advanced runtime features를 식별하는 데 여전히 유용할 수 있다:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
If you are comparing two processes, differences here can help explain odd timing behavior, checkpoint/restore artifacts, or environment-specific logging mismatches.

Impact:

- 거의 항상 reconnaissance 또는 환경 이해
- 로깅, 가동 시간(uptime), 또는 checkpoint/restore 이상 현상을 설명하는 데 유용
- 보통 그것만으로는 직접적인 container-escape 메커니즘은 아님

The important abuse nuance is that time namespaces do not virtualize `CLOCK_REALTIME`, so they do not by themselves let an attacker falsify the host wall clock or directly break certificate-expiry checks system-wide. Their value is mostly in confusing monotonic-time-based logic, reproducing environment-specific bugs, or understanding advanced runtime behavior.

## Checks

이 검사들은 주로 런타임(runtime)이 private time namespace를 사용하고 있는지 여부를 확인하는 것에 관한 것이다.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
- 많은 환경에서 이러한 값들은 즉각적인 보안 문제로 이어지지 않을 수 있지만, 특수한 런타임 기능이 작동 중인지 여부를 알려준다.
- 두 프로세스를 비교하는 경우, 여기서의 차이는 혼란스러운 타이밍이나 checkpoint/restore 동작을 설명할 수 있다.

대부분의 container breakouts에 대해, time namespace는 당신이 먼저 조사할 제어 지점이 아니다. 그럼에도 불구하고, 완전한 container-security 섹션에서는 이를 언급해야 하는데, 이는 현대 커널 모델의 일부이며 고급 런타임 시나리오에서 가끔 중요하기 때문이다.
