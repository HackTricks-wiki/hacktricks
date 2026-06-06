# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

time namespace는 host wall clock 대신 선택된 monotonic-style clocks를 virtualize합니다. 실제로 이는 **`CLOCK_MONOTONIC`** 및 **`CLOCK_BOOTTIME`**에 대한 private offsets를 의미하며, 여기에 밀접하게 관련된 **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, **`CLOCK_BOOTTIME_ALARM`** 뷰도 포함됩니다. 이는 **`CLOCK_REALTIME`**을 virtualize하지 않으므로, `date`와 certificate-expiry logic은 다른 메커니즘이 간섭하지 않는 한 계속 host wall clock을 관찰합니다.

주된 목적은 host의 전역 시간 뷰를 변경하지 않고 process가 제어된 elapsed-time offsets를 관찰할 수 있게 하는 것입니다. 이는 checkpoint/restore workflows, deterministic testing, 그리고 advanced runtime behavior에 유용합니다. mount 또는 user namespaces처럼 핵심 isolation control로 자주 언급되지는 않지만, process environment를 더 self-contained하게 만드는 데 여전히 기여합니다.

공격 관점에서 이 namespace는 일반적으로 직접적인 breakout보다 **reconnaissance, timer skew, runtime understanding**에 더 관련이 있습니다. 그래도 중요한 이유는 더 많은 container runtimes와 checkpoint/restore workflows가 이제 이를 명시적으로 요청할 수 있기 때문입니다.

## Lab

host kernel과 userspace가 이를 지원한다면, 다음으로 namespace를 inspect할 수 있습니다:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
지원 여부는 kernel과 tool 버전에 따라 다르므로, 이 페이지는 모든 lab 환경에서 보이는 것을 기대하기보다 메커니즘을 이해하는 데 더 초점이 있습니다. 중요한 관찰은 `date`는 여전히 host wall clock을 반영해야 하고, monotonic/boottime 기반 값들은 nonzero offsets가 설정될 때 변한다는 점입니다.

### Creation Nuance

Time namespaces는 mount, PID, 또는 network namespaces와 비교했을 때 약간 특이합니다:

- `unshare(CLONE_NEWTIME)`는 **future children**를 위한 새로운 time namespace를 생성합니다.
- 호출하는 task는 현재 time namespace에 그대로 남아 있습니다.
- 따라서 `/proc/<pid>/ns/time_for_children`는 runtime setup을 디버깅할 때 `/proc/<pid>/ns/time`보다 종종 더 중요합니다.

write window도 특별합니다. `/proc/<pid>/timens_offsets`의 offsets는 새 time namespace가 running tasks로 완전히 채워지기 전에 작성되어야 합니다. 실제로 runtimes는 namespace 생성과 최종 payload 시작 사이의 짧은 setup window 동안 이를 수행합니다. task가 그 안에서 이미 running 상태가 되면, 이후 write는 `EACCES`로 실패합니다. 이것이 low-level runtimes가 time-namespace setup을 이미 시작된 container process 내부에서 offset을 patch하려는 대신, 초기 bootstrap 단계로 처리하는 이유입니다.

### Time Offsets

Linux time namespaces는 `/proc/<pid>/timens_offsets`를 통해 namespace별 offsets를 노출합니다. 형식은 initial time namespace를 기준으로 한 clock 이름 또는 ID와 second/nanosecond delta의 집합입니다.

실제로 가장 신뢰할 수 있는 user-facing workflow는 `unshare`가 대신 이 offsets를 쓰도록 하는 것입니다:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
중요한 점은 정확한 명령 구문이 아니라 동작이다: 컨테이너는 host wall clock을 변경하지 않고도 다른 uptime-like view를 관찰할 수 있다.

### `unshare` Helper Flags

최근 `util-linux` 버전은 namespace 생성 중에 offsets를 자동으로 기록하는 convenience flags를 제공한다:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
이 플래그들은 대부분 사용성 개선이지만, 문서, 테스트 하니스, 런타임 래퍼에서 이 기능을 더 쉽게 인식할 수 있게도 해줍니다.

## Runtime Usage

Time namespaces는 mount나 PID namespaces보다 더 새롭고 보편적으로 사용되지는 않습니다. OCI Runtime Specification v1.1은 `time` namespace와 `linux.timeOffsets` 필드에 대한 명시적 지원을 추가했으며, 최신 runtimes는 그 데이터를 kernel bootstrap 흐름에 매핑할 수 있습니다. 최소한의 OCI 조각은 다음과 같습니다:
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
이것은 time namespacing을 틈새 kernel primitive에서 runtimes가 이식 가능하게 요청할 수 있는 것으로 바꾸기 때문에 중요합니다. 또한 runtime internals가 명시적인 synchronization step이 필요한 이유도 설명합니다: offset은 container payload가 새 namespace에 완전히 들어가기 전에 `/proc/<pid>/timens_offsets`에 기록되어야 합니다.

CRIU 같은 checkpoint/restore stack은 이것이 실제로 존재하는 주요 이유 중 하나입니다. time namespaces가 없으면, 일시 중지된 workload를 복원할 때 monotonic 및 boot-time clocks가 workload가 중단되어 있던 시간만큼 점프하게 됩니다.

## Security Impact

time namespace를 중심으로 한 classic breakout 사례는 다른 namespace type보다 적습니다. 여기서의 risk는 보통 time namespace가 직접 escape를 가능하게 한다기보다, readers가 이를 완전히 무시해서 advanced runtimes가 process behavior를 어떻게 조정하는지 놓치는 데 있습니다.

특수한 환경에서는 변경된 monotonic 또는 boottime view가 다음에 영향을 줄 수 있습니다:

- timeout 및 retry behavior
- watchdogs 및 lease logic
- `timerfd`, `nanosleep`, 그리고 `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry 및 uptime-based heuristics

따라서 이것은 보통 가장 먼저 abuse하는 namespace는 아니지만, assessment 중에 "불가능해 보이는" timing behavior를 충분히 설명할 수 있습니다.

## Abuse

여기에는 보통 직접적인 breakout primitive는 없지만, 변경된 clock behavior는 execution environment를 이해하고, advanced runtime features를 식별하고, wall clock time이 아니라 monotonic clocks 기준으로 측정되는 timer-based logic을 찾아내는 데 유용할 수 있습니다:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
두 프로세스를 비교할 때, 여기서의 차이는 이상한 타이밍 동작, checkpoint/restore 흔적, 또는 환경별 logging 불일치를 설명하는 데 도움이 될 수 있습니다.

공격자 관점에서 실용적인 포인트:

- monotonic clocks로 구현된 backoff, sleep, 또는 watchdog 로직을 혼란스럽게 함
- `/proc/uptime`와 timer-driven 동작이 host-side wall-clock 기대와 왜 다른지 설명
- CRIU/checkpoint-restore 워크플로우 및 기타 고급 런타임 기능 식별
- `nsenter -T -t <pid> -- ...`로 target time namespace에 join하는 환경을 찾아 container-local timer 동작을 debugging 또는 post-exploitation을 위해 재현할 수 있음

영향:

- 거의 항상 reconnaissance 또는 환경 이해
- logging, uptime, 또는 checkpoint/restore 이상 현상을 설명하는 데 유용
- monotonic-time-based sleeps, retries, 그리고 timers 분석에 유용
- 보통 그 자체로 직접적인 container-escape 메커니즘은 아님

중요한 abuse nuance는 time namespaces가 `CLOCK_REALTIME`을 virtualize하지 않는다는 점입니다. 따라서 공격자가 host wall clock을 위조하거나 certificate-expiry checks를 시스템 전체에서 직접 깨뜨리게 하지는 못합니다. 이 기능의 가치는 주로 monotonic-time-based logic을 혼란스럽게 하거나, 환경별 버그를 재현하거나, 고급 런타임 동작을 이해하는 데 있습니다.

## Checks

이 checks는 주로 runtime이 실제로 private time namespace를 사용 중인지, 그리고 nonzero offsets를 실제로 설정했는지 확인하는 데 관한 것입니다.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
여기서 흥미로운 점은:

- 많은 환경에서 이러한 값들은 즉각적인 보안 발견으로 이어지지는 않지만, 특수한 runtime 기능이 사용 중인지 알려줍니다.
- `time_for_children`가 `time`과 다르다면, 호출자가 자신은 들어가지 않은 child-only time namespace를 준비했을 수 있습니다.
- `date`가 host와 일치하지만 monotonic/boottime-based 값이 일치하지 않는다면, wall-clock 변조보다는 time namespacing을 보고 있을 가능성이 큽니다.
- 두 process를 비교하는 경우, 여기의 차이가 혼란스러운 timing 또는 checkpoint/restore behavior를 설명할 수 있습니다.

대부분의 container breakout에서 time namespace는 가장 먼저 조사할 control이 아닙니다. 그래도 완전한 container-security 섹션이라면 이를 언급해야 하는데, 이는 현대 kernel model의 일부이고 고급 runtime 시나리오에서 때때로 중요하기 때문입니다.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
