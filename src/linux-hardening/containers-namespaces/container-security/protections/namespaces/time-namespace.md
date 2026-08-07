# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

time namespace는 호스트 wall clock 대신 선택된 monotonic-style clock을 virtualize합니다. 실제로는 **`CLOCK_MONOTONIC`** 및 **`CLOCK_BOOTTIME`**에 대한 private offset과, 이와 밀접하게 관련된 **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, **`CLOCK_BOOTTIME_ALARM`** view를 의미합니다. **`CLOCK_REALTIME`**은 virtualize하지 않으므로, 다른 메커니즘이 간섭하지 않는 한 `date` 및 certificate-expiry logic은 여전히 호스트 wall clock을 확인합니다.<sup>[[1]](#references)</sup>

주된 목적은 호스트의 global time view를 변경하지 않고 process가 제어된 elapsed-time offset을 확인할 수 있도록 하는 것입니다. 이는 checkpoint/restore workflow, deterministic testing 및 advanced runtime behavior에 유용합니다. 일반적으로 mount 또는 user namespace와 같은 isolation control만큼 핵심적인 control은 아니지만, process environment를 더욱 self-contained하게 만드는 데 기여합니다.

offensive 관점에서 이 namespace는 direct breakout보다는 **reconnaissance, timer skew 및 runtime understanding**에 더 관련이 있습니다. 그러나 더 많은 container runtime과 checkpoint/restore workflow가 이제 이를 명시적으로 요청할 수 있으므로 중요합니다.

## Lab

host kernel과 userspace가 이를 지원한다면 다음 명령으로 namespace를 inspect할 수 있습니다:
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
커널 및 도구 버전에 따라 지원 여부가 다르므로, 이 페이지는 모든 lab 환경에서 해당 기능이 표시될 것이라고 기대하기보다는 메커니즘을 이해하는 데 중점을 둡니다. 중요한 관찰 사항은 `date`가 여전히 host wall clock을 반영해야 하며, nonzero offset이 설정되었을 때 변경되는 값은 monotonic/boottime 기반 값이라는 점입니다.

### 생성 시 주의 사항

Time namespace는 mount, PID 또는 network namespace와 비교해 약간 특이합니다.<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)`는 **future children**을 위한 새로운 time namespace를 생성합니다.
- 호출한 task는 현재 time namespace에 그대로 남습니다.
- 따라서 runtime 설정을 디버깅할 때는 `/proc/<pid>/ns/time`보다 `/proc/<pid>/ns/time_for_children`가 더 유용한 경우가 많습니다.

write window도 특수합니다. `/proc/<pid>/timens_offsets`의 offset은 새로운 time namespace가 실행 중인 task로 완전히 채워지기 전에 작성해야 합니다. 실제로 runtime은 namespace 생성과 최종 payload 시작 사이의 짧은 설정 window에서 이 작업을 수행합니다. task가 이미 해당 namespace에서 실행 중이면 이후 write는 `EACCES`와 함께 실패합니다. 따라서 low-level runtime은 이미 시작된 container process 내부에서 offset을 수정하려 하지 않고, time-namespace 설정을 초기 bootstrap 단계로 처리합니다.<sup>[[1]](#references)</sup>

### Time Offset

Linux time namespace는 `/proc/<pid>/timens_offsets`를 통해 namespace별 offset을 노출합니다. 형식은 initial time namespace를 기준으로 한 clock 이름 또는 ID와 초/나노초 단위 delta의 집합입니다.<sup>[[1]](#references)</sup>

실제로 가장 안정적인 user-facing workflow는 `unshare`가 해당 offset을 대신 작성하도록 하는 것입니다:
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
중요한 점은 정확한 명령어 구문이 아니라 동작입니다. 컨테이너는 호스트의 wall clock을 변경하지 않고도 서로 다른 uptime과 유사한 관점을 관찰할 수 있습니다.

### `unshare` Helper Flags

최근 `util-linux` 버전은 namespace 생성 중에 오프셋을 자동으로 기록하는 편의 플래그를 제공합니다:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
이 flags는 대부분 usability 개선을 위한 것이지만, documentation, test harnesses 및 runtime wrappers에서 해당 feature를 더 쉽게 인식할 수 있게 해 줍니다.

## Runtime Usage

Time namespace는 mount 또는 PID namespace보다 최신이며, 보편적으로 사용되는 정도도 낮습니다. OCI Runtime Specification v1.1에서는 `time` namespace와 `linux.timeOffsets` field에 대한 명시적 지원이 추가되었으며, 최신 runtimes는 해당 데이터를 kernel bootstrap flow에 매핑할 수 있습니다. 최소한의 OCI fragment는 다음과 같습니다:
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
이는 time namespacing을 틈새 kernel primitive에서 runtime이 portable하게 요청할 수 있는 기능으로 바꾸기 때문에 중요합니다. 또한 runtime 내부에 명시적인 synchronization 단계가 필요한 이유도 설명합니다. container payload가 새 namespace에 완전히 진입하기 전에 `/proc/<pid>/timens_offsets`에 offset을 기록해야 합니다.

CRIU와 같은 checkpoint/restore stack은 이 기능이 실제 환경에서 존재하는 주요 이유 중 하나입니다. time namespace가 없다면 일시 중지된 workload를 restore할 때 monotonic 및 boot-time clock이 workload가 suspend 상태로 있었던 시간만큼 갑자기 변경됩니다.<sup>[[2]](#references)</sup>

## Security Impact

다른 namespace 유형에 비해 time namespace를 중심으로 한 전형적인 breakout 사례는 적습니다. 여기서의 위험은 대개 time namespace가 직접 escape를 가능하게 한다는 것이 아니라, 이를 완전히 무시하여 advanced runtime이 process 동작을 어떻게 조정할 수 있는지 놓치는 데 있습니다.

특수한 환경에서는 변경된 monotonic 또는 boottime view가 다음 항목에 영향을 줄 수 있습니다.

- timeout 및 retry 동작
- watchdog 및 lease logic
- `timerfd`, `nanosleep`, `clock_nanosleep` 동작
- checkpoint/restore forensics
- elapsed-time telemetry 및 uptime 기반 heuristic

따라서 이것이 abuse하는 첫 번째 namespace인 경우는 드물지만, assessment 중 발생하는 "불가능한" timing 동작을 설명하는 데에는 분명히 도움이 될 수 있습니다.

## Abuse

일반적으로 여기에는 직접적인 breakout primitive가 없지만, 변경된 clock 동작은 execution environment를 파악하고, advanced runtime 기능을 식별하며, wall clock time이 아니라 monotonic clock을 기준으로 측정되는 timer 기반 logic을 발견하는 데 여전히 유용할 수 있습니다.
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
두 프로세스를 비교하는 경우, 여기서의 차이는 이상한 timing 동작, checkpoint/restore artifact 또는 환경별 logging 불일치의 원인을 설명하는 데 도움이 될 수 있습니다.

공격자와 관련된 실용적인 관점:

- monotonic clock을 사용해 구현된 backoff, sleep 또는 watchdog 로직을 혼란시키기
- `/proc/uptime` 및 timer 기반 동작이 host 측 wall-clock 예상과 일치하지 않는 이유 설명하기
- CRIU/checkpoint-restore workflow 및 기타 고급 runtime 기능 식별하기
- debugging 또는 post-exploitation을 위해 `nsenter -T -t <pid> -- ...`를 사용하여 대상 time namespace에 join하면 container-local timer 동작을 재현할 수 있는 환경 파악하기

영향:

- 거의 항상 reconnaissance 또는 환경 파악
- logging, uptime 또는 checkpoint/restore anomaly를 설명하는 데 유용
- monotonic-time 기반 sleep, retry 및 timer 분석에 유용
- 일반적으로 그 자체만으로 직접적인 container-escape 메커니즘은 아님

중요한 abuse 측면은 time namespace가 `CLOCK_REALTIME`을 virtualize하지 않는다는 점입니다. 따라서 time namespace만으로는 공격자가 host wall clock을 위조하거나 시스템 전반의 certificate-expiry check를 직접 무력화할 수 없습니다. time namespace의 가치는 주로 monotonic-time 기반 로직을 혼란시키고, 환경별 bug를 재현하거나, 고급 runtime 동작을 이해하는 데 있습니다.

## 점검

이러한 점검은 주로 runtime이 private time namespace를 실제로 사용하는지, 그리고 nonzero offset을 실제로 설정했는지 확인하기 위한 것입니다.
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
여기서 흥미로운 점:

- 많은 환경에서 이러한 값이 즉각적인 보안 finding으로 이어지지는 않지만, 특수한 runtime 기능이 사용 중인지 알려줍니다.
- `time_for_children`가 `time`과 다르면, caller가 자신은 진입하지 않은 child-only time namespace를 준비했을 가능성이 있습니다.
- `date`가 host와 일치하지만 monotonic/boottime 기반 값이 일치하지 않는다면, wall-clock 변조가 아니라 time namespacing을 보고 있을 가능성이 높습니다.
- 두 process를 비교하는 경우, 여기서의 차이가 혼란스러운 timing 또는 checkpoint/restore 동작을 설명할 수 있습니다.

대부분의 container breakout에서 time namespace는 가장 먼저 조사할 control은 아닙니다. 그래도 modern kernel model의 일부이며 advanced runtime 시나리오에서 가끔 중요하므로, 완전한 container-security 섹션에서는 이를 언급해야 합니다.

## References

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
