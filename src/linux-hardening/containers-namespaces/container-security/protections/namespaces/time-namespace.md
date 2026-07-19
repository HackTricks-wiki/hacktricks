# 시간 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

시간 네임스페이스는 호스트의 wall clock 대신 선택된 monotonic 스타일 clock을 virtualize합니다. 실제로는 **`CLOCK_MONOTONIC`** 및 **`CLOCK_BOOTTIME`**에 대한 private offset과, 이와 밀접하게 관련된 **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`**, **`CLOCK_BOOTTIME_ALARM`** view를 제공합니다. **`CLOCK_REALTIME`**은 virtualize하지 않으므로, 다른 메커니즘이 개입하지 않는 한 `date`와 certificate-expiry 로직은 계속 호스트의 wall clock을 확인합니다.

주요 목적은 호스트의 global time view를 변경하지 않고 프로세스가 제어된 elapsed-time offset을 관찰하도록 하는 것입니다. 이는 checkpoint/restore workflow, deterministic testing, advanced runtime behavior에 유용합니다. 일반적으로 mount 또는 user namespace와 같은 수준의 대표적인 isolation control은 아니지만, 프로세스 환경을 더욱 self-contained하게 만드는 데 기여합니다.

공격 관점에서 이 namespace는 직접적인 breakout보다는 **reconnaissance, timer skew, runtime understanding**에 더 관련이 있는 경우가 많습니다. 그러나 더 많은 container runtime과 checkpoint/restore workflow에서 이를 명시적으로 요청할 수 있게 되었으므로 중요합니다.

## Lab

호스트 kernel과 userspace가 이를 지원한다면 다음 명령으로 namespace를 확인할 수 있습니다:
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
지원 여부는 kernel 및 tool 버전에 따라 다르므로, 이 페이지는 모든 lab 환경에서 해당 기능이 표시될 것이라고 기대하기보다는 mechanism을 이해하는 데 중점을 둡니다. 중요한 점은 `date`가 여전히 host의 wall clock을 반영해야 하며, nonzero offset이 설정되었을 때 변경되는 것은 monotonic/boottime 기반 값이라는 것입니다.

### 생성 시 주의 사항

Time namespace는 mount, PID 또는 network namespace와 비교하면 약간 특이합니다.

- `unshare(CLONE_NEWTIME)`는 **향후 자식 프로세스**를 위한 새로운 time namespace를 생성합니다.
- 호출한 task는 현재 time namespace에 그대로 남습니다.
- 따라서 runtime setup을 debugging할 때는 `/proc/<pid>/ns/time`보다 `/proc/<pid>/ns/time_for_children`가 더 유용한 경우가 많습니다.

write window도 특수합니다. `/proc/<pid>/timens_offsets`의 offset은 새 time namespace가 실행 중인 task로 완전히 채워지기 전에 작성해야 합니다. 실제로 runtime은 namespace 생성과 최종 payload 시작 사이의 짧은 setup window 동안 이 작업을 수행합니다. task가 이미 그 안에서 실행 중이면 이후 write는 `EACCES`와 함께 실패합니다. 따라서 low-level runtime은 이미 시작된 container process 내부에서 offset을 patch하려 하지 않고, time-namespace setup을 초기 bootstrap 단계로 처리합니다.

### Time Offset

Linux time namespace는 `/proc/<pid>/timens_offsets`를 통해 namespace별 offset을 노출합니다. 형식은 clock 이름 또는 ID와 initial time namespace를 기준으로 한 초/나노초 단위 delta의 집합입니다.

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
중요한 점은 정확한 명령어 구문이 아니라 동작입니다. 컨테이너는 host의 wall clock을 변경하지 않고도 서로 다른 uptime과 유사한 관점을 관찰할 수 있습니다.

### `unshare` Helper Flags

최신 `util-linux` 버전은 namespace 생성 중에 offset을 자동으로 기록하는 편의성 플래그를 제공합니다:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
이러한 flags는 주로 사용성을 개선하지만, documentation, test harnesses 및 runtime wrappers에서 해당 기능을 더 쉽게 식별할 수 있도록 해줍니다.

## 런타임 사용법

Time namespace는 mount 또는 PID namespace보다 최신 기능이며, 모든 환경에서 사용되는 빈도도 낮습니다. OCI Runtime Specification v1.1에서는 `time` namespace와 `linux.timeOffsets` 필드에 대한 명시적 지원이 추가되었으며, 최신 runtimes는 해당 데이터를 kernel bootstrap flow에 매핑할 수 있습니다. 최소한의 OCI fragment는 다음과 같습니다:
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
이는 time namespacing를 niche kernel primitive에서 runtime이 portable하게 요청할 수 있는 기능으로 바꾸기 때문에 중요합니다. 또한 runtime 내부에서 명시적인 synchronization 단계가 필요한 이유도 설명합니다. container payload가 새 namespace에 완전히 진입하기 전에 `/proc/<pid>/timens_offsets`에 offset을 기록해야 합니다.

CRIU와 같은 checkpoint/restore stack은 이것이 실제 환경에 존재하는 주요 이유 중 하나입니다. time namespace가 없다면 paused workload를 restore할 때 workload가 suspended 상태로 있었던 시간만큼 monotonic 및 boot-time clock이 갑자기 건너뛰게 됩니다.

## 보안 영향

다른 namespace 유형에 비해 time namespace를 중심으로 한 전형적인 breakout 사례는 적습니다. 여기서 일반적인 risk는 time namespace가 직접 escape를 가능하게 한다는 것이 아니라, 이를 완전히 무시하여 advanced runtime이 process behavior를 어떻게 조정할 수 있는지 놓치는 데 있습니다.

특수한 환경에서는 변경된 monotonic 또는 boottime view가 다음에 영향을 줄 수 있습니다.

- timeout 및 retry behavior
- watchdog 및 lease logic
- `timerfd`, `nanosleep`, `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry 및 uptime 기반 heuristics

따라서 이것은 악용하는 첫 번째 namespace인 경우는 드물지만, assessment 중 발생하는 "impossible" timing behavior를 설명하는 데는 확실히 도움이 될 수 있습니다.

## Abuse

일반적으로 여기에는 직접적인 breakout primitive가 없지만, 변경된 clock behavior는 execution environment를 파악하고, advanced runtime 기능을 식별하며, wall clock time이 아니라 monotonic clock을 기준으로 측정되는 timer-based logic을 발견하는 데 여전히 유용할 수 있습니다.
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
두 프로세스를 비교하는 경우, 여기의 차이는 이상한 timing 동작, checkpoint/restore artifact 또는 환경별 logging 불일치를 설명하는 데 도움이 될 수 있습니다.

실용적으로 attacker와 관련된 관점:

- monotonic clock로 구현된 backoff, sleep 또는 watchdog 로직을 혼란스럽게 함
- `/proc/uptime` 및 timer 기반 동작이 host 측 wall-clock 예상과 일치하지 않는 이유를 설명함
- CRIU/checkpoint-restore workflow 및 기타 고급 runtime 기능을 인식함
- 디버깅 또는 post-exploitation을 위해 `nsenter -T -t <pid> -- ...`로 target time namespace에 join하면 container-local timer 동작을 재현할 수 있는 환경을 식별함

영향:

- 거의 항상 reconnaissance 또는 환경 파악에 해당함
- logging, uptime 또는 checkpoint/restore anomaly를 설명하는 데 유용함
- monotonic-time 기반 sleep, retry 및 timer를 분석하는 데 유용함
- 일반적으로 그 자체만으로 직접적인 container-escape 메커니즘은 아님

중요한 abuse 관련 nuance는 time namespace가 `CLOCK_REALTIME`을 virtualize하지 않는다는 점입니다. 따라서 time namespace만으로 attacker가 host wall clock을 위조하거나 system-wide certificate-expiry check를 직접 무력화할 수는 없습니다. time namespace의 가치는 주로 monotonic-time 기반 로직을 혼란스럽게 하거나, 환경별 bug를 재현하거나, 고급 runtime 동작을 파악하는 데 있습니다.

## Checks

이러한 check는 주로 runtime이 private time namespace를 실제로 사용하는지, 그리고 nonzero offset을 설정했는지 확인하기 위한 것입니다.
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
여기서 흥미로운 점은 다음과 같습니다.

- 많은 환경에서 이러한 값이 즉각적인 보안 취약점으로 이어지지는 않지만, 특수한 runtime 기능이 사용 중인지 확인하는 데 도움이 됩니다.
- `time_for_children`가 `time`과 다르면, 호출자가 자신은 진입하지 않은 child 전용 time namespace를 준비했을 가능성이 있습니다.
- `date`가 host와 일치하지만 monotonic/boottime 기반 값이 일치하지 않는다면, wall-clock 변조보다는 time namespacing을 보고 있을 가능성이 높습니다.
- 두 process를 비교하는 경우, 이러한 차이가 혼란스러운 timing 또는 checkpoint/restore 동작의 원인을 설명할 수 있습니다.

대부분의 container breakout에서는 time namespace가 가장 먼저 조사할 control은 아닙니다. 그래도 modern kernel model의 일부이며 고급 runtime 시나리오에서 가끔 중요하므로, 완전한 container-security section에서는 이를 언급해야 합니다.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
