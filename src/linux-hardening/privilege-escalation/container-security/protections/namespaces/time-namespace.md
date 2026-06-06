# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

time namespace віртуалізує вибрані monotonic-style clocks замість host wall clock. На практиці це означає приватні offsets для **`CLOCK_MONOTONIC`** і **`CLOCK_BOOTTIME`**, а також для тісно пов’язаних **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** і **`CLOCK_BOOTTIME_ALARM`** views. Воно **не** віртуалізує **`CLOCK_REALTIME`**, тому `date` і логіка certificate-expiry все ще бачать host wall clock, якщо інший механізм не втручається.

Основна мета — дати процесу змогу спостерігати контрольовані elapsed-time offsets без зміни глобального time view хоста. Це корисно для checkpoint/restore workflows, deterministic testing і advanced runtime behavior. Зазвичай це не є головним механізмом isolation у тому ж сенсі, що mount або user namespaces, але все одно допомагає зробити середовище процесу більш self-contained.

З offensive point of view, цей namespace зазвичай більш релевантний для **reconnaissance, timer skew, і runtime understanding** ніж для direct breakout. Однак це важливо, бо дедалі більше container runtimes і checkpoint/restore workflows можуть явно запитувати його.

## Lab

If the host kernel and userspace support it, you can inspect the namespace with:
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
Підтримка залежить від версій kernel і tool, тож ця сторінка більше про розуміння механізму, ніж про очікування, що він буде видимий у кожному lab environment. Важливе спостереження: `date` усе ще має відображати host wall clock, тоді як monotonic/boottime-based значення — це ті, що змінюються, коли налаштовані ненульові offsets.

### Creation Nuance

Time namespaces трохи незвичні порівняно з mount, PID або network namespaces:

- `unshare(CLONE_NEWTIME)` створює новий time namespace для **future children**.
- Task, що викликає, залишається у своєму поточному time namespace.
- `/proc/<pid>/ns/time_for_children` тому часто цікавіший за `/proc/<pid>/ns/time`, коли ви налагоджуєте runtime setup.

Вікно запису також особливе. Offsets у `/proc/<pid>/timens_offsets` потрібно записати до того, як новий time namespace буде повністю заповнений running tasks; на практиці runtimes роблять це під час вузького setup window між створенням namespace і запуском final payload. Коли task уже там працює, подальші записи завершуються з `EACCES`. Саме тому low-level runtimes обробляють time-namespace setup як ранній bootstrap step замість того, щоб намагатися пропатчити offsets зсередини вже запущеного container process.

### Time Offsets

Linux time namespaces expose per-namespace offsets через `/proc/<pid>/timens_offsets`. Формат — це набір clock names або IDs плюс second/nanosecond deltas відносно initial time namespace.

На практиці найнадійніший user-facing workflow — дозволити `unshare` записати ці offsets за вас:
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
Важливий момент не в точному синтаксисі команди, а в поведінці: container може спостерігати інший uptime-подібний вигляд без зміни host wall clock.

### `unshare` Helper Flags

Останні версії `util-linux` надають зручні flags, які автоматично записують offsets під час створення namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ці прапорці здебільшого є покращенням зручності використання, але вони також полегшують розпізнавання цієї функції в документації, test harnesses і runtime wrappers.

## Runtime Usage

Time namespaces новіші й менш універсально використовувані, ніж mount або PID namespaces. OCI Runtime Specification v1.1 додала явну підтримку `time` namespace і поля `linux.timeOffsets`, а сучасні runtimes можуть відображати ці дані в kernel bootstrap flow. Мінімальний OCI fragment виглядає так:
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
Це важливо, тому що це перетворює time namespacing з нішевого kernel primitive на щось, що runtimes можуть запитувати portably. Це також пояснює, чому внутрішнім механізмам runtime потрібен explicit synchronization step: offset має бути записаний у `/proc/<pid>/timens_offsets` до того, як container payload повністю увійде в новий namespace.

Checkpoint/restore stacks, такі як CRIU, є однією з головних практичних причин, чому це взагалі існує. Без time namespaces відновлення paused workload призводило б до того, що monotonic і boot-time clocks стрибали б на величину часу, який workload провів у suspended стані.

## Security Impact

Є менше класичних breakout stories, зосереджених на time namespace, ніж на інших типах namespace. Ризик тут зазвичай не в тому, що time namespace безпосередньо дає escape, а в тому, що читачі повністю його ігнорують і тому пропускають, як advanced runtimes можуть формувати поведінку process.

У спеціалізованих середовищах змінені monotonic або boottime views можуть впливати на:

- timeout and retry behavior
- watchdogs and lease logic
- `timerfd`, `nanosleep`, and `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry and uptime-based heuristics

Тож хоча це рідко перший namespace, який ви abuse, він цілком може пояснити "impossible" timing behavior під час assessment.

## Abuse

Зазвичай тут немає direct breakout primitive, але змінена поведінка clock все одно може бути корисною для розуміння execution environment, виявлення advanced runtime features і пошуку timer-based logic, яка вимірюється відносно monotonic clocks, а не wall clock time:
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
Якщо ви порівнюєте два процеси, відмінності тут можуть допомогти пояснити дивну поведінку таймінгу, артефакти checkpoint/restore або невідповідності в logging, залежні від environment.

Практичні, релевантні для attacker, кути:

- плутати backoff, sleep або watchdog logic, реалізовану за допомогою monotonic clocks
- пояснити, чому `/proc/uptime` і timer-driven behavior не збігаються з host-side очікуваннями wall-clock
- розпізнавати CRIU/checkpoint-restore workflows та інші advanced runtime features
- помічати environments, де приєднання до target time namespace за допомогою `nsenter -T -t <pid> -- ...` може відтворити container-local timer behavior для debugging або post-exploitation

Impact:

- майже завжди reconnaissance або understanding environment
- корисно для пояснення logging, uptime або checkpoint/restore аномалій
- корисно для аналізу monotonic-time-based sleeps, retries і timers
- зазвичай не є прямим container-escape механізмом саме по собі

Важливий нюанс abuse: time namespaces не virtualize `CLOCK_REALTIME`, тож самі по собі не дають attacker змоги підробити host wall clock або напряму зламати certificate-expiry checks system-wide. Їхня цінність здебільшого в заплутуванні monotonic-time-based logic, відтворенні environment-specific bugs або розумінні advanced runtime behavior.

## Checks

Ці checks здебільшого стосуються підтвердження того, чи runtime взагалі використовує private time namespace, і чи він справді встановив ненульові offsets.
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
Що тут цікаво:

- У багатьох середовищах ці значення не призведуть до негайної знахідки безпеки, але вони показують, чи використовується спеціалізована runtime-функція.
- Якщо `time_for_children` відрізняється від `time`, можливо, викликач підготував child-only time namespace, у який сам не увійшов.
- Якщо `date` збігається з host, але значення на основі monotonic/boottime не збігаються, ви, ймовірно, маєте справу з time namespacing, а не з підміною wall-clock.
- Якщо ви порівнюєте два процеси, відмінності тут можуть пояснити заплутану поведінку timing або checkpoint/restore.

Для більшості container breakouts time namespace не є першою control, яку ви будете досліджувати. Проте повний розділ про container-security має згадати його, тому що він є частиною сучасної kernel model і інколи має значення в advanced runtime scenarios.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
