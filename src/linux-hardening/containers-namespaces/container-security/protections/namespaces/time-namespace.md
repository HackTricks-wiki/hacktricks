# Простір імен часу

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Простір імен часу віртуалізує вибрані годинники монотонного типу замість системного годинника хоста. На практиці це означає приватні зміщення для **`CLOCK_MONOTONIC`** і **`CLOCK_BOOTTIME`**, а також тісно пов'язані представлення **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** і **`CLOCK_BOOTTIME_ALARM`**. Він **не** віртуалізує **`CLOCK_REALTIME`**, тому `date` і логіка перевірки терміну дії сертифікатів і надалі бачать системний годинник хоста, якщо цьому не перешкоджає якийсь інший механізм.<sup>[[1]](#references)</sup>

Основне призначення полягає в тому, щоб процес міг бачити контрольовані зміщення часу, що минув, не змінюючи глобальне представлення часу на хості. Це корисно для робочих процесів checkpoint/restore, детермінованого тестування та розширеної поведінки runtime. Зазвичай це не є основним засобом ізоляції, як-от mount- або user namespaces, але все одно сприяє більшій самодостатності середовища процесу.

З offensive point of view цей простір імен зазвичай важливіший для **reconnaissance, timer skew і розуміння runtime**, ніж для безпосереднього breakout. Водночас він має значення, оскільки дедалі більше container runtimes і робочих процесів checkpoint/restore тепер можуть явно його запитувати.

## Лабораторна робота

Якщо kernel хоста та userspace це підтримують, ви можете перевірити простір імен за допомогою:
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
Підтримка залежить від версій kernel і tools, тому ця сторінка більше присвячена розумінню механізму, а не очікуванню його видимості в кожному lab environment. Важливе спостереження полягає в тому, що `date` усе ще має відображати wall clock хоста, тоді як значення на основі monotonic/boottime змінюються, коли налаштовано ненульові offsets.

### Особливості створення

Time namespaces дещо незвичайні порівняно з mount, PID або network namespaces:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` створює новий time namespace для **майбутніх дочірніх процесів**.
- Викликане завдання залишається у своєму поточному time namespace.
- Тому `/proc/<pid>/ns/time_for_children>` часто цікавіший за `/proc/<pid>/ns/time` під час debugging runtime setup.

Вікно для запису також є особливим. Offsets у `/proc/<pid>/timens_offsets` потрібно записати до того, як новий time namespace буде повністю заповнений процесами, що виконуються; на практиці runtimes роблять це протягом вузького вікна setup між створенням namespace і запуском фінального payload. Після того як там уже виконується task, подальші записи завершуються помилкою `EACCES`. Саме тому low-level runtimes обробляють setup time namespace як ранній bootstrap step, а не намагаються змінити offsets з уже запущеного container process.<sup>[[1]](#references)</sup>

### Time Offsets

Linux time namespaces надають offsets для кожного namespace через `/proc/<pid>/timens_offsets`. Формат являє собою набір назв або ID clock із дельтами в секундах і наносекундах відносно initial time namespace.<sup>[[1]](#references)</sup>

На практиці найнадійніший workflow для користувача — дозволити `unshare` записати ці offsets замість вас:
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
Важливим є не точний синтаксис команди, а поведінка: контейнер може бачити інше uptime-подібне представлення, не змінюючи системний час host.

### Прапорці-помічники `unshare`

Нові версії `util-linux` надають зручні прапорці, які автоматично записують зміщення під час створення namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ці прапорці здебільшого покращують зручність використання, але також полегшують розпізнавання цієї функції в документації, тестових середовищах і runtime-обгортках.

## Використання під час виконання

Простори імен часу є новішими та використовуються не так повсюдно, як простори імен монтування або PID. OCI Runtime Specification v1.1 додала явну підтримку простору імен `time` і поля `linux.timeOffsets`, а сучасні runtime можуть передавати ці дані в потік ініціалізації ядра. Мінімальний фрагмент OCI має такий вигляд:
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
Це важливо, оскільки перетворює time namespacing із вузькоспеціалізованої примітивної функції ядра на те, що runtimes можуть запитувати портативним способом. Це також пояснює, чому внутрішнім механізмам runtime потрібен явний крок синхронізації: зміщення має бути записане до `/proc/<pid>/timens_offsets` перед тим, як payload контейнера повністю увійде до нового простору імен.

Стек checkpoint/restore, як-от CRIU, є однією з головних практичних причин існування цієї функції. Без time namespaces відновлення призупиненого workload призвело б до стрибка monotonic і boot-time clock на величину часу, протягом якого workload перебував у призупиненому стані.<sup>[[2]](#references)</sup>

## Вплив на безпеку

Існує менше класичних історій про breakout, зосереджених на time namespace, ніж на інших типах namespace. Ризик тут зазвичай полягає не в тому, що time namespace безпосередньо забезпечує escape, а в тому, що дослідники повністю його ігнорують і тому не помічають, як advanced runtimes можуть змінювати поведінку процесів.

У спеціалізованих середовищах змінені уявлення про monotonic або boottime можуть впливати на:

- поведінку timeout і retry
- watchdog і логіку lease
- поведінку `timerfd`, `nanosleep` і `clock_nanosleep`
- forensics checkpoint/restore
- telemetry щодо elapsed time та евристики на основі uptime

Тож, хоча це рідко перший namespace, який ви будете abuse, він цілком може пояснити «неможливу» поведінку часу під час assessment.

## Abuse

Зазвичай тут немає прямого breakout primitive, але змінена поведінка clock усе одно може бути корисною для розуміння середовища виконання, виявлення advanced runtime features і пошуку логіки на основі timer, яка вимірюється за monotonic clocks, а не за wall clock time:
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
Якщо ви порівнюєте два процеси, відмінності тут можуть допомогти пояснити дивну поведінку таймінгів, артефакти checkpoint/restore або невідповідності в логуванні, специфічні для середовища.

Практичні аспекти, важливі для attacker:

- заплутати логіку backoff, sleep або watchdog, реалізовану з використанням monotonic clocks
- пояснити, чому `/proc/uptime` і поведінка, керована таймерами, не відповідають очікуванням щодо wall-clock на хості
- розпізнати робочі процеси CRIU/checkpoint-restore та інші розширені runtime-функції
- виявити середовища, де приєднання до цільового time namespace за допомогою `nsenter -T -t <pid> -- ...` може відтворити локальну для контейнера поведінку таймерів під час debugging або post-exploitation

Вплив:

- майже завжди reconnaissance або розуміння середовища
- корисно для пояснення аномалій у logging, uptime або checkpoint/restore
- корисно для аналізу sleep, retry та timer, що базуються на monotonic time
- зазвичай саме по собі не є прямим механізмом container escape

Важливий нюанс зловживання полягає в тому, що time namespaces не віртуалізують `CLOCK_REALTIME`, тому самі по собі вони не дають attacker змоги підробити wall clock хоста або безпосередньо зламати перевірки завершення терміну дії сертифікатів у всій системі. Їхня цінність здебільшого полягає в заплутуванні логіки, що базується на monotonic time, відтворенні помилок, специфічних для середовища, або розумінні розширеної runtime-поведінки.

## Перевірки

Ці перевірки здебільшого призначені для підтвердження того, чи використовує runtime приватний time namespace і чи справді для нього встановлено ненульові offsets.
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
Що тут цікавого:

- У багатьох середовищах ці значення не призведуть до негайного виявлення проблеми безпеки, але вони покажуть, чи задіяна спеціалізована функція runtime.
- Якщо `time_for_children` відрізняється від `time`, можливо, викликува́ч підготував time namespace, призначений лише для дочірніх процесів, але сам до нього не увійшов.
- Якщо `date` збігається з host, але значення на основі monotonic/boottime відрізняються, імовірно, ви маєте справу з time namespacing, а не з втручанням у wall-clock.
- Якщо ви порівнюєте два процеси, відмінності тут можуть пояснити незрозумілу поведінку, пов’язану з timing або checkpoint/restore.

Для більшості container breakout time namespace не буде першим механізмом, який ви досліджуватимете. Однак повний розділ про container security має згадати його, оскільки він є частиною сучасної моделі kernel і час від часу має значення в advanced runtime scenarios.

## References

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
