# Простір імен часу

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Простір імен часу віртуалізує вибрані годинники монотонного типу замість системного годинника хоста. На практиці це означає приватні зміщення для **`CLOCK_MONOTONIC`** і **`CLOCK_BOOTTIME`**, а також пов’язані з ними представлення **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** і **`CLOCK_BOOTTIME_ALARM`**. Він **не** віртуалізує **`CLOCK_REALTIME`**, тому `date` і логіка перевірки терміну дії сертифікатів і надалі бачать системний годинник хоста, якщо цьому не перешкоджає інший механізм.

Основна мета — надати процесу можливість бачити контрольовані зміщення часу, що минув, без зміни глобального представлення часу на хості. Це корисно для робочих процесів checkpoint/restore, детермінованого тестування та розширеної поведінки runtime. Зазвичай це не є основним засобом ізоляції на рівні mount або user namespaces, але все одно сприяє тому, щоб середовище процесу було більш самодостатнім.

З offensive perspective цей простір імен зазвичай важливіший для **розвідки, викривлення таймерів і розуміння runtime**, ніж для прямого breakout. Водночас він має значення, оскільки дедалі більше container runtimes і робочих процесів checkpoint/restore можуть явно його запитувати.

## Лабораторна робота

Якщо kernel хоста та userspace це підтримують, простір імен можна перевірити за допомогою:
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
Підтримка залежить від версій kernel і tools, тому ця сторінка більше присвячена розумінню механізму, ніж очікуванню його відображення в кожному lab environment. Важливе спостереження полягає в тому, що `date` все одно має відображати wall clock хоста, тоді як значення на основі monotonic/boottime змінюються, коли налаштовано ненульові offsets.

### Нюанс створення

Простори імен часу дещо незвичайні порівняно з mount-, PID- або network-просторами імен:

- `unshare(CLONE_NEWTIME)` створює новий простір імен часу для **майбутніх дочірніх процесів**.
- Викличне task залишається у своєму поточному просторі імен часу.
- Тому `/proc/<pid>/ns/time_for_children>` часто є цікавішим за `/proc/<pid>/ns/time` під час debugging налаштування runtime.

Вікно для запису також особливе. Offsets у `/proc/<pid>/timens_offsets` потрібно записати до того, як новий простір імен часу буде повністю заповнений task, що виконуються; на практиці runtimes роблять це протягом вузького вікна налаштування між створенням простору імен і запуском фінального payload. Після того як там уже запущено task, подальші записи завершуються помилкою `EACCES`. Саме тому low-level runtimes виконують налаштування time namespace на ранньому етапі bootstrap, а не намагаються змінити offsets зсередини вже запущеного container process.

### Time Offsets

Linux time namespaces надають offsets для кожного простору імен через `/proc/<pid>/timens_offsets`. Формат являє собою набір назв або ID clock із дельтами в секундах/наносекундах відносно initial time namespace.

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
Важливим є не точний синтаксис команди, а поведінка: container може бачити інше представлення часу роботи системи, не змінюючи системний час host.

### Допоміжні прапорці `unshare`

Нові версії `util-linux` надають зручні прапорці, які автоматично записують зсуви під час створення namespace:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Ці flags здебільшого покращують зручність використання, але також спрощують розпізнавання цієї функції в документації, test harnesses і runtime wrappers.

## Використання під час виконання

Time namespaces є новішими й використовуються менш повсюдно, ніж mount- або PID namespaces. OCI Runtime Specification v1.1 додала явну підтримку `time` namespace і поля `linux.timeOffsets`, а сучасні runtimes можуть передавати ці дані до процесу bootstrap у kernel. Мінімальний фрагмент OCI має такий вигляд:
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
Це важливо, оскільки перетворює time namespacing із вузькоспеціалізованої kernel primitive на те, що runtimes можуть запитувати портативним способом. Це також пояснює, чому внутрішнім компонентам runtime потрібен явний етап синхронізації: offset має бути записаний у `/proc/<pid>/timens_offsets` до того, як payload контейнера повністю перейде до нового namespace.

Стекі checkpoint/restore, такі як CRIU, є однією з головних практичних причин існування цієї функції. Без time namespaces відновлення призупиненого workload призвело б до стрибка monotonic- і boot-time clocks на проміжок часу, протягом якого workload перебував у призупиненому стані.

## Вплив на безпеку

Існує менше класичних історій про breakout, пов’язаних із time namespace, ніж з іншими типами namespace. Ризик тут зазвичай полягає не в тому, що time namespace безпосередньо уможливлює escape, а в тому, що читачі повністю його ігнорують і тому не помічають, як advanced runtimes можуть змінювати поведінку процесів.

У спеціалізованих середовищах змінені monotonic або boottime views можуть впливати на:

- поведінку timeout і retry
- watchdogs та lease logic
- поведінку `timerfd`, `nanosleep` і `clock_nanosleep`
- forensics під час checkpoint/restore
- telemetry elapsed time та heuristics, що базуються на uptime

Тож хоча це рідко буде першим namespace, який ви будете abuse, він цілком може пояснити "неможливу" поведінку таймерів під час assessment.

## Abuse

Зазвичай тут немає прямої breakout primitive, але змінена поведінка clock усе одно може бути корисною для розуміння execution environment, виявлення advanced runtime features і пошуку timer-based logic, яка вимірюється відносно monotonic clocks, а не wall clock time:
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
Якщо ви порівнюєте два процеси, відмінності тут можуть допомогти пояснити нетипову поведінку часу, артефакти checkpoint/restore або невідповідності в журналюванні, специфічні для середовища.

Практичні аспекти, важливі для attacker:

- плутати логіку backoff, sleep або watchdog, реалізовану за допомогою монотонних годинників
- пояснювати, чому `/proc/uptime` і поведінка, керована таймерами, не відповідають очікуванням щодо системного wall-clock часу на хості
- розпізнавати робочі процеси CRIU/checkpoint-restore та інші розширені функції runtime
- виявляти середовища, де підключення до цільового time namespace за допомогою `nsenter -T -t <pid> -- ...` може відтворити поведінку таймерів, локальну для контейнера, під час debugging або post-exploitation

Вплив:

- майже завжди reconnaissance або розуміння середовища
- корисно для пояснення аномалій у журналюванні, uptime або checkpoint/restore
- корисно для аналізу sleep, retry і таймерів, заснованих на монотонному часі
- зазвичай не є прямим механізмом container escape сам по собі

Важливий нюанс зловживання полягає в тому, що time namespaces не віртуалізують `CLOCK_REALTIME`, тому самі по собі вони не дають attacker змоги сфальсифікувати системний wall clock на хості або безпосередньо порушити перевірки закінчення терміну дії сертифікатів у всій системі. Їхня цінність здебільшого полягає в заплутуванні логіки, заснованої на монотонному часі, відтворенні помилок, специфічних для середовища, або розумінні складної поведінки runtime.

## Checks

Ці перевірки здебільшого призначені для підтвердження того, чи використовує runtime приватний time namespace взагалі та чи встановив він ненульові offsets.
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

- У багатьох середовищах ці значення не призведуть до негайної security finding, але вони показують, чи використовується спеціалізована функція runtime.
- Якщо `time_for_children` відрізняється від `time`, можливо, caller підготував time namespace лише для дочірніх процесів, але сам до нього не перейшов.
- Якщо `date` збігається зі значенням на host, але значення на основі monotonic/boottime — ні, імовірно, ви маєте справу з time namespacing, а не з підміною wall clock.
- Якщо ви порівнюєте два процеси, відмінності тут можуть пояснити незрозумілу поведінку timing або checkpoint/restore.

Для більшості container breakouts time namespace не буде першим механізмом, який ви досліджуватимете. Однак повний розділ про container security має згадати його, оскільки це частина сучасної моделі kernel і він іноді має значення в розширених сценаріях runtime.

## Посилання

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
