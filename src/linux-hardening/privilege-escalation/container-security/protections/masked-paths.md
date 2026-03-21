# Приховані шляхи

{{#include ../../../../banners/hacktricks-training.md}}

Приховані шляхи — це runtime-захисти, які приховують особливо чутливі для ядра файлові локації від контейнера шляхом bind-mounting поверх них або іншим способом роблять їх недоступними. Мета — завадити workload-у безпосередньо взаємодіяти з інтерфейсами, які звичайним додаткам не потрібні, особливо всередині procfs.

Це важливо, тому що багато container escapes та прийомів, що впливають на хост, починаються зі зчитування або запису спеціальних файлів під `/proc` або `/sys`. Якщо ці локації замасковані, атакуючий втрачає прямий доступ до корисної частини surface управління ядром навіть після отримання виконання коду всередині контейнера.

## Принцип роботи

Рантайми зазвичай маскують вибрані шляхи, такі як:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Точний перелік залежить від runtime-а та конфігурації хоста. Важлива властивість у тому, що шлях стає недоступним або замінюється з точки зору контейнера, хоча на хості він все ще існує.

## Лабораторія

Перегляньте конфігурацію masked-path, яку експонує Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Перевірте фактичну поведінку монтування всередині робочого навантаження:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Вплив на безпеку

Masking не створює основну межу ізоляції, але видаляє кілька високовартісних post-exploitation targets. Без Masking компрометований container може мати змогу інспектувати kernel state, читати чутливу інформацію про процеси або ключі, або взаємодіяти з procfs/sysfs об'єктами, які ніколи не повинні були бути видимими для application.

## Неправильні конфігурації

Головна помилка — unmasking широких класів шляхів заради зручності або налагодження. У Podman це може виглядати як `--security-opt unmask=ALL` або цілеспрямоване unmasking. У Kubernetes надто широке proc exposure може з'явитися через `procMount: Unmasked`. Ще однією серйозною проблемою є експонування host `/proc` або `/sys` через bind mount, що повністю обходить ідею скороченого container view.

## Зловживання

Якщо Masking слабкий або відсутній, почніть із визначення, які чутливі procfs/sysfs шляхи доступні напряму:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Якщо нібито замаскований шлях доступний, ретельно його перевірте:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- /proc/timer_list can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- /proc/keys is much more sensitive. Depending on the host configuration, it may reveal keyring entries, key descriptions, and relationships between host services using the kernel keyring subsystem.
- /sys/firmware helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- /proc/config.gz may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- /proc/sched_debug exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Interesting results include direct reads from those files, evidence that the data belongs to the host rather than to a constrained container view, or access to other procfs/sysfs locations that are commonly masked by default.

## Перевірки

Мета цих перевірок — визначити, які шляхи середовище виконання навмисно приховало та чи все ще робоче навантаження бачить обмежену файлову систему, орієнтовану на ядро.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Що тут цікавого:

- Довгий список masked-path є нормою в захищених середовищах виконання.
- Відсутність маскування чутливих записів procfs заслуговує на ретельнішу перевірку.
- Якщо чутливий шлях доступний і контейнер також має сильні capabilities або широкі mounts, то експозиція має більшу вагу.

## Налаштування середовища виконання за замовчуванням

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Поширені ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає список masked path за замовчуванням | експозиція host proc/sys mounts, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує масковані шляхи за замовчуванням, якщо їх не розмасковано вручну | `--security-opt unmask=ALL`, цільове розмаскування, `--privileged` |
| Kubernetes | Наслідує налаштування runtime | Використовує поведінку маскування базового runtime, якщо налаштування Pod не послаблюють доступ до proc | `procMount: Unmasked`, шаблони привілейованих робочих навантажень, широкі host mounts |
| containerd / CRI-O under Kubernetes | Стан runtime за замовчуванням | Зазвичай застосовує OCI/runtime masked paths, якщо не перевизначено | прямі зміни конфігурації runtime, ті ж шляхи послаблення в Kubernetes |

Masked paths зазвичай присутні за замовчуванням. Основна операційна проблема — не відсутність у runtime, а навмисне розмаскування або host bind mounts, які нівелюють захист.
