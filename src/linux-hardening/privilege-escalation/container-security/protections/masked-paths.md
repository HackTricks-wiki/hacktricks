# Замасковані шляхи

{{#include ../../../../banners/hacktricks-training.md}}

Замасковані шляхи — це runtime-захисти, які приховують особливо чутливі файлові розташування, що взаємодіють із ядром, від контейнера шляхом bind-mounting поверх них або іншим чином роблячи їх недоступними. Мета — запобігти тому, щоб workload безпосередньо взаємодіяв із інтерфейсами, які звичайним застосункам не потрібні, особливо всередині procfs.

Це важливо, бо багато container escapes та трюків, що впливають на host, починаються з читання або запису спеціальних файлів під `/proc` або `/sys`. Якщо ці локації замасковані, атакувальник втрачає прямий доступ до корисної частини kernel control surface навіть після отримання code execution всередині контейнера.

## Принцип роботи

Runtimes зазвичай маскують обрані шляхи, такі як:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Точний список залежить від runtime та конфігурації host. Важливо, що з точки зору контейнера шлях стає недоступним або заміщується, хоча він все ще існує на хості.

## Лаб

Перегляньте конфігурацію masked-path, яку експонує Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Перевірте фактичну поведінку mount всередині workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Маскування не створює основну межу ізоляції, але прибирає кілька високовартісних цілей для post-exploitation. Без маскування скомпрометований контейнер може перевіряти стан ядра, читати конфіденційну інформацію про процеси або ключі, або взаємодіяти з об'єктами procfs/sysfs, які не мали б бути видимими для додатка.

## Misconfigurations

Головна помилка — розмаскування широких класів шляхів заради зручності або відлагодження. У Podman це може виявлятися як `--security-opt unmask=ALL` або вибіркове розмаскування. У Kubernetes надто широкий доступ до proc може проявлятися через `procMount: Unmasked`. Ще одна серйозна проблема — експонування хостового `/proc` або `/sys` через bind mount, що повністю обходить ідею обмеженого виду контейнера.

## Abuse

Якщо маскування слабке або відсутнє, почніть з визначення, які чутливі шляхи procfs/sysfs доступні безпосередньо:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Якщо нібито masked path доступний, ретельно його перевірте:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` може показати дані таймера та планувальника хоста. Це здебільшого примітив для розвідки, але підтверджує, що контейнер може читати інформацію, спрямовану на ядро, яка зазвичай прихована.
- `/proc/keys` є значно чутливішим. Залежно від конфігурації хоста, він може розкрити записи keyring, описи ключів та взаємини між службами хоста, що використовують kernel keyring subsystem.
- `/sys/firmware` допомагає визначити режим завантаження, інтерфейси прошивки та деталі платформи, корисні для fingerprinting хоста і для розуміння того, чи workload бачить стан на рівні хоста.
- `/proc/config.gz` може розкрити конфігурацію запущеного ядра, що цінно для підбору вимог публічних kernel exploit або для розуміння, чому певна функція доступна.
- `/proc/sched_debug` показує стан планувальника і часто обходить інтуїтивне очікування, що PID namespace повинна повністю приховувати несуміжну інформацію про процеси.

Цікавими результатами є прямі читання цих файлів, докази того, що дані належать хосту, а не обмеженому поданню контейнера, або доступ до інших procfs/sysfs локацій, які зазвичай маскуються за замовчуванням.

## Checks

Метою цих перевірок є визначити, які шляхи середовища виконання навмисно приховало і чи бачить поточне навантаження все ще зменшену файлову систему, звернену до ядра.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Що тут цікаво:

- Великий список маскованих шляхів є нормальною практикою в жорстко захищених runtime.
- Відсутність маскування для чутливих записів procfs заслуговує на детальнішу перевірку.
- Якщо чутливий шлях доступний, і контейнер також має розширені capabilities або широкі host mounts, ризик експозиції зростає.

## Налаштування runtime за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker визначає список маскованих шляхів за замовчуванням | експонування host proc/sys mounts, `--privileged` |
| Podman | Enabled by default | Podman застосовує масковані шляхи за замовчуванням, якщо їх не розмасковано вручну | `--security-opt unmask=ALL`, цільове розмаскування, `--privileged` |
| Kubernetes | Inherits runtime defaults | Використовує поведінку маскування базового runtime, якщо налаштування Pod не послаблюють експозицію proc | `procMount: Unmasked`, шаблони привілейованих workload, широкі host mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Зазвичай застосовує OCI/runtime масковані шляхи, якщо їх не перевизначено | прямі зміни конфігу runtime, ті самі шляхи послаблення в Kubernetes |

Масковані шляхи зазвичай присутні за замовчуванням. Головна операційна проблема — не їх відсутність у runtime, а навмисне розмаскування або host bind mounts, які нівелюють захист.
{{#include ../../../../banners/hacktricks-training.md}}
