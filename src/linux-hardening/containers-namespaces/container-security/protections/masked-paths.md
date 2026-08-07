# Замасковані шляхи

{{#include ../../../../banners/hacktricks-training.md}}

Замасковані шляхи — це runtime-захист, який приховує особливо чутливі файлові системні розташування, що взаємодіють із kernel, від container, монту́ючи поверх них bind-mount або іншим чином роблячи їх недоступними. Мета полягає в тому, щоб не дозволити workload безпосередньо взаємодіяти з інтерфейсами, які звичайним applications не потрібні, особливо всередині procfs.

Це важливо, оскільки багато container escapes і трюків, що впливають на host, починаються з читання або запису спеціальних файлів у `/proc` або `/sys`. Якщо ці розташування замасковані, attacker втрачає прямий доступ до корисної частини kernel control surface навіть після отримання code execution усередині container.

## Операція

Runtimes зазвичай маскують вибрані шляхи, такі як:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Точний список залежить від runtime і конфігурації host. Важливо, що з точки зору container шлях стає недоступним або замінюється, навіть якщо на host він усе ще існує.

## Лабораторна робота

Перегляньте конфігурацію masked paths, доступну в Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Перевірте фактичну поведінку монтування всередині workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Вплив на безпеку

Маскування не створює основну межу ізоляції, але усуває кілька високопріоритетних цілей для post-exploitation. Без маскування скомпрометований container може отримати можливість перевіряти стан kernel, читати чутливі відомості про процеси або ключі чи взаємодіяти з об'єктами procfs/sysfs, які ніколи не мали бути видимими для application.

## Неправильні конфігурації

Основна помилка полягає в розмаскуванні широких класів шляхів заради зручності або debugging. У Podman це може мати вигляд `--security-opt unmask=ALL` або цільового розмаскування. У Kubernetes надмірно широке розкриття proc може бути реалізоване через `procMount: Unmasked`. Ще одна серйозна проблема — відкриття host `/proc` або `/sys` через bind mount, що повністю обходить ідею обмеженого container view.

## Зловживання

Якщо маскування слабке або відсутнє, почніть із визначення чутливих шляхів procfs/sysfs, до яких можна безпосередньо отримати доступ:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Якщо шлях, який нібито замасковано, доступний, уважно перевірте його:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Що можуть виявити ці команди:

- `/proc/timer_list` може розкрити дані про таймери та scheduler хоста. Здебільшого це reconnaissance primitive, але вона підтверджує, що container може читати kernel-facing інформацію, яка зазвичай прихована.
- `/proc/keys` є набагато чутливішим. Залежно від конфігурації хоста, він може розкрити записи keyring, описи ключів і зв’язки між сервісами хоста, які використовують підсистему kernel keyring.
- `/sys/firmware` допомагає визначити режим завантаження, firmware interfaces і деталі платформи, корисні для fingerprinting хоста та розуміння того, чи бачить workload стан на рівні хоста.
- `/proc/config.gz` може розкрити конфігурацію запущеного kernel, що важливо для зіставлення передумов public kernel exploit або розуміння, чому доступна певна feature.
- `/proc/sched_debug` розкриває стан scheduler і часто спростовує інтуїтивне припущення, що PID namespace має повністю приховувати інформацію про непов’язані процеси.

Цікавими результатами є безпосереднє читання таких файлів, докази того, що дані належать хосту, а не обмеженому container view, або доступ до інших розташувань procfs/sysfs, які зазвичай маскуються за замовчуванням.

## Перевірки

Мета цих перевірок — визначити, які шляхи runtime навмисно приховав і чи бачить поточний workload досі зменшену kernel-facing файлову систему.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Що тут цікаво:

- Довгий список masked paths є нормальним для hardened runtimes.
- Відсутність masking для чутливих записів procfs заслуговує на ретельнішу перевірку.
- Якщо чутливий шлях доступний, а контейнер також має потужні capabilities або широкі mounts, exposure стає важливішим.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає стандартний список masked paths | відкриття host proc/sys mounts, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує стандартні masked paths, якщо їх не розмаскувати вручну | `--security-opt unmask=ALL`, цільове розмаскування, `--privileged` |
| Kubernetes | Успадковує defaults runtime | Використовує behavior underlying runtime щодо masking, якщо налаштування Pod не послаблюють proc exposure | `procMount: Unmasked`, privileged workload patterns, широкі host mounts |
| containerd / CRI-O under Kubernetes | Default runtime | Зазвичай застосовує masked paths OCI/runtime, якщо їх не перевизначено | прямі зміни конфігурації runtime, ті самі шляхи послаблення Kubernetes |

Masked paths зазвичай присутні за замовчуванням. Основна operational проблема полягає не у відсутності в runtime, а в навмисному розмаскуванні або host bind mounts, які нівелюють цей захист.

{{#include ../../../../banners/hacktricks-training.md}}
