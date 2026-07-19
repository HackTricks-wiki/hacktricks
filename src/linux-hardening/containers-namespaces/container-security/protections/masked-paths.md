# Замасковані шляхи

{{#include ../../../../banners/hacktricks-training.md}}

Замасковані шляхи — це runtime-захист, який приховує від container особливо чутливі файлові системні розташування, що взаємодіють із kernel, шляхом їхнього перекриття bind-mount або іншим способом роблячи їх недоступними. Мета полягає в тому, щоб не дозволити workload безпосередньо взаємодіяти з інтерфейсами, які звичайним applications не потрібні, особливо всередині procfs.

Це важливо, оскільки багато container escapes і трюків, що впливають на host, починаються з читання або запису спеціальних файлів у `/proc` чи `/sys`. Якщо ці розташування замасковані, attacker втрачає прямий доступ до корисної частини kernel control surface навіть після отримання code execution усередині container.

## Робота

Runtimes зазвичай маскують вибрані шляхи, наприклад:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Точний список залежить від runtime та конфігурації host. Важливо, що з погляду container шлях стає недоступним або замінюється, навіть якщо на host він усе ще існує.

## Лабораторна робота

Перевірте конфігурацію masked paths, яку надає Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Перевірте фактичну поведінку монтування всередині робочого навантаження:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Вплив на безпеку

Маскування не створює основний isolation boundary, але усуває кілька високопріоритетних цілей для post-exploitation. Без маскування скомпрометований контейнер може отримати можливість перевіряти стан kernel, читати конфіденційну інформацію про процеси або ключі чи взаємодіяти з об’єктами procfs/sysfs, які ніколи не мали бути доступними application.

## Неправильні конфігурації

Основна помилка — знімати маскування з широких класів шляхів заради зручності або debugging. У Podman це може мати вигляд `--security-opt unmask=ALL` або вибіркового зняття маскування. У Kubernetes надмірно широкий доступ до proc може бути заданий через `procMount: Unmasked`. Ще одна серйозна проблема — відкриття host `/proc` або `/sys` через bind mount, що повністю обходить ідею обмеженого view контейнера.

## Зловживання

Якщо маскування слабке або відсутнє, спочатку визначте, які конфіденційні шляхи procfs/sysfs безпосередньо доступні:
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
Що можуть розкрити ці команди:

- `/proc/timer_list` може розкрити дані про таймери та планувальник хоста. Здебільшого це примітив розвідки, але він підтверджує, що контейнер може читати інформацію, пов’язану з ядром, яка зазвичай прихована.
- `/proc/keys` набагато чутливіший. Залежно від конфігурації хоста, він може розкрити записи keyring, описи ключів і взаємозв’язки між сервісами хоста, що використовують підсистему keyring ядра.
- `/sys/firmware` допомагає визначити режим завантаження, інтерфейси firmware і відомості про платформу, корисні для fingerprinting хоста та розуміння того, чи бачить workload стан на рівні хоста.
- `/proc/config.gz` може розкрити конфігурацію запущеного ядра, що цінно для зіставлення передумов public kernel exploit або розуміння, чому доступна певна функція.
- `/proc/sched_debug` розкриває стан планувальника та часто спростовує інтуїтивне очікування, що PID namespace має повністю приховувати інформацію про непов’язані процеси.

Цікавими результатами є безпосереднє читання цих файлів, ознаки того, що дані належать хосту, а не обмеженому поданню контейнера, або доступ до інших розташувань procfs/sysfs, які зазвичай маскуються за замовчуванням.

## Перевірки

Мета цих перевірок — визначити, які шляхи runtime навмисно приховав і чи все ще бачить поточний workload урізану файлову систему, пов’язану з ядром.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Що тут цікавого:

- Довгий список `masked-path` є нормальним для hardened runtime.
- Відсутність маскування чутливих записів `procfs` заслуговує на детальніший аналіз.
- Якщо чутливий path доступний, а контейнер також має потужні capabilities або широкі mounts, таке розкриття має більше значення.

## Налаштування runtime за замовчуванням

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає стандартний список masked paths | відкриття host `proc/sys` mounts, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує стандартні masked paths, якщо їх не розмаскувати вручну | `--security-opt unmask=ALL`, вибіркове розмаскування, `--privileged` |
| Kubernetes | Успадковує налаштування runtime | Використовує поведінку маскування базового runtime, якщо налаштування Pod не послаблюють захист `proc` | `procMount: Unmasked`, шаблони privileged workload, широкі host mounts |
| containerd / CRI-O under Kubernetes | Налаштування runtime за замовчуванням | Зазвичай застосовує masked paths OCI/runtime, якщо їх не перевизначено | прямі зміни конфігурації runtime, ті самі способи послаблення в Kubernetes |

Masked paths зазвичай присутні за замовчуванням. Основна операційна проблема полягає не у відсутності masked paths у runtime, а в навмисному розмаскуванні або host bind mounts, які нівелюють цей захист.
{{#include ../../../../banners/hacktricks-training.md}}
