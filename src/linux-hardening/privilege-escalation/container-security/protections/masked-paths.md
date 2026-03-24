# Приховані шляхи

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths — це runtime захисти, які приховують особливо чутливі до kernel файлові локації від container шляхом bind-mounting поверх них або іншим чином роблячи їх недоступними. Метою є запобігти тому, щоб workload безпосередньо взаємодіяв з інтерфейсами, які звичайним додаткам не потрібні, особливо всередині procfs.

Це важливо, бо багато container escapes та трюків, що впливають на host, починаються з читання або запису спеціальних файлів у `/proc` або `/sys`. Якщо ці локації замасковані, attacker втрачає прямий доступ до корисної частини control surface kernel навіть після отримання code execution всередині контейнера.

## Робота

Runtimes зазвичай маскують обрані шляхи, такі як:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Точний список залежить від runtime та конфігурації host. Важливою властивістю є те, що з точки зору container шлях стає недоступним або заміщеним, хоча на host він і далі існує.

## Лаб

Перевірте конфігурацію masked-path, яку експонує Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Перевірте фактичну поведінку mount всередині робочого навантаження:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Вплив на безпеку

Маскування не створює головну межу ізоляції, але воно усуває кілька цінних цілей для post-exploitation. Без маскування скомпрометований container може інспектувати стан ядра, читати конфіденційну інформацію про процеси або ключі, або взаємодіяти з procfs/sysfs об'єктами, які ніколи не повинні були бути видимими для додатка.

## Помилки конфігурації

Головна помилка — розмаскування широких груп шляхів заради зручності або налагодження. У Podman це може виглядати як `--security-opt unmask=ALL` або вибіркове розмаскування. У Kubernetes надто широка експозиція proc може проявлятися через `procMount: Unmasked`. Ще однією серйозною проблемою є експонування хостової `/proc` або `/sys` через bind mount, що повністю обходить ідею звуженого вигляду контейнера.

## Зловживання

Якщо маскування слабке або відсутнє, почніть із визначення, які чутливі шляхи procfs/sysfs доступні напряму:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Якщо нібито прихований шлях доступний, ретельно його перевірте:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Що можуть виявити ці команди:

- `/proc/timer_list` може розкрити host timer та scheduler дані. Це здебільшого reconnaissance primitive, але підтверджує, що container може читати kernel-facing інформацію, яка зазвичай прихована.
- `/proc/keys` є набагато більш чутливим. Залежно від конфігурації host, він може показати keyring entries, описи ключів і взаємозв'язки між host services, що використовують kernel keyring subsystem.
- `/sys/firmware` допомагає визначити boot mode, firmware interfaces і деталі платформи, корисні для host fingerprinting та для розуміння, чи workload бачить host-level state.
- `/proc/config.gz` може показати running kernel configuration, що цінно для зіставлення public kernel exploit prerequisites або для розуміння, чому певна функція доступна.
- `/proc/sched_debug` відкриває scheduler state і часто обходить інтуїтивне очікування, що PID namespace повністю приховує несуміжну інформацію про процеси.

Цікаві результати включають прямі читання цих файлів, докази того, що дані належать host, а не обмеженому container view, або доступ до інших procfs/sysfs локацій, які зазвичай замасковані за замовчуванням.

## Checks

Мета цих перевірок — визначити, які шляхи runtime навмисно сховав і чи поточний workload все ще бачить зменшене kernel-facing filesystem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Що тут цікаво:

- Довгий masked-path list є нормою в жорстко захищених середовищах виконання.
- Відсутність маскування для конфіденційних записів procfs заслуговує на детальнішу перевірку.
- Якщо конфіденційний шлях доступний, і контейнер також має потужні capabilities або широкі mounts, експозиція стає більш критичною.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає типовий masked path list | експонування host proc/sys mounts, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує типові masked paths, якщо їх не знято вручну | `--security-opt unmask=ALL`, цілеспрямоване unmasking, `--privileged` |
| Kubernetes | Наслідує налаштування runtime за замовчуванням | Використовує поведінку маскування підлягаючого runtime, якщо налаштування Pod не послаблюють експозицію proc | `procMount: Unmasked`, шаблони привілейованих workload, широкі host mounts |
| containerd / CRI-O under Kubernetes | Стан runtime за замовчуванням | Зазвичай застосовує OCI/runtime masked paths, якщо не перевизначено | прямі зміни конфігурації runtime, ті самі шляхи послаблення в Kubernetes |

Masked paths зазвичай присутні за замовчуванням. Головна операційна проблема — не їх відсутність у runtime, а навмисне unmasking або host bind mounts, що нівелюють захист.
{{#include ../../../../banners/hacktricks-training.md}}
