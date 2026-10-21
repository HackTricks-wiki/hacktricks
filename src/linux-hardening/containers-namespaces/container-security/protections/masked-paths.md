# Замасковані шляхи

{{#include ../../../../banners/hacktricks-training.md}}

Замасковані шляхи — це захисти під час виконання, які приховують особливо чутливі шляхи файлової системи, доступні ядру, від контейнера: поверх них монтують інші файлові системи або іншим чином роблять їх недоступними. Специфікація середовища виконання OCI визначає `maskedPaths` як абсолютні шляхи, які не повинні бути доступні для читання всередині контейнера. <sup>[[1]](#references)</sup>

Це важливо, оскільки багато способів втечі з контейнера й атак, що впливають на хост, починаються з читання або запису спеціальних файлів у `/proc` або `/sys`. Якщо ці шляхи замасковані, зловмисник втрачає прямий доступ до корисної частини інтерфейсу керування ядром, навіть отримавши можливість виконувати код усередині контейнера.

## Робота

Середовища виконання зазвичай маскують вибрані шляхи, наприклад:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Точний список залежить від середовища виконання та конфігурації хоста. Важливо те, що з погляду контейнера шлях стає недоступним або замінюється, хоча на хості він і далі існує.

## Лабораторна робота

Перевірте конфігурацію замаскованих шляхів, яку надає Docker:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Перевірте фактичну поведінку монтування всередині робочого навантаження:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Перелічений шлях не обов’язково доступний для читання: runc може замаскувати файл за допомогою bind mount на `/dev/null`, а каталог — за допомогою доступного лише для читання порожнього tmpfs. Перевіряйте точку монтування, а не лише те, чи виконується `ls`. <sup>[[4]](#references)</sup>

## Вплив на безпеку

Маскування не створює основної межі ізоляції, але усуває кілька цінних цілей для post-exploitation. Без маскування скомпрометований контейнер може мати змогу перевіряти стан ядра, читати конфіденційну інформацію про процеси або ключі чи взаємодіяти з об’єктами procfs/sysfs, які ніколи не мали бути доступними застосунку.

## Неправильні конфігурації

Основна помилка — знімати маскування з широких класів шляхів заради зручності або налагодження. У Podman це може виглядати як `--security-opt unmask=ALL` або вибіркове зняття маскування. <sup>[[2]](#references)</sup> У Kubernetes надто широке надання доступу до proc може проявлятися через `procMount: Unmasked`; поточна версія Kubernetes вимагає для цього параметра `spec.hostUsers: false` (user namespace), тоді як у версіях 1.12–1.29 ця вимога не застосовувалася. <sup>[[3]](#references)</sup> Ще одна серйозна проблема — надання доступу до хостових `/proc` або `/sys` через bind mount, що повністю нівелює ідею обмеженого представлення контейнера.

## Зловживання

Якщо маскування слабке або відсутнє, спершу визначте, до яких чутливих шляхів procfs/sysfs є прямий доступ:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Якщо шлях, який нібито замасковано, доступний, уважно його перевірте:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Що можуть виявити ці команди:

- `/proc/timer_list` може розкрити дані про таймери хоста та планувальник. Здебільшого це засіб розвідки, але він підтверджує, що контейнер може читати інформацію на рівні ядра, яка зазвичай прихована.
- `/proc/keys` містить лише метадані ключів, на які читач має дозвіл **перегляду**, з урахуванням перевірок LSM. Він може розкрити типи ключів і описи, але не вміст ключів. <sup>[[6]](#references)</sup>
- `/sys/firmware` допомагає визначити режим завантаження, інтерфейси прошивки та особливості платформи, що корисно для ідентифікації хоста й розуміння того, чи бачить робоче навантаження стан на рівні хоста.
- `/proc/config.gz` може розкрити конфігурацію запущеного ядра. Це корисно, щоб перевірити передумови публічних експлойтів ядра або зрозуміти, чому доступна певна функція.
- `/proc/sched_debug` розкриває стан планувальника й часто спростовує інтуїтивне очікування, що PID namespace має повністю приховувати інформацію про сторонні процеси.

Цікавими результатами можуть бути безпосереднє читання цих файлів, свідчення того, що дані належать хосту, а не обмеженому середовищу контейнера, або доступ до інших розташувань procfs/sysfs, які зазвичай маскуються за замовчуванням.

### Гонка джерела маскування під час запуску контейнера

У вразливих реалізаціях runc маскування файлів залежить від inode `/dev/null` контейнера. Зловмисник, який може організувати паралельний запуск контейнерів зі спільними монтуваннями, зокрема паралельних кроків BuildKit, може створити гонку під час запуску й видалити `/dev/null` до того, як runc змонтує його поверх замаскованих файлів procfs. Тоді середовище виконання сприймає відсутність **джерела** так, наче ціль маскування відсутня, і без повідомлення пропускає маскування цих файлів. Збій залежить від гонки під час налаштування середовища виконання; видалення `/dev/null` після запуску не скасовує вже встановлене маскування. <sup>[[4]](#references)</sup>

Після контрольованого тесту порівняйте запитаний список маскування з точними точками монтування всередині нового контейнера. <sup>[[4]](#references)</sup> `findmnt -M` перевіряє вказану точку монтування, а не переходить до батьківського монтування; якщо `findmnt` відсутній, перевірте `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Успішне виконання `ls` або порожній вивід `cat` не доводять, що маскування відсутнє. <sup>[[4]](#references)</sup>

Скористайтеся [перевірками нижче](#checks), щоб порівняти запитане маскування з точними точками монтування в новому контейнері.

Пропущене маскування файлу може відкрити дані procfs, якщо це дозволяють звичайні права доступу та політика LSM. Саме по собі воно **не** робить `/proc/sys` доступним для запису: це окремий контроль [read-only-path](read-only-paths.md). Окрему підміну символічного посилання `/dev/null`, яка може перенаправити bind mount на доступну для запису ціль procfs, описано в розділі [гонка середовища виконання PID namespace](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Перевірки

Мета цих перевірок — визначити, які шляхи середовище виконання навмисно приховало та чи бачить поточне робоче навантаження й далі скорочену файлову систему, що надає доступ до даних ядра.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Використовуйте перевірку точного mount, оскільки masked file усе ще може існувати, а читання може повертати порожній результат із `/dev/null`. Відсутній mountpoint — це знахідка, яку слід дослідити, а не доказ того, що дані хоста доступні для читання. <sup>[[4]](#references)[[5]](#references)</sup>

На що тут варто звернути увагу:

- Довгий список masked paths — це норма для hardened runtime.
- Відсутність маскування на чутливих записах procfs потребує ретельнішої перевірки.
- Якщо чутливий шлях доступний, а контейнер також має широкі capabilities або широкі mounts, це створює більший ризик.

## Типові налаштування runtime

| Runtime / платформа | Типовий стан | Типова поведінка | Поширені способи послаблення вручну |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає типовий список masked paths | відкриття host mounts proc/sys, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує типові masked paths, якщо їх не скасувати вручну | `--security-opt unmask=ALL`, вибіркове скасування маскування, `--privileged` |
| Kubernetes | Успадковує типові налаштування runtime | Використовує поведінку маскування базового runtime, якщо налаштування Pod не послаблюють захист proc | `procMount: Unmasked` (у поточних версіях вимагає `hostUsers: false`), шаблони привілейованих workload, широкі host mounts |
| containerd / CRI-O у Kubernetes | Типове налаштування runtime | Зазвичай застосовує masked paths OCI/runtime, якщо їх не перевизначено | безпосередня зміна конфігурації runtime, ті самі способи послаблення в Kubernetes |

Зазвичай masked paths присутні за замовчуванням. Головна операційна проблема — не їх відсутність у runtime, а навмисне скасування маскування або host bind mounts, які нівелюють захист.

## References

- [1] [Open Container Initiative — конфігурація Linux-контейнерів: Masked Paths](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Документація Podman — параметри безпеки `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Документація Kubernetes — ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Попередження runc: race condition джерела mount для masked path](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Посібник findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Посібник keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
