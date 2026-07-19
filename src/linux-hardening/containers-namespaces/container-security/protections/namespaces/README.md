# Простори імен

{{#include ../../../../../banners/hacktricks-training.md}}

Простори імен — це функція ядра, завдяки якій контейнер виглядає як «власна машина», хоча насправді він є лише деревом процесів хоста. Вони не створюють нового ядра й не віртуалізують усе, але дають ядру змогу надавати різним групам процесів різні уявлення про вибрані ресурси. Це основа ілюзії контейнера: workload бачить файлову систему, таблицю процесів, мережевий стек, ім’я хоста, ресурси IPC і модель ідентифікації користувачів та груп, які здаються локальними, хоча базова система є спільною.

Саме тому простори імен — це перше поняття, з яким стикається більшість людей під час вивчення роботи контейнерів. Водночас це одне з найбільш неправильно зрозумілих понять, оскільки читачі часто припускають, що «наявність просторів імен» означає «безпечну ізоляцію». Насправді простір імен ізолює лише конкретний клас ресурсів, для якого його створено. Процес може мати приватний PID namespace і все одно бути небезпечним, якщо має доступний для запису bind mount хоста. Він може мати приватний network namespace і все одно бути небезпечним, якщо зберігає `CAP_SYS_ADMIN` та працює без seccomp. Простори імен є фундаментальними, але вони лише один із рівнів загального кордону безпеки.

## Типи просторів імен

Linux-контейнери зазвичай одночасно використовують кілька типів просторів імен. **Mount namespace** надає процесу окрему таблицю монтувань і, відповідно, контрольоване уявлення про файлову систему. **PID namespace** змінює видимість і нумерацію процесів, завдяки чому workload бачить власне дерево процесів. **Network namespace** ізолює інтерфейси, маршрути, сокети та стан firewall. **IPC namespace** ізолює SysV IPC і черги повідомлень POSIX. **UTS namespace** ізолює ім’я хоста та ім’я домену NIS. **User namespace** перепризначає ідентифікатори користувачів і груп, тому root усередині контейнера не обов’язково означає root на хості. **Cgroup namespace** віртуалізує видиму ієрархію cgroup, а **time namespace** у новіших ядрах віртуалізує вибрані годинники.

Кожен із цих просторів імен розв’язує окрему проблему. Саме тому практичний аналіз безпеки контейнерів часто зводиться до перевірки, **які простори імен ізольовані**, а **які навмисно спільно використовуються з хостом**.

## Спільне використання просторів імен хоста

Багато container breakouts починаються не з уразливості ядра. Вони починаються з того, що оператор навмисно послаблює модель ізоляції. Приклади `--pid=host`, `--network=host` і `--userns=host` — це **Docker/Podman-style CLI flags**, які тут використовуються як конкретні приклади спільного використання просторів імен хоста. Інші runtimes виражають ту саму ідею інакше. У Kubernetes відповідники зазвичай з’являються як налаштування Pod, наприклад `hostPID: true`, `hostNetwork: true` або `hostIPC: true`. У низькорівневих runtime-стеках, таких як containerd або CRI-O, такої самої поведінки часто досягають через згенеровану конфігурацію OCI runtime, а не через користувацький прапорець із такою самою назвою. У всіх цих випадках результат подібний: workload більше не отримує типове ізольоване уявлення про простори імен.

Саме тому під час перевірки просторів імен не можна зупинятися на твердженні «процес перебуває в якомусь просторі імен». Важливим є питання, чи є простір імен приватним для контейнера, спільним із сусідніми контейнерами або безпосередньо приєднаним до хоста. У Kubernetes та сама ідея проявляється у flags на кшталт `hostPID`, `hostNetwork` і `hostIPC`. Назви відрізняються між платформами, але pattern ризику той самий: спільний простір імен хоста робить решту привілеїв контейнера та доступний стан хоста значно важливішими.

## Перевірка

Найпростіший огляд такий:
```bash
ls -l /proc/self/ns
```
Кожен запис є символічним посиланням з ідентифікатором, подібним до inode. Якщо два процеси вказують на один і той самий ідентифікатор namespace, вони перебувають в одному namespace цього типу. Це робить `/proc` дуже корисним місцем для порівняння поточного процесу з іншими цікавими процесами на машині.

Для початку часто достатньо цих коротких команд:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Звідти наступним кроком є порівняння процесу контейнера з процесами host або сусідніх контейнерів і визначення, чи є namespace справді приватним.

### Перелік екземплярів namespace з host

Якщо ви вже отримали доступ до host і хочете зрозуміти, скільки окремих namespace певного типу існує, `/proc` надає швидкий інвентар:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Якщо потрібно визначити, які процеси належать одному конкретному ідентифікатору namespace, замініть `readlink` на `ls -l` і виконайте grep для пошуку номера цільового namespace:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ці команди корисні, оскільки дають змогу визначити, чи працює на хості одне ізольоване робоче навантаження, багато ізольованих робочих навантажень або поєднання спільних і приватних екземплярів просторів імен.

### Вхід до цільового простору імен

Якщо викликач має достатні привілеї, `nsenter` є стандартним способом приєднатися до простору імен іншого процесу:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Сенс наведення цих форм разом не в тому, що кожна оцінка потребує їх усіх, а в тому, що специфічний для namespace post-exploitation часто стає значно простішим, коли оператор знає точний синтаксис входу, а не пам’ятає лише форму для всіх namespace.

## Сторінки

На наведених нижче сторінках кожен namespace пояснюється докладніше:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Під час читання пам’ятайте про дві ідеї. По-перше, кожен namespace ізолює лише один тип представлення. По-друге, приватний namespace корисний лише тоді, коли решта моделі привілеїв і надалі робить цю ізоляцію значущою.

## Типові налаштування runtime

| Runtime / платформа | Типова конфігурація namespace | Поширене ручне послаблення |
| --- | --- | --- |
| Docker Engine | Нові mount, PID, network, IPC і UTS namespace за замовчуванням; user namespace доступні, але зазвичай не ввімкнені у стандартних rootful-конфігураціях | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Нові namespace за замовчуванням; rootless Podman автоматично використовує user namespace; значення cgroup namespace за замовчуванням залежать від версії cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods **не** використовують спільні host PID, network або IPC за замовчуванням; мережа Pod є приватною для Pod, а не для кожного окремого контейнера; user namespace вмикаються явно через `spec.hostUsers: false` у підтримуваних кластерах | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / відсутність opt-in для user namespace, налаштування privileged workload |
| containerd / CRI-O під Kubernetes | Зазвичай дотримуються типових налаштувань Kubernetes Pod | те саме, що в рядку Kubernetes; прямі CRI/OCI-специфікації також можуть запитувати приєднання до host namespace |

Головне правило переносимості просте: **концепція** спільного використання host namespace є спільною для різних runtime, але **синтаксис** залежить від runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
