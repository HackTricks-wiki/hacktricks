# Простори імен

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces — це можливість ядра, яка робить контейнер відчутним як «власна машина», хоча насправді це просто дерево процесів хоста. Вони не створюють нове ядро і не віртуалізують усе, але дозволяють ядру показувати різні уявлення про окремі ресурси різним групам процесів. Це ядро ілюзії контейнера: робоче навантаження бачить файлову систему, таблицю процесів, мережевий стек, hostname, IPC-ресурси та модель ідентичності користувача/групи, які здаються локальними, хоча підлягаюча система спільна.

Ось чому namespaces — перше поняття, з яким стикаються більшість людей, коли вивчають, як працюють контейнери. Водночас це одне з найпоширеніше невірно зрозумілих понять, бо читачі часто припускають, що «has namespaces» означає «є безпечно ізольованим». Насправді namespace ізолює лише той клас ресурсів, для якого він призначений. Процес може мати приватний PID namespace і все одно бути небезпечним, тому що має записуваний host bind mount. Він може мати приватний network namespace і все одно бути небезпечним, бо зберігає `CAP_SYS_ADMIN` і запускається без seccomp. Namespaces є фундаментальними, але вони — лише один шар у кінцевому межевому захисті.

## Типи просторів імен

Linux контейнери зазвичай одночасно покладаються на кілька типів namespace. The **mount namespace** дає процесу окрему таблицю маунтів і, отже, контрольований огляд файлової системи. The **PID namespace** змінює видимість і нумерацію процесів, тож робоче навантаження бачить власне дерево процесів. The **network namespace** ізолює інтерфейси, маршрути, сокети та стан firewall. The **IPC namespace** ізолює SysV IPC і POSIX message queues. The **UTS namespace** ізолює hostname і NIS domain name. The **user namespace** перенаправляє ідентифікатори користувачів і груп так, що root всередині контейнера не обов’язково означає root на хості. The **cgroup namespace** віртуалізує видиму ієрархію cgroup, а The **time namespace** віртуалізує обрані годинники в новіших ядрах.

Кожен із цих namespace вирішує різну задачу. Саме тому практичний аналіз безпеки контейнерів часто зводиться до перевірки того, **які простори імен ізольовано**, і **які з них навмисно поділені з хостом**.

## Спільне використання просторів імен хоста

Багато breakout-ів контейнера не починаються з вразливості ядра. Вони починаються з того, що оператор навмисно послаблює модель ізоляції. Приклади `--pid=host`, `--network=host` і `--userns=host` — це **Docker/Podman-style CLI flags**, наведені тут як конкретні приклади спільного використання просторів імен з хостом. Інші рантайми виражають ту саму ідею інакше. В Kubernetes еквіваленти зазвичай з’являються як налаштування Pod, наприклад `hostPID: true`, `hostNetwork: true` або `hostIPC: true`. В більш низькорівневих стекках рантаймів, таких як containerd або CRI-O, та сама поведінка часто досягається через згенеровану OCI runtime конфігурацію замість користувацького прапора з тією ж назвою. У всіх цих випадках результат подібний: робоче навантаження більше не отримує стандартний ізольований вигляд namespace.

Ось чому огляд просторів імен не повинен зупинятися на «процес знаходиться в якомусь namespace». Важливе питання — чи є namespace приватним для контейнера, спільним із сусідніми контейнерами, чи приєднаним безпосередньо до хоста. В Kubernetes та сама ідея фігурує з прапорцями такими як `hostPID`, `hostNetwork` і `hostIPC`. Назви змінюються між платформами, але патерн ризику однаковий: спільний host namespace робить залишкові привілеї контейнера та доступний стан хоста набагато більш значущими.

## Перевірка

Найпростіший огляд такий:
```bash
ls -l /proc/self/ns
```
Кожен запис є символічним посиланням з ідентифікатором, схожим на inode. Якщо два процеси вказують на один і той же ідентифікатор namespace, вони знаходяться в одному і тому ж namespace цього типу. Це робить `/proc` дуже корисним місцем для порівняння поточного процесу з іншими цікавими процесами на машині.

Ці швидкі команди часто достатні, щоб почати:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Звідти наступний крок — порівняти процес контейнера з процесами на хості або сусідніми процесами й визначити, чи є простір імен справді приватним.

### Перерахунок екземплярів простору імен на хості

Коли ви вже маєте доступ до хоста і хочете дізнатися, скільки різних екземплярів простору імен певного типу існує, `/proc` дає швидкий огляд:
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
Якщо ви хочете дізнатись, які процеси належать певному ідентифікатору простору імен, замініть `readlink` на `ls -l` і використайте grep для пошуку цільового номера простору імен:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ці команди корисні, оскільки дозволяють визначити, чи host запускає одне ізольоване робоче навантаження, багато ізольованих робочих навантажень або суміш спільних і приватних екземплярів простору імен.

### Вхід у цільовий простір імен

Якщо виконавець має достатні привілеї, `nsenter` — стандартний спосіб приєднатися до простору імен іншого процесу:
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
Мета перерахування цих форм разом не в тому, що під час кожної оцінки потрібні всі вони, а в тому, що namespace-specific post-exploitation часто стає набагато простішою, коли оператор знає точний синтаксис входу замість того, щоб пам'ятати лише all-namespaces форму.

## Сторінки

Наступні сторінки пояснюють кожен namespace детальніше:

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

Коли будете їх читати, майте на увазі дві ідеї. По-перше, кожен namespace ізолює лише один тип подання. По-друге, приватний namespace корисний лише тоді, коли решта моделі привілеїв все ще робить цю ізоляцію значущою.

## Налаштування Runtime за замовчуванням

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | За замовчуванням створюються нові mount, PID, network, IPC і UTS namespaces; user namespaces доступні, але не увімкнені за замовчуванням у стандартних rootful налаштуваннях | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | За замовчуванням створюються нові namespaces; rootless Podman автоматично використовує user namespace; значення за замовчуванням для cgroup namespace залежать від версії cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / пропуск user-namespace opt-in, налаштування привілейованих робочих навантажень |
| containerd / CRI-O under Kubernetes | Зазвичай слідують Kubernetes Pod defaults | те ж саме, що й для Kubernetes; прямі CRI/OCI специфікації також можуть запитувати приєднання до host namespace |

Головне правило портативності просте: **concept** спільного використання host namespace є поширеним серед runtime-ів, але **syntax** залежить від конкретного runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
