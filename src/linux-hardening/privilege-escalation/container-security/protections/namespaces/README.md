# Простіри імен

{{#include ../../../../../banners/hacktricks-training.md}}

Простіри імен — це функція ядра, яка змушує контейнер відчуватися як «власна машина», хоча насправді це просто дерево процесів хоста. Вони не створюють нового ядра і не віртуалізують усе, але дозволяють ядру показувати різні уявлення про вибрані ресурси різним групам процесів. Це суть ілюзії контейнера: робоче навантаження бачить файлову систему, таблицю процесів, мережевий стек, ім’я хоста, IPC-ресурси та модель ідентичності користувачів/груп, які здаються локальними, хоча базова система є спільною.

Саме тому простори імен — перша концепція, з якою знайомляться більшість людей, коли вивчають, як працюють контейнери. Водночас це одна з найчастіше неправильно зрозумілих концепцій, бо читачі часто припускають, що «є простори імен» означає «безпечна ізоляція». Насправді простір імен ізолює тільки той клас ресурсів, для якого він призначений. Процес може мати приватний PID-простір імен і все одно бути небезпечним, бо має записуване host bind mount. Він може мати приватний network namespace і все одно бути небезпечним, бо зберігає `CAP_SYS_ADMIN` і працює без seccomp. Простіри імен є базовими, але це лише один шар у підсумковому кордоні ізоляції.

## Namespace Types

Linux-контейнери зазвичай покладаються одночасно на кілька типів просторів імен. The **mount namespace** дає процесу окрему таблицю монтувань і, отже, контрольований вид файлової системи. The **PID namespace** змінює видимість і нумерацію процесів, тож робоче навантаження бачить власне дерево процесів. The **network namespace** ізолює інтерфейси, маршрути, сокети та стан брандмауера. The **IPC namespace** ізолює SysV IPC і POSIX черги повідомлень. The **UTS namespace** ізолює ім’я хоста та NIS-домен. The **user namespace** переназначає ідентифікатори користувачів та груп так, що root всередині контейнера не обов’язково означає root на хості. The **cgroup namespace** віртуалізує видиму ієрархію cgroup, а The **time namespace** віртуалізує вибрані часові показники в новіших ядрах.

Кожен з цих просторів імен вирішує іншу задачу. Саме тому практичний аналіз безпеки контейнерів часто зводиться до перевірки того, **які простори імен ізольовані** і **які навмисно розділені з хостом**.

## Host Namespace Sharing

Багато виходів з контейнера починаються не з вразливості ядра. Вони починаються з наміром оператора послабити модель ізоляції. Приклади `--pid=host`, `--network=host`, і `--userns=host` — це **Docker/Podman-style CLI flags**, які тут наведені як конкретні приклади спільного використання просторів імен з хостом. Інші рантайми виражають ту ж ідею інакше. У Kubernetes еквіваленти зазвичай з’являються як налаштування Pod, наприклад `hostPID: true`, `hostNetwork: true`, або `hostIPC: true`. У нижчорівневих стекових рантаймах, таких як containerd або CRI-O, така сама поведінка часто досягається через згенеровану OCI runtime конфігурацію, а не через флаг із тим самим іменем для користувача. У всіх цих випадках результат схожий: робоче навантаження більше не отримує стандартного ізольованого уявлення про простір імен.

Ось чому перевірки просторів імен ніколи не повинні обмежуватися думкою «процес знаходиться в якомусь просторі імен». Важливе питання — чи є простір імен приватним для контейнера, спільним із сусідніми контейнерами, чи приєднаним безпосередньо до хоста. У Kubernetes та сама ідея з’являється через прапорці, такі як `hostPID`, `hostNetwork` і `hostIPC`. Імена змінюються між платформами, але шаблон ризику однаковий: спільний хост-простір імен робить залишкові привілеї контейнера та досяжний стан хоста набагато більш значущими.

## Inspection

Найпростіший огляд:
```bash
ls -l /proc/self/ns
```
Кожен запис — це символічне посилання з ідентифікатором, схожим на inode. Якщо два процеси вказують на той самий ідентифікатор простору імен, вони перебувають в одному просторі імен цього типу. Це робить `/proc` дуже корисним місцем для порівняння поточного процесу з іншими цікавими процесами на машині.

Цих швидких команд часто достатньо, щоб почати:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Звідси наступним кроком є порівняння процесу контейнера з процесами хоста або сусідніми процесами та визначення, чи є namespace насправді приватним чи ні.

### Перелічування екземплярів namespace з хоста

Коли ви вже маєте доступ до хоста і хочете зрозуміти, скільки різних namespace певного типу існує, `/proc` дає швидкий перелік:
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
Якщо ви хочете знайти, які процеси належать певному namespace identifier, замініть `readlink` на `ls -l` і виконайте `grep` за цільовим номером namespace:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Ці команди корисні, оскільки дозволяють визначити, чи працює на хості одне ізольоване робоче навантаження, багато ізольованих навантажень або суміш спільних і приватних екземплярів простору імен.

### Вхід у цільовий простір імен

Коли виконавець має достатні привілеї, `nsenter` — стандартний спосіб приєднатися до простору імен іншого процесу:
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
Мета перерахування цих форм разом не в тому, що кожна оцінка потребує всіх з них, а в тому, що namespace-specific post-exploitation часто стає значно простішою, коли оператор знає точний синтаксис входу замість того, щоб пам'ятати лише форму all-namespaces.

## Pages

Наступні сторінки пояснюють кожен namespace докладніше:

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

Коли ви їх читаєте, тримайте на увазі дві ідеї. По-перше, кожен namespace ізолює лише один тип вигляду. По-друге, приватний namespace корисний лише тоді, коли решта моделі привілеїв все ще робить цю ізоляцію змістовною.

## Налаштування середовища виконання за замовчуванням

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Головне правило портативності просте: **концепція** спільного використання host namespace є спільною для різних runtime, але **синтаксис** специфічний для конкретного runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
